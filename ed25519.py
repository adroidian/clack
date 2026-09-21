#!/usr/bin/env python3
"""Ed25519 sign/verify/keygen, pure stdlib.

This is the public-domain reference implementation by Daniel J. Bernstein,
Niels Duif, Tanja Lange, Peter Schwabe and Bo-Yin Yang
(http://ed25519.cr.yp.to/python/ed25519.py), trimmed to keygen/sign/verify
and wrapped in a small friendly API.

Vendored (not a new dependency) because the relay is stdlib-only by design
and neither `cryptography` nor PyNaCl is guaranteed on every machine that
runs it (verified absent 2026-09-21). Pure-Python signing costs ~50-200ms
per operation -- fine for invite flows, which are rare. Do NOT use this for
high-throughput signing; that is out of scope for the relay.
"""

import hashlib
import secrets as _secrets

b = 256
q = (1 << 255) - 19
l = (1 << 252) + 27742317777372353535851937790883648493


def _H(m):
    return hashlib.sha512(m).digest()


def _expmod(base, exp, mod):
    if exp == 0:
        return 1
    t = _expmod(base, exp // 2, mod) ** 2 % mod
    if exp & 1:
        t = (t * base) % mod
    return t


def _inv(x):
    return _expmod(x, q - 2, q)


_d = -121665 * _inv(121666)
_I = _expmod(2, (q - 1) // 4, q)


def _xrecover(y):
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = _expmod(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0:
        x = (x * _I) % q
    if x % 2 != 0:
        x = q - x
    return x


_By = 4 * _inv(5)
_Bx = _xrecover(_By)
_B = [_Bx % q, _By % q]


def _edwards(P, Q):
    # Twisted Edwards addition for a*x^2 + y^2 = 1 + d*x^2*y^2 with a = -1
    # (Ed25519). NOTE the y-numerator is (y1*y2 + x1*x2): the "- a*x1*x2"
    # term becomes "+" when a = -1. Getting this sign wrong produces a
    # self-consistent-but-wrong group law that fails the l*B == identity
    # check -- which is exactly how the bug was caught (2026-09-21).
    x1, y1 = P[0], P[1]
    x2, y2 = Q[0], Q[1]
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _d * x1 * x2 * y1 * y2)
    return [x3 % q, y3 % q]


def _scalarmult(P, e):
    if e == 0:
        return [0, 1]
    Q = _scalarmult(P, e // 2)
    Q = _edwards(Q, Q)
    if e & 1:
        Q = _edwards(Q, P)
    return Q


def _encodeint(y):
    bits = [(y >> i) & 1 for i in range(b)]
    return b"".join(
        bytes([sum(bits[i * 8 + j] << j for j in range(8))]) for i in range(b // 8)
    )


def _encodepoint(P):
    x, y = P[0], P[1]
    bits = [(y >> i) & 1 for i in range(b - 1)] + [x & 1]
    return b"".join(
        bytes([sum(bits[i * 8 + j] << j for j in range(8))]) for i in range(b // 8)
    )


def _bit(h, i):
    return (h[i // 8] >> (i % 8)) & 1


def _publickey(sk):
    h = _H(sk)
    a = 2 ** (b - 2) + sum(2**i * _bit(h, i) for i in range(3, b - 2))
    return _encodepoint(_scalarmult(_B, a))


def _Hint(m):
    h = _H(m)
    return sum(2**i * _bit(h, i) for i in range(2 * b))


def _signature(m, sk, pk):
    h = _H(sk)
    a = 2 ** (b - 2) + sum(2**i * _bit(h, i) for i in range(3, b - 2))
    r = _Hint(h[b // 8 : b // 4] + m)
    R = _scalarmult(_B, r)
    S = (r + _Hint(_encodepoint(R) + pk + m) * a) % l
    return _encodepoint(R) + _encodeint(S)


def _isoncurve(P):
    x, y = P[0], P[1]
    return (-x * x + y * y - 1 - _d * x * x * y * y) % q == 0


def _decodeint(s):
    return sum(2**i * _bit(s, i) for i in range(b))


def _decodepoint(s):
    y = sum(2**i * _bit(s, i) for i in range(b - 1))
    sign = _bit(s, b - 1)
    x = _xrecover(y)
    if x & 1 != sign:
        x = q - x
    P = [x, y]
    if not _isoncurve(P):
        raise ValueError("decoding point that is not on curve")
    return P


def _checkvalid(s, m, pk):
    if len(s) != b // 4:
        raise ValueError("signature length is wrong")
    if len(pk) != b // 8:
        raise ValueError("public-key length is wrong")
    R = _decodepoint(s[0 : b // 8])
    A = _decodepoint(pk)
    S = _decodeint(s[b // 8 : b // 4])
    h = _Hint(_encodepoint(R) + pk + m)
    v1 = _scalarmult(_B, S)
    v2 = _edwards(R, _scalarmult(A, h))
    return v1 == v2


# --- Friendly API -----------------------------------------------------------


def keygen():
    """Generate a fresh ed25519 keypair. Returns (seed_bytes, pubkey_bytes)."""
    seed = _secrets.token_bytes(32)
    return seed, _publickey(seed)


def sign(seed, msg):
    """Sign msg (bytes) with the 32-byte seed. Returns 64-byte signature."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    return _signature(bytes(msg), bytes(seed), _publickey(bytes(seed)))


def verify(pubkey, signature, msg):
    """Verify. Returns True/False, never raises on bad input."""
    try:
        return bool(_checkvalid(bytes(signature), bytes(msg), bytes(pubkey)))
    except Exception:
        return False
