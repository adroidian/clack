#!/usr/bin/env python3
"""Ed25519 sign/verify/keygen, pure stdlib.

This is the public-domain reference implementation by Daniel J. Bernstein,
Niels Duif, Tanja Lange, Peter Schwabe and Bo-Yin Yang
(http://ed25519.cr.yp.to/python/ed25519.py), trimmed to keygen/sign/verify
and wrapped in a small friendly API.

Vendored (not a new dependency) because the relay is stdlib-only by design
and neither `cryptography` nor PyNaCl is guaranteed on every machine that
runs it (verified absent 2026-09-21).

Security posture: this is the DJB reference implementation, which is not
constant-time (double-and-add branches on secret scalar bits). That matches
the reference and is acceptable here: the relay only ever verifies
(all inputs public), and signing happens on the key owner's own machine.
Do not use this module where a local timing adversary is in scope.

v0.2.12 performance rework (2026-09-23): the original affine formulas
inverted twice per point addition -- each inversion a full 255-bit modular
exponentiation in pure Python -- costing ~3.1s per sign/verify on this VM.
The group law below uses extended coordinates (Hisilop-Wong-Carter-Dawson):
additions/doublings need only multiplications, with a single inversion when
converting back to affine. Measured tens of ms per operation after the
rework. Signatures are deterministic, so the rework is verified
byte-identical against the old affine implementation on random inputs
(see test-signing.py).
"""

import hashlib
import secrets as _secrets

b = 256
q = (1 << 255) - 19
l = (1 << 252) + 27742317777372353535851937790883648493


def _H(m):
    return hashlib.sha512(m).digest()


def _inv(x):
    # C-speed builtin; the old recursive pure-Python _expmod was the
    # dominant cost of every point operation (~3s per sign/verify).
    return pow(x, q - 2, q)


_d = (-121665 * _inv(121666)) % q
_2d = (2 * _d) % q
_I = pow(2, (q - 1) // 4, q)


def _xrecover(y):
    xx = (y * y - 1) * _inv(_d * y * y + 1) % q
    x = pow(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0:
        x = (x * _I) % q
    if x & 1:
        x = q - x
    return x


# --- Extended-coordinate group law ---------------------------------------
# A point is (X, Y, Z, T) with affine x = X/Z, y = Y/Z. Addition and
# doubling use only multiplications; _to_affine inverts once at the end.
# Formulas: Hisilop-Wong-Carter-Dawson, "Twisted Edwards Curves Revisited"
# (addition), with a = -1 for Ed25519.

_IDENT = (0, 1, 1, 0)


def _to_ext_affine(x, y):
    return (x % q, y % q, 1, (x * y) % q)


def _to_affine(P):
    X, Y, Z, _T = P
    iz = _inv(Z)
    return (X * iz % q, Y * iz % q)


def _point_eq(P, Q):
    # Projective equality without inverting: X1/Z1 == X2/Z2 and
    # Y1/Z1 == Y2/Z2  <=>  cross-multiplied differences are 0 mod q.
    X1, Y1, Z1, _t1 = P
    X2, Y2, Z2, _t2 = Q
    return (X1 * Z2 - X2 * Z1) % q == 0 and (Y1 * Z2 - Y2 * Z1) % q == 0


def _edwards_add(P, Q):
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q
    A = (Y1 - X1) * (Y2 - X2) % q
    B = (Y1 + X1) * (Y2 + X2) % q
    C = T1 * _2d % q * T2 % q
    D = (2 * Z1 % q) * Z2 % q
    E = (B - A) % q
    F = (D - C) % q
    G = (D + C) % q
    H = (B + A) % q
    return (E * F % q, G * H % q, F * G % q, E * H % q)


def _edwards_dbl(P):
    X1, Y1, Z1, _T1 = P
    A = X1 * X1 % q
    B = Y1 * Y1 % q
    C = 2 * Z1 * Z1 % q
    D = (-A) % q  # a = -1 for Ed25519
    E = ((X1 + Y1) * (X1 + Y1) - A - B) % q
    G = (D + B) % q
    F = (G - C) % q
    H = (D - B) % q
    return (E * F % q, G * H % q, F * G % q, E * H % q)


def _scalarmult(P, e):
    # NB: scalars here can be up to 512 bits (r and h in _signature /
    # _checkvalid are full _Hint outputs). Must iterate every bit --
    # truncating to 256 silently produces wrong points.
    Q = _IDENT
    for i in range(max(b, e.bit_length()) - 1, -1, -1):
        Q = _edwards_dbl(Q)
        if (e >> i) & 1:
            Q = _edwards_add(Q, P)
    return Q


# --- Base point (extended) -------------------------------------------------

_By = (4 * _inv(5)) % q
_Bx = _xrecover(_By)
_B = (_Bx, _By, 1, _Bx * _By % q)


def _bit(h, i):
    return (h[i // 8] >> (i % 8)) & 1


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


def _Hint(m):
    h = _H(m)
    return sum(2**i * _bit(h, i) for i in range(2 * b))


def _publickey_point(sk):
    h = _H(sk)
    a = 2 ** (b - 2) + sum(2**i * _bit(h, i) for i in range(3, b - 2))
    return _scalarmult(_B, a)


def _publickey(sk):
    return _encodepoint(_to_affine(_publickey_point(sk)))


def _signature(m, sk, pk):
    h = _H(sk)
    a = 2 ** (b - 2) + sum(2**i * _bit(h, i) for i in range(3, b - 2))
    r = _Hint(h[b // 8 : b // 4] + m)
    Rext = _scalarmult(_B, r)
    Renc = _encodepoint(_to_affine(Rext))
    S = (r + _Hint(Renc + pk + m) * a) % l
    return Renc + _encodeint(S)


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
    P = (x, y)
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
    v2 = _edwards_add(_to_ext_affine(*R), _scalarmult(_to_ext_affine(*A), h))
    return _point_eq(v1, v2)


# --- Friendly API -----------------------------------------------------------


def is_valid_pubkey(pubkey):
    """True iff pubkey is the canonical encoding of a prime-order point.

    Rejects wrong-length input, non-canonical encodings, the identity
    point, and small-order points. The last matters: _checkvalid admits a
    trivial fixed signature for *different* messages under a small-order
    key (R5), so such keys must never be enrolled as peer identities nor
    trusted for request signing. Costs one scalar multiply; callers cache
    the result per key.
    """
    try:
        raw = bytes(pubkey)
    except Exception:
        return False
    if len(raw) != 32:
        return False
    try:
        x, y = _decodepoint(raw)
    except Exception:
        return False
    P = _to_ext_affine(x, y)
    # Canonical encoding: re-encoding must reproduce the input exactly.
    if _encodepoint(P) != raw:
        return False
    # Identity and small-order points: a prime-order point P satisfies
    # [l]P == identity; a low-order point does not (l is odd, so
    # [l]P = [l mod 8]P != identity for P of order dividing 8).
    if _point_eq(P, _IDENT):
        return False
    try:
        Q = _scalarmult(P, l)
    except Exception:
        return False
    return bool(_point_eq(Q, _IDENT))


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
