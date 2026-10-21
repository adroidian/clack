#!/usr/bin/env python3
"""CLI for the Clack A2A relay.

Two config flavors (auto-detected):

  legacy:   relay-config.json style {"peers": {"nugget": "<token>"}, ...}
            -- existing commands keep working exactly as before.
  identity: {"kind": "clack-identity-v1", "relay_url": ..., "identity_pubkey":
            ..., "identity_privkey_path": ..., "service_token": ..., "peer_name": ...}
            -- created by `keygen` / `redeem`, used by every command. The
            private key lives in a separate mode-600 key file
            (identity_privkey_path, default <config>.key); older configs may
            still carry an inline identity_privkey, which is migrated into
            the key file on the next save.

Invite-link onboarding (v0.2.5 MVP):
  mint-request TARGET_IDENTITY  public request for an enrolled target (no secret)
  redeem-request URL           existing identity only; returns pending, no accept
  accept-handshake ID           separate explicit consent (--enc-v 0 or 1)
  keygen                     create an ed25519 identity (mode 600)
  mint-invite                mint a shareable join link (any authed peer)
  redeem <link>              full join flow: confirm -> keygen -> challenge ->
                             sign -> redeem -> save config -> send hello
  invite-list / invite-revoke  manage your outstanding invites

Agent self-enrollment (v0.2.9):
  enroll                     no link needed: confirm -> keygen -> challenge ->
                             (solve PoW) -> sign -> enroll -> save config.
                             Uses the relay's enabled enrollment gate
                             (invite/pow/open); --invite-id/--secret select
                             the invite gate explicitly.

Request signing (v0.2.12): ordinary post-enrollment operations carry BOTH
the Bearer token AND an Ed25519 signature, added automatically:
  X-Clack-Scheme: 1, X-Clack-Key: <peer name>, X-Clack-Nonce: <ts>:<32hex>,
  X-Clack-Sig: hex(Ed25519_sign(seed, "clack-ed25519-v1\n"+METHOD+"\n"+
  path_and_query+"\n"+sha256_hex(raw_body)+"\n"+nonce))

The Bearer token remains identity authority: `register-key` deliberately uses
token-only bootstrap auth and can register or rotate the signing key. Operators
can also configure a narrow trusted-network signature exemption. Protect the
token and private key as separate control credentials.

Never print a token or private key.
"""
import argparse
import base64
import datetime

import http.client
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

# --- BEGIN vendored e2ee (embedded from e2ee.py; that file remains the
# --- canonical copy). Embedded as a raw string + exec so relay-cli.py stays a
# --- single runnable file: /join/client serves ONLY this file. A test
# --- asserts the embedded copy matches e2ee.py byte-for-byte.
_E2EE_SOURCE = r'''"""Clack E2EE envelope crypto, pure stdlib.

Vendored (not a new dependency) because the relay and reference client are
stdlib-only by design and neither `cryptography` nor PyNaCl is guaranteed on
every machine that runs them. Follows the ed25519.py vendoring precedent.

Construction (per the E2EE design brief, CLIENT_CONTRACT.md):
  per-message ephemeral X25519 ECDH in the NaCl crypto_box shape, recipient
  long-term key via Ed25519->X25519 conversion (no new key distribution),
  message key via HKDF-SHA256(shared_secret, info="clack-enc-v1"||sender||
  recipient), payload via ChaCha20-Poly1305 (RFC 8439) with a random 96-bit
  nonce. The 16-byte Poly1305 tag is appended to the ciphertext and both
  ride in the envelope's `ct` field.

Security posture: pure-Python field arithmetic is NOT constant-time (the
Montgomery ladder branches on secret scalar bits, Poly1305 uses big-int
multiplication). That matches the ed25519.py precedent and is acceptable
here: encryption/decryption happen on the key owner's own machine, and the
relay never touches this module's decrypt path (it shape-validates the
envelope only). Do not use this module where a local timing adversary is
in scope.

Performance: pure-Python ChaCha20 does single-digit MB/s and the X25519
ladder is ~255 modular multiplications -- tens of ms per message on this
VM. Ample for agent messages (KBs).

Envelope (JSON, carried in /v1/send `enc`):
  {"v":1, "alg":"x25519-chacha20poly1305",
   "eph":"<b64u 32B ephemeral X25519 pub>",
   "nonce":"<b64u 12B nonce>", "kid":"<b64u 8B key id>",
   "ct":"<b64u ciphertext || 16B tag>"}
kid = first 8 bytes of SHA256(recipient X25519 public key): lets the
recipient confirm the envelope was built for their current key generation
before attempting decryption.
"""

import hashlib
import hmac
import secrets
import struct

# ---------------------------------------------------------------------------
# Constants

ENC_VERSION = 1
ENC_ALG = "x25519-chacha20poly1305"
_HKDF_INFO_PREFIX = b"clack-enc-v1"

_P25519 = (1 << 255) - 19
_A24 = 121665  # (486662 - 2) // 4, RFC 7748
_X25519_BASE = (9).to_bytes(32, "little")


def b64u_encode(b):
    import base64
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64u_decode(s):
    import base64
    if not isinstance(s, str):
        raise ValueError("b64u input must be str")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ---------------------------------------------------------------------------
# X25519 (RFC 7748, Montgomery ladder)

def x25519_scalarmult(scalar32, point32):
    """X25519(scalar, point). Both 32-byte little-endian. Returns 32 bytes."""
    if len(scalar32) != 32 or len(point32) != 32:
        raise ValueError("x25519 inputs must be 32 bytes")
    k = bytearray(scalar32)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k = int.from_bytes(bytes(k), "little")
    u = int.from_bytes(point32, "little") % _P25519

    x1 = u
    x2, z2 = 1, 0
    x3, z3 = u, 1
    swap = 0
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        A = (x2 + z2) % _P25519
        AA = (A * A) % _P25519
        B = (x2 - z2) % _P25519
        BB = (B * B) % _P25519
        E = (AA - BB) % _P25519
        C = (x3 + z3) % _P25519
        D = (x3 - z3) % _P25519
        DA = (D * A) % _P25519
        CB = (C * B) % _P25519
        x5 = pow(DA + CB, 2, _P25519)
        z5 = (x1 * pow(DA - CB, 2, _P25519)) % _P25519
        x4 = (AA * BB) % _P25519
        z4 = (E * (AA + _A24 * E)) % _P25519
        x2, z2, x3, z3 = x4, z4, x5, z5
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return ((x2 * pow(z2, _P25519 - 2, _P25519)) % _P25519).to_bytes(32, "little")


def x25519_keygen():
    """Fresh random X25519 keypair. Returns (priv32, pub32)."""
    priv = secrets.token_bytes(32)
    return priv, x25519_scalarmult(priv, _X25519_BASE)


# ---------------------------------------------------------------------------
# Ed25519 -> X25519 conversion (RFC 7748 section 5)

def ed25519_seed_to_x25519_priv(seed32):
    """X25519 private key from a 32-byte Ed25519 seed.

    libsodium crypto_sign_ed25519_sk_to_curve25519: clamp the first 32
    bytes of SHA-512(seed). The seed is what relay-cli stores (b64u in the
    .key file); the same seed feeds Ed25519 signing.
    """
    if len(seed32) != 32:
        raise ValueError("ed25519 seed must be 32 bytes")
    h = hashlib.sha512(seed32).digest()
    k = bytearray(h[:32])
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return bytes(k)


def ed25519_pub_to_x25519_pub(pub32):
    """X25519 public key from a 32-byte Ed25519 public key.

    u = (1 + y) / (1 - y) mod p, where y is the Edwards y-coordinate
    decoded from the Ed25519 public key (RFC 7748 section 5,
    libsodium crypto_sign_ed25519_pk_to_curve25519).
    """
    if len(pub32) != 32:
        raise ValueError("ed25519 public key must be 32 bytes")
    y = int.from_bytes(pub32, "little") & ((1 << 255) - 1)
    # A valid Ed25519 pubkey always has y != 1; guard anyway.
    if y == 1:
        raise ValueError("invalid ed25519 public key for conversion")
    u = ((1 + y) * pow((1 - y) % _P25519, _P25519 - 2, _P25519)) % _P25519
    return u.to_bytes(32, "little")


def x25519_pubkey_id(x_pub32):
    """8-byte key id: first 8 bytes of SHA256(X25519 public key)."""
    return hashlib.sha256(x_pub32).digest()[:8]


# ---------------------------------------------------------------------------
# HKDF-SHA256 (RFC 5869)

def hkdf_sha256(ikm, info, length=32, salt=None):
    if salt is None:
        salt = b"\x00" * hashlib.sha256().digest_size
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    t = b""
    for i in range(1, (length // hashlib.sha256().digest_size) + 2):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


# ---------------------------------------------------------------------------
# ChaCha20 (RFC 8439 section 2.1-2.3)

def _rotl32(v, n):
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def _qr(a, b, c, d):
    a = (a + b) & 0xFFFFFFFF
    d ^= a
    d = _rotl32(d, 16)
    c = (c + d) & 0xFFFFFFFF
    b ^= c
    b = _rotl32(b, 12)
    a = (a + b) & 0xFFFFFFFF
    d ^= a
    d = _rotl32(d, 8)
    c = (c + d) & 0xFFFFFFFF
    b ^= c
    b = _rotl32(b, 7)
    return a, b, c, d


def _chacha20_block(key32, counter, nonce12):
    if len(key32) != 32 or len(nonce12) != 12:
        raise ValueError("chacha20 needs 32-byte key and 12-byte nonce")
    st = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    st += list(struct.unpack("<8L", key32))
    st += [counter & 0xFFFFFFFF]
    st += list(struct.unpack("<3L", nonce12))
    w = list(st)
    for _ in range(10):
        w[0], w[4], w[8], w[12] = _qr(w[0], w[4], w[8], w[12])
        w[1], w[5], w[9], w[13] = _qr(w[1], w[5], w[9], w[13])
        w[2], w[6], w[10], w[14] = _qr(w[2], w[6], w[10], w[14])
        w[3], w[7], w[11], w[15] = _qr(w[3], w[7], w[11], w[15])
        w[0], w[5], w[10], w[15] = _qr(w[0], w[5], w[10], w[15])
        w[1], w[6], w[11], w[12] = _qr(w[1], w[6], w[11], w[12])
        w[2], w[7], w[8], w[13] = _qr(w[2], w[7], w[8], w[13])
        w[3], w[4], w[9], w[14] = _qr(w[3], w[4], w[9], w[14])
    return struct.pack("<16L", *[((a + b) & 0xFFFFFFFF) for a, b in zip(w, st)])


def _chacha20_xor(key32, counter, nonce12, data):
    out = b""
    for i in range(0, len(data), 64):
        ks = _chacha20_block(key32, counter, nonce12)
        counter = (counter + 1) & 0xFFFFFFFF
        chunk = data[i:i + 64]
        out += bytes(x ^ y for x, y in zip(chunk, ks))
    return out


# ---------------------------------------------------------------------------
# Poly1305 (RFC 8439 section 2.5)

def poly1305_mac(msg, key32):
    if len(key32) != 32:
        raise ValueError("poly1305 key must be 32 bytes")
    r = int.from_bytes(key32[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key32[16:], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        block = msg[i:i + 16]
        n = int.from_bytes(block, "little") + (1 << (8 * len(block)))
        acc = ((acc + n) * r) % p
    return ((acc + s) % (1 << 128)).to_bytes(16, "little")


# ---------------------------------------------------------------------------
# ChaCha20-Poly1305 AEAD (RFC 8439 section 2.8)

def _pad16(b):
    return b + b"\x00" * (-len(b) % 16)


def aead_encrypt(key32, nonce12, plaintext, aad=b""):
    """Returns (ciphertext, tag16)."""
    otk = _chacha20_block(key32, 0, nonce12)[:32]
    ct = _chacha20_xor(key32, 1, nonce12, plaintext)
    mac_data = (_pad16(aad) + _pad16(ct)
                + struct.pack("<Q", len(aad)) + struct.pack("<Q", len(ct)))
    return ct, poly1305_mac(mac_data, otk)


class DecryptError(ValueError):
    """Authentication or format failure on decrypt. Never carries key material."""


def aead_decrypt(key32, nonce12, ct, tag16, aad=b""):
    if len(tag16) != 16:
        raise DecryptError("bad tag length")
    otk = _chacha20_block(key32, 0, nonce12)[:32]
    mac_data = (_pad16(aad) + _pad16(ct)
                + struct.pack("<Q", len(aad)) + struct.pack("<Q", len(ct)))
    expect = poly1305_mac(mac_data, otk)
    if not hmac.compare_digest(expect, tag16):
        raise DecryptError("authentication failed")
    return _chacha20_xor(key32, 1, nonce12, ct)


# ---------------------------------------------------------------------------
# Envelope

def _hkdf_info(sender, recipient):
    if not sender or not recipient:
        raise ValueError("sender and recipient names required")
    return _HKDF_INFO_PREFIX + sender.encode("utf-8") + recipient.encode("utf-8")


def encrypt_envelope(sender, recipient, recipient_x25519_pub32, plaintext):
    """Build a v1 envelope dict for plaintext (bytes). Fresh ephemeral per
    message; the ephemeral private key is discarded before return
    (sender-side forward secrecy)."""
    if len(recipient_x25519_pub32) != 32:
        raise ValueError("recipient X25519 public key must be 32 bytes")
    if not isinstance(plaintext, (bytes, bytearray)):
        raise ValueError("plaintext must be bytes")
    eph_priv, eph_pub = x25519_keygen()
    shared = x25519_scalarmult(eph_priv, recipient_x25519_pub32)
    # eph_priv goes out of scope here: sender-side forward secrecy.
    del eph_priv
    if shared == b"\x00" * 32:
        # Fail closed: an all-zero X25519 public key forces an all-zero
        # shared secret, which would derive a predictable message key.
        raise ValueError("refusing to encrypt: all-zero X25519 shared secret")
    key = hkdf_sha256(shared, _hkdf_info(sender, recipient), 32)
    nonce = secrets.token_bytes(12)
    ct, tag = aead_encrypt(key, nonce, bytes(plaintext))
    return {
        "v": ENC_VERSION,
        "alg": ENC_ALG,
        "eph": b64u_encode(eph_pub),
        "nonce": b64u_encode(nonce),
        "kid": b64u_encode(x25519_pubkey_id(recipient_x25519_pub32)),
        "ct": b64u_encode(ct + tag),
    }


def decrypt_envelope(recipient_seed32, envelope, sender, recipient):
    """Decrypt a v1 envelope with the recipient's 32-byte Ed25519 seed.
    Returns plaintext bytes. Raises DecryptError on any failure."""
    err = validate_envelope(envelope)
    if err:
        raise DecryptError(err)
    x_priv = ed25519_seed_to_x25519_priv(recipient_seed32)
    x_pub = x25519_scalarmult(x_priv, _X25519_BASE)
    if b64u_encode(x25519_pubkey_id(x_pub)) != envelope["kid"]:
        raise DecryptError("kid mismatch: envelope not built for this key")
    eph_pub = b64u_decode(envelope["eph"])
    shared = x25519_scalarmult(x_priv, eph_pub)
    if shared == b"\x00" * 32:
        # Fail closed: all-zero shared secret (malicious all-zero eph key).
        raise DecryptError("refusing to decrypt: all-zero X25519 shared secret")
    key = hkdf_sha256(shared, _hkdf_info(sender, recipient), 32)
    nonce = b64u_decode(envelope["nonce"])
    ct_tag = b64u_decode(envelope["ct"])
    ct, tag = ct_tag[:-16], ct_tag[-16:]
    return aead_decrypt(key, nonce, ct, tag)


def validate_envelope(enc):
    """Shape validation only (what the relay enforces). Returns an error
    string, or None when the envelope is well-formed. Never decrypts."""
    if not isinstance(enc, dict):
        return "envelope must be an object"
    if enc.get("v") != ENC_VERSION:
        return "unsupported envelope version"
    if enc.get("alg") != ENC_ALG:
        return "unsupported algorithm"
    try:
        eph = b64u_decode(enc.get("eph"))
        nonce = b64u_decode(enc.get("nonce"))
        kid = b64u_decode(enc.get("kid"))
        ct = b64u_decode(enc.get("ct"))
    except Exception:
        return "envelope fields must be base64url strings"
    if len(eph) != 32:
        return "bad eph length"
    if len(nonce) != 12:
        return "bad nonce length"
    if len(kid) != 8:
        return "bad kid length"
    if len(ct) < 16:  # 16-byte tag, ciphertext may be empty
        return "bad ct length"
    return None


def serialize_envelope(enc):
    """Canonical JSON for storage (sorted keys, compact separators)."""
    import json
    return json.dumps(enc, sort_keys=True, separators=(",", ":"))
'''

import types as _types
e2ee = _types.ModuleType("e2ee")
exec(compile(_E2EE_SOURCE, "e2ee.py", "exec"), e2ee.__dict__)
# --- END vendored e2ee ---


# --- BEGIN vendored ed25519 (inlined from ed25519.py; that file remains
# --- the canonical, libsodium-verified copy) ---
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
# --- END vendored ed25519 ---

BASE = os.path.expanduser("~/workspace/clack-relay")
DEFAULT_CONFIG = os.environ.get(
    "CLACK_RELAY_CONFIG", os.path.join(BASE, "relay-config.json")
)
IDENTITY_KIND = "clack-identity-v1"


def b64u_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64u_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def load_config(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def is_identity_cfg(cfg):
    return isinstance(cfg, dict) and cfg.get("kind") == IDENTITY_KIND


# Peer name selected via --peer for legacy (token) configs. None means
# "nugget" for backward compatibility, or the only peer if there is one.
_selected_peer = None


def auth_token(cfg):
    if is_identity_cfg(cfg):
        return cfg.get("service_token")
    peers = cfg.get("peers") or {}
    if _selected_peer:
        return peers.get(_selected_peer)
    if "nugget" in peers:
        return peers["nugget"]
    if len(peers) == 1:
        return next(iter(peers.values()))
    return None


def base_url(cfg):
    if is_identity_cfg(cfg):
        return cfg["relay_url"].rstrip("/")
    return (cfg.get("base_url") or "http://127.0.0.1:%d" % cfg.get("port", 18802)).rstrip("/")


def user_agent(cfg):
    return cfg.get("user_agent") or "ClackRelay-CLI/1.1.0"


# --- Ed25519 request signing (v0.2.12) ----------------------------------------
# Mirrors relay.py: ordinary post-enrollment requests carry
#   X-Clack-Scheme: 1
#   X-Clack-Key: <peer name, must match the Bearer token's peer>
#   X-Clack-Nonce: <unix_seconds>:<32 hex chars random>
#   X-Clack-Sig: hex(Ed25519_sign(seed, canonical))
# with canonical bytes
#   clack-ed25519-v1\n{METHOD_UPPER}\n{path_and_query}\n{sha256_hex(raw_body)}\n{nonce}
# Signs only when the config carries an identity seed AND a peer_name (i.e.
# post-enrollment). Pre-enrollment calls have no peer_name and stay unsigned.
# `register-key` is a separate bearer-only bootstrap/rotation authority, and
# an operator may explicitly exempt selected trusted-network traffic. Public
# request mint, redeem and accept never honor that network exemption.
SIGN_SCHEME_ID = "clack-ed25519-v1"


def signing_seed(cfg):
    """Return the 32-byte Ed25519 seed for an identity config, or None.

    Preferred: identity_privkey_path (a separate mode-600 key file holding
    the b64u seed). Legacy: inline identity_privkey (b64u). Never prints or
    logs the seed."""
    if not is_identity_cfg(cfg):
        return None
    path = cfg.get("identity_privkey_path")
    if path:
        try:
            with open(path, "rb") as f:
                raw = f.read().strip()
        except OSError:
            return None
        if len(raw) == 32:
            return raw
        try:
            seed = b64u_decode(raw.decode("ascii"))
        except Exception:
            return None
        return seed if len(seed) == 32 else None
    inline = cfg.get("identity_privkey")
    if not inline:
        return None
    try:
        seed = b64u_decode(inline)
    except Exception:
        return None
    return seed if len(seed) == 32 else None


def _e2ee_handshake_state_for_peer(cfg, peer_name, base_url):
    """Look up the handshake with peer_name via GET /v1/handshakes.

    Returns (state, peer_identity_b64, enc_capable) where state is one of:

      "capable"   -- active handshake, valid 32-byte Ed25519 identity key,
                     enc_capable negotiated: encrypt.
      "incapable" -- active handshake, valid identity key, enc_capable NOT
                     negotiated: verified-incapable compatibility; the caller
                     may send plaintext (dual-mode transition).
      "unknown"   -- anything else: HTTP error, malformed/unparseable body,
                     no matching handshake row, inactive row, missing or
                     invalid identity key. The caller MUST stop without
                     sending; unknown state must never fall through to
                     plaintext.

    KIT-SCOPED PATCH (e2ee-kit-v1.0.1), carried into v1.1.0: the maintained
    upstream relay-cli maps every one of these cases to (None, 0) and needs
    the same fix. See SOURCE-CONTRACT.md.
    """
    try:
        code, out = req(cfg, "GET", "/v1/handshakes", base=base_url)
    except Exception:
        return "unknown", None, 0
    if not (200 <= code < 300) or not isinstance(out, dict):
        return "unknown", None, 0
    rows = out.get("handshakes", [])
    if not isinstance(rows, list):
        return "unknown", None, 0
    for hs in rows:
        if not isinstance(hs, dict):
            continue
        # Match by name hint (what the user typed) or raw peer name.
        if hs.get("peer_name_hint") != peer_name and hs.get("peer") != peer_name:
            continue
        if hs.get("status") != "active":
            return "unknown", None, 0
        ident = hs.get("peer_identity")
        if not isinstance(ident, str) or not ident:
            return "unknown", None, 0
        try:
            raw = b64u_decode(ident)
        except Exception:
            return "unknown", None, 0
        if len(raw) != 32:
            # Legacy name-based identity: no Ed25519 key to convert.
            return "unknown", None, 0
        capable = hs.get("enc_capable") or 0
        if capable:
            return "capable", ident, capable
        return "incapable", ident, 0
    return "unknown", None, 0


def _e2ee_handshake_for_peer(cfg, peer_name, base_url):
    """Look up the handshake with peer_name via GET /v1/handshakes.

    Returns (peer_identity_b64, enc_capable) for the matching pair, or
    (None, 0) when there is no handshake or no usable identity key.
    peer_identity is the b64 Ed25519 pubkey; enc_capable is 0/1 from the
    relay's capability negotiation.

    KIT-SCOPED PATCH (e2ee-kit-v1.0.1), carried into v1.1.0: compatibility
    wrapper over _e2ee_handshake_state_for_peer; preserves the historical
    (ident, capable) shape. Callers that need to distinguish
    verified-incapable from unknown/error state MUST use
    _e2ee_handshake_state_for_peer instead -- (None, 0) here conflates
    both, and unknown must never fall through to plaintext.
    """
    state, ident_b64, capable = _e2ee_handshake_state_for_peer(
        cfg, peer_name, base_url)
    if state == "unknown":
        return None, 0
    return ident_b64, capable


class E2EEError(RuntimeError):
    """Negotiated encryption failed, or the negotiation state is unknown:
    fail closed, never fall back to plaintext."""
    pass


def _require_send_identity(cfg):
    """Hard prerequisite check for the CLI `send` path (kit-scoped).

    Raises E2EEError when the config claims the identity kind but is
    missing its signing seed or its peer_name: the send path must STOP
    hard BEFORE any /v1/send -- no plaintext fallback from the main
    path, ever. A config that cannot prove its identity must never emit
    a message that looks like it came from that identity in the clear.

    Legacy (non-identity) token configs are NOT subject to this check:
    they carry no E2EE identity at all, plaintext is their only mode,
    and the relay answers their signed endpoints with 401s (the existing
    upgrade-and-re-enroll path). Verified-incapable pairs are likewise
    unaffected: this check is about the SENDER's identity prerequisites,
    not the pair's negotiated capability -- an explicitly verified
    incapable pair still sends plaintext (dual-mode), never promoted to
    verified-capable.

    KIT-SCOPED PATCH (e2ee-kit-v1.0.2), carried into v1.1.0: the maintained
    upstream relay-cli still allows the missing-prerequisite plaintext
    fall-through and needs this same fix. See SOURCE-CONTRACT.md.
    """
    if not is_identity_cfg(cfg):
        return
    if signing_seed(cfg) is None:
        raise E2EEError(
            "refusing to send: identity config is missing its signing "
            "seed (no plaintext fallback)")
    if not cfg.get("peer_name"):
        raise E2EEError(
            "refusing to send: identity config is missing peer_name "
            "(no plaintext fallback)")


def _e2ee_encrypt_for(cfg, peer_name, plaintext, base_url):
    """Encrypt plaintext for peer_name when the pair is enc_capable.

    Returns (envelope_dict, None) on success, (None, reason) when the pair
    VERIFIED incapable (active handshake, valid identity key, enc_capable
    not negotiated -- dual-mode transition: caller may send plaintext).
    Raises E2EEError when the sender identity prerequisites are missing
    (no signing seed / no peer_name on an identity config), when the
    handshake state is unknown/unavailable (HTTP error, malformed,
    no/inactive row, bad identity key), or when the pair IS enc_capable
    but encryption fails -- fail closed, never silently send plaintext
    when the negotiation outcome is not a positively verified incapable
    pair.

    KIT-SCOPED PATCH (e2ee-kit-v1.0.1), carried into v1.1.0: unknown state
    previously fell through to (None, reason) and callers sent plaintext.
    KIT-SCOPED PATCH (e2ee-kit-v1.0.2), carried into v1.1.0: missing sender
    prerequisites now raise here as well (defense in depth; the CLI main
    send path checks first via _require_send_identity). Legacy non-identity
    configs keep the historical (None, reason) shape.
    """
    _require_send_identity(cfg)
    seed = signing_seed(cfg)
    if seed is None:
        # Legacy non-identity config: no E2EE identity at all.
        return None, "no signing seed"
    sender_name = cfg.get("peer_name")
    if not sender_name:
        # Legacy non-identity config without a peer name.
        return None, "no peer_name"
    state, ident_b64, capable = _e2ee_handshake_state_for_peer(
        cfg, peer_name, base_url)
    if state == "unknown":
        raise E2EEError(
            "refusing: handshake state for %r is unknown/unavailable "
            "(no plaintext fallback)" % (peer_name,))
    if state == "incapable":
        return None, "pair not enc_capable"
    try:
        recip_x25519 = e2ee.ed25519_pub_to_x25519_pub(b64u_decode(ident_b64))
    except Exception as ex:
        raise E2EEError("pair enc_capable but recipient identity key invalid: %s" % ex)
    try:
        env = e2ee.encrypt_envelope(sender_name, peer_name, recip_x25519,
                                    plaintext.encode("utf-8"))
    except Exception as ex:
        raise E2EEError("pair enc_capable but encryption failed: %s" % ex)
    return env, None


def _e2ee_receive_admission(cfg, messages, base_url=None):
    """Decide which inbound messages may enter caller-visible state.

    Returns (kept, rejections). `kept` is the subset that may be handed
    downstream; `rejections` carries {"id","from","reason","peer_state"} for
    every message refused, so a refusal is always visible and attributable
    rather than a silent drop.

    Fail-closed, mirroring the send-side table in _e2ee_encrypt_for:

      peer "incapable" -- POSITIVELY VERIFIED incapable (active handshake,
        valid key, enc_capable not negotiated). Plaintext inbound is allowed,
        the dual-mode counterpart of the send path's verified-incapable
        plaintext send.
      peer "capable"   -- encryption is required. Plaintext refused.
      peer "unknown"   -- refused. Unknown must never be treated as incapable,
        exactly as unknown must never fall through to plaintext on send.

    Capability is looked up once per distinct sender and cached for the poll;
    _e2ee_handshake_state_for_peer performs a network call per invocation.

    Legacy non-identity configs carry no E2EE identity at all. They keep the
    historical behaviour, mirroring the _require_send_identity carve-out: this
    check governs an identity config's inbound handling, it does not invent an
    identity for configs that never had one.

    KIT-SCOPED PATCH (receive-side fail-closed, PR 2): previously every
    unencrypted message was passed through untouched and every decrypt failure
    was retained and handed to the caller carrying decrypt_error. Neither is
    fail-closed; both are corrected here.
    """
    if not is_identity_cfg(cfg):
        # No E2EE identity configured: historical behaviour, nothing to enforce.
        return list(messages), []
    seed = signing_seed(cfg)
    my_name = cfg.get("peer_name") or ""
    kept, rejections = [], []
    state_cache = {}
    if seed is None:
        # Identity config with no signing seed cannot decrypt anything. Refuse
        # rather than pass plaintext through as though it were acceptable.
        for m in messages:
            rejections.append({
                "id": m.get("id") if isinstance(m, dict) else None,
                "from": m.get("from") if isinstance(m, dict) else None,
                "reason": "identity config has no signing seed; refusing inbound",
                "peer_state": "unknown",
            })
        return kept, rejections
    for m in messages:
        if not isinstance(m, dict):
            rejections.append({"id": None, "from": None,
                               "reason": "non-dict message entry",
                               "peer_state": "unknown"})
            continue
        sender_name = m.get("from") or ""
        if not m.get("enc_v"):
            # Unencrypted inbound: admissible ONLY for a verified-incapable pair.
            if sender_name not in state_cache:
                state_cache[sender_name] = _e2ee_handshake_state_for_peer(
                    cfg, sender_name, base_url)[0]
            state = state_cache[sender_name]
            if state == "incapable":
                kept.append(m)
            else:
                rejections.append({
                    "id": m.get("id"), "from": sender_name,
                    "reason": ("plaintext refused: pair enc_capable"
                               if state == "capable"
                               else "plaintext refused: pair state unknown"),
                    "peer_state": state,
                })
            continue
        try:
            env = json.loads(m.get("text") or "")
            pt_bytes = e2ee.decrypt_envelope(seed, env, sender_name, my_name)
            m["text"] = pt_bytes.decode("utf-8")
            m["was_encrypted"] = True
            kept.append(m)
        except Exception as ex:
            # REFUSED, not retained-with-a-flag. The envelope is not handed on.
            rejections.append({
                "id": m.get("id"), "from": sender_name,
                "reason": "decrypt failed: %s: %s" % (type(ex).__name__, ex),
                "peer_state": "capable",
            })
    return kept, rejections


def _e2ee_decrypt_poll_messages(cfg, messages, base_url=None):
    """Backwards-compatible wrapper: decrypt in place, keep only admitted.

    Retained so existing callers and downstream tooling keep working. Returns
    (kept, rejections); `messages` is filtered in place to the admitted subset.
    """
    kept, rejections = _e2ee_receive_admission(cfg, messages, base_url=base_url)
    messages[:] = kept
    return kept, rejections


def sign_headers(cfg, method, path, body_bytes):
    """Build the X-Clack-* signing headers for one request, or {} when the
    config cannot sign yet (no seed or no peer_name). Pure function of its
    inputs apart from the fresh random nonce."""
    seed = signing_seed(cfg)
    peer = cfg.get("peer_name") if is_identity_cfg(cfg) else None
    if seed is None or not peer:
        return {}
    nonce = "%d:%s" % (int(time.time()), _secrets.token_hex(16))
    canon = (
        SIGN_SCHEME_ID + "\n"
        + method.upper() + "\n"
        + path + "\n"
        + hashlib.sha256(body_bytes or b"").hexdigest() + "\n"
        + nonce
    ).encode("utf-8")
    return {
        "X-Clack-Scheme": "1",
        "X-Clack-Key": peer,
        "X-Clack-Nonce": nonce,
        "X-Clack-Sig": sign(seed, canon).hex(),
    }


def _write_key_file(path, seed):
    """Write the b64u seed to path with mode 600. Private key material:
    never printed, never transmitted."""
    d = os.path.dirname(os.path.abspath(path))
    if d:
        os.makedirs(d, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(b64u_encode(seed) + "\n")


def _save_identity_config(path, cfg, seed, key_path=None):
    """Persist an identity config (mode 600) with the private key in a
    separate mode-600 key file. cfg records identity_privkey_path; any
    legacy inline identity_privkey is migrated into the file."""
    kp = key_path or cfg.get("identity_privkey_path") or (path + ".key")
    cfg.pop("identity_privkey", None)
    cfg["identity_privkey_path"] = kp
    _write_key_file(kp, seed)
    d = os.path.dirname(os.path.abspath(path))
    if d:
        os.makedirs(d, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
        f.write("\n")


# --- Fail-closed transport (v0.2.12, Flint review F1/F2/F5) -------------------
# F2: the CLI never follows redirects. urllib's default opener would resend
# the bearer token and X-Clack-* signing headers to the redirect target,
# crossing the configured origin boundary -- so a 3xx on an authenticated
# or identity request is a failure, not a detour.
# F1: the relay's identity is verified BEFORE any bearer token, secret, or
# message body is transmitted, on every origin, including --base-url
# overrides. The check lives in req(), the single choke point for all
# API traffic, not just in the enrollment flows.
# F5: TLS is the primary server-authentication boundary. The pinned relay
# key is a second layer (catches key changes, stops unsophisticated
# impersonators); it does not by itself prove the connection is direct --
# a determined intermediary that can reach the genuine relay can proxy the
# challenge and return a valid proof. The CLI enforces the pin and refuses
# redirects; it does not claim the challenge authenticates the channel.
#
# v0.2.13 handshake release gate (spec section 11, review F1-F4):
# F1: centralized in req()/_ensure_origin_verified -- every request carrying
# a bearer token, claim secret, signature, or message body routes through
# this one transport, which verifies the relay identity (pin check) BEFORE
# transmitting, on every origin including --base-url overrides.
# F2: _NoRedirect raises on ANY 3xx (cross-host, cross-port, scheme-change,
# method-changing 301/302/303/307/308) -- the client never follows with
# credentials.
# F3: fetch_relay_identity requires the echoed nonce to EXACTLY equal the
# locally generated challenge, strictly validates the algorithm field, and
# verifies the signature over the local nonce bytes (never the echo).
# F4: fail closed -- identity unavailable (503, transport error, missing
# material) aborts before any secret, enrollment proof, or message body
# leaves the client, with or without a stored pin. No warning/--yes
# bypass: first contact verifies-and-pins, or aborts.

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code,
            "refusing redirect (%s -> %s): the Clack CLI never follows "
            "redirects with credentials" % (req.full_url, newurl),
            headers, fp)


_opener = urllib.request.build_opener(_NoRedirect)


def _open(req, timeout):
    """urlopen through the no-redirect opener. A 3xx raises HTTPError."""
    return _opener.open(req, timeout=timeout)


_verified_origins = {}  # origin -> (level, verified_pin); level is
                         # "pinned" | "confirmed", verified_pin the pin
                         # that verdict was earned against
# Only positive verdicts are cached. A "tofu"/"unverified" verdict is never
# cached because a pin can be established mid-process (redeem/enroll TOFU):
# the next request must re-evaluate the now-pinned config instead of serving
# a stale negative verdict and refusing to send. As a bonus, the pin is
# re-validated against the live identity on every request until it is pinned.
# The verified pin is part of the cache entry: when the pin CHANGES
# mid-process (redeem/enroll TOFU rewrites relay_identity_fingerprint in the
# same cfg) the entry is invalidated and the new pin is re-verified (fetch +
# compare) before the next request proceeds -- a changed pin is never
# trusted on the back of the old verification.
_config_path = None         # set by main(); TOFU pin persistence target


def _is_loopback_url(url):
    try:
        host = urllib.parse.urlsplit(url).hostname or ""
    except Exception:
        return False
    return host in ("127.0.0.1", "::1", "localhost")


def _persist_tofu_pin(cfg, fingerprint):
    """Persist a first-contact TOFU pin so later runs enforce it (F1). The
    private key is untouched (it lives in its own mode-600 key file); only
    the JSON config gains relay_identity_fingerprint."""
    cfg["relay_identity_fingerprint"] = fingerprint
    path = _config_path
    if not path:
        return
    try:
        d = os.path.dirname(os.path.abspath(path))
        if d:
            os.makedirs(d, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
            f.write("\n")
        # O_CREAT mode applies only on create; the config holds bearer
        # tokens, so enforce 0600 on rewrite too.
        os.chmod(path, 0o600)
    except OSError as e:
        print("warning: could not save relay identity pin to %s: %s"
              % (path, e), file=sys.stderr)


def _ensure_origin_verified(origin, cfg):
    """Verify the relay identity for `origin` before any secret crosses it.

    Returns the verification level: "pinned" (stored pin matched),
    "confirmed" (fingerprint interactively confirmed this session), "tofu"
    (first-contact TOFU, tokenless configs only), or "unverified" (relay
    has no identity key and the config bears no token).

    Fail-closed (Flint review P1/P2): a config that bears a Bearer <redacted>
    NEVER sends it unless the origin is "pinned" or "confirmed".
      - pin mismatch, or identity unavailable (503) while a pin exists,
        aborts (existing F1/F4 behavior);
      - identity unavailable with no pin but an existing token aborts: a
        hostile endpoint must not harvest credentials by answering 503 (P1);
      - first contact with no pin and an existing token requires the
        operator to confirm the presented fingerprint out-of-band before it
        is pinned and any request is sent (P2). Non-interactive sessions
        abort with instructions instead of silently pinning.
    Tokenless configs (fresh enroll/redeem) keep the explicit enrollment
    path, which shows the fingerprint at its own confirmation tap and never
    transmits an existing secret.
    """
    entry = _verified_origins.get(origin)
    if entry is not None:
        level, verified_pin = entry
        if verified_pin == (cfg or {}).get("relay_identity_fingerprint"):
            return level
        # Pin changed since this origin was verified (e.g. redeem/enroll
        # TOFU pinned a new fingerprint mid-process): the stale level must
        # not cover the new pin. Invalidate and re-verify below.
        print("note: relay identity pin for %s changed mid-process; "
              "re-verifying before the next request" % origin,
              file=sys.stderr)
        del _verified_origins[origin]
    if (urllib.parse.urlsplit(origin).scheme == "http"
            and not _is_loopback_url(origin)):
        # Without TLS there is no server-authentication boundary at all;
        # say so loudly rather than letting the pin imply safety.
        print("WARNING: relay URL is cleartext %s -- Bearer <redacted> and "
              "message bodies travel unencrypted" % origin, file=sys.stderr)
    token = auth_token(cfg)
    try:
        fingerprint, _pubkey = fetch_relay_identity(origin, cfg)
    except Exception as e:
        print("could not verify relay identity for %s: %s" % (origin, e),
              file=sys.stderr)
        sys.exit(1)
    pinned = (cfg or {}).get("relay_identity_fingerprint")
    if fingerprint is None:
        # Relay has no identity key (503). Never downgrade an existing pin
        # to unauthenticated operation (F4), and never let an unavailable
        # identity launder an existing Bearer <redacted> (P1).
        if pinned:
            print("relay identity unavailable for %s but this config pins %s;"
                  " aborting rather than sending credentials unauthenticated"
                  % (origin, pinned), file=sys.stderr)
            sys.exit(1)
        if token:
            print("relay identity unavailable for %s and this config bears "
                  "credentials; aborting rather than sending them "
                  "unauthenticated (an endpoint that answers 503 could be "
                  "harvesting tokens)" % origin, file=sys.stderr)
            sys.exit(1)
        print("WARNING: relay at %s has no identity key; continuing without "
              "relay authentication (no pin established)" % origin,
              file=sys.stderr)
        # Not cached: a pin established later in this process must take
        # effect on the next request (see _verified_origins comment).
        return "unverified"
    _enforce_full_pin(_pubkey, cfg)
    if pinned and pinned != fingerprint:
        print("RELAY IDENTITY CHANGED: config pins %s but %s presents %s"
              % (pinned, origin, fingerprint), file=sys.stderr)
        print("aborting: verify out-of-band before proceeding. If you moved "
              "relays intentionally, update relay_identity_fingerprint in "
              "the config (or re-enroll).", file=sys.stderr)
        sys.exit(1)
    if pinned:
        _verified_origins[origin] = ("pinned", pinned)
        return "pinned"
    if token:
        # P2: first contact while bearing a token. Silent TOFU would let a
        # stolen/reassigned endpoint become the stored pin and receive the
        # first Bearer <redacted> The operator must confirm the fingerprint
        # out-of-band before it is pinned.
        if not sys.stdin.isatty():
            print("relay at %s presents identity %s, but this config has no "
                  "stored pin and bears credentials."
                  % (origin, fingerprint), file=sys.stderr)
            print("aborting: confirm the fingerprint out-of-band, then add "
                  "\"relay_identity_fingerprint\": \"%s\" to the config, "
                  "or run once interactively to confirm and pin it."
                  % fingerprint, file=sys.stderr)
            sys.exit(1)
        print("FIRST CONTACT: relay at %s presents identity" % origin)
        print("  fingerprint: %s" % fingerprint)
        print("Confirm this fingerprint out-of-band (relay operator, invite "
              "material, or the relay's published identity page) before any "
              "credential is sent.")
        ans = input("Type YES to pin this relay identity and continue: "
                    ).strip()
        if ans != "YES":
            print("aborted: relay identity not confirmed", file=sys.stderr)
            sys.exit(1)
        _persist_tofu_pin(cfg, fingerprint)
        _verified_origins[origin] = ("confirmed", fingerprint)
        return "confirmed"
    print("pinned relay identity %s for %s (TOFU, first contact)"
          % (fingerprint, origin), file=sys.stderr)
    _persist_tofu_pin(cfg, fingerprint)
    # Not cached: the pin is now in cfg, so the next request re-evaluates
    # and lands on "pinned" (a stale "tofu" here broke redeem/enroll hellos).
    return "tofu"


def _curl_req(cfg, method, url, headers, data, timeout):
    """Execute an HTTP request via curl subprocess.

    curl's TLS fingerprint is allowlisted by edges that filter Python's
    urllib JA3 (Cloudflare, TypeSafe, etc.). This is the primary transport;
    Python urllib is the fallback.
    """
    import subprocess
    import tempfile
    import os

    cmd = ["curl", "-s", "-m", str(timeout), "-X", method, url]
    # Response headers + body separated
    cmd += ["-D", "-", "-o", "-"]
    # Don't use proxy for localhost
    # (curl respects NO_PROXY env var automatically)
    for k, v in headers.items():
        cmd += ["-H", "%s: %s" % (k, v)]
    if data is not None:
        # Write body to temp file to avoid shell quoting issues
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.json') as f:
            f.write(data)
            body_file = f.name
        cmd += ["--data-binary", "@" + body_file]
    else:
        body_file = None

    try:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout + 10)
        if body_file:
            os.unlink(body_file)
        if result.returncode != 0:
            raise ConnectionError("curl failed: %s" % result.stderr.decode()[:200])
        # Parse: curl -D - prints headers for the proxy CONNECT (when using
        # a proxy) followed by the actual response headers, then the body.
        # Split on all header/body separators and take the LAST block as body.
        output = result.stdout
        # Find all occurrences of the header/body separator
        import re
        # Split into header blocks and body: the last \r\n\r\n separates
        # final headers from body
        parts = re.split(b"\r\n\r\n|\n\n", output)
        if len(parts) < 2:
            raise ValueError("curl output missing header/body separator")
        body = parts[-1]
        # The final header block is parts[-2]
        header_text = parts[-2]
        # Parse status from first line: HTTP/1.1 200 OK
        status_line = header_text.strip().split(b"\n")[0].decode()
        status = int(status_line.split()[1])
        # Refuse redirects (same policy as Python transport)
        if 300 <= status < 400:
            print("refusing redirect from relay: HTTP %d" % status, file=sys.stderr)
            sys.exit(1)
        try:
            payload = json.loads(body.decode("utf-8")) if body.strip() else {}
        except Exception:
            payload = {"error": "http_%d" % status} if status >= 400 else {}
        return status, payload
    except Exception:
        if body_file and os.path.exists(body_file):
            os.unlink(body_file)
        raise


def req(cfg, method, path, body=None, base=None):
    # Consent mutations must not resend the same nonce after an ambiguous
    # failure. Reconcile server state instead of silently replaying a POST.
    public_request = path in ("/v1/handshakes/requests", "/v1/handshakes/requests/redeem",
                              "/v1/handshakes/accept")
    origin = (base or base_url(cfg)).rstrip("/")
    token = auth_token(cfg)
    level = _ensure_origin_verified(origin, cfg)
    if token and level not in ("pinned", "confirmed"):
        # Defense in depth (Flint P1): a Bearer <redacted> only crosses a
        # pin-matched or explicitly confirmed origin. _ensure_origin_verified
        # already aborts in these cases; the invariant is stated here too so
        # no future caller can bypass it.
        print("refusing to send credentials to %s: relay identity %s"
              % (origin, level), file=sys.stderr)
        sys.exit(1)
    url = origin + path
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    headers["User-Agent"] = user_agent(cfg)
    headers.update(sign_headers(cfg, method, path, data))
    if data is not None:
        headers["Content-Type"] = "application/json"

    # Primary transport: curl (TLS fingerprint allowlisted by edges).
    # Fallback: Python urllib (for environments without curl).
    # Controlled by CLACK_USE_CURL env (default: 1). Set to 0 to force Python.
    use_curl = os.environ.get("CLACK_USE_CURL", "1") == "1"
    if use_curl:
        try:
            return _curl_req(cfg, method, url, headers, data, timeout=130)
        except Exception as e:
            if public_request and not isinstance(e, FileNotFoundError):
                raise RuntimeError("Public request outcome UNKNOWN; reconcile handshakes before retrying") from e
            print("curl transport failed (%s), falling back to Python"
                  % type(e).__name__, file=sys.stderr)

    # Fallback: Python urllib with retry
    r = urllib.request.Request(url, data=data, method=method)
    for k, v in headers.items():
        r.add_header(k, v)
    # Retry on transient connection drops. The relay/Cloudflare occasionally
    # drops mid-read (IncompleteRead) or closes without response
    # (RemoteDisconnected) after processing. For idempotent GETs, retry is safe.
    # For POSTs, the caller must use stable IDs (relay dedupes on id+sender).
    last_exc = None
    for attempt in range(3):
        try:
            with _open(r, timeout=130) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if 300 <= e.code < 400:
                # _NoRedirect raises for 3xx: never treat as a normal response.
                loc = e.headers.get("Location") if e.headers else None
                print("refusing redirect from relay: HTTP %d%s"
                      % (e.code, (" -> " + loc) if loc else ""),
                      file=sys.stderr)
                sys.exit(1)
            try:
                payload = json.loads(e.read().decode("utf-8"))
            except Exception:
                payload = {"error": "http_%d" % e.code}
            return e.code, payload
        except (http.client.IncompleteRead, http.client.RemoteDisconnected,
                ConnectionError, TimeoutError) as e:
            last_exc = e
            if public_request:
                raise RuntimeError("Public request outcome UNKNOWN; reconcile handshakes before retrying") from e
            if attempt < 2:
                time.sleep(1 + attempt)
                # Rebuild the request: urllib Request objects are single-use
                # after a failed open on some Python versions.
                r = urllib.request.Request(url, data=data, method=method)
                for k, v in headers.items():
                    r.add_header(k, v)
                continue
            raise


# --- Relay identity (TOFU, v0.2.10) -------------------------------------------
# The relay exposes its STABLE identity public key at GET /v1/identity. The
# fingerprint is computed over that key -- never over the per-nonce
# signature, which varies every run and is unconfirmable theater. The
# construction is: sha256("clack-relay-identity-v1" || ":" || n_be || ":"
# || e_be), displayed as "sha256:<first 16 hex chars>", where n_be / e_be
# are the minimal big-endian encodings of the "n" / "e" hex fields.
#
# Trust boundary (Flint review F5): TLS is the primary server
# authentication -- your https:// origin. The pinned key is a second
# layer: it catches a relay that changed keys and stops unsophisticated
# impersonators, but it does not by itself prove the connection is direct.
# A determined intermediary that can reach the genuine relay can proxy the
# challenge and return a valid proof. The CLI enforces the pin on every
# authenticated request and never follows redirects with credentials; it
# does not claim the nonce challenge authenticates the channel.

_IDENTITY_FP_DOMAIN = b"clack-relay-identity-v1"


def relay_identity_fingerprint_full(pubkey):
    """Full stable key digest for trusted invite metadata; not the nonce proof."""
    n = int(pubkey["n"], 16)
    e = int(pubkey["e"], 16)
    n_be = n.to_bytes((n.bit_length() + 7) // 8, "big")
    e_be = e.to_bytes((e.bit_length() + 7) // 8, "big")
    digest = hashlib.sha256(_IDENTITY_FP_DOMAIN + b":" + n_be + b":" + e_be).hexdigest()
    return "sha256:" + digest


def relay_identity_fingerprint(pubkey):
    """Legacy short display/config format, preserved for existing clients."""
    return relay_identity_fingerprint_full(pubkey)[:23]


def _enforce_full_pin(pubkey, cfg):
    pinned = (cfg or {}).get("relay_identity_fingerprint_full")
    if pinned and (pubkey is None or pinned != relay_identity_fingerprint_full(pubkey)):
        print("RELAY IDENTITY CHANGED: full invite/config pin mismatch; aborting before credentials", file=sys.stderr)
        sys.exit(1)


_SHA256_DINFO_HEAD = bytes.fromhex("3031300d060960864801650304020105000420")


def relay_identity_verify(pubkey, nonce_hex, signature_b64):
    """Verify the relay's /v1/identity nonce signature. Pure stdlib RSA."""
    n = int(pubkey["n"], 16)
    e = int(pubkey["e"], 16)
    nonce = bytes.fromhex(nonce_hex)
    sig = base64.b64decode(signature_b64)
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    t = _SHA256_DINFO_HEAD + hashlib.sha256(nonce).digest()
    em = pow(int.from_bytes(sig, "big"), e, n).to_bytes(k, "big")
    expect = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return em == expect


def fetch_relay_identity(relay_url, cfg=None):
    """Fetch and verify the relay's identity.

    Strict (Flint review F3): the proof must answer OUR challenge -- the
    echoed nonce must equal the locally generated one exactly, the
    algorithm field must be the expected value, and the signature is
    verified over the local nonce bytes, not the echoed value. A recorded
    valid proof for a different challenge is rejected even though its
    signature is genuine.

    The configured user_agent is sent (default ClackRelay-CLI/1.1.0):
    Cloudflare-fronted relays 403 Python-urllib's default signature, so a
    bare _open() fails closed before any normal operation can run.

    Returns (fingerprint, pubkey). Raises on transport/HTTP errors other
    than 503 (relay has no identity key), in which case returns (None, None)
    and the caller must fail closed when a pin exists (F4).
    """
    nonce = os.urandom(32).hex()
    id_req = urllib.request.Request(relay_url + "/v1/identity?nonce=" + nonce)
    id_req.add_header("User-Agent", user_agent(cfg or {}))
    # Retry on transient connection drops (IncompleteRead, RemoteDisconnected).
    # The relay/Cloudflare occasionally drops mid-read; the identity itself
    # is stable, so retrying the fetch is safe.
    last_exc = None
    for attempt in range(3):
        try:
            with _open(id_req, timeout=30) as resp:
                ident = json.loads(resp.read().decode("utf-8"))
            last_exc = None
            break
        except urllib.error.HTTPError as e:
            if e.code == 503:
                return None, None
            raise
        except (http.client.IncompleteRead, http.client.RemoteDisconnected,
                ConnectionError, TimeoutError) as e:
            last_exc = e
            if attempt < 2:
                time.sleep(1 + attempt)
                continue
            raise
    if not isinstance(ident, dict):
        raise ValueError("relay identity response is not a JSON object")
    if ident.get("nonce") != nonce:
        raise ValueError("relay identity proof answers a different challenge")
    if ident.get("algorithm") != "rsassa-pkcs1-v1_5-sha256":
        raise ValueError("relay identity uses unexpected algorithm %r"
                         % (ident.get("algorithm"),))
    pubkey = ident.get("public_key")
    if not isinstance(pubkey, dict):
        raise ValueError("relay identity response has no public_key")
    for field in ("n", "e"):
        try:
            val = int(pubkey[field], 16)
        except (KeyError, TypeError, ValueError):
            raise ValueError("relay identity public_key has bad %r field"
                             % field)
        if val <= 0:
            raise ValueError("relay identity public_key has non-positive %r"
                             % field)
    if not ident.get("signature"):
        raise ValueError("relay identity response has no signature")
    if not relay_identity_verify(pubkey, nonce, ident["signature"]):
        raise ValueError("relay identity signature verification failed")
    return relay_identity_fingerprint(pubkey), pubkey


def check_relay_identity(relay_url, cfg):
    """TOFU for the identity-establishing flows (redeem, enroll).

    Fetches the relay's stable identity key, verifies the nonce signature
    against it, and enforces the pinned fingerprint when the config already
    has one. Returns the fingerprint. Aborts the process on pin mismatch
    -- a changed relay key is never silently accepted -- and whenever the
    identity service is unavailable for ANY reason (503, transport error,
    missing identity material), whether or not a pin exists (v0.2.13 F4:
    fail closed before any secret, enrollment proof, or message body leaves
    the client). There is no warn-and-continue and no --yes bypass for
    identity authentication: first contact verifies-and-pins, or aborts.
    """
    try:
        fingerprint, _pubkey = fetch_relay_identity(relay_url, cfg)
    except urllib.error.HTTPError as e:
        print("could not verify relay identity: HTTP Error %d" % e.code,
              file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print("could not verify relay identity: %s" % e, file=sys.stderr)
        sys.exit(1)
    if fingerprint is None:
        # Relay has no identity key (503) or identity material is missing.
        # Fail closed: never downgrade to unauthenticated onboarding, with
        # or without a stored pin -- a hostile endpoint must not harvest
        # claim secrets or enrollment proofs by answering 503 (F4/P1).
        pinned = (cfg or {}).get("relay_identity_fingerprint")
        print("relay identity unavailable for %s%s; aborting before any "
              "secret or enrollment proof is sent"
              % (relay_url,
                 (" (this config pins %s)" % pinned) if pinned else ""),
              file=sys.stderr)
        sys.exit(1)
    pinned = (cfg or {}).get("relay_identity_fingerprint")
    _enforce_full_pin(_pubkey, cfg)
    if pinned and pinned != fingerprint:
        print("RELAY IDENTITY CHANGED: pinned %s but relay now presents %s"
              % (pinned, fingerprint), file=sys.stderr)
        print("aborting: verify out-of-band before proceeding", file=sys.stderr)
        sys.exit(1)
    return fingerprint


def cmd_keygen(args):
    if os.path.exists(args.config) and not args.force:
        print("refusing to overwrite existing %s (use --force)" % args.config,
              file=sys.stderr)
        return 1
    seed, pub = keygen()
    cfg = {
        "kind": IDENTITY_KIND,
        "relay_url": args.relay_url,
        "identity_pubkey": b64u_encode(pub),
    }
    if args.user_agent:
        cfg["user_agent"] = args.user_agent
    os.makedirs(os.path.dirname(os.path.abspath(args.config)) or ".", exist_ok=True)
    _save_identity_config(args.config, cfg, seed, key_path=args.key_path)
    print("identity created: %s" % args.config)
    print("private key:      %s (mode 600; never leaves this machine)" % cfg["identity_privkey_path"])
    print("pubkey: %s" % cfg["identity_pubkey"])
    return 0


def cmd_attach_key(args, cfg):
    """Attach a fresh Ed25519 signing key to an existing client config.

    Legacy token-only configs (no "kind") are converted to identity
    configs (kind == IDENTITY_KIND) so the CLI auto-signs every request;
    identity configs that lost their key file get a fresh keypair. The
    operator must register the printed pubkey in the relay's
    "identity_pubkeys" map before the relay will accept signed requests.
    Idempotent: a config that already has a usable seed is left alone.
    """
    if is_identity_cfg(cfg) and signing_seed(cfg) is not None:
        pub = b64u_decode(cfg["identity_pubkey"])
        print("already has a signing key: %s" % args.config)
        print("pubkey: %s" % b64u_encode(pub))
        return 0

    if is_identity_cfg(cfg):
        # Identity config whose key file is missing/unreadable: fresh
        # keypair, keep everything else (relay_url, peer_name, token...).
        new_cfg = dict(cfg)
        peer_name = new_cfg.get("peer_name")
        if not peer_name:
            print("identity config has no peer_name; cannot attach a key",
                  file=sys.stderr)
            return 1
    else:
        # Legacy token config: pick the peer, carry token + URL forward.
        peers = cfg.get("peers") or {}
        peer_name = args.peer
        if peer_name and peer_name not in peers:
            print("peer %r not in %s" % (peer_name, args.config),
                  file=sys.stderr)
            return 1
        if not peer_name:
            if len(peers) == 1:
                peer_name = next(iter(peers))
            else:
                print("config has %d peers; pass --peer <name>" % len(peers),
                      file=sys.stderr)
                return 1
        token = peers.get(peer_name)
        if not token:
            print("no token for peer %r in %s" % (peer_name, args.config),
                  file=sys.stderr)
            return 1
        relay_url = (cfg.get("base_url") or cfg.get("relay_url")
                     or "http://127.0.0.1:%d" % cfg.get("port", 18802))
        new_cfg = {
            "kind": IDENTITY_KIND,
            "relay_url": relay_url.rstrip("/"),
            "peer_name": peer_name,
            "service_token": token
        }
        if cfg.get("user_agent"):
            new_cfg["user_agent"] = cfg["user_agent"]
        if cfg.get("relay_identity_fingerprint"):
            new_cfg["relay_identity_fingerprint"] = \
                cfg["relay_identity_fingerprint"]

    seed, pub = keygen()
    new_cfg["identity_pubkey"] = b64u_encode(pub)
    _save_identity_config(args.config, new_cfg, seed,
                          key_path=getattr(args, "key_path", None))
    print("signing key attached: %s (peer %s)" % (args.config, peer_name))
    print("private key: %s (mode 600; never leaves this machine)"
          % new_cfg["identity_privkey_path"])
    print("pubkey for the relay operator's identity_pubkeys map:")
    print(b64u_encode(pub))
    return 0


def cmd_register_key(args, cfg):
    """Self-service Ed25519 key registration (v0.2.17).

    Ensures the identity file carries a signing keypair (generating one
    when missing, like attach-key), then POSTs the public key to
    /v1/register-key with bearer-token auth. The endpoint is
    signature-exempt -- it IS the upgrade path for token-only peers --
    so this works before the client can sign. Reports whether the relay
    recorded a fresh registration or a rotation.
    """
    if is_identity_cfg(cfg):
        peer_name = cfg.get("peer_name")
        if not peer_name:
            print("identity config has no peer_name; cannot register a key",
                  file=sys.stderr)
            return 1
        if not cfg.get("service_token"):
            print("no service_token in %s" % args.config, file=sys.stderr)
            return 1
        new_cfg = dict(cfg)
    else:
        peers = cfg.get("peers") or {}
        peer_name = args.peer
        if peer_name and peer_name not in peers:
            print("peer %r not in %s" % (peer_name, args.config),
                  file=sys.stderr)
            return 1
        if not peer_name:
            if len(peers) == 1:
                peer_name = next(iter(peers))
            else:
                print("config has %d peers; pass --peer <name>" % len(peers),
                      file=sys.stderr)
                return 1
        token = peers.get(peer_name)
        if not token:
            print("no token for peer %r in %s" % (peer_name, args.config),
                  file=sys.stderr)
            return 1
        relay_url = (cfg.get("base_url") or "http://127.0.0.1:%d"
                     % cfg.get("port", 18802)).rstrip("/")
        new_cfg = {
            "kind": IDENTITY_KIND,
            "relay_url": relay_url,
            "peer_name": peer_name,
            "service_token": token,
        }
        if cfg.get("user_agent"):
            new_cfg["user_agent"] = cfg["user_agent"]
        if cfg.get("relay_identity_fingerprint"):
            new_cfg["relay_identity_fingerprint"] = \
                cfg["relay_identity_fingerprint"]

    seed = signing_seed(new_cfg)
    if seed is None:
        seed, pub = keygen()
        new_cfg["identity_pubkey"] = b64u_encode(pub)
        _save_identity_config(args.config, new_cfg, seed,
                              key_path=getattr(args, "key_path", None))
        print("generated signing keypair; private key: %s (mode 600; never "
              "leaves this machine)" % new_cfg["identity_privkey_path"])
    elif not new_cfg.get("identity_pubkey"):
        # Seed without a recorded pubkey: derive it and persist.
        new_cfg["identity_pubkey"] = b64u_encode(_publickey(seed))
        _save_identity_config(args.config, new_cfg, seed,
                              key_path=getattr(args, "key_path", None))
    cfg = new_cfg
    pub_b64 = new_cfg["identity_pubkey"]

    code, out = req(cfg, "POST", "/v1/register-key", {"pubkey": pub_b64},
                    base=args.base_url)
    if code == 200 and out.get("registered"):
        print("registered signing key for peer %r%s"
              % (peer_name, " (rotated)" if out.get("rotated") else ""))
        print("pubkey: %s" % pub_b64)
        return 0
    print("register-key failed: HTTP %d %s" % (code, json.dumps(out)),
          file=sys.stderr)
    return 1


def parse_link(link):
    link = link.strip()
    if "#" not in link:
        raise ValueError("link has no fragment")
    frag = link.split("#", 1)[1]
    q = urllib.parse.parse_qs(frag, keep_blank_values=True)
    get = lambda k: (q.get(k) or [None])[0]
    fields = {k: get(k) for k in ("r", "i", "h", "k", "v", "by", "exp", "max", "relay_fp", "fp_scheme", "peer_name")}
    import re as _re
    for k in ("relay_fp", "fp_scheme", "peer_name"):
        if k in q and len(q[k]) != 1:
            raise ValueError("duplicate invite metadata: " + k)
    if fields["relay_fp"] is not None or fields["fp_scheme"] is not None:
        if fields["fp_scheme"] != "clack-relay-identity-v1" or not _re.fullmatch(r"sha256:[0-9a-f]{64}", fields["relay_fp"] or ""):
            raise ValueError("unsupported scheme or invalid full relay fingerprint")
        origin = b64u_decode(fields["r"] or "").decode("utf-8")
        if urllib.parse.urlsplit(origin).scheme != "https":
            raise ValueError("pinned invite requires HTTPS")
    if fields["peer_name"] is not None:
        if not _re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,30}", fields["peer_name"]) or fields["peer_name"].startswith("guest-"):
            raise ValueError("invalid invite peer name")
    if not fields["r"] or not fields["k"]:
        raise ValueError("link missing r/k fields")
    if not fields["i"] and not fields["h"]:
        raise ValueError("link missing i (v3 invite) or h (v4 handshake) id")
    return fields


def parse_request_url(link, relay_url):
    """Validate locally BEFORE any signed request; never trust URL metadata."""
    def split_origin(value):
        if (type(value) is not str or not value
                or any(ord(c) <= 32 or ord(c) == 127 for c in value)
                or "?" in value or "#" in value or "\\" in value):
            raise ValueError("request URL must be a clean absolute URL")
        parsed = urllib.parse.urlsplit(value)
        if (parsed.scheme not in ("http", "https") or not parsed.hostname
                or parsed.username is not None or parsed.password is not None):
            raise ValueError("request URL requires an HTTP(S) origin without credentials")
        parsed.port
        return parsed
    configured = split_origin(relay_url)
    supplied = split_origin(link)
    if configured.path not in ("", "/"):
        raise ValueError("configured relay must be an origin")
    if (supplied.scheme, supplied.netloc.lower()) != (
            configured.scheme, configured.netloc.lower()):
        raise ValueError("request URL origin differs from configured relay")
    if not supplied.path.startswith("/join/"):
        raise ValueError("request URL must be exactly /join/<canonical UUID>")
    handle = supplied.path[len("/join/"):]
    try:
        canonical = str(uuid.UUID(handle))
    except (ValueError, AttributeError):
        raise ValueError("request URL requires a canonical UUID") from None
    if handle != canonical:
        raise ValueError("request URL requires a canonical UUID")
    return handle


def cmd_public_request(args, cfg):
    """Use only an existing enrolled identity; never enroll or auto-accept."""
    try:
        origin = base_url(cfg)
        # Overrides must not silently move existing credentials to another relay.
        if args.base_url and args.base_url.rstrip("/") != origin:
            raise ValueError("public requests require the configured relay, not --base-url")
        if args.cmd == "redeem-request":
            handle = parse_request_url(args.link, origin)
            path, body = "/v1/handshakes/requests/redeem", {"h": handle}
        elif args.cmd == "mint-request":
            import re
            import math
            target = args.target_identity
            if (not re.fullmatch(r"[A-Za-z0-9_-]{43}", target)
                    or len(b64u_decode(target)) != 32
                    or b64u_encode(b64u_decode(target)) != target):
                raise ValueError("target_identity must be a canonical Ed25519 public key (base64url)")
            if not math.isfinite(args.exp_days) or args.exp_days <= 0:
                raise ValueError("exp_days must be a positive finite number")
            path = "/v1/handshakes/requests"
            body = {"target_identity": target, "exp_days": args.exp_days,
                    "enc_v": args.enc_v}
        else:
            path = "/v1/handshakes/accept"
            body = {"handshake_id": args.handshake_id}
            if args.enc_v is not None:
                body["enc_v"] = args.enc_v
        if (not is_identity_cfg(cfg) or not auth_token(cfg)
                or not cfg.get("peer_name") or signing_seed(cfg) is None):
            raise ValueError("public requests require an existing enrolled signing identity; "
                             "use v4 capability onboarding for a new agent")
        if not cfg.get("relay_identity_fingerprint"):
            raise ValueError("public requests require an existing configured relay pin; "
                             "establish relay trust separately before using this command")
    except (ValueError, KeyError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    try:
        code, out = req(cfg, "POST", path, body, base=origin)
    except RuntimeError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    print(json.dumps(out, indent=2))
    if 200 <= code < 300 and args.cmd == "redeem-request":
        print("Pending only: review the handshake, then explicitly run accept-handshake HANDSHAKE_ID.",
              file=sys.stderr)
    return 0 if 200 <= code < 300 else 1


def cmd_mint_invite(args, cfg):
    body = {
        "expiry_seconds": int(args.expiry_hours * 3600),
        "max_uses": args.max_uses,
    }
    code, out = req(cfg, "POST", "/v1/invites/mint", body, base=args.base_url)
    if 200 <= code < 300:
        print(out["link"])
        print("invite_id: %s" % out["invite_id"])
        print("expires:   %s" % datetime.datetime.fromtimestamp(out["exp"]).strftime("%Y-%m-%d %H:%M:%S"))
        print("max_uses:  %d" % out["max_uses"])
    else:
        print(json.dumps(out, indent=2))
    return 0 if 200 <= code < 300 else 1


def _apply_enrollment_response(cfg, out, what, requested_name=None):
    """Apply an enrollment/redeem response to an identity config.

    Fresh inline (the normal first-enrollment response): carries
    service_token and peer_name -- both are stored. Existing-identity
    path: the relay answers an authenticated re-enroll of an
    already-enrolled identity WITHOUT service_token -- the peer retains
    its existing name/key/token and proceeds (no new identity, no
    overwrite). Anything else fails closed. Collision, origin-pin, and
    local-key handling are untouched: this only decides what to store,
    never how the identity was made or where the token is sent.

    requested_name is the name the operator explicitly asked for (the
    redeem name prompt answer, or the enroll --name flag); None means
    guest/no-preference and disables the check. A requested name is NEVER
    silently substituted or silently dropped: a mismatch fails loudly
    (returns False) instead of accepting a server-picked name."""
    token = out.get("service_token")
    if token:
        if not out.get("peer_name"):
            print("%s response missing peer_name" % what, file=sys.stderr)
            return False
        if (requested_name is not None
                and out["peer_name"] != requested_name):
            print("%s: requested peer name %r but the relay enrolled %r; "
                  "refusing to silently accept a substituted name"
                  % (what, requested_name, out["peer_name"]), file=sys.stderr)
            return False
        cfg["service_token"] = token
        cfg["peer_name"] = out["peer_name"]
        cfg["display_name"] = out.get("display_name")
    elif cfg.get("service_token") and cfg.get("peer_name"):
        if (requested_name is not None
                and requested_name != cfg["peer_name"]):
            print("%s: requested peer name %r does not match the enrolled "
                  "identity %r; refusing to silently drop the request"
                  % (what, requested_name, cfg["peer_name"]), file=sys.stderr)
            return False
        # Already-enrolled identity: retain existing name/key/token.
        print("note: %s on an already-enrolled identity; retaining existing "
              "name/key/token" % what)
    else:
        print("%s response missing service_token and no existing token; "
              "cannot proceed" % what, file=sys.stderr)
        return False
    return True


def cmd_redeem(args):
    try:
        f = parse_link(args.link)
    except ValueError as e:
        print("bad link: %s" % e, file=sys.stderr)
        return 1
    relay_url = b64u_decode(f["r"]).decode("utf-8")
    exp_human = datetime.datetime.fromtimestamp(int(f["exp"])).strftime("%Y-%m-%d %H:%M:%S")

    # Verify a trusted invite's full pin, or preserve legacy TOFU confirmation,
    # before sending the claim secret. Missing/unverifiable identity aborts.
    existing_cfg = load_config(args.config) if os.path.exists(args.config) else None
    verification_cfg = dict(existing_cfg or {})
    if f.get("relay_fp"):
        if existing_cfg and existing_cfg.get("relay_url", "").rstrip("/") != relay_url.rstrip("/"):
            print("refusing to overwrite an existing different-relay config; use an isolated config", file=sys.stderr)
            return 1
        stored = verification_cfg.get("relay_identity_fingerprint_full")
        if stored and stored != f["relay_fp"]:
            print("invite pin conflicts with stored full pin", file=sys.stderr)
            return 1
        verification_cfg["relay_identity_fingerprint_full"] = f["relay_fp"]
    relay_fp = check_relay_identity(relay_url, verification_cfg)

    print("You are about to join a relay:")
    print("  relay:            %s" % relay_url)
    # check_relay_identity aborts when the relay has no verifiable identity
    # (F4: fail closed), so relay_fp is always set here.
    if f.get("relay_fp"):
        print("  relay key:        %s  <- full trusted-invite pin verified" % f["relay_fp"])
    else:
        print("  relay key (TOFU): %s  <- stable key; confirm once, pinned after" % relay_fp)
    print("  invited by:       %s" % f["by"])
    print("  link expires:     %s" % exp_human)
    print("  link version:     %s" % f["v"])
    print()
    print("This creates YOUR OWN identity keypair on this machine. The relay")
    print("never sees your private key.")
    # Trusted, full-pin-bearing invites authorize automated agent enrollment.
    # Older unpinned links retain their interactive confirmation.
    ans = "YES" if f.get("relay_fp") else input("Type YES to redeem this invitation: ").strip()
    if ans != "YES":
        print("aborted.")
        return 1

    # Load or create the identity at --config (existing config = existing
    # user path: the same identity is reused, never duplicated).
    if os.path.exists(args.config):
        cfg = load_config(args.config)
        if not is_identity_cfg(cfg):
            print("%s exists but is not an identity config" % args.config,
                  file=sys.stderr)
            return 1
        if cfg.get("relay_url", "").rstrip("/") != relay_url:
            print("warning: config targets %s, link targets %s"
                  % (cfg.get("relay_url"), relay_url), file=sys.stderr)
    else:
        seed, pub = keygen()
        cfg = {
            "kind": IDENTITY_KIND,
            "relay_url": relay_url,
            "identity_pubkey": b64u_encode(pub),
            "user_agent": "ClackRelay-CLI/1.1.0",
        }
        # Persist the private key immediately (mode 600 key file): the relay
        # never sees it, and nothing below may proceed without it on disk.
        _save_identity_config(args.config, cfg, seed)
    seed = signing_seed(cfg)
    if seed is None:
        print("config has no usable identity private key", file=sys.stderr)
        return 1
    pub = b64u_decode(cfg["identity_pubkey"])
    if f.get("relay_fp"):
        cfg["relay_identity_fingerprint_full"] = f["relay_fp"]

    # v0.2.13+: handshake links (v=4, h= link id). v3 invite links (i=)
    # keep the legacy flow below.
    if f.get("h"):
        return _redeem_v4_handshake(args, cfg, f, relay_url, relay_fp,
                                    seed, pub)

    # Challenge -> sign(nonce || invite_id || pubkey) -> redeem.
    code, ch = req(cfg, "POST", "/v1/invites/challenge",
                   {"invite_id": f["i"]}, base=relay_url)
    if not (200 <= code < 300):
        print("challenge failed: %s" % json.dumps(ch), file=sys.stderr)
        return 1
    nonce_raw = b64u_decode(ch["nonce"])
    sig = sign(seed, nonce_raw + f["i"].encode("utf-8") + pub)
    code, out = req(cfg, "POST", "/v1/invites/redeem", {
        "invite_id": f["i"],
        "secret": f["k"],
        "identity_pubkey": b64u_encode(pub),
        "proof": {"nonce": ch["nonce"], "signature": b64u_encode(sig)},
    }, base=relay_url)
    if not (200 <= code < 300):
        print("redeem failed: %s" % json.dumps(out), file=sys.stderr)
        return 1

    if not _apply_enrollment_response(cfg, out, "redeem"):
        return 1
    # check_relay_identity guarantees relay_fp (it aborts otherwise).
    cfg["relay_identity_fingerprint"] = relay_fp  # TOFU pin
    # Same config-save path as keygen: private key stays in its 0600 file.
    _save_identity_config(args.config, cfg, seed)
    print("enrolled as %s (identity %s...)"
          % (cfg["peer_name"], str(out.get("identity", ""))[:12]))

    # Greeting exchange: hello to the inviter. Onboarding succeeds when the
    # invitee receives AND acknowledges the inviter's reply (checked by the
    # inviter via /v1/receipts -> acked).
    # F4: the hello bears the fresh token, so it only goes to the
    # pin-verified origin -- check_relay_identity above guaranteed a
    # verifiable relay identity, and the pin is stored below.
    inviter = out.get("inviter_name")
    if inviter and cfg.get("relay_identity_fingerprint"):
        hello_id = str(uuid.uuid4())
        hello_text = ("hello %s -- joined via your invite link "
                      "(Clack onboarding MVP)" % inviter)
        hello_body = {
            "id": hello_id,
            "to": inviter,
            "topic": "introductions",
        }
        try:
            env, reason = _e2ee_encrypt_for(cfg, inviter, hello_text,
                                           base_url=relay_url)
        except E2EEError as ex:
            print("hello skipped: encryption failed (%s)" % ex,
                  file=sys.stderr)
            env, reason = None, "encryption failed"
        if env is not None:
            hello_body["enc"] = env
            code, sent = req(cfg, "POST", "/v1/send", hello_body,
                             base=relay_url)
            if 200 <= code < 300:
                print("hello sent to %s (id %s, encrypted)" % (inviter, hello_id))
            else:
                print("hello failed: %s" % json.dumps(sent), file=sys.stderr)
        else:
            print("hello skipped: pair not enc_capable (%s); "
                  "not sending plaintext" % reason, file=sys.stderr)
    elif inviter:
        print("note: relay has no identity key; skipping hello rather than "
              "sending credentials to an unverified relay")
    else:
        print("note: inviter has no messageable peer name; skipping hello")
    print("config saved: %s" % args.config)
    return 0


def _redeem_v4_handshake(args, cfg, f, relay_url, relay_fp, seed, pub):
    """Redeem a v4 handshake link: inline enrollment (invite/PoW/open gate)
    via POST /v1/handshakes/redeem, then accept the pending handshake via
    POST /v1/handshakes/accept. The minter already consented at mint time;
    the redeemer consents by accepting."""
    h = f["h"]
    k = f["k"]

    # v0.2.15: let the redeemer choose their peer name (lowercase
    # alphanumeric, _ and - allowed, 1-31 chars, may not start with
    # "guest-"). Empty input = server assigns a guest name.
    #
    # #721 (independent acceptance, round 2): an already-authenticated
    # identity (service_token + peer_name present) redeems on its EXISTING
    # identity -- no interactive name prompt, no fresh-enrollment rename,
    # no requested_name in the redeem body. _apply_enrollment_response
    # retains the existing name/key/token below.
    import re as _re
    _name_re = _re.compile(r"^[a-z0-9][a-z0-9_-]{0,30}$")
    requested_name = None
    already_enrolled = bool(cfg.get("service_token") and cfg.get("peer_name"))
    if already_enrolled:
        print("note: redeeming on already-enrolled identity %r; keeping "
              "existing peer name (no rename)" % cfg["peer_name"])
    else:
        while True:
            ans = input("Choose your peer name (lowercase, or Enter for guest): ").strip()
            if not ans:
                break
            if _name_re.match(ans) and not ans.startswith("guest-"):
                requested_name = ans
                break
            print("  invalid name: use lowercase letters, digits, _ or -, 1-31 chars", file=sys.stderr)

    body = {"h": h, "k": k, "identity_pubkey": b64u_encode(pub)}
    if requested_name:
        body["requested_name"] = requested_name
    if already_enrolled:
        # #721 (independent acceptance, round 3/4): an existing authenticated
        # identity redeems on its live credentials. The request carries
        # Bearer + Ed25519 auth at the HTTP layer, so NO fresh enrollment
        # challenge is fetched. Per the authoritative redeem handler
        # (relay.py _handle_handshake_redeem), an authenticated caller's
        # identity comes from caller_identity(peer) -- the body's
        # identity_pubkey is only consulted on the fresh-enrollment path.
        # The exact contract body here is {h, k}: no proof, no pubkey.
        # Trace for this path starts [/v1/handshakes/redeem,
        # /v1/handshakes/accept].
        print("note: already-enrolled identity; skipping "
              "/v1/enroll/challenge, redeeming {h,k} on existing credentials")
        body = {"h": h, "k": k}
    else:
        # Enrollment challenge. The relay prefers the invite gate when enabled
        # (challenge bound to this link id); otherwise PoW or open. Only fall
        # back past {"invite_id": h} when the invite gate itself is disabled --
        # a bad link must fail here, not silently switch gates.
        code, ch = req(cfg, "POST", "/v1/enroll/challenge",
                       {"invite_id": h}, base=relay_url)
        if code == 400 and ch.get("error") == "invite_not_allowed":
            code, ch = req(cfg, "POST", "/v1/enroll/challenge", {},
                           base=relay_url)
        if not (200 <= code < 300):
            print("challenge failed: %s" % json.dumps(ch), file=sys.stderr)
            return 1
        gate = ch.get("gate")
        if gate == "pow":
            chal_raw = b64u_decode(ch["challenge"])
            difficulty = int(ch.get("difficulty", 20))
            print("solving proof-of-work (difficulty %d bits)..." % difficulty)
            pow_nonce = None
            while pow_nonce is None:
                cand = os.urandom(16)
                if _pow_lead_zero(hashlib.sha256(chal_raw + cand).digest()) >= difficulty:
                    pow_nonce = cand
            body["pow_nonce"] = b64u_encode(pow_nonce)
            sig = sign(seed, chal_raw + pow_nonce + pub)
        elif gate == "invite":
            chal_raw = b64u_decode(ch["nonce"])
            sig = sign(seed, chal_raw + h.encode("utf-8") + pub)
        elif gate == "open":
            chal_raw = b64u_decode(ch["nonce"])
            sig = sign(seed, chal_raw + pub)
        else:
            print("unknown enrollment gate: %r" % gate, file=sys.stderr)
            return 1
        body["proof"] = {"nonce": b64u_encode(chal_raw),
                         "signature": b64u_encode(sig)}
    code, out = req(cfg, "POST", "/v1/handshakes/redeem", body,
                    base=relay_url)
    if not (200 <= code < 300):
        print("redeem failed: %s" % json.dumps(out), file=sys.stderr)
        return 1

    if not _apply_enrollment_response(cfg, out, "redeem", requested_name):
        return 1
    if relay_fp:
        cfg["relay_identity_fingerprint"] = relay_fp  # TOFU pin
    # Same config-save path as keygen: private key stays in its 0600 file.
    _save_identity_config(args.config, cfg, seed)
    print("enrolled as %s (identity %s..., via %s gate)"
          % (cfg["peer_name"], str(out.get("identity", ""))[:12],
             out.get("enrollment")))
    print("handshake: %s (status %s)"
          % (out.get("handshake_id"), out.get("status")))

    # The redeemer consents by accepting. Authenticated: the fresh token
    # and signing key prove key possession. E2EE: advertise enc_v=1 so the
    # relay marks the pair enc_capable when the minter advertised too.
    code, acc = req(cfg, "POST", "/v1/handshakes/accept",
                    {"handshake_id": out["handshake_id"], "enc_v": 1},
                    base=relay_url)
    if not (200 <= code < 300):
        print("accept failed: %s" % json.dumps(acc), file=sys.stderr)
        return 1
    print("handshake active with %s"
          % (out.get("minter_name_hint") or acc.get("peer") or "peer"))

    # Greeting exchange: hello to the minter. The handshake is active now,
    # so the send is authorized. E2EE-only: encrypt the hello; fail closed
    # (skip) if the pair is not enc_capable or encryption fails. Never send
    # plaintext.
    minter = out.get("minter_name_hint")
    if minter and cfg.get("relay_identity_fingerprint"):
        hello_id = str(uuid.uuid4())
        hello_text = ("hello %s -- joined via your handshake link "
                      "(Clack onboarding)" % minter)
        hello_body = {
            "id": hello_id,
            "to": minter,
            "topic": "introductions",
        }
        try:
            env, reason = _e2ee_encrypt_for(cfg, minter, hello_text,
                                           base_url=relay_url)
        except E2EEError as ex:
            print("hello skipped: encryption failed (%s)" % ex,
                  file=sys.stderr)
            env, reason = None, "encryption failed"
        if env is not None:
            hello_body["enc"] = env
            code, sent = req(cfg, "POST", "/v1/send", hello_body,
                             base=relay_url)
            if 200 <= code < 300:
                print("hello sent to %s (id %s, encrypted)" % (minter, hello_id))
            else:
                print("hello failed: %s" % json.dumps(sent), file=sys.stderr)
        else:
            print("hello skipped: pair not enc_capable (%s); "
                  "not sending plaintext" % reason, file=sys.stderr)
    elif minter:
        print("note: relay has no identity key; skipping hello rather than "
              "sending credentials to an unverified relay")
    else:
        print("note: minter has no messageable peer name; skipping hello")
    print("config saved: %s" % args.config)
    return 0


def _pow_lead_zero(digest):
    """Count leading zero bits of a SHA-256 digest (PoW check)."""
    n = 0
    for byte in digest:
        if byte == 0:
            n += 8
        else:
            n += 8 - byte.bit_length()
            break
    return n


def cmd_enroll(args):
    # Resolve the relay URL: explicit --relay wins; otherwise reuse the
    # existing identity config's relay_url (same machine, new enrollment).
    relay_url = args.relay
    if not relay_url and os.path.exists(args.config):
        try:
            cfg0 = load_config(args.config)
            if is_identity_cfg(cfg0):
                relay_url = cfg0.get("relay_url")
        except Exception:
            pass
    if not relay_url:
        print("no relay URL: pass --relay <url> "
              "(or keep a relay_url in %s)" % args.config, file=sys.stderr)
        return 1
    relay_url = relay_url.rstrip("/")
    invite_id = args.invite_id
    if invite_id and not args.secret:
        print("--invite-id needs --secret", file=sys.stderr)
        return 1

    # Fetch the relay's stable identity key BEFORE enrolling (TOFU: the human
    # sees the fingerprint at the confirmation tap, and it is pinned in the
    # saved config), mirroring redeem.
    existing_cfg = load_config(args.config) if os.path.exists(args.config) else None
    relay_fp = check_relay_identity(relay_url, existing_cfg)

    print("You are about to enroll a new agent identity on a relay:")
    print("  relay:            %s" % relay_url)
    # check_relay_identity aborts when the relay has no verifiable identity
    # (F4: fail closed), so relay_fp is always set here.
    print("  relay key (TOFU): %s  <- stable key; confirm once, pinned after" % relay_fp)
    if invite_id:
        print("  invite gate:      %s" % invite_id)
    if args.name:
        print("  desired name:     %s" % args.name)
    print()
    print("This creates YOUR OWN identity keypair on this machine. The relay")
    print("never sees your private key.")
    ans = None
    if args.yes:
        pass  # non-interactive agent use: the caller already decided
    elif not sys.stdin.isatty():
        print("not a terminal: re-run with --yes to enroll non-interactively",
              file=sys.stderr)
        return 1
    else:
        ans = input("Type YES to enroll: ").strip()
    if ans is not None and ans != "YES":
        print("aborted.")
        return 1

    # Load or create the identity at --config (existing config = existing
    # user path: the same identity is reused, never duplicated).
    if os.path.exists(args.config):
        cfg = load_config(args.config)
        if not is_identity_cfg(cfg):
            print("%s exists but is not an identity config" % args.config,
                  file=sys.stderr)
            return 1
        if cfg.get("relay_url", "").rstrip("/") != relay_url:
            print("warning: config targets %s, enrolling on %s"
                  % (cfg.get("relay_url"), relay_url), file=sys.stderr)
    else:
        seed, pub = keygen()
        cfg = {
            "kind": IDENTITY_KIND,
            "relay_url": relay_url,
            "identity_pubkey": b64u_encode(pub),
            "user_agent": "ClackRelay-CLI/1.1.0",
        }
        # Persist the private key immediately (mode 600 key file): the relay
        # never sees it, and nothing below may proceed without it on disk.
        _save_identity_config(args.config, cfg, seed)
    seed = signing_seed(cfg)
    if seed is None:
        print("config has no usable identity private key", file=sys.stderr)
        return 1
    pub = b64u_decode(cfg["identity_pubkey"])

    # Challenge -> (solve PoW when the gate is pow) -> sign -> enroll.
    ch_body = {"invite_id": invite_id} if invite_id else {}
    code, ch = req(cfg, "POST", "/v1/enroll/challenge", ch_body, base=relay_url)
    if not (200 <= code < 300):
        print("challenge failed: %s" % json.dumps(ch), file=sys.stderr)
        return 1
    gate = ch.get("gate")
    chal_raw = b64u_decode(ch["challenge"] if gate == "pow" else ch["nonce"])
    body = {"identity_pubkey": b64u_encode(pub)}
    if args.name:
        body["name"] = args.name
    if gate == "pow":
        difficulty = int(ch.get("difficulty", 20))
        pow_nonce = None
        while pow_nonce is None:
            cand = os.urandom(16)
            if _pow_lead_zero(hashlib.sha256(chal_raw + cand).digest()) >= difficulty:
                pow_nonce = cand
        body["pow_nonce"] = b64u_encode(pow_nonce)
        sig = sign(seed, chal_raw + pow_nonce + pub)
    elif gate == "invite":
        body["invite_id"] = invite_id
        body["secret"] = args.secret
        sig = sign(seed, chal_raw + invite_id.encode("utf-8") + pub)
    elif gate == "open":
        sig = sign(seed, chal_raw + pub)
    else:
        print("unknown enrollment gate: %r" % gate, file=sys.stderr)
        return 1
    body["proof"] = {"nonce": b64u_encode(chal_raw),
                     "signature": b64u_encode(sig)}
    code, out = req(cfg, "POST", "/v1/enroll", body, base=relay_url)
    if not (200 <= code < 300):
        print("enroll failed: %s" % json.dumps(out), file=sys.stderr)
        return 1

    # Same config-save path as redeem: private key stays in its 0600 file.
    cfg["relay_url"] = relay_url
    if not _apply_enrollment_response(cfg, out, "enroll",
                                      getattr(args, "name", None)):
        return 1
    # check_relay_identity guarantees relay_fp (it aborts otherwise).
    cfg["relay_identity_fingerprint"] = relay_fp  # TOFU pin
    _save_identity_config(args.config, cfg, seed)
    print("enrolled as %s (identity %s..., via %s gate)"
          % (cfg["peer_name"], str(out.get("identity", ""))[:12],
             out.get("enrollment")))

    # Greeting exchange, mirroring redeem: hello to the inviter when the
    # invite gate names one. F4: token-bearing, so only to the pin-verified
    # origin -- check_relay_identity above guaranteed a verifiable relay
    # identity, and the pin is stored above.
    inviter = out.get("inviter_name")
    if inviter and cfg.get("relay_identity_fingerprint"):
        hello_id = str(uuid.uuid4())
        hello_text = ("hello %s -- self-enrolled on the relay "
                      "(Clack agent onboarding)" % inviter)
        hello_body = {
            "id": hello_id,
            "to": inviter,
            "topic": "introductions",
        }
        try:
            env, reason = _e2ee_encrypt_for(cfg, inviter, hello_text,
                                           base_url=relay_url)
        except E2EEError as ex:
            print("hello skipped: encryption failed (%s)" % ex,
                  file=sys.stderr)
            env, reason = None, "encryption failed"
        if env is not None:
            hello_body["enc"] = env
            code, sent = req(cfg, "POST", "/v1/send", hello_body,
                             base=relay_url)
            if 200 <= code < 300:
                print("hello sent to %s (id %s, encrypted)" % (inviter, hello_id))
            else:
                print("hello failed: %s" % json.dumps(sent), file=sys.stderr)
        else:
            print("hello skipped: pair not enc_capable (%s); "
                  "not sending plaintext" % reason, file=sys.stderr)
    elif inviter:
        print("note: relay has no identity key; skipping hello rather than "
              "sending credentials to an unverified relay")
    else:
        print("note: inviter has no messageable peer name; skipping hello")
    print("config saved: %s" % args.config)
    return 0


def cmd_invite_list(args, cfg):
    code, out = req(cfg, "GET", "/v1/invites/list", base=args.base_url)
    print(json.dumps(out, indent=2))
    return 0 if 200 <= code < 300 else 1


def cmd_invite_revoke(args, cfg):
    code, out = req(cfg, "POST", "/v1/invites/revoke",
                    {"invite_id": args.invite_id}, base=args.base_url)
    print(json.dumps(out, indent=2))
    return 0 if 200 <= code < 300 else 1


def main():
    ap = argparse.ArgumentParser(description="Clack relay CLI")
    ap.add_argument("--config", default=DEFAULT_CONFIG,
                    help="config path (legacy relay-config.json or identity config)")
    ap.add_argument("--base-url", default=None, help="override relay base URL")
    ap.add_argument("--peer", default=None,
                    help="peer name for legacy token configs "
                         "(default: nugget, or the only peer if there is one)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    # --- existing commands (legacy-compatible) ---
    p = sub.add_parser("poll", help="long-poll for your messages")
    p.add_argument("--timeout", type=float, default=25.0)

    r = sub.add_parser("receipts", help="delivery states of messages you sent")
    r.add_argument("--since", type=float, default=0.0)
    r.add_argument("--limit", type=int, default=100)

    w = sub.add_parser("watch", help="wake-nudge webhook: show, set, or clear")
    w.add_argument("--url", default=None)
    w.add_argument("--clear", action="store_true")

    s = sub.add_parser("send", help="send a text message")
    s.add_argument("--to", required=True)
    s.add_argument("--text", required=True)
    s.add_argument("--plaintext", action="store_true",
                   help="force plaintext send even when the pair is enc_capable")
    s.add_argument("--topic", default=None)
    s.add_argument("--in-reply-to", default=None)
    s.add_argument("--id", default=None)

    a = sub.add_parser("ack", help="ack handled message ids")
    a.add_argument("--ids", required=True, help="comma-separated ids")

    sub.add_parser("peers", help="list peer names")

    # --- invite-link onboarding (v0.2.5 MVP) ---
    k = sub.add_parser("keygen", help="create an ed25519 identity config")
    k.add_argument("--relay-url", required=True, help="relay base URL, e.g. http://127.0.0.1:18998")
    k.add_argument("--force", action="store_true", help="overwrite existing config")
    k.add_argument("--key-path", default=None,
                   help="private key file path (mode 600; default: <config>.key)")
    k.add_argument("--user-agent", default=None)

    ak = sub.add_parser("attach-key",
                        help="attach an ed25519 signing key to a legacy "
                             "token config (prints the pubkey for the relay "
                             "operator's identity_pubkeys map)")
    ak.add_argument("--key-path", default=None,
                    help="private key file path (mode 600; default: <config>.key)")

    rk = sub.add_parser("register-key",
                        help="self-service Ed25519 key registration: "
                             "generate a signing key if needed, then register "
                             "its pubkey with the relay (token auth, no "
                             "operator involvement)")
    rk.add_argument("--key-path", default=None,
                    help="private key file path (mode 600; default: <config>.key)")

    m = sub.add_parser("mint-invite", help="mint a shareable join link")
    m.add_argument("--max-uses", type=int, default=1)
    m.add_argument("--expiry-hours", type=float, default=24.0)

    mr = sub.add_parser("mint-request", help="mint a public request for a known enrolled identity")
    mr.add_argument("target_identity", help="canonical Ed25519 public key (base64url)")
    mr.add_argument("--exp-days", type=float, default=7)
    mr.add_argument("--enc-v", type=int, choices=(0, 1), default=0)
    rr = sub.add_parser("redeem-request", help="redeem a public URL into a pending handshake (no acceptance)")
    rr.add_argument("link", help="same-configured-relay /join/UUID URL")
    ah = sub.add_parser("accept-handshake", help="explicitly consent to a pending handshake")
    ah.add_argument("handshake_id")
    ah.add_argument("--enc-v", type=int, choices=(0, 1), default=None,
                    help="explicit capability advertisement; omission leaves an active pair unchanged")

    rd = sub.add_parser("redeem", help="redeem an invite link (full join flow)")
    rd.add_argument("link", help="the invite link (or its #fragment payload)")

    e = sub.add_parser("enroll", help="self-enroll a new agent identity (v0.2.9)")
    e.add_argument("--name", default=None, help="desired peer name (optional)")
    e.add_argument("--invite-id", default=None, help="invite id (invite gate)")
    e.add_argument("--secret", default=None, help="invite claim secret (invite gate)")
    e.add_argument("--relay", default=None,
                   help="relay base URL, e.g. http://127.0.0.1:18998")
    e.add_argument("--yes", action="store_true",
                   help="skip the confirmation prompt (non-interactive/agent use)")

    sub.add_parser("invite-list", help="list your outstanding invites")
    rv = sub.add_parser("invite-revoke", help="revoke one of your invites")
    rv.add_argument("invite_id")

    args = ap.parse_args()
    global _selected_peer, _config_path
    _selected_peer = args.peer
    # TOFU pin persistence target for _ensure_origin_verified (F1).
    _config_path = args.config

    if args.cmd in ("keygen", "redeem", "enroll"):
        # These manage the identity config file itself; no prior config needed.
        if args.cmd == "keygen":
            return cmd_keygen(args)
        if args.cmd == "redeem":
            return cmd_redeem(args)
        return cmd_enroll(args)

    cfg = load_config(args.config)
    if args.cmd in ("mint-request", "redeem-request", "accept-handshake"):
        return cmd_public_request(args, cfg)
    token = auth_token(cfg)
    if not token and args.cmd in ("mint-invite", "invite-list", "invite-revoke",
                                  "poll", "receipts", "watch", "send", "ack"):
        print("no usable auth token in %s" % args.config, file=sys.stderr)
        return 1

    if args.cmd == "poll":
        t = float(args.timeout)
        t_str = str(int(t)) if t.is_integer() else str(t)
        code, out = req(cfg, "GET", "/v1/poll?timeout=%s" % t_str, base=args.base_url)
        # E2EE: decrypt enc_v=1 messages in place; failures are surfaced
        # as decrypt_error on the message, never silent.
        if 200 <= code < 300 and isinstance(out, dict):
            _kept, _rej = _e2ee_decrypt_poll_messages(
                cfg, out.get("messages", []), base_url=args.base_url)
            out["messages"] = _kept
            # Rejections are reported, never silent: a sender-side regression
            # must show up as an explicit refusal rather than as no traffic.
            if _rej:
                out["rejected"] = _rej
                print("refused %d inbound message(s) on fail-closed policy:"
                      % len(_rej), file=sys.stderr)
                for _r in _rej:
                    print("  from=%s id=%s peer_state=%s reason=%s"
                          % (_r.get("from"), _r.get("id"),
                             _r.get("peer_state"), _r.get("reason")),
                          file=sys.stderr)
    elif args.cmd == "receipts":
        code, out = req(cfg, "GET",
                        "/v1/receipts?since=%s&limit=%d" % (args.since, args.limit),
                        base=args.base_url)
    elif args.cmd == "watch":
        if args.clear:
            code, out = req(cfg, "POST", "/v1/watch", {"url": None}, base=args.base_url)
        elif args.url:
            code, out = req(cfg, "POST", "/v1/watch", {"url": args.url}, base=args.base_url)
        else:
            code, out = req(cfg, "GET", "/v1/watch", base=args.base_url)
    elif args.cmd == "send":
        # KIT-SCOPED PATCH (e2ee-kit-v1.0.2), carried into v1.1.0: missing
        # sender identity prerequisites (seed/peer_name) stop hard BEFORE any
        # send -- no plaintext fallback from the main path, ever, not even
        # with --plaintext. A broken identity config is unusable for signed
        # relay operation; the relay would 401 unsigned requests anyway.
        # Verified-incapable pairs and legacy token configs are unaffected
        # (see _require_send_identity).
        try:
            _require_send_identity(cfg)
        except E2EEError as ex:
            print("error: refusing to send: %s" % ex, file=sys.stderr)
            return 1
        body = {"id": args.id or str(uuid.uuid4()), "to": args.to}
        if args.topic:
            body["topic"] = args.topic
        if args.in_reply_to:
            body["in_reply_to"] = args.in_reply_to
        # E2EE: encrypt when the pair is enc_capable (automatic), unless
        # --plaintext forces the legacy path. Falls back to plaintext with
        # a stderr note only when the pair is VERIFIED incapable (active
        # handshake, valid identity key, enc_capable not negotiated --
        # dual-mode transition). Unknown/unavailable handshake state or a
        # negotiated-but-failed encryption raises E2EEError: fail closed,
        # never silently send plaintext without a verified incapable pair.
        # KIT-SCOPED PATCH (e2ee-kit-v1.0.1), carried into v1.1.0.
        # _require_send_identity ran above -- a missing seed/peer_name never
        # reaches this branch.
        if args.plaintext:
            body["text"] = args.text
        else:
            try:
                env, reason = _e2ee_encrypt_for(cfg, args.to, args.text,
                                               base_url=args.base_url)
            except E2EEError as ex:
                # KIT-SCOPED PATCH (e2ee-kit-v1.0.1), carried into v1.1.0:
                # unknown handshake state or negotiated-but-failed
                # encryption stops the send entirely -- never a plaintext
                # fallback.
                print("error: refusing to send: %s" % ex, file=sys.stderr)
                return 1
            if env is not None:
                body["enc"] = env
                print("note: sending encrypted (pair enc_capable)",
                      file=sys.stderr)
            else:
                body["text"] = args.text
                print("note: sending plaintext (%s)" % reason, file=sys.stderr)
        code, out = req(cfg, "POST", "/v1/send", body, base=args.base_url)
    elif args.cmd == "ack":
        ids = [i.strip() for i in args.ids.split(",") if i.strip()]
        code, out = req(cfg, "POST", "/v1/ack", {"ids": ids}, base=args.base_url)
    elif args.cmd == "peers":
        code, out = req(cfg, "GET", "/v1/peers", base=args.base_url)
    elif args.cmd == "mint-invite":
        return cmd_mint_invite(args, cfg)
    elif args.cmd == "invite-list":
        return cmd_invite_list(args, cfg)
    elif args.cmd == "invite-revoke":
        return cmd_invite_revoke(args, cfg)
    elif args.cmd == "attach-key":
        return cmd_attach_key(args, cfg)
    elif args.cmd == "register-key":
        return cmd_register_key(args, cfg)

    try:
        print(json.dumps(out, indent=2, ensure_ascii=False))
    except UnicodeEncodeError:
        # Windows non-UTF-8 consoles (e.g. cp1252) can't encode every glyph;
        # fall back to ASCII-escaped JSON rather than crashing the command.
        print(json.dumps(out, indent=2, ensure_ascii=True))
    return 0 if 200 <= code < 300 else 1


if __name__ == "__main__":
    sys.exit(main())
