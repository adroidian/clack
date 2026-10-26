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

`register-key` permits Bearer-only bootstrap only when the relay has no valid
key for the peer. For an existing identity, the command derives the public key
from the configured current private seed and can only submit that same key; it
does not expose rotation. The server API rejects any later re-registration or
rotation unless the current key authorizes the proposed body. Operators can
also configure a narrow trusted-network signature exemption for ordinary
traffic. Protect the token and private key as separate control credentials.

Never print a token or private key.
"""
import argparse
import base64
import ctypes
import datetime
import errno
try:
    import fcntl
except ImportError:
    fcntl = None

import http.client
import json
try:
    import msvcrt
except ImportError:
    msvcrt = None
import os
import socket
import stat
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


def _windows_config_api():
    """Load native read/security APIs lazily; import/help need none of these."""
    if sys.platform != "win32" or not hasattr(ctypes, "WinDLL"):
        raise OSError(errno.ENOSYS, "secure Windows config reads require the native Windows file/security APIs")
    DWORD, BOOL, HANDLE = ctypes.c_uint32, ctypes.c_int32, ctypes.c_void_p

    class FILETIME(ctypes.Structure):
        _fields_ = [("low", DWORD), ("high", DWORD)]

    class FILE_INFO(ctypes.Structure):
        _fields_ = [("attributes", DWORD), ("created", FILETIME),
                    ("accessed", FILETIME), ("written", FILETIME),
                    ("volume", DWORD), ("size_high", DWORD), ("size_low", DWORD),
                    ("links", DWORD), ("index_high", DWORD), ("index_low", DWORD)]

    class TOKEN_USER(ctypes.Structure):
        _fields_ = [("sid", HANDLE), ("attributes", DWORD)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    pointer = ctypes.POINTER
    for library, name, arguments, result in (
            (kernel, "CreateFileW", [ctypes.c_wchar_p, DWORD, DWORD, HANDLE, DWORD, DWORD, HANDLE], HANDLE),
            (kernel, "GetFileType", [HANDLE], DWORD),
            (kernel, "GetFileInformationByHandle", [HANDLE, pointer(FILE_INFO)], BOOL),
            (kernel, "ReadFile", [HANDLE, HANDLE, DWORD, pointer(DWORD), HANDLE], BOOL),
            (kernel, "CloseHandle", [HANDLE], BOOL),
            (kernel, "FlushFileBuffers", [HANDLE], BOOL),
            (kernel, "GetCurrentProcess", [], HANDLE),
            (kernel, "LocalFree", [HANDLE], HANDLE),
            (security, "GetSecurityInfo", [HANDLE, DWORD, DWORD, pointer(HANDLE), HANDLE, HANDLE, HANDLE, pointer(HANDLE)], DWORD),
            (security, "OpenProcessToken", [HANDLE, DWORD, pointer(HANDLE)], BOOL),
            (security, "GetTokenInformation", [HANDLE, DWORD, HANDLE, DWORD, pointer(DWORD)], BOOL),
            (security, "EqualSid", [HANDLE, HANDLE], BOOL)):
        function = getattr(library, name)
        function.argtypes, function.restype = arguments, result
    return kernel, security, DWORD, FILE_INFO, TOKEN_USER


def _windows_config_components(path):
    """Reject symlinks/junctions/reparse points, including ancestor components."""
    drive, rest = os.path.splitdrive(path)
    current = drive + os.sep if rest.startswith(os.sep) else drive
    for part in (part for part in rest.split(os.sep) if part):
        current = os.path.join(current, part) if current else part
        st = os.lstat(current)  # read-only: never create missing parents
        if (stat.S_ISLNK(st.st_mode)
                or getattr(st, "st_file_attributes", 0) & 0x400):
            raise ValueError("config path contains a symlink or Windows reparse point: %s" % current)


def _read_windows_private_config(path, with_snapshot=False):
    """Read a caller-owned regular file through stable native handles.

    Denying write/delete sharing keeps the opened object stable. Owner SID,
    link count, reparse state and identity are re-attested before use. The
    optional snapshot is the native equivalent of the POSIX inode snapshot.
    """
    kernel, security, DWORD, FILE_INFO, TOKEN_USER = _windows_config_api()
    absolute = _private_abs(path)
    invalid = ctypes.c_void_p(-1).value

    def failure(operation, code=None):
        if code is None:
            code = ctypes.get_last_error()
        return OSError(code, "secure Windows config read failed: " + operation, absolute)

    def open_existing():
        # GENERIC_READ | READ_CONTROL; FILE_SHARE_READ only; OPEN_EXISTING;
        # FILE_FLAG_OPEN_REPARSE_POINT (do not follow a final reparse point).
        handle = kernel.CreateFileW(absolute, 0x80020000, 1, None, 3, 0x00200000, None)
        if handle in (None, invalid):
            raise failure("CreateFileW")
        return handle

    def information(handle):
        info = FILE_INFO()
        if kernel.GetFileType(handle) != 1:  # FILE_TYPE_DISK
            raise ValueError("config is not a disk file")
        if not kernel.GetFileInformationByHandle(handle, ctypes.byref(info)):
            raise failure("GetFileInformationByHandle")
        if info.attributes & (0x10 | 0x400) or info.links != 1:
            raise ValueError("config must be a single-link regular file without reparse points")
        return (info.volume, info.index_high, info.index_low,
                info.size_high, info.size_low, info.written.high, info.written.low,
                info.created.high, info.created.low, info.attributes, info.links)

    def owned_by_caller(handle):
        owner, descriptor, token = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
        try:
            code = security.GetSecurityInfo(handle, 1, 1, ctypes.byref(owner),
                                            None, None, None, ctypes.byref(descriptor))
            if code or not owner.value or not descriptor.value:
                raise failure("GetSecurityInfo(owner)", code or errno.EACCES)
            if not security.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
                raise failure("OpenProcessToken")
            needed = DWORD()
            security.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
            if not ctypes.sizeof(TOKEN_USER) <= needed.value <= 65536:
                raise ValueError("Windows token user information is unavailable or invalid")
            buffer = ctypes.create_string_buffer(needed.value)
            if not security.GetTokenInformation(token, 1, buffer, needed.value, ctypes.byref(needed)):
                raise failure("GetTokenInformation(TokenUser)")
            user = ctypes.cast(buffer, ctypes.POINTER(TOKEN_USER)).contents
            if not user.sid or not security.EqualSid(owner, user.sid):
                raise ValueError("config file is not owned by the current Windows user")
            # Snapshots need a stable SID value, not the address of the freed
            # owner buffer. Ordinary secret reads only need the equality check.
            return _windows_current_sid(kernel, security) if with_snapshot else None
        finally:
            if token.value:
                kernel.CloseHandle(token)
            if descriptor.value:
                kernel.LocalFree(descriptor)

    _windows_config_components(absolute)
    handle = open_existing()
    try:
        before = information(handle)
        owner = owned_by_caller(handle)
        chunks = []
        while True:
            buffer, count = ctypes.create_string_buffer(65536), DWORD()
            if not kernel.ReadFile(handle, buffer, len(buffer), ctypes.byref(count), None):
                raise failure("ReadFile")
            if count.value > len(buffer):
                raise ValueError("invalid Windows config read length")
            if not count.value:
                break
            chunks.append(buffer.raw[:count.value])
        data = b"".join(chunks)
        if information(handle) != before or len(data) != (before[3] << 32 | before[4]):
            raise ValueError("config file changed while it was read")
        owned_by_caller(handle)
        _windows_config_components(absolute)
        visible = open_existing()
        try:
            if information(visible) != before:
                raise ValueError("config path changed while it was read")
        finally:
            kernel.CloseHandle(visible)
        if with_snapshot:
            snapshot = {
                "dev": before[0], "ino": (before[1] << 32) | before[2],
                "mode": before[9], "uid": owner, "nlink": before[10],
                "size": (before[3] << 32) | before[4], "data": data,
            }
            return data, snapshot
        return data
    finally:
        kernel.CloseHandle(handle)


def _windows_current_sid(kernel=None, security=None):
    """Return the current token user's SID without POSIX uid emulation."""
    _kernel, _security, DWORD, _FILE_INFO, TOKEN_USER = _windows_config_api()
    if kernel is None or security is None:
        kernel, security = _kernel, _security
    for library, name, arguments, result in (
            (security, "ConvertSidToStringSidW", [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)], ctypes.c_int32),):
        function = getattr(library, name)
        function.argtypes, function.restype = arguments, result
    token = ctypes.c_void_p()
    text = ctypes.c_wchar_p()
    try:
        if not security.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
            raise OSError(ctypes.get_last_error(), "OpenProcessToken failed")
        needed = DWORD()
        security.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        if not ctypes.sizeof(TOKEN_USER) <= needed.value <= 65536:
            raise ValueError("Windows token user information is unavailable or invalid")
        buffer = ctypes.create_string_buffer(needed.value)
        if not security.GetTokenInformation(token, 1, buffer, needed.value, ctypes.byref(needed)):
            raise OSError(ctypes.get_last_error(), "GetTokenInformation(TokenUser) failed")
        user = ctypes.cast(buffer, ctypes.POINTER(TOKEN_USER)).contents
        if not user.sid or not security.ConvertSidToStringSidW(user.sid, ctypes.byref(text)):
            raise OSError(ctypes.get_last_error(), "ConvertSidToStringSidW failed")
        return text.value
    finally:
        if text.value:
            kernel.LocalFree(ctypes.cast(text, ctypes.c_void_p))
        if token.value:
            kernel.CloseHandle(token)


def _windows_restrict_handle_acl(handle):
    """Apply a protected DACL granting full control only to the caller."""
    kernel, security, _DWORD, _FILE_INFO, _TOKEN_USER = _windows_config_api()
    DWORD, BOOL, HANDLE = ctypes.c_uint32, ctypes.c_int32, ctypes.c_void_p
    for name, arguments, result in (
            ("ConvertStringSecurityDescriptorToSecurityDescriptorW",
             [ctypes.c_wchar_p, DWORD, ctypes.POINTER(HANDLE), ctypes.POINTER(DWORD)], BOOL),
            ("GetSecurityDescriptorDacl",
             [HANDLE, ctypes.POINTER(BOOL), ctypes.POINTER(HANDLE), ctypes.POINTER(BOOL)], BOOL),
            ("SetSecurityInfo",
             [HANDLE, DWORD, DWORD, HANDLE, HANDLE, HANDLE, HANDLE], DWORD)):
        function = getattr(security, name)
        function.argtypes, function.restype = arguments, result
    sid = _windows_current_sid(kernel, security)
    descriptor = ctypes.c_void_p()
    try:
        sddl = "D:P(A;;FA;;;%s)" % sid
        if not security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, 1, ctypes.byref(descriptor), None):
            raise OSError(ctypes.get_last_error(), "cannot construct Windows private DACL")
        present, defaulted, dacl = BOOL(), BOOL(), ctypes.c_void_p()
        if not security.GetSecurityDescriptorDacl(
                descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)):
            raise OSError(ctypes.get_last_error(), "cannot read Windows private DACL")
        if not present.value or not dacl.value:
            raise ValueError("Windows private DACL is absent")
        # SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION.
        code = security.SetSecurityInfo(
            ctypes.c_void_p(handle), 1, 0x80000004, None, None, dacl, None)
        if code:
            raise OSError(code, "cannot protect Windows private artifact")
    finally:
        if descriptor.value:
            kernel.LocalFree(descriptor)


def _windows_restrict_path_acl(path):
    kernel, _security, _DWORD, _FILE_INFO, _TOKEN_USER = _windows_config_api()
    absolute = _private_abs(path)
    _windows_config_components(absolute)
    # GENERIC_WRITE (for flush) | READ_CONTROL | WRITE_DAC | WRITE_OWNER.
    handle = kernel.CreateFileW(absolute, 0x400E0000, 1, None, 3, 0x00200000, None)
    invalid = ctypes.c_void_p(-1).value
    if handle in (None, invalid):
        raise OSError(ctypes.get_last_error(), "cannot open Windows private artifact for ACL protection", absolute)
    try:
        _windows_restrict_handle_acl(handle)
        if not kernel.FlushFileBuffers(handle):
            raise OSError(ctypes.get_last_error(), "cannot flush Windows private ACL", absolute)
    finally:
        kernel.CloseHandle(handle)


def _windows_open_private_stage(path):
    """Create a non-shared stage with WRITE_DAC before secret bytes arrive."""
    if msvcrt is None:
        raise OSError(errno.ENOSYS, "native Windows file handles are unavailable")
    kernel, _security, _DWORD, _FILE_INFO, _TOKEN_USER = _windows_config_api()
    # GENERIC_WRITE | READ_CONTROL | WRITE_DAC | WRITE_OWNER; no sharing.
    handle = kernel.CreateFileW(path, 0x400E0000, 0, None, 1, 0x00200000, None)
    invalid = ctypes.c_void_p(-1).value
    if handle in (None, invalid):
        raise OSError(ctypes.get_last_error(), "cannot create Windows private stage", path)
    try:
        _windows_restrict_handle_acl(handle)
        return msvcrt.open_osfhandle(handle, os.O_WRONLY)
    except Exception:
        kernel.CloseHandle(handle)
        raise


def _windows_flush_fd(fd):
    if msvcrt is None:
        raise OSError(errno.ENOSYS, "native Windows file handles are unavailable")
    kernel, _security, _DWORD, _FILE_INFO, _TOKEN_USER = _windows_config_api()
    if not kernel.FlushFileBuffers(ctypes.c_void_p(msvcrt.get_osfhandle(fd))):
        raise OSError(ctypes.get_last_error(), "FlushFileBuffers failed")


def _windows_move(source, destination, replace=False):
    kernel, _security, _DWORD, _FILE_INFO, _TOKEN_USER = _windows_config_api()
    function = kernel.MoveFileExW
    function.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
    function.restype = ctypes.c_int32
    # MOVEFILE_WRITE_THROUGH, optionally MOVEFILE_REPLACE_EXISTING.
    if not function(source, destination, 8 | (1 if replace else 0)):
        raise OSError(ctypes.get_last_error(), "MoveFileExW failed", destination)


def _windows_replace(destination, source, backup):
    kernel, _security, _DWORD, _FILE_INFO, _TOKEN_USER = _windows_config_api()
    function = kernel.ReplaceFileW
    function.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
                         ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p]
    function.restype = ctypes.c_int32
    if not function(destination, source, backup, 0, None, None):
        raise OSError(ctypes.get_last_error(), "ReplaceFileW failed", destination)


def _windows_mutex_acquire(name):
    kernel, _security, _DWORD, _FILE_INFO, _TOKEN_USER = _windows_config_api()
    for function_name, arguments, result in (
            ("CreateMutexW", [ctypes.c_void_p, ctypes.c_int32, ctypes.c_wchar_p], ctypes.c_void_p),
            ("WaitForSingleObject", [ctypes.c_void_p, ctypes.c_uint32], ctypes.c_uint32)):
        function = getattr(kernel, function_name)
        function.argtypes, function.restype = arguments, result
    handle = kernel.CreateMutexW(None, False, "Local\\" + name)
    invalid = ctypes.c_void_p(-1).value
    if handle in (None, invalid):
        raise OSError(ctypes.get_last_error(), "CreateMutexW failed")
    result = kernel.WaitForSingleObject(handle, 0)
    if result not in (0, 0x80):  # owned, or abandoned by a dead process
        kernel.CloseHandle(handle)
        raise ValueError("another register-key operation is already active")
    return handle


def _windows_mutex_release(handle):
    kernel, _security, _DWORD, _FILE_INFO, _TOKEN_USER = _windows_config_api()
    kernel.ReleaseMutex.argtypes = [ctypes.c_void_p]
    kernel.ReleaseMutex.restype = ctypes.c_int32
    try:
        if not kernel.ReleaseMutex(handle):
            raise OSError(ctypes.get_last_error(), "ReleaseMutex failed")
    finally:
        kernel.CloseHandle(handle)


def load_config(path):
    if callable(getattr(os, "geteuid", None)):
        raw = _read_private_regular(path, correct_mode=False)
    else:
        raw = _read_windows_private_config(path)
    return json.loads(raw.decode("utf-8"))


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
    return cfg.get("user_agent") or "ClackRelay-CLI/1.2.0"


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
# `register-key` is bearer-only only for initial bootstrap. Because req() uses
# this same helper, an existing identity naturally signs same-key registration;
# cmd_register_key derives and submits exactly that seed's public key and does
# not expose rotation. The relay still enforces current-key authorization.
# An operator may explicitly exempt selected trusted-network traffic. Public
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
            if sys.platform == "win32":
                raw = _read_windows_private_config(path).strip()
            else:
                with open(path, "rb") as f:
                    raw = f.read().strip()
        except (OSError, ValueError):
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


_LOCAL_REPLACE = os.replace
_LOCAL_FSYNC = os.fsync
_LOCAL_UNLINK = os.unlink
_LOCAL_PUBLICATION_HOOK = None
_REGISTER_KEY_JOURNAL_KIND = "clack-register-key-pending-v1"
_RENAME_NOREPLACE = 1
_RENAME_EXCHANGE = 2
_AT_FDCWD = -100
_LIBC = ctypes.CDLL(None, use_errno=True) if sys.platform == "linux" else None
_RENAMEAT2 = getattr(_LIBC, "renameat2", None)
if _RENAMEAT2 is not None:
    _RENAMEAT2.argtypes = (
        ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
        ctypes.c_uint,
    )
    _RENAMEAT2.restype = ctypes.c_int


PRIVATE_PUBLICATION_REQUIREMENT = (
    "private credential publication requires supported native Linux or Windows "
    "file, security and locking APIs"
)


def _require_private_publication_platform():
    """Reject unsupported enrollment/publication before local or remote effects."""
    if sys.platform == "win32":
        if msvcrt is None or not hasattr(ctypes, "WinDLL"):
            raise OSError(errno.ENOSYS, PRIVATE_PUBLICATION_REQUIREMENT)
        _windows_config_api()  # Fail before key generation or network mutation.
        return
    if (sys.platform != "linux" or fcntl is None
            or not hasattr(fcntl, "flock") or not hasattr(os, "geteuid")
            or not hasattr(socket, "AF_UNIX") or _RENAMEAT2 is None):
        raise OSError(errno.ENOSYS, PRIVATE_PUBLICATION_REQUIREMENT)


def _local_publication_event(name):
    hook = _LOCAL_PUBLICATION_HOOK
    if hook is not None:
        hook(name)


def _private_abs(path):
    if not isinstance(path, str) or not path:
        raise ValueError("private artifact path must be a non-empty string")
    return os.path.abspath(path)


def _renameat2(source, destination, flags):
    """Linux atomic namespace transition used for CAS-style publication."""
    if _RENAMEAT2 is None:
        raise OSError(errno.ENOSYS, "renameat2 is required for private publication")
    result = _RENAMEAT2(
        _AT_FDCWD, os.fsencode(source), _AT_FDCWD, os.fsencode(destination), flags)
    if result != 0:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number), destination)


def _rename_exchange(source, destination):
    return _renameat2(source, destination, _RENAME_EXCHANGE)


def _rename_noreplace(source, destination):
    return _renameat2(source, destination, _RENAME_NOREPLACE)


# Explicit seams let the regression suite inject a mutation immediately before
# the kernel operation, below every Python-level precondition check.
_LOCAL_RENAME_EXCHANGE = _rename_exchange
_LOCAL_RENAME_NOREPLACE = _rename_noreplace


def _reject_symlink_components(path):
    """Reject every existing symlink component, including the destination."""
    absolute = _private_abs(path)
    drive, rest = os.path.splitdrive(absolute)
    current = drive + os.sep if absolute.startswith(os.sep) else drive
    for part in [p for p in rest.split(os.sep) if p]:
        current = os.path.join(current, part) if current else part
        try:
            st = os.lstat(current)
        except FileNotFoundError:
            continue
        if (stat.S_ISLNK(st.st_mode)
                or (sys.platform == "win32"
                    and getattr(st, "st_file_attributes", 0) & 0x400)):
            raise ValueError("private artifact path contains a symlink or reparse point: %s" % current)
    return absolute


def _ensure_private_parent(path):
    absolute = _private_abs(path)
    parent = os.path.dirname(absolute) or "."
    _reject_symlink_components(parent)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    _reject_symlink_components(parent)
    if not stat.S_ISDIR(os.lstat(parent).st_mode):
        raise ValueError("private artifact parent is not a directory: %s" % parent)
    return absolute, parent


def _validate_private_destination(path, must_exist=False):
    absolute, parent = _ensure_private_parent(path)
    try:
        st = os.lstat(absolute)
    except FileNotFoundError:
        if must_exist:
            raise ValueError("private artifact does not exist: %s" % absolute)
        return absolute, parent, None
    if (stat.S_ISLNK(st.st_mode)
            or (sys.platform == "win32"
                and getattr(st, "st_file_attributes", 0) & 0x400)):
        raise ValueError("private artifact destination is a symlink or reparse point: %s" % absolute)
    if not stat.S_ISREG(st.st_mode):
        raise ValueError("private artifact destination is not a regular file: %s"
                         % absolute)
    if sys.platform == "win32":
        # Native handles verify the owner SID, real link count and stable file ID.
        _read_windows_private_config(absolute)
    else:
        if st.st_nlink != 1:
            raise ValueError("private artifact destination has %d hardlinks: %s"
                             % (st.st_nlink, absolute))
        if st.st_uid != os.geteuid():
            raise ValueError("private artifact destination is not owned by this user: %s"
                             % absolute)
    return absolute, parent, st


def _paths_alias(first, second):
    a = _private_abs(first)
    b = _private_abs(second)
    if os.path.normcase(os.path.realpath(a)) == os.path.normcase(os.path.realpath(b)):
        return True
    if os.path.lexists(a) and os.path.lexists(b):
        try:
            return os.path.samefile(a, b)
        except OSError:
            pass
    return False


def _file_snapshot(st, data):
    return {
        "dev": st.st_dev,
        "ino": st.st_ino,
        "mode": stat.S_IMODE(st.st_mode),
        "uid": st.st_uid,
        "nlink": st.st_nlink,
        "size": st.st_size,
        "data": bytes(data),
    }


def _same_file_snapshot(first, second):
    return (
        first is not None and second is not None
        and first["dev"] == second["dev"]
        and first["ino"] == second["ino"]
        and first["mode"] == second["mode"]
        and first["uid"] == second["uid"]
        and first["nlink"] == second["nlink"]
        and first["size"] == second["size"]
        and first["data"] == second["data"]
    )


def _fsync_parent(path, label):
    if sys.platform == "win32":
        # MoveFileExW(MOVEFILE_WRITE_THROUGH) persists namespace transitions;
        # Windows does not provide POSIX directory fsync semantics.
        _local_publication_event(label + ":before_dir_fsync")
        return
    parent = os.path.dirname(_private_abs(path)) or "."
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(parent, flags)
    try:
        _local_publication_event(label + ":before_dir_fsync")
        _LOCAL_FSYNC(fd)
    finally:
        os.close(fd)


def _read_private_regular_snapshot(path, correct_mode=False):
    if sys.platform == "win32":
        # Readback never mutates ACLs; explicit repair uses _correct_private_mode.
        return _read_windows_private_config(path, with_snapshot=True)
    absolute, _parent, opening_path_st = _validate_private_destination(
        path, must_exist=True)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(absolute, flags)
    mode_changed = False
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                or st.st_uid != os.geteuid()):
            raise ValueError("private artifact is not a single-link owned regular file: %s"
                             % absolute)
        if (opening_path_st.st_dev, opening_path_st.st_ino) != (st.st_dev, st.st_ino):
            raise ValueError("private artifact changed while it was opened: %s"
                             % absolute)
        if correct_mode and stat.S_IMODE(st.st_mode) != 0o600:
            # Recheck link count through the held descriptor immediately before
            # chmod so an outside hardlink can never inherit a mode mutation.
            if os.fstat(fd).st_nlink != 1:
                raise ValueError("private artifact gained a hardlink: %s" % absolute)
            os.fchmod(fd, 0o600)
            _LOCAL_FSYNC(fd)
            mode_changed = True
        chunks = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        data = b"".join(chunks)
        st = os.fstat(fd)
        visible = os.lstat(absolute)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                or visible.st_nlink != 1
                or (visible.st_dev, visible.st_ino) != (st.st_dev, st.st_ino)):
            raise ValueError("private artifact changed while it was read: %s"
                             % absolute)
        snapshot = _file_snapshot(st, data)
    finally:
        os.close(fd)
    if mode_changed:
        _fsync_parent(absolute, "chmod")
    return data, snapshot


def _read_private_regular(path, correct_mode=False):
    data, _snapshot = _read_private_regular_snapshot(
        path, correct_mode=correct_mode)
    return data


def _snapshot_at_path(path, correct_mode=False):
    _data, snapshot = _read_private_regular_snapshot(
        path, correct_mode=correct_mode)
    return snapshot


def _require_snapshot(path, expected, label):
    actual = _snapshot_at_path(path, correct_mode=False)
    if not _same_file_snapshot(actual, expected):
        raise ValueError("%s changed at the publication boundary" % label)
    return actual


def _correct_private_mode(path):
    if os.path.lexists(_private_abs(path)):
        if sys.platform == "win32":
            _windows_restrict_path_acl(path)
        _read_private_regular(path, correct_mode=True)


def _safe_unlink_snapshot(path, expected):
    """Remove only the exact single-link inode held by this transaction."""
    _require_snapshot(path, expected, "private artifact")
    _LOCAL_UNLINK(path)


_LOCAL_WINDOWS_MOVE = _windows_move
_LOCAL_WINDOWS_REPLACE = _windows_replace


def _windows_atomic_publish_private(path, data, label, expected_snapshot=None):
    """Publish with native flush, no-replace moves and replace backups.

    ReplaceFileW preserves the displaced destination until its exact native
    snapshot is verified. Operator drift is never overwritten deliberately.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("private artifact data must be bytes")
    absolute, parent, current_st = _validate_private_destination(path)
    if expected_snapshot is None and current_st is not None:
        _old_data, expected_snapshot = _read_private_regular_snapshot(
            absolute, correct_mode=True)
    elif expected_snapshot is not None:
        _require_snapshot(absolute, expected_snapshot, label + " destination")
    expected_absent = expected_snapshot is None
    token = _secrets.token_hex(8)
    tmp = os.path.join(parent, ".%s.%s-%s.tmp" % (os.path.basename(absolute), label, token))
    backup = os.path.join(parent, ".%s.%s-%s.prior" % (os.path.basename(absolute), label, token))
    fd = None
    stage_snapshot = displaced_snapshot = None
    transitioned = False
    try:
        _local_publication_event(label + ":before_stage_open")
        fd = _windows_open_private_stage(tmp)
        view = memoryview(bytes(data))
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write while staging %s" % label)
            view = view[written:]
        _local_publication_event(label + ":before_file_fsync")
        _windows_flush_fd(fd)
        os.close(fd)
        fd = None
        stage_snapshot = _snapshot_at_path(tmp)
        _local_publication_event(label + ":before_replace")
        if _ACTIVE_REGISTER_KEY_OPERATION is not None:
            _assert_register_key_operation()
        if expected_absent:
            _absolute, _parent, late_st = _validate_private_destination(absolute)
            if late_st is not None:
                raise ValueError("%s destination appeared before publication" % label)
            _LOCAL_WINDOWS_MOVE(tmp, absolute, replace=False)
            transitioned = True
        else:
            _require_snapshot(absolute, expected_snapshot, label + " destination")
            _LOCAL_WINDOWS_REPLACE(absolute, tmp, backup)
            transitioned = True
            candidate_now = _snapshot_at_path(absolute)
            displaced_snapshot = _snapshot_at_path(backup)
            if (not _same_file_snapshot(candidate_now, stage_snapshot)
                    or not _same_file_snapshot(displaced_snapshot, expected_snapshot)):
                _LOCAL_WINDOWS_MOVE(backup, absolute, replace=True)
                raise ValueError("%s destination changed during publication" % label)
        _local_publication_event(label + ":after_replace")
        actual = _snapshot_at_path(absolute, correct_mode=True)
        if not _same_file_snapshot(actual, stage_snapshot):
            raise OSError("published %s file ID/bytes do not match staged bytes" % label)
        if displaced_snapshot is not None:
            _safe_unlink_snapshot(backup, displaced_snapshot)
        return absolute
    except Exception:
        if fd is not None:
            os.close(fd)
        try:
            if not transitioned and os.path.lexists(tmp) and stage_snapshot is not None:
                _safe_unlink_snapshot(tmp, stage_snapshot)
            elif not transitioned and os.path.lexists(tmp):
                os.unlink(tmp)
        except (OSError, ValueError):
            pass
        # A retained backup is recovery evidence, never blindly deleted.
        raise


def _atomic_publish_private(path, data, label, expected_snapshot=None):
    """Durably publish bytes with native compare-and-recover semantics."""
    _require_private_publication_platform()
    if sys.platform == "win32":
        return _windows_atomic_publish_private(path, data, label, expected_snapshot)
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("private artifact data must be bytes")
    absolute, parent, current_st = _validate_private_destination(path)
    if expected_snapshot is None and current_st is not None:
        _old_data, expected_snapshot = _read_private_regular_snapshot(
            absolute, correct_mode=True)
    elif expected_snapshot is not None:
        _require_snapshot(absolute, expected_snapshot, label + " destination")
    expected_absent = expected_snapshot is None
    tmp = os.path.join(
        parent,
        ".%s.%s-%s.tmp" % (
            os.path.basename(absolute), label, _secrets.token_hex(8)),
    )
    fd = None
    stage_snapshot = None
    transitioned = False
    displaced_snapshot = None
    try:
        _local_publication_event(label + ":before_stage_open")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= (getattr(os, "O_CLOEXEC", 0)
                  | getattr(os, "O_NOFOLLOW", 0)
                  | getattr(os, "O_NONBLOCK", 0))
        fd = os.open(tmp, flags, 0o600)
        os.fchmod(fd, 0o600)
        view = memoryview(bytes(data))
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write while staging %s" % label)
            view = view[written:]
        stage_snapshot = _file_snapshot(os.fstat(fd), bytes(data))
        _local_publication_event(label + ":after_stage_write")
        _local_publication_event(label + ":before_file_fsync")
        _LOCAL_FSYNC(fd)
        stage_snapshot = _file_snapshot(os.fstat(fd), bytes(data))
        os.close(fd)
        fd = None
        _local_publication_event(label + ":before_replace")
        if _ACTIVE_REGISTER_KEY_OPERATION is not None:
            _assert_register_key_operation()
        _require_snapshot(tmp, stage_snapshot, label + " stage")
        if expected_absent:
            _absolute, _parent, late_st = _validate_private_destination(absolute)
            if late_st is not None:
                raise ValueError("%s destination appeared before publication" % label)
            _LOCAL_RENAME_NOREPLACE(tmp, absolute)
            transitioned = True
        else:
            _require_snapshot(absolute, expected_snapshot, label + " destination")
            _LOCAL_RENAME_EXCHANGE(tmp, absolute)
            transitioned = True
            candidate_now = _snapshot_at_path(absolute)
            displaced_snapshot = _snapshot_at_path(tmp)
            if (not _same_file_snapshot(candidate_now, stage_snapshot)
                    or not _same_file_snapshot(
                        displaced_snapshot, expected_snapshot)):
                # Restore the exact mapping observed by the kernel transition,
                # including a finite substitution injected inside the syscall
                # seam. Never overwrite or delete that foreign inode.
                before_inverse_candidate = candidate_now
                before_inverse_displaced = displaced_snapshot
                _LOCAL_RENAME_EXCHANGE(tmp, absolute)
                transitioned = False
                restored_destination = _snapshot_at_path(absolute)
                restored_stage = _snapshot_at_path(tmp)
                if (not _same_file_snapshot(
                            restored_destination, before_inverse_displaced)
                        or not _same_file_snapshot(
                            restored_stage, before_inverse_candidate)):
                    raise OSError(
                        "publication compensation could not prove exact restoration")
                raise ValueError("%s destination changed during publication" % label)
        _local_publication_event(label + ":after_replace")
        if _ACTIVE_REGISTER_KEY_OPERATION is not None:
            _assert_register_key_operation()
        _fsync_parent(absolute, label)
        actual = _snapshot_at_path(absolute, correct_mode=True)
        if not _same_file_snapshot(actual, stage_snapshot):
            raise OSError("published %s inode/bytes do not match staged bytes" % label)
        if not expected_absent:
            _safe_unlink_snapshot(tmp, displaced_snapshot)
            _fsync_parent(absolute, label + "-hold-retire")
        return absolute
    except Exception:
        if fd is not None:
            os.close(fd)
        # Cleanup is capability-bound: remove only our staged inode or the
        # proven displaced prior inode. A substituted/hardlinked path remains.
        try:
            if os.path.lexists(tmp):
                if transitioned and displaced_snapshot is not None:
                    _safe_unlink_snapshot(tmp, displaced_snapshot)
                elif (not transitioned and stage_snapshot is not None):
                    _safe_unlink_snapshot(tmp, stage_snapshot)
        except (OSError, ValueError):
            pass
        raise


_ACTIVE_REGISTER_KEY_OPERATION = None
_REGISTER_KEY_PENDING_ACTIVE = False


class _RegisterKeyOperationLock:
    """Process-lifetime exclusion using a native kernel-owned lock.

    Linux uses its abstract socket/flock pair. Windows uses a named mutex,
    which cannot be replaced through the filesystem and is released on process
    death. An existing lock file remains a validated audit artifact only.
    """

    def __init__(self, config_path):
        _require_private_publication_platform()
        self.config_path = _private_abs(config_path)
        self.lock_path = self.config_path + ".register-key.lock"
        owner = (_windows_current_sid() if sys.platform == "win32"
                 else str(os.geteuid()))
        digest = hashlib.sha256(
            (owner + "\0" + self.config_path).encode("utf-8")).hexdigest()
        self.socket_name = "\0clack-register-key-v1-" + digest
        self.mutex_name = "clack-register-key-v1-" + digest
        self._socket = None
        self._mutex = None
        self._lock_fd = None
        self._lock_snapshot = None

    def __enter__(self):
        if sys.platform == "win32":
            try:
                self._mutex = _windows_mutex_acquire(self.mutex_name)
            except ValueError as exc:
                raise ValueError(
                    "another register-key operation is already active for %s"
                    % self.config_path) from exc
        else:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.set_inheritable(False)
            try:
                sock.bind(self.socket_name)
            except OSError as exc:
                sock.close()
                if exc.errno == errno.EADDRINUSE:
                    raise ValueError(
                        "another register-key operation is already active for %s"
                        % self.config_path) from exc
                raise
            self._socket = sock
        try:
            lock_parent = os.path.dirname(self.lock_path) or "."
            _reject_symlink_components(lock_parent)
            if not os.path.isdir(lock_parent):
                raise ValueError(
                    "register-key lock parent must already be a directory: %s"
                    % lock_parent)
            _absolute, _parent, st = _validate_private_destination(
                self.lock_path)
            if st is not None and sys.platform == "win32":
                self._lock_snapshot = _snapshot_at_path(self.lock_path)
            elif st is not None:
                if stat.S_IMODE(st.st_mode) != 0o600:
                    raise ValueError(
                        "register-key audit lock must already be mode 0600: %s"
                        % self.lock_path)
                flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
                flags |= (getattr(os, "O_NOFOLLOW", 0)
                          | getattr(os, "O_NONBLOCK", 0))
                fd = os.open(self.lock_path, flags)
                try:
                    opened = os.fstat(fd)
                    if (not stat.S_ISREG(opened.st_mode)
                            or opened.st_nlink != 1
                            or opened.st_uid != os.geteuid()
                            or (opened.st_dev, opened.st_ino)
                               != (st.st_dev, st.st_ino)):
                        raise ValueError(
                            "register-key audit lock changed while opening")
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError as exc:
                        raise ValueError(
                            "register-key audit lock is held by another process") from exc
                    os.lseek(fd, 0, os.SEEK_SET)
                    chunks = []
                    while True:
                        chunk = os.read(fd, 1024 * 1024)
                        if not chunk:
                            break
                        chunks.append(chunk)
                    data = b"".join(chunks)
                    opened = os.fstat(fd)
                    self._lock_snapshot = _file_snapshot(opened, data)
                    self._lock_fd = fd
                    fd = None
                finally:
                    if fd is not None:
                        os.close(fd)
            self.assert_held()
            return self
        except Exception:
            self.__exit__(None, None, None)
            raise

    def assert_held(self):
        if sys.platform == "win32":
            if self._mutex is None:
                raise ValueError("register-key operation lock is not held")
        elif self._socket is None or self._socket.fileno() < 0:
            raise ValueError("register-key operation lock is not held")
        if self._lock_snapshot is None:
            if os.path.lexists(self.lock_path):
                _validate_private_destination(self.lock_path)
                raise ValueError(
                    "register-key audit lock appeared during the operation")
        else:
            _require_snapshot(
                self.lock_path, self._lock_snapshot,
                "register-key audit lock")
        return True

    def __exit__(self, exc_type, exc, traceback):
        if self._lock_fd is not None:
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(self._lock_fd)
                self._lock_fd = None
        if self._socket is not None:
            self._socket.close()
            self._socket = None
        if self._mutex is not None:
            mutex, self._mutex = self._mutex, None
            _windows_mutex_release(mutex)
        return False


def _assert_register_key_operation():
    operation = _ACTIVE_REGISTER_KEY_OPERATION
    if operation is None:
        raise ValueError("register-key operation lock is not held")
    operation.assert_held()
    return operation


def _private_json_bytes(value):
    return (json.dumps(value, indent=2) + "\n").encode("utf-8")


def _write_key_file(path, seed):
    """Atomically publish a mode-0600 b64u seed and fsync its directory."""
    return _atomic_publish_private(
        path, (b64u_encode(seed) + "\n").encode("ascii"), "key")


def _save_identity_config(path, cfg, seed, key_path=None):
    """Atomically publish key then config, rejecting unsafe destinations."""
    _require_private_publication_platform()
    cp = _private_abs(path)
    kp = _private_abs(
        key_path or cfg.get("identity_privkey_path") or (path + ".key"))
    if _paths_alias(cp, kp):
        raise ValueError("config and private key paths must name different files")
    _validate_private_destination(cp)
    _validate_private_destination(kp)
    _correct_private_mode(cp)
    _correct_private_mode(kp)
    cfg.pop("identity_privkey", None)
    cfg["identity_privkey_path"] = kp
    _write_key_file(kp, seed)
    _atomic_publish_private(cp, _private_json_bytes(cfg), "config")


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
    """CAS-publish first-contact trust before any pending mutation exists."""
    _require_private_publication_platform()
    if _REGISTER_KEY_PENDING_ACTIVE:
        raise ValueError(
            "refusing TOFU config write during an active register-key transaction")
    path = _config_path
    if not path:
        raise ValueError("cannot persist relay identity pin without a config path")
    raw, snapshot = _read_private_regular_snapshot(path, correct_mode=True)
    try:
        live_cfg = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise ValueError("cannot pin relay identity into malformed live config") from exc
    if live_cfg != cfg:
        raise ValueError("live config changed before relay identity pin publication")
    updated = dict(cfg)
    updated["relay_identity_fingerprint"] = fingerprint
    _atomic_publish_private(
        path, _private_json_bytes(updated), "config",
        expected_snapshot=snapshot)
    cfg["relay_identity_fingerprint"] = fingerprint


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

    header_file = None
    body_file = None
    try:
        # Neither bearer/signature headers nor claim bodies belong in argv.
        # Track each path before writing so every exit cleans up private data.
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.headers') as f:
            header_file = f.name
            os.chmod(header_file, 0o600)
            for k, v in headers.items():
                f.write("%s: %s\n" % (k, v))
        # -q MUST be first: ambient curlrc must not enable redirects or alter
        # the pinned-origin request. NO_PROXY remains honored by curl.
        cmd = ["curl", "-q", "-s", "-m", str(timeout), "-X", method,
               "--header", "@" + header_file, "--max-redirs", "0",
               "-D", "-", "-o", "-", url]
        if data is not None:
            with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.json') as f:
                body_file = f.name
                os.chmod(body_file, 0o600)
                f.write(data)
            cmd += ["--data-binary", "@" + body_file]
        result = subprocess.run(cmd, capture_output=True, timeout=timeout + 10)
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
    finally:
        for path in (header_file, body_file):
            if path and os.path.exists(path):
                os.unlink(path)


class UnknownMutationOutcome(RuntimeError):
    """A non-idempotent request may have reached the relay."""


def req(cfg, method, path, body=None, base=None):
    # These mutations must never be resent after an ambiguous transport
    # failure. register-key has no application id; its retained candidate is
    # reconciled with the read-only status endpoint before any later send.
    public_request = path in ("/v1/handshakes/requests", "/v1/handshakes/requests/redeem",
                              "/v1/handshakes/accept")
    register_mutation = method.upper() == "POST" and path == "/v1/register-key"
    invitation_mutation = method.upper() == "POST" and path in (
        "/v1/handshakes/invitations", "/v1/handshakes/redeem", "/v1/enroll/challenge")
    unknown_sensitive = public_request or register_mutation or invitation_mutation
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
    if path.startswith("/i/"):
        headers["Accept"] = "application/json"
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
            if unknown_sensitive and not isinstance(e, FileNotFoundError):
                what = "register-key" if register_mutation else "public request"
                raise UnknownMutationOutcome(
                    "%s outcome UNKNOWN; reconcile before retrying" % what) from e
            print("curl transport failed (%s), falling back to Python"
                  % type(e).__name__, file=sys.stderr)

    # Fallback: Python urllib with retry
    r = urllib.request.Request(url, data=data, method=method)
    for k, v in headers.items():
        r.add_header(k, v)
    # Retry on transient connection drops only when the request is safe to
    # replay. register-key and consent mutations make exactly one attempt.
    attempts = 1 if unknown_sensitive else 3
    last_exc = None
    for attempt in range(attempts):
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
            if unknown_sensitive:
                what = "register-key" if register_mutation else "public request"
                raise UnknownMutationOutcome(
                    "%s outcome UNKNOWN; reconcile before retrying" % what) from e
            if attempt < attempts - 1:
                time.sleep(1 + attempt)
                # Rebuild the request: urllib Request objects are single-use
                # after a failed open on some Python versions.
                r = urllib.request.Request(url, data=data, method=method)
                for k, v in headers.items():
                    r.add_header(k, v)
                continue
            raise
        except (ValueError, urllib.error.URLError, OSError) as exc:
            # A malformed success body or wrapped socket failure can arrive
            # AFTER the server committed. Do not downgrade or replay it.
            if unknown_sensitive:
                raise UnknownMutationOutcome(
                    "mutation outcome UNKNOWN; reconcile before retrying") from exc
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

    The configured user_agent is sent (default ClackRelay-CLI/1.2.0):
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
    _require_private_publication_platform()
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
    protection = "owner-only ACL" if sys.platform == "win32" else "mode 600"
    print("private key:      %s (%s; never leaves this machine)"
          % (cfg["identity_privkey_path"], protection))
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
    _require_private_publication_platform()
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
    protection = "owner-only ACL" if sys.platform == "win32" else "mode 600"
    print("private key: %s (%s; never leaves this machine)"
          % (new_cfg["identity_privkey_path"], protection))
    print("pubkey for the relay operator's identity_pubkeys map:")
    print(b64u_encode(pub))
    return 0


def _register_key_pending_path(config_path):
    return _private_abs(config_path) + ".register-key.pending"


def _blob_encode(data):
    return base64.b64encode(data).decode("ascii")


def _blob_decode(value, field):
    if type(value) is not str:
        raise ValueError("pending journal %s must be base64 text" % field)
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError("pending journal %s is malformed" % field) from exc


def _canonical_candidate_pub(value):
    if type(value) is not str:
        return None
    try:
        raw = b64u_decode(value)
    except Exception:
        return None
    if len(raw) != 32 or b64u_encode(raw) != value:
        return None
    return value


def _snapshot_token(snapshot):
    return {
        name: snapshot[name]
        for name in ("dev", "ino", "mode", "uid", "nlink", "size")
    }


def _validate_snapshot_token(token, field):
    required = ("dev", "ino", "mode", "uid", "nlink", "size")
    if (type(token) is not dict
            or set(token) != set(required)
            or any(type(token.get(name)) is not int for name in required)
            or token["mode"] != 0o600
            or token["uid"] != os.geteuid()
            or token["nlink"] != 1
            or token["size"] < 0):
        raise ValueError("register-key pending %s token is invalid" % field)
    return token


def _snapshot_matches_token(snapshot, token, data):
    return (
        snapshot is not None
        and all(snapshot[name] == token[name]
                for name in ("dev", "ino", "mode", "uid", "nlink", "size"))
        and snapshot["data"] == bytes(data)
    )


def _register_key_stage_path(journal, role):
    if role not in ("config", "key"):
        raise ValueError("unknown register-key publication role")
    target = journal["config_path"] if role == "config" else journal["key_path"]
    parent = os.path.dirname(target) or "."
    return os.path.join(
        parent,
        ".%s.register-key-%s.%s-stage"
        % (os.path.basename(target), journal["transaction_id"], role),
    )


def _register_key_quarantine_path(path, journal):
    return "%s.rejected-%s" % (path, journal["transaction_id"])


def _write_register_key_journal(path, journal):
    _assert_register_key_operation()
    _atomic_publish_private(path, _private_json_bytes(journal), "journal")


def _validate_register_key_journal(journal, config_path):
    if type(journal) is not dict or journal.get("kind") != _REGISTER_KEY_JOURNAL_KIND:
        raise ValueError("invalid register-key pending journal kind")
    required_text = (
        "transaction_id", "phase", "config_path", "key_path", "peer",
        "request_base", "identity_pubkey", "identity_seed",
        "base_config_sha256", "base_config_bytes", "target_config_bytes",
        "token_sha256",
    )
    if any(type(journal.get(name)) is not str for name in required_text):
        raise ValueError("register-key pending journal has invalid field types")
    if journal["phase"] not in (
            "prepared", "requesting", "accepted", "publishing", "published"):
        raise ValueError("register-key pending journal has invalid phase")
    transaction_id = journal["transaction_id"]
    if (len(transaction_id) != 32
            or any(ch not in "0123456789abcdef" for ch in transaction_id)):
        raise ValueError("register-key pending transaction id is invalid")
    if journal["config_path"] != _private_abs(config_path):
        raise ValueError("register-key pending journal belongs to another config")
    seed = b64u_decode(journal["identity_seed"])
    if (len(seed) != 32 or b64u_encode(seed) != journal["identity_seed"]
            or b64u_encode(_publickey(seed)) != journal["identity_pubkey"]):
        raise ValueError("register-key pending seed/public key mismatch")
    if _canonical_candidate_pub(journal["identity_pubkey"]) is None:
        raise ValueError("register-key pending public key is not canonical")
    base_bytes = _blob_decode(journal["base_config_bytes"], "base_config_bytes")
    if hashlib.sha256(base_bytes).hexdigest() != journal["base_config_sha256"]:
        raise ValueError("register-key pending base config digest mismatch")
    target_bytes = _blob_decode(journal["target_config_bytes"], "target_config_bytes")
    try:
        target = json.loads(target_bytes.decode("utf-8"))
    except Exception as exc:
        raise ValueError("register-key pending target config is malformed") from exc
    if (type(target) is not dict
            or target.get("kind") != IDENTITY_KIND
            or target.get("peer_name") != journal["peer"]
            or target.get("identity_pubkey") != journal["identity_pubkey"]
            or _private_abs(target.get("identity_privkey_path"))
               != journal["key_path"]):
        raise ValueError("register-key pending target config binding mismatch")
    token = auth_token(target)
    if (not token or hashlib.sha256(token.encode("utf-8")).hexdigest()
            != journal["token_sha256"]):
        raise ValueError("register-key pending token binding mismatch")
    publication = journal.get("publication")
    if journal["phase"] == "publishing" or publication is not None:
        required_publication = {
            "config_stage", "config_expected", "config_state",
            "key_stage", "key_expected", "key_state",
        }
        if type(publication) is not dict or set(publication) != required_publication:
            raise ValueError("register-key pending publication state is invalid")
        _validate_snapshot_token(
            publication["config_stage"], "config publication stage")
        _validate_snapshot_token(
            publication["config_expected"], "config publication baseline")
        _validate_snapshot_token(
            publication["key_stage"], "key publication stage")
        if publication["config_state"] not in ("base", "target"):
            raise ValueError("register-key pending config publication state is invalid")
        if publication["key_state"] not in ("absent", "prior", "candidate"):
            raise ValueError("register-key pending key publication state is invalid")
        if publication["key_state"] == "absent":
            if publication["key_expected"] is not None:
                raise ValueError("register-key absent-key publication token is invalid")
        else:
            _validate_snapshot_token(
                publication["key_expected"], "key publication baseline")
    return seed, target, base_bytes, target_bytes


def _load_register_key_journal(path, config_path):
    raw = _read_private_regular(path, correct_mode=True)
    try:
        journal = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise ValueError("register-key pending journal is malformed") from exc
    _validate_register_key_journal(journal, config_path)
    return journal


def _journal_update(path, journal, **changes):
    updated = dict(journal)
    updated.update(changes)
    _validate_register_key_journal(updated, updated["config_path"])
    _write_register_key_journal(path, updated)
    return updated


def _journal_phase(path, journal, phase):
    return _journal_update(path, journal, phase=phase)


def _pending_request_cfg(journal):
    seed, target, _base, _target_bytes = _validate_register_key_journal(
        journal, journal["config_path"])
    request_cfg = dict(target)
    request_cfg.pop("identity_privkey_path", None)
    request_cfg["identity_privkey"] = b64u_encode(seed)
    return request_cfg


def _validate_register_key_artifacts(path, journal):
    """Re-attest every credential-bearing name before a boundary."""
    operation = _assert_register_key_operation()
    _validate_private_destination(journal["config_path"], must_exist=True)
    _validate_private_destination(path, must_exist=True)
    _validate_private_destination(journal["key_path"])
    operation.assert_held()
    stage_paths = [
        _register_key_stage_path(journal, "config"),
        _register_key_stage_path(journal, "key"),
    ]
    for stage_path in stage_paths:
        _validate_private_destination(stage_path)
    quarantine = _register_key_quarantine_path(path, journal)
    _absolute, _parent, quarantine_st = _validate_private_destination(quarantine)
    if quarantine_st is not None:
        raise ValueError("register-key quarantine destination already exists")
    paths = [journal["config_path"], path, journal["key_path"]] + stage_paths
    normalized = [_private_abs(item) for item in paths]
    if len(set(normalized)) != len(normalized):
        raise ValueError("register-key artifact paths must be distinct")
    return True


def _register_key_status(journal, args):
    _validate_register_key_artifacts(
        _register_key_pending_path(journal["config_path"]), journal)
    request_cfg = _pending_request_cfg(journal)
    _assert_register_key_operation()
    try:
        code, out = req(
            request_cfg, "GET", "/v1/register-key/status",
            base=args.base_url or journal["request_base"],
        )
    except Exception as exc:
        return "unavailable", None, {"error": type(exc).__name__}
    if code != 200:
        return "unavailable", code, out
    if (type(out) is not dict or out.get("peer") != journal["peer"]
            or type(out.get("registered")) is not bool):
        return "malformed", code, out
    accepted = out.get("identity_pubkey")
    if out["registered"] is False:
        if accepted is not None:
            return "malformed", code, out
        return "absent", code, out
    if _canonical_candidate_pub(accepted) is None:
        return "malformed", code, out
    if accepted == journal["identity_pubkey"]:
        return "candidate", code, out
    return "different", code, out


def _pending_artifacts_match(journal):
    try:
        seed, _target, _base, target_bytes = _validate_register_key_journal(
            journal, journal["config_path"])
        key_bytes = (b64u_encode(seed) + "\n").encode("ascii")
        return (
            _read_private_regular(journal["key_path"], correct_mode=True) == key_bytes
            and _read_private_regular(journal["config_path"], correct_mode=True)
            == target_bytes
            and stat.S_IMODE(os.lstat(journal["key_path"]).st_mode) == 0o600
            and stat.S_IMODE(os.lstat(journal["config_path"]).st_mode) == 0o600
        )
    except (OSError, ValueError):
        return False


def _optional_private_snapshot(path, correct_mode=False):
    _absolute, _parent, st = _validate_private_destination(path)
    if st is None:
        return None
    return _snapshot_at_path(path, correct_mode=correct_mode)


def _stage_register_key_artifact(path, data, label):
    existing = _optional_private_snapshot(path)
    if existing is not None:
        if existing["mode"] != 0o600 or existing["data"] != bytes(data):
            raise ValueError("register-key %s stage is occupied by foreign state"
                             % label)
        return existing
    fd = None
    snapshot = None
    try:
        _local_publication_event(label + ":before_stage_open")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= (getattr(os, "O_CLOEXEC", 0)
                  | getattr(os, "O_NOFOLLOW", 0)
                  | getattr(os, "O_NONBLOCK", 0))
        fd = os.open(path, flags, 0o600)
        os.fchmod(fd, 0o600)
        view = memoryview(bytes(data))
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write while staging %s" % label)
            view = view[written:]
        snapshot = _file_snapshot(os.fstat(fd), bytes(data))
        _local_publication_event(label + ":after_stage_write")
        _local_publication_event(label + ":before_file_fsync")
        _LOCAL_FSYNC(fd)
        snapshot = _file_snapshot(os.fstat(fd), bytes(data))
        os.close(fd)
        fd = None
        _require_snapshot(path, snapshot, label + " stage")
        _fsync_parent(path, label + "-stage")
        return snapshot
    except Exception:
        if fd is not None:
            os.close(fd)
        try:
            if snapshot is not None and os.path.lexists(path):
                _safe_unlink_snapshot(path, snapshot)
        except (OSError, ValueError):
            pass
        raise


def _publication_materials(journal):
    seed, _target, base_bytes, target_bytes = _validate_register_key_journal(
        journal, journal["config_path"])
    candidate_key = (b64u_encode(seed) + "\n").encode("ascii")
    if journal.get("prior_key_exists") is True:
        prior_key = _blob_decode(
            journal.get("prior_key_bytes"), "prior_key_bytes")
    elif journal.get("prior_key_exists") is False:
        prior_key = None
    else:
        raise ValueError("register-key pending prior-key marker is invalid")
    return base_bytes, target_bytes, prior_key, candidate_key


def _prepare_register_key_publication(path, journal):
    if journal["phase"] in ("publishing", "published"):
        return _adopt_restored_publication_baselines(path, journal)
    base_bytes, target_bytes, prior_key, candidate_key = \
        _publication_materials(journal)
    key_stage_path = _register_key_stage_path(journal, "key")
    config_stage_path = _register_key_stage_path(journal, "config")
    key_stage = _stage_register_key_artifact(
        key_stage_path, candidate_key, "key")
    config_stage = _stage_register_key_artifact(
        config_stage_path, target_bytes, "config")
    _validate_register_key_artifacts(path, journal)
    current_config = _snapshot_at_path(
        journal["config_path"], correct_mode=True)
    if current_config["data"] == base_bytes:
        config_state = "base"
    elif current_config["data"] == target_bytes:
        config_state = "target"
    else:
        raise ValueError(
            "local config changed while register-key was pending; retained journal")
    current_key = _optional_private_snapshot(
        journal["key_path"], correct_mode=True)
    if current_key is None:
        if prior_key is not None:
            raise ValueError(
                "local key disappeared while register-key was pending; retained journal")
        key_state = "absent"
        key_expected = None
    elif current_key["data"] == candidate_key:
        key_state = "candidate"
        key_expected = _snapshot_token(current_key)
    elif prior_key is not None and current_key["data"] == prior_key:
        key_state = "prior"
        key_expected = _snapshot_token(current_key)
    else:
        raise ValueError(
            "local key changed while register-key was pending; retained journal")
    publication = {
        "config_stage": _snapshot_token(config_stage),
        "config_expected": _snapshot_token(current_config),
        "config_state": config_state,
        "key_stage": _snapshot_token(key_stage),
        "key_expected": key_expected,
        "key_state": key_state,
    }
    return _journal_update(
        path, journal, phase="publishing", publication=publication)


def _adopt_restored_publication_baselines(path, journal):
    """Allow an operator to restore exact baseline bytes on a new inode."""
    if journal["phase"] != "publishing":
        return journal
    base_bytes, _target_bytes, prior_key, candidate_key = \
        _publication_materials(journal)
    publication = dict(journal["publication"])
    changed = False
    config_stage = _optional_private_snapshot(
        _register_key_stage_path(journal, "config"))
    current_config = _snapshot_at_path(journal["config_path"])
    if (publication["config_state"] == "base"
            and config_stage is not None
            and _snapshot_matches_token(
                config_stage, publication["config_stage"],
                _blob_decode(journal["target_config_bytes"],
                             "target_config_bytes"))
            and current_config["data"] == base_bytes
            and not _snapshot_matches_token(
                current_config, publication["config_expected"], base_bytes)):
        publication["config_expected"] = _snapshot_token(current_config)
        changed = True
    key_stage = _optional_private_snapshot(
        _register_key_stage_path(journal, "key"))
    current_key = _optional_private_snapshot(journal["key_path"])
    if (publication["key_state"] == "prior"
            and prior_key is not None
            and key_stage is not None
            and _snapshot_matches_token(
                key_stage, publication["key_stage"], candidate_key)
            and current_key is not None
            and current_key["data"] == prior_key
            and not _snapshot_matches_token(
                current_key, publication["key_expected"], prior_key)):
        publication["key_expected"] = _snapshot_token(current_key)
        changed = True
    if changed:
        return _journal_update(path, journal, publication=publication)
    return journal


def _transition_register_key_artifact(journal, role):
    base_bytes, target_bytes, prior_key, candidate_key = \
        _publication_materials(journal)
    publication = journal["publication"]
    if role == "config":
        destination = journal["config_path"]
        stage_path = _register_key_stage_path(journal, "config")
        stage_token = publication["config_stage"]
        expected_token = publication["config_expected"]
        state = publication["config_state"]
        candidate_data = target_bytes
        expected_data = target_bytes if state == "target" else base_bytes
        already_candidate = state == "target"
    elif role == "key":
        destination = journal["key_path"]
        stage_path = _register_key_stage_path(journal, "key")
        stage_token = publication["key_stage"]
        expected_token = publication["key_expected"]
        state = publication["key_state"]
        candidate_data = candidate_key
        expected_data = (candidate_key if state == "candidate" else prior_key)
        already_candidate = state == "candidate"
    else:
        raise ValueError("unknown register-key publication role")

    current = _optional_private_snapshot(destination)
    stage = _optional_private_snapshot(stage_path)
    if already_candidate:
        if not _snapshot_matches_token(current, expected_token, candidate_data):
            raise ValueError("local %s changed while register-key was pending"
                             % role)
        return {"changed": False, "kind": "already", "role": role}

    # A completed transition after a crash: the staged inode is canonical and
    # the baseline is retained at the deterministic stage name (or absent for
    # a destination that was initially absent).
    if _snapshot_matches_token(current, stage_token, candidate_data):
        if state == "absent":
            if stage is not None:
                raise ValueError("unexpected key stage after completed publication")
        elif _snapshot_matches_token(stage, expected_token, expected_data):
            return {"changed": False, "kind": "completed", "role": role}
        else:
            # A process may have died after the kernel exchange but before the
            # immediate mismatch compensation. The canonical candidate token
            # proves which side of that finite exchange we are observing. Put
            # the displaced (possibly operator-supplied) inode back at the
            # canonical name, retain the candidate at the stage name, and fail
            # closed for an explicit later reconciliation.
            if stage is None:
                raise ValueError(
                    "%s publication hold disappeared after transition" % role)
            before_destination = current
            before_stage = stage
            _LOCAL_RENAME_EXCHANGE(stage_path, destination)
            restored_destination = _snapshot_at_path(destination)
            restored_stage = _snapshot_at_path(stage_path)
            if (not _same_file_snapshot(restored_destination, before_stage)
                    or not _same_file_snapshot(
                        restored_stage, before_destination)):
                raise OSError(
                    "%s crash-window compensation is uncertain" % role)
            _fsync_parent(destination, role + "-crash-compensate")
            raise ValueError(
                "%s changed in an interrupted publication exchange" % role)
        return {"changed": False, "kind": "completed", "role": role}

    stage_ready = _snapshot_matches_token(stage, stage_token, candidate_data)
    if state == "absent":
        destination_ready = current is None
    else:
        destination_ready = _snapshot_matches_token(
            current, expected_token, expected_data)
    if not stage_ready or not destination_ready:
        raise ValueError(
            "local %s changed while register-key was pending; retained journal"
            % role)

    _local_publication_event(role + ":before_replace")
    _assert_register_key_operation()
    # The event hook is an adversarial boundary: re-attest after it.
    stage = _snapshot_at_path(stage_path)
    current = _optional_private_snapshot(destination)
    if (not _snapshot_matches_token(stage, stage_token, candidate_data)
            or (state == "absent" and current is not None)
            or (state != "absent" and not _snapshot_matches_token(
                current, expected_token, expected_data))):
        raise ValueError("%s publication boundary drift" % role)

    if state == "absent":
        _LOCAL_RENAME_NOREPLACE(stage_path, destination)
        kind = "noreplace"
        after_destination = _snapshot_at_path(destination)
        if not _snapshot_matches_token(
                after_destination, stage_token, candidate_data):
            raise OSError("%s publication did not install staged inode" % role)
    else:
        _LOCAL_RENAME_EXCHANGE(stage_path, destination)
        kind = "exchange"
        after_destination = _snapshot_at_path(destination)
        after_stage = _snapshot_at_path(stage_path)
        if (not _snapshot_matches_token(
                    after_destination, stage_token, candidate_data)
                or not _snapshot_matches_token(
                    after_stage, expected_token, expected_data)):
            # Exact inverse restores whatever finite substitution the kernel
            # actually exchanged; then prove both names before failing.
            before_inverse_destination = after_destination
            before_inverse_stage = after_stage
            _LOCAL_RENAME_EXCHANGE(stage_path, destination)
            restored_destination = _snapshot_at_path(destination)
            restored_stage = _snapshot_at_path(stage_path)
            if (not _same_file_snapshot(
                        restored_destination, before_inverse_stage)
                    or not _same_file_snapshot(
                        restored_stage, before_inverse_destination)):
                raise OSError(
                    "%s publication compensation is uncertain" % role)
            raise ValueError("%s changed inside publication syscall" % role)
    _local_publication_event(role + ":after_replace")
    _fsync_parent(destination, role)
    _assert_register_key_operation()
    final_destination = _snapshot_at_path(destination)
    if not _snapshot_matches_token(
            final_destination, stage_token, candidate_data):
        raise OSError("%s publication failed exact readback" % role)
    return {"changed": True, "kind": kind, "role": role}


def _rollback_register_key_transition(journal, transition):
    if not transition or not transition.get("changed"):
        return
    role = transition["role"]
    publication = journal["publication"]
    _base, target_bytes, prior_key, candidate_key = _publication_materials(journal)
    if role == "config":
        destination = journal["config_path"]
        stage_path = _register_key_stage_path(journal, "config")
        stage_token = publication["config_stage"]
        candidate_data = target_bytes
        expected_token = publication["config_expected"]
        expected_data = _blob_decode(
            journal["base_config_bytes"], "base_config_bytes")
    else:
        destination = journal["key_path"]
        stage_path = _register_key_stage_path(journal, "key")
        stage_token = publication["key_stage"]
        candidate_data = candidate_key
        expected_token = publication["key_expected"]
        expected_data = prior_key
    if transition["kind"] == "noreplace":
        current = _snapshot_at_path(destination)
        if not _snapshot_matches_token(current, stage_token, candidate_data):
            raise OSError("cannot prove key publication rollback source")
        _LOCAL_RENAME_NOREPLACE(destination, stage_path)
        if (_optional_private_snapshot(destination) is not None
                or not _snapshot_matches_token(
                    _snapshot_at_path(stage_path), stage_token, candidate_data)):
            raise OSError("key publication rollback is uncertain")
    elif transition["kind"] == "exchange":
        current = _snapshot_at_path(destination)
        held = _snapshot_at_path(stage_path)
        if (not _snapshot_matches_token(current, stage_token, candidate_data)
                or not _snapshot_matches_token(
                    held, expected_token, expected_data)):
            raise OSError("cannot prove %s publication rollback mapping" % role)
        _LOCAL_RENAME_EXCHANGE(stage_path, destination)
        if (not _snapshot_matches_token(
                    _snapshot_at_path(destination), expected_token, expected_data)
                or not _snapshot_matches_token(
                    _snapshot_at_path(stage_path), stage_token, candidate_data)):
            raise OSError("%s publication rollback is uncertain" % role)
    _fsync_parent(destination, role + "-rollback")


def _cleanup_register_key_stages(journal):
    for role in ("key", "config"):
        stage_path = _register_key_stage_path(journal, role)
        snapshot = _optional_private_snapshot(stage_path)
        if snapshot is not None:
            _safe_unlink_snapshot(stage_path, snapshot)
            _fsync_parent(stage_path, role + "-stage-retire")


def _retire_register_key_journal(path):
    try:
        snapshot = _snapshot_at_path(path)
        _local_publication_event("journal:before_retire")
        _assert_register_key_operation()
        _safe_unlink_snapshot(path, snapshot)
        _fsync_parent(path, "journal-retire")
    except FileNotFoundError:
        pass
    except (OSError, ValueError) as exc:
        # Artifacts are already fully durable. Retention is safe; a published
        # journal that survives can be verified and retired on the next run.
        print("warning: published register-key journal retained: %s" % exc,
              file=sys.stderr)


def _quarantine_register_key_journal(path, journal):
    destination = _register_key_quarantine_path(path, journal)
    _validate_register_key_artifacts(path, journal)
    source_snapshot = _snapshot_at_path(path)
    _local_publication_event("journal:before_quarantine")
    _validate_register_key_artifacts(path, journal)
    _require_snapshot(path, source_snapshot, "register-key pending journal")
    _LOCAL_RENAME_NOREPLACE(path, destination)
    moved = _snapshot_at_path(destination)
    if (not _same_file_snapshot(moved, source_snapshot)
            or os.path.lexists(path)):
        raise OSError("register-key quarantine transition failed exact readback")
    _fsync_parent(destination, "journal-quarantine")
    return destination


def _publish_accepted_register_key(path, journal):
    journal = _prepare_register_key_publication(path, journal)
    if journal["phase"] == "published":
        if not _pending_artifacts_match(journal):
            raise ValueError("published register-key artifacts no longer match")
        _cleanup_register_key_stages(journal)
        _retire_register_key_journal(path)
        return journal
    _validate_register_key_artifacts(path, journal)
    _transition_register_key_artifact(journal, "config")
    # Config is authoritative. Re-attest it immediately before the key
    # transition; a concurrent operator replacement therefore blocks the key.
    _transition_register_key_artifact(journal, "config")
    key_transition = _transition_register_key_artifact(journal, "key")
    try:
        _transition_register_key_artifact(journal, "config")
    except (OSError, ValueError):
        # A drift discovered after the key syscall must not leave the candidate
        # published. Restore the exact prior/absent key mapping when provable.
        _rollback_register_key_transition(journal, key_transition)
        raise
    _transition_register_key_artifact(journal, "key")
    if not _pending_artifacts_match(journal):
        raise OSError("published register-key artifacts failed exact readback")
    published = _journal_phase(path, journal, "published")
    _cleanup_register_key_stages(published)
    _retire_register_key_journal(path)
    return published


def _finish_accepted_register_key(path, journal):
    try:
        accepted = journal
        if journal["phase"] not in ("accepted", "publishing", "published"):
            accepted = _journal_phase(path, journal, "accepted")
        _publish_accepted_register_key(path, accepted)
    except (OSError, ValueError) as exc:
        print("register-key accepted by relay, but local publication is pending: %s"
              % exc, file=sys.stderr)
        return 1
    if journal.get("generated"):
        protection = "owner-only ACL" if sys.platform == "win32" else "mode 600"
        print("generated signing keypair; private key: %s (%s; never leaves this machine)"
              % (journal["key_path"], protection))
    print("registered signing key for peer %r" % journal["peer"])
    print("pubkey: %s" % journal["identity_pubkey"])
    return 0


def _send_register_key_candidate(path, journal, args):
    try:
        requesting = _journal_phase(path, journal, "requesting")
        _validate_register_key_artifacts(path, requesting)
        request_cfg = _pending_request_cfg(requesting)
        _assert_register_key_operation()
    except (OSError, ValueError) as exc:
        print("could not durably mark register-key request pending: %s" % exc,
              file=sys.stderr)
        return 1
    try:
        code, out = req(
            request_cfg, "POST", "/v1/register-key",
            {"pubkey": requesting["identity_pubkey"]},
            base=args.base_url or requesting["request_base"],
        )
    except Exception as exc:
        print("register-key outcome UNKNOWN; pending candidate retained at %s: %s"
              % (path, type(exc).__name__), file=sys.stderr)
        return 1
    exact_acceptance = (
        code == 200
        and type(out) is dict
        and out.get("registered") is True
        and out.get("peer") == requesting["peer"]
        and out.get("identity_pubkey") == requesting["identity_pubkey"]
        and type(out.get("rotated")) is bool
    )
    if exact_acceptance:
        return _finish_accepted_register_key(path, requesting)
    if code >= 500:
        print("register-key returned HTTP %d; pending candidate retained at %s"
              % (code, path), file=sys.stderr)
        return 1
    if code == 200:
        print("register-key response did not bind the exact candidate/peer; "
              "pending candidate retained for reconciliation", file=sys.stderr)
        return 1
    # A non-5xx rejection is retired only after the read-only status endpoint
    # proves that this exact candidate is not the relay's current valid key.
    state, _status_code, _status = _register_key_status(requesting, args)
    if state == "candidate":
        return _finish_accepted_register_key(path, requesting)
    if state in ("absent", "different"):
        try:
            quarantine = _quarantine_register_key_journal(path, requesting)
        except (OSError, ValueError) as exc:
            print("register-key rejected, but pending candidate could not be "
                  "quarantined safely: %s" % exc, file=sys.stderr)
            return 1
        print("register-key failed: HTTP %d %s; rejected candidate quarantined at %s"
              % (code, json.dumps(out), quarantine), file=sys.stderr)
        return 1
    print("register-key failed: HTTP %d %s; status reconciliation unavailable, "
          "pending candidate retained at %s" % (code, json.dumps(out), path),
          file=sys.stderr)
    return 1


def _resume_register_key(path, journal, args):
    if journal["phase"] == "published":
        try:
            _publish_accepted_register_key(path, journal)
        except (OSError, ValueError) as exc:
            print("published register-key state retained for safe restart: %s"
                  % exc, file=sys.stderr)
            return 1
        print("registered signing key for peer %r" % journal["peer"])
        print("pubkey: %s" % journal["identity_pubkey"])
        return 0
    if journal["phase"] == "prepared":
        return _send_register_key_candidate(path, journal, args)
    try:
        state, code, out = _register_key_status(journal, args)
    except (OSError, ValueError) as exc:
        print("cannot safely reconcile pending register-key candidate: %s" % exc,
              file=sys.stderr)
        return 1
    if state == "candidate":
        return _finish_accepted_register_key(path, journal)
    if state == "absent":
        # This is a new send decision based on a read-only proof that no valid
        # server key exists, not a blind retry of the uncertain POST.
        return _send_register_key_candidate(path, journal, args)
    if state == "different":
        try:
            quarantine = _quarantine_register_key_journal(path, journal)
        except (OSError, ValueError) as exc:
            print("different relay key found; pending candidate retained: %s" % exc,
                  file=sys.stderr)
            return 1
        print("relay has a different valid key; pending candidate quarantined at %s"
              % quarantine, file=sys.stderr)
        return 1
    print("cannot reconcile pending register-key candidate (HTTP %r %s); retained at %s"
          % (code, json.dumps(out), path), file=sys.stderr)
    return 1


def _load_register_key_config(config_path):
    raw = _read_private_regular(config_path, correct_mode=True)
    try:
        cfg = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise ValueError("register-key config is malformed") from exc
    if type(cfg) is not dict:
        raise ValueError("register-key config must be a JSON object")
    return cfg


def cmd_register_key(args, cfg=None):
    """Serialize the complete durable register-key state machine."""
    _require_private_publication_platform()
    del cfg  # Caller snapshots are advisory; authority is re-read under lock.
    global _ACTIVE_REGISTER_KEY_OPERATION, _REGISTER_KEY_PENDING_ACTIVE
    global _config_path, _selected_peer
    config_path = _private_abs(args.config)
    previous_path = _config_path
    previous_peer = _selected_peer
    try:
        with _RegisterKeyOperationLock(config_path) as operation:
            if _ACTIVE_REGISTER_KEY_OPERATION is not None:
                raise ValueError("nested register-key operation is not allowed")
            _ACTIVE_REGISTER_KEY_OPERATION = operation
            _config_path = config_path
            _selected_peer = getattr(args, "peer", None)
            try:
                return _cmd_register_key_locked(args, config_path)
            finally:
                _REGISTER_KEY_PENDING_ACTIVE = False
                _ACTIVE_REGISTER_KEY_OPERATION = None
                _config_path = previous_path
                _selected_peer = previous_peer
    except (OSError, ValueError) as exc:
        print("register-key local state is unsafe: %s" % exc, file=sys.stderr)
        return 1


def _cmd_register_key_locked(args, config_path):
    global _REGISTER_KEY_PENDING_ACTIVE
    pending_path = _register_key_pending_path(config_path)
    try:
        _assert_register_key_operation()
        _validate_private_destination(config_path, must_exist=True)
        # Pending is checked before chmod so an unsafe pending alias cannot
        # cause even a mode mutation to another credential artifact.
        _validate_private_destination(pending_path)
        _correct_private_mode(config_path)
        if os.path.lexists(pending_path):
            journal = _load_register_key_journal(pending_path, config_path)
            if getattr(args, "key_path", None) is not None and _private_abs(
                    args.key_path) != journal["key_path"]:
                raise ValueError("--key-path differs from retained pending candidate")
            if getattr(args, "peer", None) not in (None, journal["peer"]):
                raise ValueError("--peer differs from retained pending candidate")
            if (_paths_alias(config_path, journal["key_path"])
                    or _paths_alias(pending_path, journal["key_path"])):
                raise ValueError("pending/config/key paths must name different files")
            _validate_register_key_artifacts(pending_path, journal)
            _REGISTER_KEY_PENDING_ACTIVE = True
            try:
                return _resume_register_key(pending_path, journal, args)
            finally:
                _REGISTER_KEY_PENDING_ACTIVE = False
        cfg = _load_register_key_config(config_path)
    except (OSError, ValueError) as exc:
        print("register-key local state is unsafe: %s" % exc, file=sys.stderr)
        return 1

    generated = False
    if is_identity_cfg(cfg):
        peer_name = cfg.get("peer_name")
        if not peer_name:
            print("identity config has no peer_name; cannot register a key",
                  file=sys.stderr)
            return 1
        if not cfg.get("service_token"):
            print("no service_token in %s" % args.config, file=sys.stderr)
            return 1
        existing_key_path = cfg.get("identity_privkey_path")
        try:
            if existing_key_path:
                _validate_private_destination(existing_key_path, must_exist=True)
                _correct_private_mode(existing_key_path)
            seed = signing_seed(cfg)
        except (OSError, ValueError):
            seed = None
        if seed is None:
            print("identity config has no usable signing seed; refusing to "
                  "replace local credentials", file=sys.stderr)
            return 1
        try:
            derived_pub = b64u_encode(_publickey(seed))
        except Exception:
            print("identity signing seed is invalid; refusing registration",
                  file=sys.stderr)
            return 1
        configured_pub = cfg.get("identity_pubkey")
        if configured_pub is not None and configured_pub != derived_pub:
            print("identity_pubkey does not match the configured signing "
                  "seed; refusing before any request", file=sys.stderr)
            return 1
        new_cfg = dict(cfg)
        new_cfg["identity_pubkey"] = derived_pub
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
            new_cfg["relay_identity_fingerprint"] = cfg["relay_identity_fingerprint"]
        seed, pub = keygen()
        derived_pub = b64u_encode(pub)
        new_cfg["identity_pubkey"] = derived_pub
        generated = True

    try:
        key_path = _private_abs(
            getattr(args, "key_path", None)
            or new_cfg.get("identity_privkey_path")
            or (config_path + ".key"))
        if (_paths_alias(config_path, key_path)
                or _paths_alias(pending_path, key_path)):
            raise ValueError("config, private key, and pending paths must differ")
        _validate_private_destination(key_path)
        _correct_private_mode(key_path)

        # Resolve first-contact trust before freezing the journal baseline. The
        # pin CAS runs while no pending transaction exists; any attempted TOFU
        # write after this point is blocked by _REGISTER_KEY_PENDING_ACTIVE.
        request_origin = (args.base_url or base_url(cfg)).rstrip("/")
        if not cfg.get("relay_identity_fingerprint"):
            try:
                _ensure_origin_verified(request_origin, cfg)
            except SystemExit:
                return 1
            _assert_register_key_operation()
            _absolute, _parent, pending_st = _validate_private_destination(
                pending_path)
            if pending_st is not None:
                raise ValueError(
                    "pending journal appeared during relay trust preparation")
            cfg = _load_register_key_config(config_path)
            pinned = cfg.get("relay_identity_fingerprint")
            if not pinned:
                raise ValueError("relay identity confirmation was not persisted")
            new_cfg["relay_identity_fingerprint"] = pinned

        base_bytes = _read_private_regular(config_path, correct_mode=True)
        live_cfg = json.loads(base_bytes.decode("utf-8"))
        if live_cfg != cfg:
            raise ValueError("live config changed before pending baseline creation")
        saved_cfg = dict(new_cfg)
        saved_cfg.pop("identity_privkey", None)
        saved_cfg["identity_privkey_path"] = key_path
        target_bytes = _private_json_bytes(saved_cfg)
        prior_key_exists = os.path.lexists(key_path)
        prior_key_bytes = (
            _read_private_regular(key_path, correct_mode=True)
            if prior_key_exists else bytes()
        )
        token = auth_token(saved_cfg)
        request_base = (args.base_url or base_url(saved_cfg)).rstrip("/")
        journal = {
            "kind": _REGISTER_KEY_JOURNAL_KIND,
            "transaction_id": _secrets.token_hex(16),
            "phase": "prepared",
            "config_path": config_path,
            "key_path": key_path,
            "peer": peer_name,
            "request_base": request_base,
            "identity_pubkey": derived_pub,
            "identity_seed": b64u_encode(seed),
            "base_config_sha256": hashlib.sha256(base_bytes).hexdigest(),
            "base_config_bytes": _blob_encode(base_bytes),
            "target_config_bytes": _blob_encode(target_bytes),
            "token_sha256": hashlib.sha256(token.encode("utf-8")).hexdigest(),
            "prior_key_exists": prior_key_exists,
            "prior_key_bytes": _blob_encode(prior_key_bytes),
            "generated": generated,
        }
        _validate_register_key_journal(journal, config_path)
        _assert_register_key_operation()
        _REGISTER_KEY_PENDING_ACTIVE = True
        _write_register_key_journal(pending_path, journal)
        _validate_register_key_artifacts(pending_path, journal)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        _REGISTER_KEY_PENDING_ACTIVE = False
        print("refusing register-key before request: %s" % exc, file=sys.stderr)
        return 1
    try:
        return _send_register_key_candidate(pending_path, journal, args)
    finally:
        _REGISTER_KEY_PENDING_ACTIVE = False


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


def _canonical_inviter(value):
    import re
    if (type(value) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{43}", value)
            or b64u_encode(b64u_decode(value)) != value):
        raise ValueError("inviter identity must be a canonical Ed25519 public key")
    return value


def parse_invitation_url(link, relay_url=None):
    """Standalone equivalent of SDK invitations.parse_invitation_url."""
    import re
    import ipaddress
    def split(value):
        if (type(value) is not str or not value
                or any(ord(c) <= 32 or ord(c) == 127 for c in value)
                or any(c in value for c in ("?", "\\", "%"))):
            raise ValueError("invitation requires a clean absolute URL")
        p = urllib.parse.urlsplit(value)
        if (not p.hostname or p.username is not None or p.password is not None
                or p.scheme not in ("http", "https")):
            raise ValueError("invitation requires HTTPS without credentials")
        p.port
        if p.netloc.endswith(":"):
            raise ValueError("invalid origin port")
        if p.scheme == "http":
            try:
                local = ipaddress.ip_address(p.hostname).is_loopback
            except ValueError:
                local = p.hostname == "localhost"
            if not local:
                raise ValueError("HTTP invitations are allowed only on loopback")
        return p
    p = split(link)
    origin = p.scheme + "://" + p.netloc
    if relay_url is not None:
        configured = split(relay_url)
        if (configured.path not in ("", "/") or "#" in relay_url
                or (p.scheme, p.netloc.lower()) != (configured.scheme, configured.netloc.lower())):
            raise ValueError("invitation origin differs from configured relay")
    match = re.fullmatch(r"/i/([A-Za-z0-9_-]{22})", p.path)
    if not match or link.count("#") != 1:
        raise ValueError("invitation must be /i/<22-character handle>#<secret>")
    handle = match.group(1)
    raw = b64u_decode(handle)
    if b64u_encode(raw) != handle:
        raise ValueError("noncanonical invitation handle")
    _canonical_inviter(p.fragment)
    return {"origin": origin, "h": str(uuid.UUID(bytes=raw)), "k": p.fragment,
            "path": p.path}


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
        elif args.cmd == "mint-invitation":
            import math
            if not math.isfinite(args.exp_days) or args.exp_days <= 0:
                raise ValueError("exp_days must be a positive finite number")
            path = "/v1/handshakes/invitations"
            body = {"exp_days": args.exp_days, "enc_v": 1}
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
        if args.cmd == "mint-invitation":
            print("Mint outcome UNKNOWN; do not mint again blindly. Read-only invite-list reconciliation:",
                  file=sys.stderr)
            try:
                _, listed = req(cfg, "GET", "/v1/invites/list", base=origin)
                print(json.dumps(listed, indent=2), file=sys.stderr)
            except Exception:
                print("Readback unavailable; run invite-list later before deciding on a new mint.", file=sys.stderr)
        return 1
    if 200 <= code < 300 and args.cmd == "mint-invitation":
        try:
            parsed = parse_invitation_url(out["link"], origin)
            _canonical_inviter(out.get("inviter_identity"))
            if (out.get("mode") != "private_invitation" or out.get("max_uses") != 1
                    or out.get("link_id") != parsed["h"] or len(out["link"]) > 120):
                raise ValueError("unexpected invitation metadata")
        except (ValueError, KeyError, TypeError, AttributeError):
            print("Invalid mint response; outcome UNKNOWN. Reconcile with invite-list before minting again.",
                  file=sys.stderr)
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


def _redeem_private_invitation(args):
    """Serialize short-invitation setup against other identity setup work."""
    try:
        _ensure_private_parent(_private_abs(args.config))
        with _RegisterKeyOperationLock(args.config):
            if os.path.lexists(_register_key_pending_path(args.config)):
                raise ValueError("finish pending register-key recovery before redeeming")
            return _redeem_private_invitation_locked(args)
    except (ValueError, OSError) as exc:
        print("private invitation local state unsafe: %s" % exc, file=sys.stderr)
        return 1


def _redeem_private_invitation_locked(args):
    """Read-only discovery, named consent, durable identity, pending only."""
    try:
        existing = load_config(args.config) if os.path.exists(args.config) else None
        if existing is not None and not is_identity_cfg(existing):
            raise ValueError("existing config is not an identity; use an isolated config")
        if existing is not None and not existing.get("relay_url"):
            raise ValueError("existing identity has no configured relay origin")
        f = parse_invitation_url(args.link, existing.get("relay_url") if existing else None)
        origin = f["origin"]
        if args.base_url and args.base_url.rstrip("/") != origin:
            raise ValueError("--base-url differs from invitation origin")
        if existing and auth_token(existing) and not (
                existing.get("relay_identity_fingerprint") or existing.get("relay_identity_fingerprint_full")):
            raise ValueError("existing enrolled identity requires an established relay pin")
        expected = getattr(args, "expect_inviter", None)
        if expected is not None:
            _canonical_inviter(expected)
        if getattr(args, "yes", False) and expected is None:
            raise ValueError("--yes requires --expect-inviter CANONICAL_PUBLIC_KEY")
        name = getattr(args, "name", None)
        import re
        if name is not None and (not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,30}", name)
                                 or name.startswith("guest-")):
            raise ValueError("invalid --name")
        if (getattr(args, "yes", False) and not (existing or {}).get("service_token")
                and name is None):
            raise ValueError("fresh automated redemption requires --name")
        relay_fp = check_relay_identity(origin, existing or {})
        # Discovery is deliberately unauthenticated, and contains NO fragment.
        discovery = {"relay_url": origin, "relay_identity_fingerprint": relay_fp}
        if existing and existing.get("relay_identity_fingerprint_full"):
            discovery["relay_identity_fingerprint_full"] = existing["relay_identity_fingerprint_full"]
        code, metadata = req(discovery, "GET", f["path"], base=origin)
        if not 200 <= code < 300 or metadata.get("mode") != "private_invitation":
            raise ValueError("private invitation unavailable")
        inviter = _canonical_inviter(metadata.get("inviter_identity"))
        f["inviter_identity"] = inviter
        print("Relay: %s (key %s)" % (origin, relay_fp))
        print("Inviter identity: %s" % inviter)
        print("Inviter name hint (not identity): %s" % json.dumps(metadata.get("inviter_name_hint")))
        print("Expires: %s" % metadata.get("exp"))
        if expected is not None and expected != inviter:
            raise ValueError("inviter identity does not match --expect-inviter")
        if not getattr(args, "yes", False):
            if input("Type CONNECT %s to enroll/redeem (acceptance remains separate): " % inviter) != "CONNECT " + inviter:
                raise ValueError("aborted: connect consent not given")
        cfg = dict(existing) if existing else {
            "kind": IDENTITY_KIND, "relay_url": origin,
            "user_agent": "ClackRelay-CLI/1.2.0"}
        if existing:
            seed = signing_seed(cfg)
            if seed is None or b64u_encode(_publickey(seed)) != cfg.get("identity_pubkey"):
                raise ValueError("existing identity key is missing or inconsistent")
            pub = _publickey(seed)
        else:
            if os.path.lexists(args.config + ".key"):
                raise ValueError("orphan key exists; recover it explicitly instead of overwriting")
            seed, pub = keygen()
            cfg["identity_pubkey"] = b64u_encode(pub)
        cfg["relay_identity_fingerprint"] = relay_fp
        # Key, identity and pin are durable BEFORE challenge or claim mutation.
        _save_identity_config(args.config, cfg, seed)
        return _redeem_v4_handshake(args, cfg, f, origin, relay_fp, seed, pub,
                                    private_invitation=True)
    except (ValueError, OSError, RuntimeError, EOFError, KeyError, TypeError, AttributeError) as exc:
        print("private invitation failed: %s; keep this config for same-identity recovery; "
              "do not mint/redeem blindly" % exc, file=sys.stderr)
        return 1


def cmd_redeem(args):
    _require_private_publication_platform()
    if "/i/" in args.link:
        return _redeem_private_invitation(args)
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
            "user_agent": "ClackRelay-CLI/1.2.0",
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


def _redeem_v4_handshake(args, cfg, f, relay_url, relay_fp, seed, pub,
                         private_invitation=False):
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
        if private_invitation and getattr(args, "name", None) not in (None, cfg["peer_name"]):
            raise ValueError("--name cannot rename an existing identity")
        print("note: redeeming on already-enrolled identity %r; keeping "
              "existing peer name (no rename)" % cfg["peer_name"])
    else:
        while True:
            chosen = getattr(args, "name", None) if private_invitation else None
            if private_invitation and getattr(args, "yes", False) and chosen is None:
                raise ValueError("fresh automated redemption requires --name")
            ans = chosen if chosen is not None else input("Choose your peer name (lowercase, or Enter for guest): ").strip()
            if not ans:
                break
            if _name_re.match(ans) and not ans.startswith("guest-"):
                requested_name = ans
                break
            print("  invalid name: use lowercase letters, digits, _ or -, 1-31 chars", file=sys.stderr)
            if chosen is not None:
                raise ValueError("invalid --name")

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
                       ({"invite_id": h, "k": k, "identity_pubkey": b64u_encode(pub)}
                        if private_invitation else {"invite_id": h}), base=relay_url)
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

    if private_invitation and (out.get("status") != "pending" or not out.get("handshake_id")):
        raise ValueError("private invitation did not return a pending handshake; reconcile before retrying")
    if private_invitation and out.get("minter_identity") != f["inviter_identity"]:
        raise ValueError("redeem inviter identity mismatch; reconcile before retrying")
    if private_invitation and already_enrolled:
        # Existing credentials remain authoritative even if an unexpected
        # server response includes enrollment fields.
        out = dict(out)
        out.pop("service_token", None)
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

    if private_invitation:
        import shlex
        summary = {key: out.get(key) for key in (
            "status", "handshake_id", "minter_identity", "pending_expires_at",
            "via_link_id", "generation", "enc_capable")}
        print(json.dumps({"pending_handshake": summary}, indent=2))
        print("Pending only. Review the actual inviter and pending deadline before accepting.")
        print("Next command: " + shlex.join([
            sys.executable, os.path.abspath(__file__), "--config", os.path.abspath(args.config),
            "accept-handshake", "--enc-v", "1", "--", out["handshake_id"]]))
        print("config saved: %s" % args.config)
        return 0

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
    _require_private_publication_platform()
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
            "user_agent": "ClackRelay-CLI/1.2.0",
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
                   help="private key file path (mode 600 on POSIX, owner-only ACL "
                        "on Windows; default: <config>.key)")
    k.add_argument("--user-agent", default=None)

    ak = sub.add_parser("attach-key",
                        help="attach an ed25519 signing key to a legacy "
                             "token config (prints the pubkey for the relay "
                             "operator's identity_pubkeys map)")
    ak.add_argument("--key-path", default=None,
                    help="private key file path (mode 600; default: <config>.key)")

    rk = sub.add_parser("register-key",
                        help="self-service Ed25519 key registration: bootstrap "
                             "a legacy token config, or re-register exactly "
                             "the key derived from an existing identity seed "
                             "(no key rotation)")
    rk.add_argument("--key-path", default=None,
                    help="private key file path (mode 600; default: <config>.key)")

    m = sub.add_parser("mint-invite", help="mint a shareable join link")
    m.add_argument("--max-uses", type=int, default=1)
    m.add_argument("--expiry-hours", type=float, default=24.0)

    mr = sub.add_parser("mint-request", help="mint a public request for a known enrolled identity")
    mr.add_argument("target_identity", help="canonical Ed25519 public key (base64url)")
    mr.add_argument("--exp-days", type=float, default=7)
    mr.add_argument("--enc-v", type=int, choices=(0, 1), default=0)
    mi = sub.add_parser("mint-invitation", help="mint a short private single-use invitation for a new agent")
    mi.add_argument("--exp-days", type=float, default=7)
    rr = sub.add_parser("redeem-request", help="redeem a public URL into a pending handshake (no acceptance)")
    rr.add_argument("link", help="same-configured-relay /join/UUID URL")
    ah = sub.add_parser("accept-handshake", help="explicitly consent to a pending handshake")
    ah.add_argument("handshake_id")
    ah.add_argument("--enc-v", type=int, choices=(0, 1), default=None,
                    help="explicit capability advertisement; omission leaves an active pair unchanged")

    rd = sub.add_parser("redeem", help="redeem an invite link (full join flow)")
    rd.add_argument("link", help="the invite link (or its #fragment payload)")
    rd.add_argument("--name", default=None, help="peer name for short private invitation enrollment")
    rd.add_argument("--yes", action="store_true", help="explicit connect consent; requires --expect-inviter")
    rd.add_argument("--expect-inviter", default=None, help="expected canonical inviter Ed25519 public key")

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
    if args.cmd in ("keygen", "attach-key", "register-key", "redeem", "enroll"):
        try:
            _require_private_publication_platform()
        except OSError as exc:
            print(str(exc), file=sys.stderr)
            return 1
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

    # register-key acquires its process-lifetime operation lock before reading
    # any config, pending journal, key, or quarantine state.
    if args.cmd == "register-key":
        return cmd_register_key(args)

    try:
        cfg = load_config(args.config)
    except (OSError, ValueError) as exc:
        print("cannot read client config: %s" % exc, file=sys.stderr)
        return 1
    if args.cmd in ("mint-request", "mint-invitation", "redeem-request", "accept-handshake"):
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
