#!/usr/bin/env python3
"""Clack E2EE envelope crypto, pure stdlib.

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
