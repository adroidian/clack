"""Ed25519 request signing — matches the relay's actual scheme.

Relay expects (relay.py _verify_signature):
    X-Clack-Scheme: 1
    X-Clack-Key:    <peer name, must match Bearer's peer>
    X-Clack-Nonce:  <unix_seconds>:<32 hex chars random>
    X-Clack-Sig:    <hex Ed25519 signature>

Signed bytes:
    clack-ed25519-v1\n{METHOD_UPPER}\n{path_and_query}\n{sha256_hex(raw_body)}\n{nonce}
"""

import base64
import hashlib
import os
import secrets
import time


SCHEME_ID = "clack-ed25519-v1"


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def load_private_key(path: str) -> bytes:
    """Load a 32-byte Ed25519 seed.

    Supports:
    - Raw 32 bytes (checked FIRST, before any whitespace handling — a seed
      whose first or last byte is 0x20 must not be mangled by stripping)
    - Base64url-encoded 32 bytes + optional trailing newline (what relay-cli.py writes)
    - PEM PKCS8 (validated with real DER structure parsing)

    Fails explicitly on anything else. Never silently misreads.
    """
    with open(path, "rb") as f:
        raw = f.read()

    # PEM?
    if b"-----BEGIN" in raw:
        return _load_pem_seed(raw)

    # Raw 32 bytes — checked BEFORE stripping. A file that is exactly
    # 32 bytes is a seed, even if it starts/ends with whitespace bytes.
    if len(raw) == 32:
        return raw

    # Otherwise: strip ASCII whitespace and try base64url.
    stripped = raw.strip()
    if len(stripped) == 32 and stripped == raw:
        # Already handled above; unreachable, kept for clarity.
        return stripped
    try:
        decoded = _b64u_decode(stripped.decode("ascii"))
        if len(decoded) == 32:
            return decoded
    except Exception:
        pass

    raise ValueError(
        f"Invalid key file {path}: expected raw 32 bytes, base64url 32 bytes, "
        f"or PEM PKCS8. Got {len(raw)} bytes."
    )


def _der_read(data: bytes, offset: int):
    """Read one DER TLV at offset. Returns (tag, value_bytes, next_offset).

    Minimal DER reader: short and long form lengths only, no indefinite
    length, no constructed-bit games. Enough to validate PKCS8 structure.
    """
    if offset + 2 > len(data):
        raise ValueError("DER truncated at header")
    tag = data[offset]
    lb = data[offset + 1]
    pos = offset + 2
    if lb & 0x80:
        nbytes = lb & 0x7F
        if nbytes == 0 or nbytes > 4:
            raise ValueError("DER: unsupported length encoding")
        if pos + nbytes > len(data):
            raise ValueError("DER truncated in length bytes")
        length = int.from_bytes(data[pos:pos + nbytes], "big")
        pos += nbytes
    else:
        length = lb
    if pos + length > len(data):
        raise ValueError("DER truncated in value")
    return tag, data[pos:pos + length], pos + length


# OID 1.3.101.112 (Ed25519) as DER content bytes: 06 03 2B 65 70 -> content 2B 65 70
_ED25519_OID_CONTENT = bytes([0x2B, 0x65, 0x70])


def _load_pem_seed(pem: bytes) -> bytes:
    """Extract the Ed25519 seed from PEM PKCS8 with real structure validation.

    Parses the DER as:
        SEQUENCE {
            INTEGER 0,                          # version
            SEQUENCE { OID 1.3.101.112 },       # algorithm = Ed25519
            OCTET STRING { OCTET STRING (32) }  # private key -> seed
        }
    Any structural deviation raises ValueError. No OID-substring heuristics,
    no taking the last 32 bytes of an unparsed blob.
    """
    lines = [l.strip() for l in pem.decode().split("\n")
             if l.strip() and not l.startswith("-----")]
    try:
        der = base64.b64decode("".join(lines))
    except Exception as e:
        raise ValueError(f"PEM base64 decode failed: {e}")

    tag, outer, end = _der_read(der, 0)
    if tag != 0x30 or end != len(der):
        raise ValueError("PEM is not a well-formed PKCS8 SEQUENCE")

    # Child 1: INTEGER version == 0
    tag, ver, pos = _der_read(outer, 0)
    if tag != 0x02 or int.from_bytes(ver, "big") != 0:
        raise ValueError("PEM PKCS8: expected INTEGER version 0")

    # Child 2: SEQUENCE { OID }
    tag, alg_seq, pos = _der_read(outer, pos)
    if tag != 0x30:
        raise ValueError("PEM PKCS8: expected algorithm SEQUENCE")
    tag, oid, oid_end = _der_read(alg_seq, 0)
    if tag != 0x06 or oid != _ED25519_OID_CONTENT or oid_end != len(alg_seq):
        raise ValueError("PEM PKCS8: algorithm is not Ed25519 (OID 1.3.101.112)")

    # Child 3: OCTET STRING wrapping the key
    tag, key_wrap, pos = _der_read(outer, pos)
    if tag != 0x04 or pos != len(outer):
        raise ValueError("PEM PKCS8: expected trailing OCTET STRING")
    tag, seed, seed_end = _der_read(key_wrap, 0)
    if tag != 0x04 or len(seed) != 32 or seed_end != len(key_wrap):
        raise ValueError("PEM PKCS8: inner OCTET STRING is not a 32-byte seed")
    return seed


def _ed25519_sign(seed: bytes, message: bytes) -> bytes:
    try:
        import nacl.signing
        sk = nacl.signing.SigningKey(seed)
        return sk.sign(message).signature
    except ImportError:
        raise RuntimeError("PyNaCl required: pip install pynacl")


def sign_headers(seed: bytes, peer_name: str, method: str,
                 path_and_query: str, body: bytes | None) -> dict:
    """Generate the relay's expected signature headers.

    Creates a fresh random nonce per call — never reuse across retries.
    """
    nonce = f"{int(time.time())}:{secrets.token_hex(16)}"
    body_hash = hashlib.sha256(body or b"").hexdigest()
    canonical = (
        f"{SCHEME_ID}\n"
        f"{method.upper()}\n"
        f"{path_and_query}\n"
        f"{body_hash}\n"
        f"{nonce}"
    ).encode("utf-8")
    sig = _ed25519_sign(seed, canonical)
    return {
        "X-Clack-Scheme": "1",
        "X-Clack-Key": peer_name,
        "X-Clack-Nonce": nonce,
        "X-Clack-Sig": sig.hex(),
    }


def parse_handshake_link(link: str) -> dict:
    """Parse a v4 handshake link URL into components.

    Strict parsing:
    - Duplicate fields are REJECTED (dict(parse_qsl) silently keeps the
      last; an attacker or a mangled copy-paste must not get that).
    - Unknown version rejected. Missing h/k rejected here; the caller
      must still check r (origin) — see ClackClient.redeem_handshake.

    Returns dict with v, h, k, r, by, exp, max, and _base (the URL without
    the fragment, for origin cross-checking).
    Does NOT validate origin — caller must check r matches relay identity.
    """
    import urllib.parse
    if "#" not in link:
        raise ValueError("Invalid handshake link: missing # fragment")
    base, fragment = link.split("#", 1)
    pairs = urllib.parse.parse_qsl(fragment, keep_blank_values=True)
    seen = set()
    params = {}
    for k, v in pairs:
        if k in seen:
            raise ValueError(
                f"Invalid handshake link: duplicate field {k!r}"
            )
        seen.add(k)
        params[k] = v
    v = params.get("v", "4")
    if v != "4":
        raise ValueError(f"Unsupported handshake link version: {v} (expected 4)")
    h = params.get("h")
    k = params.get("k")
    if not h or not k:
        raise ValueError("Invalid handshake link: missing h or k")
    return {
        "v": v, "h": h, "k": k,
        "r": params.get("r"),
        "by": params.get("by"),
        "exp": params.get("exp"),
        "max": params.get("max"),
        "_base": base,
    }
