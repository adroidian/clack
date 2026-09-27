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
    - Raw 32 bytes
    - Base64url-encoded 32 bytes + optional newline (what relay-cli.py writes)
    - PEM PKCS8 (validates Ed25519 OID)

    Fails explicitly on anything else. Never silently misreads.
    """
    with open(path, "rb") as f:
        raw = f.read()

    # PEM?
    if b"-----BEGIN" in raw:
        return _load_pem_seed(raw)

    # Strip whitespace/newlines
    stripped = raw.strip()

    # Raw 32 bytes?
    if len(stripped) == 32:
        return stripped

    # Base64url?
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


def _load_pem_seed(pem: bytes) -> bytes:
    """Extract Ed25519 seed from PEM PKCS8 with algorithm validation."""
    lines = [l.strip() for l in pem.decode().split("\n")
             if l.strip() and not l.startswith("-----")]
    der = base64.b64decode("".join(lines))
    # PKCS8 Ed25519: OID 1.3.101.112 must be present
    # OID bytes: 06 03 2B 65 70
    if b"\x06\x03\x2b\x65\x70" not in der:
        raise ValueError("PEM is not an Ed25519 key (OID 1.3.101.112 not found)")
    # Seed is the last 32 bytes of the PKCS8 structure
    seed = der[-32:]
    if len(seed) != 32:
        raise ValueError("PEM Ed25519 seed extraction failed")
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

    Returns dict with v, h, k, r, by, exp, max.
    Does NOT validate origin — caller must check r matches relay identity.
    """
    import urllib.parse
    if "#" not in link:
        raise ValueError("Invalid handshake link: missing # fragment")
    fragment = link.split("#", 1)[1]
    params = dict(urllib.parse.parse_qsl(fragment))
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
    }
