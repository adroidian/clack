"""Ed25519 request signing for Clack relay authentication."""

import base64
import hashlib
import hmac
import json
import time
import urllib.parse


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def load_private_key(path: str) -> bytes:
    """Load raw 32-byte Ed25519 private key from file."""
    with open(path, "rb") as f:
        key = f.read()
    # Handle PEM or raw
    if b"-----BEGIN" in key:
        # Extract base64 body, decode DER, take last 32 bytes (simplified)
        lines = [l for l in key.decode().split("\n") if l and not l.startswith("-----")]
        der = base64.b64decode("".join(lines))
        # Ed25519 PKCS8: private key is last 32 bytes
        return der[-32:]
    return key[:32]


def _ed25519_sign(private_key: bytes, message: bytes) -> bytes:
    """Sign with Ed25519. Uses PyNaCl if available, else pure-Python fallback."""
    try:
        import nacl.signing
        sk = nacl.signing.SigningKey(private_key)
        return sk.sign(message).signature
    except ImportError:
        # Pure Python Ed25519 (RFC 8032) — simplified, for environments
        # without PyNaCl. In production, install pynacl.
        raise RuntimeError("PyNaCl required for Ed25519 signing: pip install pynacl")


def sign_headers(private_key: bytes, method: str, path: str, body: bytes | None) -> dict:
    """Generate Clack signature headers for a request."""
    timestamp = str(int(time.time()))
    body_hash = hashlib.sha256(body or b"").hexdigest()
    # Canonical string: method + path + timestamp + body_hash
    canonical = f"{method}\n{path}\n{timestamp}\n{body_hash}".encode()
    signature = _ed25519_sign(private_key, canonical)
    return {
        "X-Clack-Timestamp": timestamp,
        "X-Clack-Body-Hash": body_hash,
        "X-Clack-Signature": _b64url_encode(signature),
    }


def parse_handshake_link(link: str) -> dict:
    """Parse a v4 handshake link URL into its components.

    Handles the URL fragment (after #) which is never sent to the server.
    Returns dict with h, k, r, by, exp, max, v.
    Raises ValueError on malformed links.
    """
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
        "v": v,
        "h": h,
        "k": k,
        "r": params.get("r"),
        "by": params.get("by"),
        "exp": params.get("exp"),
        "max": params.get("max"),
    }
