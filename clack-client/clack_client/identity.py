"""Relay identity verification — TOFU pinning with challenge-response.

Mirrors relay-cli.py's proven verifier (v0.2.13+):

1. Client generates a fresh 32-byte nonce (hex-encoded).
2. GET /v1/identity?nonce=<hex>
3. Relay returns {nonce, algorithm, signature (base64),
   public_key: {"n": hex, "e": hex}}.
4. Client checks the echoed nonce EXACTLY equals the local challenge,
   checks the algorithm field, then verifies the RSA PKCS#1 v1.5 SHA-256
   signature over the LOCAL nonce bytes (never the echo).
5. Fingerprint format matches the CLI exactly:
   "sha256:" + sha256(b"clack-relay-identity-v1" + b":" + n_be + b":" + e_be).hexdigest()[:16]
   so pins are interoperable between the CLI and this library.
6. Pin file maps relay_url -> fingerprint string. Old-format pins
   (dicts, raw JSON blobs, url: fallbacks) are rejected, not migrated.

Fail-closed rules (Flint review):
- 503 / transport error / malformed proof -> abort, never send credentials.
- Pin mismatch -> abort.
- Corrupt pin store -> abort (never treated as first contact).
- First contact with auto_pin=False -> abort with the fingerprint and
  instructions to verify out-of-band (mirrors the CLI's P2 rule).
- No URL-only fallback. No --yes bypass. No skip.

Never send a Bearer <redacted>, claim secret, or message body before the
origin is verified.
"""

import base64
import hashlib
import json
import os
import secrets
import time

from . import transport
from .errors import ClackError


_IDENTITY_FP_DOMAIN = b"clack-relay-identity-v1"
_EXPECTED_ALGORITHM = "rsassa-pkcs1-v1_5-sha256"
# DER prefix for SHA-256 in PKCS#1 v1.5: DigestInfo SEQUENCE header.
_SHA256_DINFO_HEAD = bytes.fromhex("3031300d060960864801650304020105000420")


def _parse_pubkey(pubkey) -> tuple[int, int]:
    """Validate the relay's {"n": hex, "e": hex} public key. Returns (n, e)."""
    if not isinstance(pubkey, dict):
        raise ClackError("Identity check failed: public_key is not an object")
    try:
        n = int(pubkey["n"], 16)
        e = int(pubkey["e"], 16)
    except (KeyError, TypeError, ValueError):
        raise ClackError("Identity check failed: public_key has bad n/e fields")
    if n <= 0 or e <= 0:
        raise ClackError("Identity check failed: public_key has non-positive n/e")
    return n, e


def relay_identity_fingerprint(pubkey) -> str:
    """Stable fingerprint of a relay identity public key.

    Byte-identical to relay-cli.py's relay_identity_fingerprint so pins
    are interoperable between the CLI and this library.
    """
    n, e = _parse_pubkey(pubkey)
    n_be = n.to_bytes((n.bit_length() + 7) // 8, "big")
    e_be = e.to_bytes((e.bit_length() + 7) // 8, "big")
    digest = hashlib.sha256(
        _IDENTITY_FP_DOMAIN + b":" + n_be + b":" + e_be
    ).hexdigest()
    return "sha256:" + digest[:16]


def relay_identity_verify(pubkey, nonce_hex: str, signature_b64: str) -> bool:
    """Verify the relay's /v1/identity nonce signature. Pure stdlib RSA.

    Manual PKCS#1 v1.5 verification via pow() — no extra dependency,
    same construction as relay-cli.py.
    """
    try:
        n, e = _parse_pubkey(pubkey)
        nonce = bytes.fromhex(nonce_hex)
        sig = base64.b64decode(signature_b64)
    except Exception:
        return False
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    t = _SHA256_DINFO_HEAD + hashlib.sha256(nonce).digest()
    em = pow(int.from_bytes(sig, "big"), e, n).to_bytes(k, "big")
    expect = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return em == expect


def _fetch_identity_proof(relay_url, user_agent, timeout):
    """Fetch and strictly validate the /v1/identity proof.

    Returns (fingerprint, pubkey). Raises ClackError on any failure,
    including 503 (identity unavailable) — the caller decides nothing;
    there is no degraded path.
    """
    nonce = secrets.token_hex(32)  # 32 random bytes, hex-encoded
    url = f"{relay_url.rstrip('/')}/v1/identity?nonce={nonce}"

    last_exc = None
    raw = None
    status = None
    for attempt in range(3):
        try:
            status, raw = transport.request(
                "GET", url,
                {"User-Agent": user_agent},
                timeout=timeout,
                allow_fallback=False,  # pin check must use primary transport
            )
            last_exc = None
            break
        except Exception as e:
            last_exc = e
            if attempt < 2:
                time.sleep(1 + attempt)
                continue

    if last_exc is not None:
        raise ClackError(
            f"Identity check failed: cannot reach {relay_url}/v1/identity: {last_exc}"
        )

    if status == 503:
        raise ClackError(
            f"Identity check failed: relay identity unavailable (503) for {relay_url}. "
            f"Refusing to proceed unauthenticated."
        )
    if status != 200:
        raise ClackError(
            f"Identity check failed: HTTP {status} from {relay_url}/v1/identity"
        )

    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception:
        raise ClackError("Identity check failed: malformed JSON from /v1/identity")
    if not isinstance(data, dict):
        raise ClackError("Identity check failed: identity response is not an object")

    # The proof must answer OUR challenge. The echoed nonce must equal the
    # locally generated one exactly; the signature is verified over the
    # LOCAL nonce bytes, never the echo.
    if data.get("nonce") != nonce:
        raise ClackError(
            "Identity check failed: proof answers a different challenge "
            "(nonce mismatch — possible replay)"
        )
    if data.get("algorithm") != _EXPECTED_ALGORITHM:
        raise ClackError(
            f"Identity check failed: unexpected algorithm {data.get('algorithm')!r}"
        )
    pubkey = data.get("public_key")
    signature = data.get("signature")
    if not signature:
        raise ClackError("Identity check failed: missing signature")

    if not relay_identity_verify(pubkey, nonce, signature):
        raise ClackError(
            "Identity check failed: RSA signature does not verify. "
            "Possible MITM or compromised relay."
        )

    return relay_identity_fingerprint(pubkey), pubkey


def _load_pins(pin_file) -> dict:
    """Load the pin store. Corrupt state fails closed — never treated as
    first contact. Old-format values fail closed with a migration hint."""
    if not os.path.exists(pin_file):
        return {}
    try:
        with open(pin_file, encoding="utf-8") as f:
            pins = json.load(f)
    except Exception as e:
        raise ClackError(
            f"Identity check failed: pin store corrupt ({e}). "
            f"Refusing to treat corruption as first contact."
        )
    if not isinstance(pins, dict):
        raise ClackError(
            "Identity check failed: pin store is not an object. "
            "Refusing to treat corruption as first contact."
        )
    return pins


def _write_pin(pin_file, relay_url, fingerprint):
    """Atomically store a first-contact pin. Mode 0600."""
    pins = _load_pins(pin_file)
    pins[relay_url] = fingerprint
    d = os.path.dirname(os.path.abspath(pin_file))
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = pin_file + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(pins, f, indent=2)
        f.write("\n")
    os.chmod(tmp, 0o600)
    os.rename(tmp, pin_file)


def verify_relay_identity(relay_url, user_agent="ClackClient/1.0",
                          timeout=30, pin_file=None, auto_pin=False):
    """Verify relay identity via challenge-response. Returns the fingerprint.

    Raises ClackError on ANY verification failure. There is no fallback,
    no degraded identity, and no silent first-contact pinning.

    auto_pin=False (default): first contact aborts with the presented
    fingerprint and instructions to verify it out-of-band before pinning.
    This mirrors relay-cli.py's P2 rule: a config bearing credentials never
    silently TOFU-pins a new relay. Pass auto_pin=True only when the
    operator has verified the fingerprint through another channel.

    Pin values must be fingerprint strings ("sha256:..."). Anything else
    in the pin store — dicts, raw JSON blobs, url: fallbacks from older
    client versions — fails closed with a re-pin instruction.
    """
    pin_file = pin_file or os.path.expanduser("~/.clack/relay_pins.json")

    fingerprint, _pubkey = _fetch_identity_proof(relay_url, user_agent, timeout)
    pins = _load_pins(pin_file)
    stored = pins.get(relay_url)

    if stored is None:
        # First contact.
        if not auto_pin:
            raise ClackError(
                f"First contact with {relay_url}: relay presents identity "
                f"{fingerprint}. Verify this fingerprint out-of-band (relay "
                f"operator, invite material, or the relay's published identity "
                f"page), then re-run with auto_pin=True to pin it. Refusing "
                f"to silently trust a new relay."
            )
        _write_pin(pin_file, relay_url, fingerprint)
        return fingerprint

    if not isinstance(stored, str) or not stored.startswith("sha256:"):
        raise ClackError(
            f"Identity check failed: pin for {relay_url} is in an old or "
            f"unrecognized format ({type(stored).__name__}). Delete the entry "
            f"from {pin_file}, verify the relay's fingerprint out-of-band, "
            f"and re-pin with auto_pin=True. Refusing to honor a pin I "
            f"cannot interpret."
        )

    if stored != fingerprint:
        raise ClackError(
            f"Relay identity PIN MISMATCH for {relay_url}. "
            f"Pinned: {stored}, presented: {fingerprint}. "
            f"Possible MITM or relay rebuild. Verify out-of-band before "
            f"updating the pin."
        )

    return fingerprint
