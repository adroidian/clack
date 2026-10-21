"""Public request validation. Links never select a relay or confer consent."""

import base64
import math
import re
import urllib.parse
import uuid


def parse_request_url(link, relay_url):
    """Return canonical public UUID, bound to the already configured origin.

    No network access, metadata lookup, secret parsing, or URL normalization.
    Reject even empty query/fragment delimiters and parser-stripped controls.
    """
    def split_origin(value):
        if (type(value) is not str or not value
                or any(ord(c) <= 32 or ord(c) == 127 for c in value)
                or "?" in value or "#" in value or "\\" in value):
            raise ValueError("request URL must be a clean absolute URL")
        parsed = urllib.parse.urlsplit(value)
        if (parsed.scheme not in ("http", "https") or not parsed.hostname
                or parsed.username is not None or parsed.password is not None):
            raise ValueError("request URL must have an HTTP(S) origin without credentials")
        # Force validation of malformed/out-of-range port syntax.
        parsed.port
        return parsed

    configured = split_origin(relay_url)
    supplied = split_origin(link)
    if configured.path not in ("", "/"):
        raise ValueError("configured relay must be an origin")
    if (supplied.scheme, supplied.netloc.lower()) != (
            configured.scheme, configured.netloc.lower()):
        raise ValueError("request URL origin differs from configured relay")
    prefix = "/join/"
    if not supplied.path.startswith(prefix):
        raise ValueError("request URL must be exactly /join/<canonical UUID>")
    handle = supplied.path[len(prefix):]
    try:
        canonical = str(uuid.UUID(handle))
    except (ValueError, AttributeError):
        raise ValueError("request URL requires a canonical UUID") from None
    if canonical != handle:
        raise ValueError("request URL requires a canonical UUID")
    return handle


def validate_request_options(target_identity, exp_days=7, enc_v=0):
    """Check wire shape; enrollment/identity validity is the relay's authority."""
    if (type(target_identity) is not str
            or not re.fullmatch(r"[A-Za-z0-9_-]{43}", target_identity)):
        raise ValueError("target_identity must be a canonical Ed25519 public key (base64url)")
    raw = base64.urlsafe_b64decode(target_identity + "=")
    if len(raw) != 32 or base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != target_identity:
        raise ValueError("target_identity must be a canonical Ed25519 public key (base64url)")
    if type(exp_days) not in (int, float) or not math.isfinite(exp_days) or exp_days <= 0:
        raise ValueError("exp_days must be a positive finite number")
    validate_request_enc_v(enc_v)


def validate_request_enc_v(enc_v):
    if type(enc_v) is not int or enc_v not in (0, 1):
        raise ValueError("enc_v must be exact integer 0 or 1")
