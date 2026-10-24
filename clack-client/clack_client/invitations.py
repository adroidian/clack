"""Strict short private invitation parsing. No network or key storage."""
import base64
import ipaddress
import math
import re
import urllib.parse
import uuid


def validate_invitation_expiry(exp_days):
    if type(exp_days) not in (int, float) or not math.isfinite(exp_days) or exp_days <= 0:
        raise ValueError("exp_days must be a positive finite number")


def canonical_key(value):
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
        raise ValueError("inviter identity must be a canonical Ed25519 public key")
    raw = base64.urlsafe_b64decode(value + "=")
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != value:
        raise ValueError("inviter identity must be a canonical Ed25519 public key")
    return value


def parse_invitation_url(link, relay_url=None):
    """Return origin, canonical UUID, secret, and secret-free metadata path.

    HTTPS only, except literal loopback HTTP for local testing. Deliberately
    reject rather than repair URL syntax, encoded paths and base64 pad bits.
    """
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
    raw = base64.urlsafe_b64decode(handle + "==")
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != handle:
        raise ValueError("noncanonical invitation handle")
    canonical_key(p.fragment)
    return {"origin": origin, "h": str(uuid.UUID(bytes=raw)), "k": p.fragment,
            "path": p.path}