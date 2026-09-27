"""Clack reference client."""

from .client import ClackClient
from .errors import (
    ClackError, HandshakeRequired, LinkExpired, LinkUnusable,
    RelayUnreachable, AuthFailed,
)
from .signing import parse_handshake_link

__version__ = "1.0.0"
__all__ = [
    "ClackClient",
    "ClackError", "HandshakeRequired", "LinkExpired", "LinkUnusable",
    "RelayUnreachable", "AuthFailed",
    "parse_handshake_link",
]
