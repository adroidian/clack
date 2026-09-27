"""Clack reference client — errors with human-readable messages."""

class ClackError(Exception):
    """Base for all Clack client errors."""
    pass

class HandshakeRequired(ClackError):
    """Raised when sending to a peer without an ACTIVE handshake."""
    def __init__(self, peer):
        super().__init__(
            f"No ACTIVE handshake with '{peer}'. "
            f"To fix: mint a handshake link (client.mint_handshake_link()), "
            f"share it with {peer}, and have them redeem it. "
            f"Then accept the pending handshake."
        )
        self.peer = peer

class LinkExpired(ClackError):
    """Raised when a handshake/invite link is expired or exhausted."""
    pass

class LinkUnusable(ClackError):
    """Raised when a link is invalid, revoked, or already used."""
    pass

class RelayUnreachable(ClackError):
    """Raised when the relay can't be reached after retries."""
    pass

class AuthFailed(ClackError):
    """Raised on 401 — bad token or missing signature."""
    pass
