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

class TransportUnavailable(ClackError):
    """Raised when the preferred transport (curl) is not available."""
    pass

class CurlMissing(TransportUnavailable):
    """The curl binary is absent or unlaunchable.

    This is the ONLY condition under which the client falls back to the
    Python transport. Every other curl failure (TLS errors, DNS, timeouts,
    parse failures) is a real error and propagates — it is never a reason
    to downgrade to a weaker transport.
    """
    pass

class CurlFailed(ClackError):
    """curl ran but the request failed (TLS, DNS, timeout, HTTP parse...).

    Never triggers transport fallback. A TLS failure in particular must
    not downgrade to urllib — that would silently drop the stronger
    verification for a weaker one.

    Carries the curl exit code (returncode) so callers can distinguish
    transient failures (retryable) from fatal ones (60/77 = TLS, never
    retry).
    """
    def __init__(self, message, returncode=None):
        super().__init__(message)
        self.returncode = returncode
    pass

class AuthFailed(ClackError):
    """Raised on 401 — bad token or missing signature."""
    pass
