"""Clack reference client — the standard way to talk to a Clack relay.

This is THE client. If you're building a Clack integration, use this
instead of writing your own HTTP code. It handles:
- Transport (curl primary, Python fallback)
- Ed25519 request signing
- Retries on transient failures
- Human-readable errors (no bare 403s)
- Handshake link parsing (v4)

Example:
    from clack_client import ClackClient

    client = ClackClient(
        relay_url="https://clack.kasnet.us",
        token="your-bearer-token",
        privkey_path="/path/to/ed25519.key",
        peer_name="myp eer",
    )
    client.send("zari", "Hello!")
    for msg in client.poll(timeout=25):
        print(msg)
        client.ack([msg["id"]])
"""

import json
import uuid

from . import transport
from .signing import load_private_key, sign_headers, parse_handshake_link
from .errors import (
    ClackError, HandshakeRequired, LinkExpired, LinkUnusable,
    RelayUnreachable, AuthFailed,
)


class ClackClient:
    def __init__(self, relay_url, token, privkey_path, peer_name,
                 user_agent="ClackClient/1.0", timeout=30):
        self.relay_url = relay_url.rstrip("/")
        self.token = token
        self.peer_name = peer_name
        self.user_agent = user_agent
        self.timeout = timeout
        self._privkey = load_private_key(privkey_path) if privkey_path else None

    def _request(self, method, path, body=None):
        """Low-level signed request. Returns parsed JSON."""
        data = json.dumps(body).encode() if body is not None else None
        headers = {
            "Authorization": f"Bearer {self.token}",
            "User-Agent": self.user_agent,
            "Content-Type": "application/json",
        }
        if self._privkey:
            headers.update(sign_headers(self._privkey, method, path, data))

        url = self.relay_url + path
        try:
            status, raw = transport.request(method, url, headers, data, self.timeout)
        except Exception as e:
            raise RelayUnreachable(f"Cannot reach {self.relay_url}: {e}")

        # Parse response
        try:
            payload = json.loads(raw.decode()) if raw.strip() else {}
        except Exception:
            payload = {}

        # Human-readable errors
        if status == 401:
            raise AuthFailed(f"Authentication failed: {payload.get('error', 'unauthorized')}")
        if status == 403:
            err = payload.get("error", "")
            if err in ("handshake_required", "no_handshake"):
                # Extract peer from path or body context
                raise HandshakeRequired(body.get("to", "unknown") if body else "unknown")
            if err == "link_unusable":
                raise LinkUnusable("Link is invalid, revoked, or already used")
            if err == "link_expired":
                raise LinkExpired("Link has expired")
            raise ClackError(f"Forbidden (403): {err or payload}")
        if status == 429:
            raise ClackError("Rate limited (429) — back off and retry")
        if status >= 400:
            raise ClackError(f"HTTP {status}: {payload.get('error', payload)}")
        if 300 <= status < 400:
            raise ClackError(f"Unexpected redirect (HTTP {status}) — refusing")

        return payload

    # --- Messaging ---

    def send(self, to, text, topic=None, msg_id=None):
        """Send a text message to a peer. Returns message ID."""
        body = {
            "id": msg_id or str(uuid.uuid4()),
            "to": to,
            "text": text,
        }
        if topic:
            body["topic"] = topic
        result = self._request("POST", "/v1/send", body)
        return result.get("id", body["id"])

    def poll(self, timeout=25):
        """Poll for new messages. Returns list of message dicts."""
        result = self._request("GET", f"/v1/poll?timeout={int(timeout)}")
        msgs = result.get("messages", [])
        # Handle both formats: {"messages": [...]} and bare list
        if isinstance(result, list):
            return result
        return msgs

    def ack(self, ids):
        """Acknowledge handled message IDs."""
        return self._request("POST", "/v1/ack", {"ids": ids})

    def peers(self):
        """List enrolled peer names."""
        result = self._request("GET", "/v1/peers")
        return result.get("peers", [])

    # --- Handshakes ---

    def mint_handshake_link(self):
        """Mint a handshake link for another peer to redeem."""
        result = self._request("POST", "/v1/handshakes/mint-link", {})
        return result.get("link")

    def redeem_handshake(self, link_or_hk):
        """Redeem a handshake link.

        Accepts either a full URL or a dict/tuple of (h, k).
        Returns handshake_id.
        """
        if isinstance(link_or_hk, str):
            parsed = parse_handshake_link(link_or_hk)
            h, k = parsed["h"], parsed["k"]
        elif isinstance(link_or_hk, dict):
            h, k = link_or_hk["h"], link_or_hk["k"]
        else:
            h, k = link_or_hk
        result = self._request("POST", "/v1/handshakes/redeem", {"h": h, "k": k})
        return result.get("handshake_id")

    def accept_handshake(self, handshake_id):
        """Accept a pending handshake."""
        return self._request("POST", "/v1/handshakes/accept", {"handshake_id": handshake_id})

    def list_handshakes(self):
        """List handshakes (pending and active)."""
        return self._request("GET", "/v1/handshakes")
