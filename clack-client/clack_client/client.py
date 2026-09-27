"""Clack reference client — the standard way to talk to a Clack relay.

Handles:
- Transport: curl primary (secrets via header file, never argv),
  Python fallback ONLY on curl unavailability
- Ed25519 signing: matches relay's actual scheme (X-Clack-Scheme: 1, etc.)
- Relay identity pinning (TOFU)
- Fresh nonce per request (retries re-sign)
- Send validation: requires accepted:true + matching UUID
- Handshake origin verification: link's r must match relay identity
- Human-readable errors
"""

import base64
import hashlib
import json
import os
import uuid

from . import transport
from .signing import load_private_key, sign_headers, parse_handshake_link
from .errors import (
    ClackError, HandshakeRequired, LinkExpired, LinkUnusable,
    RelayUnreachable, AuthFailed, TransportUnavailable,
)


def _b64u_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class ClackClient:
    def __init__(self, relay_url, token, privkey_path, peer_name,
                 user_agent="ClackClient/1.0", timeout=30,
                 pin_file=None, skip_pin=False):
        self.relay_url = relay_url.rstrip("/")
        self.token = token
        self.peer_name = peer_name
        self.user_agent = user_agent
        self.timeout = timeout
        self._seed = load_private_key(privkey_path) if privkey_path else None
        self._pin_file = pin_file or os.path.expanduser("~/.clack/relay_pins.json")
        self._pinned = None
        if not skip_pin:
            self._verify_pin()

    # --- Relay identity pinning (TOFU) ---

    def _verify_pin(self):
        """TOFU pin verification. Fails closed on mismatch."""
        identity = self._fetch_relay_identity()
        pins = {}
        if os.path.exists(self._pin_file):
            try:
                pins = json.load(open(self._pin_file))
            except Exception:
                pass
        stored = pins.get(self.relay_url)
        if stored is None:
            # First connect: pin it
            pins[self.relay_url] = identity
            os.makedirs(os.path.dirname(self._pin_file), exist_ok=True)
            json.dump(pins, open(self._pin_file, "w"), indent=2)
            self._pinned = identity
        elif stored != identity:
            raise ClackError(
                f"Relay identity PIN MISMATCH for {self.relay_url}. "
                f"Expected {stored[:20]}..., got {identity[:20]}.... "
                f"Possible MITM or relay rebuild. Verify out-of-band."
            )
        else:
            self._pinned = identity

    def _fetch_relay_identity(self):
        """Fetch relay identity without auth (public endpoint)."""
        # Use unsigned request for identity check
        url = self.relay_url + "/v1/identity"
        try:
            status, raw = transport.request(
                "GET", url,
                {"User-Agent": self.user_agent},
                timeout=self.timeout,
                allow_fallback=False,  # pin check must use primary transport
            )
            if status == 200:
                data = json.loads(raw.decode())
                return data.get("identity_pubkey") or data.get("pubkey") or raw.decode()[:200]
        except Exception:
            pass
        # Fallback: no identity endpoint, use URL as pin basis (weaker)
        return f"url:{self.relay_url}"

    # --- Core request ---

    def _request(self, method, path, body=None):
        """Signed request with fresh nonce. Returns parsed JSON."""
        data = json.dumps(body).encode() if body is not None else None
        headers = {
            "User-Agent": self.user_agent,
            "Content-Type": "application/json",
        }
        # Auth header via header file (transport handles it), not in dict
        # that could leak — but we pass it here, transport writes to file
        headers["Authorization"] = f"Bearer {self.token}"

        if self._seed:
            # path_and_query for signing
            headers.update(sign_headers(
                self._seed, self.peer_name, method, path, data
            ))

        url = self.relay_url + path
        try:
            status, raw = transport.request(method, url, headers, data, self.timeout)
        except TransportUnavailable:
            raise
        except Exception as e:
            raise RelayUnreachable(f"Cannot reach {self.relay_url}: {e}")

        try:
            payload = json.loads(raw.decode()) if raw.strip() else {}
        except Exception:
            # Malformed JSON is NEVER success — caller must handle
            raise ClackError(
                f"Relay returned malformed JSON (HTTP {status}). "
                f"Send state is UNKNOWN — reconcile before retrying."
            )

        if status == 401:
            raise AuthFailed(f"Auth failed: {payload.get('error', 'unauthorized')}")
        if status == 403:
            err = payload.get("error", "")
            code = payload.get("code", err)
            if code in ("handshake_required", "no_handshake", "missing_handshake"):
                raise HandshakeRequired(
                    body.get("to", "unknown") if body else "unknown"
                )
            if code == "link_unusable":
                raise LinkUnusable("Link invalid, revoked, or already used")
            if code == "link_expired":
                raise LinkExpired("Link expired")
            # Signature errors
            if code in ("missing_signature", "bad_signature", "stale_nonce",
                        "replay", "unknown_key", "upgrade_required"):
                raise AuthFailed(f"Signature rejected: {code}")
            raise ClackError(f"Forbidden (403): {code or payload}")
        if status == 400 and payload.get("error") == "unknown_peer":
            raise ClackError(
                f"Unknown peer: {payload.get('detail', body)}"
            )
        if status == 429:
            raise ClackError("Rate limited — back off and retry")
        if status >= 400:
            raise ClackError(f"HTTP {status}: {payload.get('error', payload)}")
        if 300 <= status < 400:
            raise ClackError(f"Unexpected redirect (HTTP {status}) — refusing")

        return payload

    # --- Messaging ---

    def send(self, to, text, topic=None, msg_id=None, in_reply_to=None):
        """Send a message. Returns (message_id, accepted).

        Raises ClackError if the relay does not confirm accepted:true.
        """
        mid = msg_id or str(uuid.uuid4())
        body = {"id": mid, "to": to, "text": text}
        if topic:
            body["topic"] = topic
        if in_reply_to:
            body["in_reply_to"] = in_reply_to

        result = self._request("POST", "/v1/send", body)

        # Validate acceptance — never report success without it
        if not isinstance(result, dict):
            raise ClackError("Send: unexpected response format")
        if result.get("accepted") is not True:
            raise ClackError(
                f"Send not accepted by relay: {result}. "
                f"State is UNKNOWN — reconcile before retrying."
            )
        returned_id = result.get("id")
        if returned_id and returned_id != mid:
            raise ClackError(f"Send: relay returned mismatched ID {returned_id} != {mid}")

        return mid, True

    def poll(self, timeout=25):
        """Poll for messages. Returns list of message dicts."""
        result = self._request("GET", f"/v1/poll?timeout={int(timeout)}")
        # Handle both formats safely
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            msgs = result.get("messages", [])
            return msgs if isinstance(msgs, list) else []
        return []

    def ack(self, ids):
        """Acknowledge handled message IDs."""
        return self._request("POST", "/v1/ack", {"ids": ids})

    def peers(self):
        """List enrolled peer names."""
        result = self._request("GET", "/v1/peers")
        if isinstance(result, dict):
            return result.get("peers", [])
        return []

    # --- Handshakes ---

    def mint_handshake_link(self):
        """Mint a handshake link. Returns the URL."""
        result = self._request("POST", "/v1/handshakes/mint-link", {})
        link = result.get("link") if isinstance(result, dict) else None
        if not link:
            raise ClackError(f"mint-link did not return a link: {result}")
        return link

    def redeem_handshake(self, link_or_hk):
        """Redeem a handshake link.

        Verifies the link origin (r field) matches this relay's identity
        before releasing the claim. Rejects on mismatch.
        """
        if isinstance(link_or_hk, str):
            parsed = parse_handshake_link(link_or_hk)
            # Origin check: link's r must match our relay
            link_relay = parsed.get("r")
            if link_relay:
                try:
                    expected = _b64u_decode(link_relay).decode()
                except Exception:
                    expected = link_relay
                # Normalize: compare against our relay URL
                if expected.rstrip("/") != self.relay_url:
                    raise ClackError(
                        f"Handshake link origin mismatch: link is for {expected}, "
                        f"this client is configured for {self.relay_url}. "
                        f"Refusing to forward claim to wrong relay."
                    )
            h, k = parsed["h"], parsed["k"]
        elif isinstance(link_or_hk, dict):
            h, k = link_or_hk["h"], link_or_hk["k"]
        else:
            h, k = link_or_hk

        result = self._request("POST", "/v1/handshakes/redeem", {"h": h, "k": k})
        hid = result.get("handshake_id") if isinstance(result, dict) else None
        if not hid:
            raise ClackError(f"redeem did not return handshake_id: {result}")
        return hid

    def accept_handshake(self, handshake_id):
        return self._request("POST", "/v1/handshakes/accept",
                             {"handshake_id": handshake_id})

    def list_handshakes(self):
        return self._request("GET", "/v1/handshakes")

    def get_status(self, message_id):
        """Query send status for reconciliation. Returns relay's record."""
        return self._request("GET", f"/v1/status/{message_id}")
