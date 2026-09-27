"""Clack reference client — the standard way to talk to a Clack relay.

Handles:
- Transport: curl primary (secrets via header file, never argv),
  Python fallback ONLY when the curl binary is missing/unlaunchable
- Ed25519 signing: matches relay's actual scheme (X-Clack-Scheme: 1, etc.)
- Relay identity pinning (TOFU with challenge-response) — MANDATORY,
  no bypass flag
- Fresh nonce per request; retries re-sign with a fresh nonce
- Retries only for idempotent operations; non-idempotent ops (mint,
  redeem) fail with outcome-unknown instead of blind retry
- Send validation: requires accepted:true + matching UUID
- Handshake origin verification: link's r must match relay identity,
  and the link URL's own origin must agree with r
- Human-readable errors
"""

import base64
import json
import os
import time
import urllib.parse
import uuid

from . import transport
from .signing import load_private_key, sign_headers, parse_handshake_link
from .identity import verify_relay_identity
from .errors import (
    ClackError, HandshakeRequired, LinkExpired, LinkUnusable,
    RelayUnreachable, AuthFailed, TransportUnavailable, CurlFailed,
)


def _b64u_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# curl exit codes that are never worth retrying: 60 = peer cert cannot be
# authenticated, 77 = problem with the SSL CA cert. Retrying a TLS
# failure is pointless at best and masks a MITM at worst.
_CURL_FATAL_CODES = {60, 77}


def _is_transient(exc) -> bool:
    """Is this transport failure worth one retry with a fresh signature?"""
    if isinstance(exc, RelayUnreachable):
        return True
    if isinstance(exc, CurlFailed):
        return exc.returncode not in _CURL_FATAL_CODES
    return False


class ClackClient:
    def __init__(self, relay_url, token, privkey_path, peer_name,
                 user_agent="ClackClient/1.0", timeout=30,
                 pin_file=None, auto_pin=False):
        self.relay_url = relay_url.rstrip("/")
        self.token = token
        self.peer_name = peer_name
        self.user_agent = user_agent
        self.timeout = timeout
        self._seed = load_private_key(privkey_path) if privkey_path else None
        self._pin_file = pin_file or os.path.expanduser("~/.clack/relay_pins.json")
        # Relay identity verification is MANDATORY. There is no skip flag:
        # a client that talks to an unverified relay is a credential leak.
        # First contact requires auto_pin=True (operator verified the
        # fingerprint out-of-band) — see identity.verify_relay_identity.
        self._fingerprint = verify_relay_identity(
            self.relay_url,
            user_agent=self.user_agent,
            timeout=self.timeout,
            pin_file=self._pin_file,
            auto_pin=auto_pin,
        )

    @property
    def relay_fingerprint(self):
        """The verified relay identity fingerprint (sha256:...)."""
        return self._fingerprint

    # --- Core request ---

    def _request(self, method, path, body=None, idempotent=False):
        """Signed request with fresh nonce per attempt. Returns parsed JSON.

        idempotent=True: transient transport failures are retried (up to 2
        retries) with a FRESH signature each attempt — never the same nonce
        twice. Safe for GETs, /v1/send (stable UUID dedupes server-side),
        and /v1/ack.

        idempotent=False (default): any transport failure raises immediately
        with the outcome UNKNOWN — the caller must reconcile (e.g. via
        get_receipt) before retrying. Used for mint-link and redeem, where
        a blind retry could mint a second link or burn a single-use claim.
        """
        data = json.dumps(body).encode() if body is not None else None
        url = self.relay_url + path

        last_exc = None
        for attempt in range(3):
            headers = {
                "User-Agent": self.user_agent,
                "Content-Type": "application/json",
                # Written to a 0600 header file by transport, never argv.
                "Authorization": f"Bearer {self.token}",
            }
            if self._seed:
                # Fresh signature EVERY attempt — a reused nonce is a replay.
                headers.update(sign_headers(
                    self._seed, self.peer_name, method, path, data
                ))

            try:
                status, raw = transport.request(
                    method, url, headers, data, self.timeout)
            except (RelayUnreachable, CurlFailed, TransportUnavailable) as e:
                last_exc = e
                if idempotent and _is_transient(e) and attempt < 2:
                    time.sleep(0.5 * (attempt + 1))
                    continue
                if not _is_transient(e) and not isinstance(e, TransportUnavailable):
                    raise ClackError(
                        f"Request to {path} failed ({type(e).__name__}: {e}). "
                        f"State is UNKNOWN — reconcile before retrying."
                    )
                raise
            break
        else:
            raise last_exc  # pragma: no cover — loop always breaks or raises

        try:
            payload = json.loads(raw.decode()) if raw.strip() else {}
        except Exception:
            # Malformed JSON is NEVER success — caller must handle
            raise ClackError(
                f"Relay returned malformed JSON (HTTP {status}). "
                f"State is UNKNOWN — reconcile before retrying."
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
            if code == "handshake_revoked":
                raise ClackError(
                    f"Handshake with '{body.get('to', 'unknown') if body else 'unknown'}' "
                    f"was revoked or expired. Re-establish the handshake before sending."
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
            peer = body.get("to", "unknown") if isinstance(body, dict) else "unknown"
            raise ClackError(
                f"Unknown peer '{peer}': not enrolled on this relay."
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
        Idempotent: the same msg_id is reused across retries and the relay
        dedupes on (id, sender), so a retry after a dropped connection is
        safe — but ALWAYS reconcile via get_receipt() if the outcome is
        unclear rather than assuming.
        """
        mid = msg_id or str(uuid.uuid4())
        body = {"id": mid, "to": to, "text": text}
        if topic:
            body["topic"] = topic
        if in_reply_to:
            body["in_reply_to"] = in_reply_to

        result = self._request("POST", "/v1/send", body, idempotent=True)

        # Validate acceptance — never report success without it
        if not isinstance(result, dict):
            raise ClackError("Send: unexpected response format")
        if result.get("accepted") is not True:
            raise ClackError(
                f"Send not accepted by relay: {result}. "
                f"State is UNKNOWN — reconcile before retrying."
            )
        returned_id = result.get("id")
        if not returned_id:
            raise ClackError(
                f"Send: relay accepted but returned no ID. "
                f"State is UNKNOWN — reconcile before retrying."
            )
        if returned_id != mid:
            raise ClackError(f"Send: relay returned mismatched ID {returned_id} != {mid}")

        return mid, True

    def poll(self, timeout=25):
        """Poll for messages. Returns list of message dicts."""
        result = self._request("GET", f"/v1/poll?timeout={int(timeout)}",
                               idempotent=True)
        # Handle both formats safely
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            msgs = result.get("messages", [])
            return msgs if isinstance(msgs, list) else []
        return []

    def ack(self, ids):
        """Acknowledge handled message IDs. Idempotent."""
        return self._request("POST", "/v1/ack", {"ids": ids}, idempotent=True)

    def peers(self):
        """List enrolled peer names."""
        result = self._request("GET", "/v1/peers", idempotent=True)
        if isinstance(result, dict):
            return result.get("peers", [])
        return []

    # --- Handshakes ---

    def mint_handshake_link(self):
        """Mint a handshake link. Returns the URL.

        NOT idempotent: a retry could mint a second link. Transport
        failures raise with outcome UNKNOWN — do not blind-retry.
        """
        result = self._request("POST", "/v1/handshakes/mint-link", {})
        link = result.get("link") if isinstance(result, dict) else None
        if not link:
            raise ClackError(f"mint-link did not return a link: {result}")
        return link

    def redeem_handshake(self, link_or_hk):
        """Redeem a handshake link.

        For URL inputs, verifies origin in two steps before releasing the
        claim secret:
        1. The link's r field is REQUIRED, must be valid base64url, and must
           decode to this client's relay URL. No silent fallback.
        2. The link URL's own origin (host) must agree with r's origin —
           a link minted for relay A must not arrive via relay B's domain.

        Raw {"h": ..., "k": ...} dicts are a separate trusted-caller
        interface (no origin to check — the caller constructed it).

        NOT idempotent: the claim is single-use. Transport failures raise
        with outcome UNKNOWN — reconcile via list_handshakes() before
        retrying, never blind-retry.
        """
        if isinstance(link_or_hk, str):
            parsed = parse_handshake_link(link_or_hk)
            # Origin check 1: r is REQUIRED for URL inputs.
            link_relay = parsed.get("r")
            if not link_relay:
                raise ClackError(
                    "Handshake link missing required 'r' (relay) field. "
                    "Refusing to redeem a link with unverified origin."
                )
            try:
                expected = _b64u_decode(link_relay).decode()
            except Exception:
                raise ClackError(
                    f"Handshake link 'r' field is not valid base64url: "
                    f"{link_relay[:30]}"
                )
            if expected.rstrip("/") != self.relay_url:
                raise ClackError(
                    f"Handshake link origin mismatch: link is for {expected}, "
                    f"this client is configured for {self.relay_url}. "
                    f"Refusing to forward claim to wrong relay."
                )
            # Origin check 2: the link URL's own host must agree with r.
            try:
                link_host = urllib.parse.urlsplit(
                    parsed["_base"]).netloc.lower()
                relay_host = urllib.parse.urlsplit(expected).netloc.lower()
            except Exception:
                raise ClackError("Handshake link has an unparsable URL origin")
            if not link_host or link_host != relay_host:
                raise ClackError(
                    f"Handshake link origin disagreement: link URL is served "
                    f"from {link_host or '(none)'}, but its r field names "
                    f"{relay_host or '(none)'}. Refusing."
                )
            h, k = parsed["h"], parsed["k"]
        elif isinstance(link_or_hk, dict):
            # Trusted-caller interface: no URL, no origin to verify.
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
        return self._request("GET", "/v1/handshakes", idempotent=True)

    def get_receipt(self, message_id):
        """Find the delivery receipt for a sent message.

        The relay exposes sender-visible delivery states via /v1/receipts
        (states: queued, collected, acked, expired, dead) — there is no
        per-ID endpoint, so this pages recent receipts and filters
        client-side. Raises ClackError if the message is not found.
        """
        result = self._request("GET", "/v1/receipts?limit=1000",
                               idempotent=True)
        receipts = result.get("receipts", []) if isinstance(result, dict) else []
        for r in receipts:
            if isinstance(r, dict) and r.get("id") == message_id:
                return r
        raise ClackError(
            f"No receipt found for message {message_id} in recent receipts. "
            f"The message may have expired from the retention window."
        )
