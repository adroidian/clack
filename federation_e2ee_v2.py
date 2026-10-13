#!/usr/bin/env python3
"""enc_v=2-capable federation adapter overlay (candidate-679-py-federation-v1).

ENGINEERED (not custody): ``AdapterV2`` subclasses the byte-verified v1-only
``federation_adapter.Adapter`` and overrides only the version-policy points:

- ``send`` admits ONLY exact-integer enc_v=2 native envelopes. Plaintext and
  enc_v=1 are refused: no downgrade, ever. Before any journal or wire effect,
  the envelope passes the CNS/context/authenticity gate below, and the
  configured transport endpoint plus the operator's Ed25519 federation
  attestation pin (v2 supplement, relay_attestation_pins) are bound to the
  CNS authority for the sender's relay (a mismatch fails closed before any
  client, credential, journal, or egress effect). The endpoint's pin_ref
  stays the native RSA transport identity pin, verified independently by
  ClackClient over the /v1/identity fresh-nonce proof: the two pins name
  different keys and can never share one value (Zari d8728e50).
- ``receive`` accepts ONLY enc_v=2 messages; v1/plaintext relay messages are
  skipped (never journaled, never acked by this adapter). The polled
  endpoint's URL plus its operator attestation pin are bound to the CNS
  authority for the local peer before any client/credential effect; then,
  before any cap, journal, or ACK effect, each envelope passes the
  CNS/context/authenticity gate below.
- ``reconcile`` resumes ONLY enc_v=2 durable payloads; any other stored
  version fails closed. It re-enters ``send``, so the gate applies.

The gate implements docs/e2ee-v2-protocol.md "Verification order" steps 2-5
for the adapter (step 1 is the existing shape validation; step 6, decrypt, is
owner-side; step 7 is the caller's journal-before-ACK discipline):

  2. signed ctx == observed outer transport context (id/sender/recipient/
     topic/in_reply_to);
  3. the expected sender Ed25519 verification key comes from the
     operator-pinned static supplement (never from the envelope) and the
     envelope skid agrees with BOTH that key and the CNS snapshot;
  4. the Ed25519 sender signature is REALLY verified (vendored stdlib
     Ed25519 over the custody-canonical v2 transcript);
  5. sender/recipient identity/home/generation and kid bind to the
     signed-static CNS route snapshot.

A missing CNS snapshot fails closed: static cfg routes alone never authorize
work. Exact-byte same-ID retries reconcile without re-consulting the
snapshot, so later route rotation cannot erase the durable outcome.

Journaling, partition-cap enforcement, the authority fence, grant checks,
snapshot/recheck/receive-ack discipline, and transport plumbing are inherited
unchanged from the base adapter. The base adapter remains the negative
control: an enc_v=2 send through it raises ``ValueError``.
"""
from __future__ import annotations

import base64
import hmac
import json
import os
import re
import sys
import uuid
from pathlib import Path

_REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(_REPO / "clack-client"))
from clack_client import e2ee as _ce2ee  # noqa: E402
from clack_client.envelope import native_payload, validate_message_context  # noqa: E402

import ed25519  # vendored pure-stdlib Ed25519 (see ed25519.py)  # noqa: E402
import federation_adapter as _base  # noqa: E402
import federation_cns as _cns  # noqa: E402

_ENC_V2 = 2

# Operator-curated v2 supplement: static sender verification-key pins.
# The base Adapter strictly validates the shared cfg field set, so the v2
# overlay carries its pins in this separate mode-0600 file inside state_dir
# (validated at construction; a missing/malformed file fails the adapter).
_V2_PINS_SCHEMA = "clack-federation-v2-pins/v1"
_V2_PINS_FILENAME = "v2-sender-pins.json"
# Federation attestation authority, pinned independently of the native
# transport identity: the Ed25519 relay attestation key id
# ("sha256:"+sha256(full 32-byte Ed25519 relay public key)) per relay URL.
# This is SEPARATE from the endpoint's pin_ref RSA transport identity pin
# (verified by ClackClient via the /v1/identity fresh-nonce proof). One pin
# file cannot serve both: the CNS relay_identity_key_id is an Ed25519
# digest while the native transport pin is an RSA-domain digest, so a
# single pin_ref value can never satisfy both checks (Zari d8728e50).
# The transport binding below asserts the operator's attestation pin for
# the configured endpoint URL equals the CNS snapshot's
# relay_identity_key_id; absence or disagreement fails closed before any
# client/credential/journal/egress effect.
_ATTESTATION_KEY_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
# Signed-static CNS route state, populated by the operator with
# federation_cns.load_snapshot. Read-only for the adapter; absence fails
# closed (static cfg routes alone never authorize work).
_CNS_STATE_FILENAME = "cns-routes.db"


def _b64u_32(value):
    """Strict canonical base64url decode of a pinned 32-byte key."""
    if type(value) is not str or not value:
        raise ValueError("pinned sender key must be a nonempty string")
    try:
        raw = base64.urlsafe_b64decode(
            (value + "=" * (-len(value) % 4)).encode("ascii"))
    except Exception:
        raise ValueError("pinned sender key is not base64url") from None
    if len(raw) != 32:
        raise ValueError("pinned sender key must be 32 bytes")
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
        raise ValueError("pinned sender key is not canonical base64url")
    return raw


def _verify_v2_sender_signature(enc, sender_pub32):
    """Verify the v2 envelope's Ed25519 sender signature (protocol step 4).

    Reconstructs the custody-canonical transcript with clack_client.e2ee's
    own constructors — the exact bytes decrypt_envelope_v2 verifies — and
    checks them with the vendored stdlib Ed25519 implementation. No new
    crypto construction, no private keys, no decryption. Raises
    federation_cns.CNSResolutionError (fail-closed) on any failure.
    """
    try:
        eph = _ce2ee._b64u_decode_strict(enc["eph"])
        nonce = _ce2ee._b64u_decode_strict(enc["nonce"])
        kid = _ce2ee._b64u_decode_strict(enc["kid"])
        skid = _ce2ee._b64u_decode_strict(enc["skid"])
        ct_tag = _ce2ee._b64u_decode_strict(enc["ct"])
        signature = _ce2ee._b64u_decode_strict(enc["sig"])
        aad = _ce2ee._v2_aad(enc["ctx"], eph, nonce, kid, skid)
        transcript = _ce2ee._v2_signature_transcript(aad, ct_tag)
    except Exception:
        raise _cns.CNSResolutionError(
            _cns.E2EE_V2_CONTEXT_UNTRUSTED,
            "signature transcript reconstruction failed") from None
    if not ed25519.verify(sender_pub32, signature, transcript):
        raise _cns.CNSResolutionError(
            _cns.E2EE_V2_CONTEXT_UNTRUSTED,
            "sender signature verification failed")


class AdapterV2(_base.Adapter):
    """Federation adapter that carries enc_v=2 end to end."""

    def __init__(self, config_path):
        super().__init__(config_path)
        # Boundary-2: owner authenticity needs the operator-pinned sender
        # verification keys. A missing or malformed supplement fails the
        # adapter at construction — never silently at first use. The base
        # Adapter's strict cfg field set is untouched.
        pins = _base.strict_json(
            _base.private_read(str(self.base / _V2_PINS_FILENAME)))
        _base.fields(pins, {"schema", "peer_verify_keys",
                            "relay_attestation_pins"})
        if pins["schema"] != _V2_PINS_SCHEMA:
            raise ValueError("unknown v2 pins schema")
        keyed = pins["peer_verify_keys"]
        if type(keyed) is not dict or not keyed:
            raise ValueError("v2 pins must map at least one peer")
        parsed = {}
        for peer, b64 in keyed.items():
            _base.label(peer)
            parsed[peer] = _b64u_32(b64)
        self.v2_peer_verify_keys = parsed
        # Federation attestation pins: operator-pinned Ed25519 relay
        # attestation key ids, one per relay URL. Validated at construction;
        # absence of a pin for an endpoint URL fails the transport binding
        # at use. This stays independent of the endpoint's pin_ref, which
        # remains the native RSA transport identity pin for ClackClient.
        attested = pins["relay_attestation_pins"]
        if type(attested) is not dict or not attested:
            raise ValueError("v2 pins must map at least one relay attestation")
        attest_parsed = {}
        for url, key_id in attested.items():
            if (not isinstance(url, str) or not url
                    or any(ord(c) < 32 for c in url)):
                raise ValueError("relay attestation pin needs a URL key")
            if (type(key_id) is not str
                    or _ATTESTATION_KEY_ID_RE.match(key_id) is None):
                raise ValueError(
                    "relay attestation key id must be sha256:+64 lowercase hex")
            norm = url.rstrip("/")
            if norm in attest_parsed:
                raise ValueError("duplicate relay attestation pin for URL")
            attest_parsed[norm] = key_id
        self.v2_relay_attestation_pins = attest_parsed
        self.v2_cns_state_path = str(self.base / _CNS_STATE_FILENAME)

    def _v2_cns_gate(self, enc, *, outer_id, outer_from, outer_to,
                     outer_topic, outer_in_reply_to):
        """CNS-pinned route/key/home/generation + owner-authenticity gate.

        Protocol "Verification order" steps 2-5. Raises
        federation_cns.CNSResolutionError (fail-closed, a ValueError) on any
        violation. No side effects: call before journal/egress/ACK, and skip
        for exact-byte same-ID retries.
        """
        ctx = enc["ctx"]
        # Step 2: signed context == trusted/observed outer transport context.
        if (outer_id != ctx.get("id") or outer_from != ctx.get("sender")
                or outer_to != ctx.get("recipient")
                or outer_topic != ctx.get("topic")
                or outer_in_reply_to != ctx.get("in_reply_to")):
            raise _cns.CNSResolutionError(
                _cns.E2EE_V2_CONTEXT_UNTRUSTED, "outer/inner context mismatch")
        # Steps 3-5 need the signed-static CNS snapshot. Absence fails
        # closed: static cfg routes alone never authorize work.
        state = self.v2_cns_state_path
        if not os.path.isfile(state):
            raise _cns.CNSResolutionError(
                _cns.CNS_SNAPSHOT_UNAVAILABLE, "no CNS route snapshot loaded")
        sender_route = _cns.resolve_route(state, outer_from)
        recipient_route = _cns.resolve_route(state, outer_to)
        # Owner authenticity, part 1: the envelope's claimed sender is pinned
        # by the signed CNS snapshot (identity/home/generation cannot drift).
        if (ctx.get("sender_id") != sender_route["identity"]
                or ctx.get("sender_home") != sender_route["home"]
                or ctx.get("sender_home_generation") != sender_route["generation"]):
            raise _cns.CNSResolutionError(
                _cns.E2EE_V2_CONTEXT_UNTRUSTED, "sender context != CNS route")
        # Owner authenticity, part 2: the expected sender Ed25519 key comes
        # from the operator-pinned static supplement — never from the
        # envelope — and the envelope skid must agree with BOTH that key and
        # the CNS snapshot's signing_key_id. A key is never accepted merely
        # because a signature verifies with it.
        try:
            pinned_pub = self.v2_peer_verify_keys[outer_from]
        except KeyError:
            raise _cns.CNSResolutionError(
                _cns.E2EE_V2_CONTEXT_UNTRUSTED,
                "no pinned sender verification key") from None
        if not hmac.compare_digest(_ce2ee.signing_pubkey_id(pinned_pub),
                                   _ce2ee._b64u_decode_strict(enc["skid"])):
            raise _cns.CNSResolutionError(
                _cns.E2EE_V2_CONTEXT_UNTRUSTED, "skid != pinned sender key id")
        if enc["skid"] != sender_route["signing_key_id"]:
            raise _cns.CNSResolutionError(
                _cns.E2EE_V2_CONTEXT_UNTRUSTED, "skid != CNS signing_key_id")
        # Owner authenticity, part 3: real Ed25519 signature verification.
        _verify_v2_sender_signature(enc, pinned_pub)
        # Recipient binding against the CNS recipient route.
        if (ctx.get("recipient_id") != recipient_route["identity"]
                or ctx.get("recipient_home") != recipient_route["home"]
                or ctx.get("recipient_home_generation") != recipient_route["generation"]):
            raise _cns.CNSResolutionError(
                _cns.E2EE_V2_CONTEXT_UNTRUSTED, "recipient context != CNS route")
        if enc["kid"] != recipient_route["encryption_key_id"]:
            raise _cns.CNSResolutionError(
                _cns.E2EE_V2_CONTEXT_UNTRUSTED, "kid != CNS encryption_key_id")
        return sender_route, recipient_route

    def _v2_transport_binding(self, endpoint_name, cns_route):
        """Bind the configured transport endpoint and attestation pin to the
        CNS authority.

        The wire must terminate at the relay the signed CNS snapshot names
        for the relevant party: a statically configured endpoint URL the
        snapshot disagrees with must never carry traffic. The relay's
        Ed25519 federation attestation key — operator-pinned per relay URL
        in the v2 supplement (relay_attestation_pins) — must equal the
        snapshot's relay_identity_key_id for that route. This pin is
        deliberately INDEPENDENT of the endpoint's pin_ref, which remains
        the native RSA transport identity pin verified by ClackClient over
        the /v1/identity fresh-nonce proof: the two pins name different
        keys (Ed25519 attestation vs RSA transport identity) and can never
        share one value (Zari d8728e50).

        Raises federation_cns.CNSResolutionError (fail-closed, a
        ValueError) on any mismatch. No side effects: call BEFORE any
        client/credential, journal, or egress effect. The static cfg
        topology is preserved; it is verified against authority, not
        redirected.
        """
        ep = self.cfg["endpoints"][endpoint_name]
        configured_url = ep["url"].rstrip("/")
        cns_url = cns_route["relay_endpoint"].rstrip("/")
        if configured_url != cns_url:
            raise _cns.CNSResolutionError(
                _cns.RELAY_PIN_MISMATCH,
                "configured endpoint %s != CNS relay_endpoint %s"
                % (configured_url, cns_url))
        attested = self.v2_relay_attestation_pins.get(configured_url)
        if (not isinstance(attested, str)
                or not hmac.compare_digest(
                    attested, cns_route["relay_identity_key_id"])):
            raise _cns.CNSResolutionError(
                _cns.RELAY_PIN_MISMATCH,
                "operator attestation pin != CNS relay_identity_key_id")

    def send(self, grant, msg_id, text=None, *, enc=None, enc_v=None,
             topic=None, in_reply_to=None):
        # No-downgrade policy: plaintext and v1 are refused outright.
        if text is not None:
            raise ValueError("v2 adapter refuses plaintext")
        if type(enc_v) is not int or enc_v != _ENC_V2:
            raise ValueError("v2 adapter requires enc_v=2")
        topic, in_reply_to = validate_message_context(topic, in_reply_to)
        if grant not in self.cfg["routes"]:
            raise ValueError("unmapped grant")
        if str(uuid.UUID(msg_id)) != msg_id:
            raise ValueError("stable UUID required")
        # native_payload owns the hostile-object boundary: exact-int version,
        # exact field set/algorithm per version, shape, and size.
        enc_raw = native_payload(enc, _ENC_V2)
        enc = json.loads(enc_raw)  # immutable caller snapshot before journal/action
        if enc["v"] != _ENC_V2:  # native_payload already guarantees this
            raise ValueError("v2 adapter requires enc_v=2")
        text = enc_raw  # storage contract: canonical envelope JSON + enc_v=2
        enc_v = _ENC_V2
        route = self.cfg["routes"][grant]  # grant membership checked above
        send_peer = self.cfg["endpoints"][route["send_endpoint"]]["peer"]
        a = self.authority
        # Stable-ID retry: an identical (grant, payload) retry must still
        # pass the CNS/transport gate UNLESS durable proof exists that the
        # gate already ran for this message. A reservation row is that
        # proof: authority.action() creates it, and action() is only
        # reachable after the gate passed in this same send() flow. A bare
        # runtime_payloads row (interrupted between payload commit and
        # reservation) proves nothing — the CNS authority's pin/endpoint
        # may have drifted since, so the gate MUST be re-run with current
        # data before any client/credential/transport effect. Completed
        # same-ID retries (reservation + terminal outbox) still reconcile
        # without re-consulting the snapshot: action() returns the durable
        # outcome and performs no wire, so route rotation cannot erase it.
        # Read-only; the write block below re-checks.
        with a.authority_lock():
            c = a._connect()
            try:
                replay_row = c.execute(
                    "SELECT grant_id,text,enc_v FROM runtime_payloads WHERE msg_id=?",
                    (msg_id,)).fetchone()
                gate_proven = (
                    replay_row is not None
                    and c.execute(
                        "SELECT 1 FROM reservations WHERE msg_id=?",
                        (msg_id,)).fetchone() is not None
                )
            finally:
                c.close()
        if replay_row is not None:
            if replay_row != (grant, text, enc_v):
                raise ValueError("stable ID payload or grant changed")
        if not gate_proven:
            # Hostile envelope and CNS authority are validated FIRST: no
            # durable mutation — cap enforcement included — may precede the
            # authenticity gate. Boundary-2 egress gate: CNS-pinned
            # route/key/home/generation, owner authenticity (real
            # sender-signature verification), and outer/inner context
            # equality — BEFORE any durable or wire effect. Raises
            # ValueError (fail-closed) on any violation.
            sender_route, _recipient_route = self._v2_cns_gate(
                enc,
                outer_id=msg_id,
                outer_from=send_peer,
                outer_to=route["to"],
                outer_topic=topic,
                outer_in_reply_to=in_reply_to,
            )
            # Transport-authority seam: the actual wire endpoint and the
            # operator's Ed25519 attestation pin must be the ones the CNS
            # authority names for the sender's relay — BEFORE any
            # client/credential/journal/egress effect.
            self._v2_transport_binding(route["send_endpoint"], sender_route)
        with a.authority_lock():
            c = a._connect()
            try:
                a._begin(c)
                row = c.execute("SELECT grant_id,text,enc_v FROM runtime_payloads WHERE msg_id=?", (msg_id,)).fetchone()
                if row is not None and row != (grant, text, enc_v):
                    raise ValueError("stable ID payload or grant changed")
                c.execute("INSERT OR IGNORE INTO runtime_payloads(msg_id,grant_id,text,enc_v) VALUES (?,?,?,?)", (msg_id, grant, text, enc_v))
                c.execute("COMMIT")
            except Exception:
                a._rollback_quiet(c)
                raise
            finally:
                c.close()
        context_kwargs = {}
        if topic is not None:
            context_kwargs["topic"] = topic
        if in_reply_to is not None:
            context_kwargs["in_reply_to"] = in_reply_to

        def transport(mid, body):
            try:
                returned, accepted = self.client(route["send_endpoint"]).send(
                    route["to"], msg_id=mid, enc=json.loads(enc_raw),
                    enc_v=_ENC_V2, required_enc_v=_ENC_V2, **context_kwargs)
                if returned != mid or accepted is not True:
                    return {"transport_parse_error": True}
                return {"accepted": True}
            except Exception:
                # Never persist raw client exception strings or response bodies.
                raise RuntimeError("transport outcome unknown; reconcile stable ID") from None
        # Trusted-clock cap enforcement at the final action fence: only after
        # the hostile envelope and CNS authority are validated. The
        # authority's own action() re-evaluates the cap inside its final
        # serialized decision boundary regardless.
        self.enforce_cap(grant)
        outcome, _ = a.action(grant, msg_id, text, transport=transport)
        return {"id": msg_id, "outcome": outcome, "enc_v": _ENC_V2,
                "proof_only": self.cfg["proof_only"]}

    def receive(self, endpoint):
        # v2-only: relay messages that are not exactly enc_v=2 are skipped.
        if endpoint not in self.cfg["endpoints"]:
            raise ValueError("unmapped endpoint")
        # Transport-authority seam, shared with send: the polled endpoint's
        # URL and operator attestation pin must be the ones the CNS authority
        # names for the local peer — BEFORE any client/credential effect.
        # Absence or mismatch fails closed: an unverified relay is never
        # polled.
        local_peer = self.cfg["endpoints"][endpoint]["peer"]
        state = self.v2_cns_state_path
        if not os.path.isfile(state):
            raise _cns.CNSResolutionError(
                _cns.CNS_SNAPSHOT_UNAVAILABLE, "no CNS route snapshot loaded")
        self._v2_transport_binding(endpoint, _cns.resolve_route(state, local_peer))
        try:
            messages = self.client(endpoint).poll(timeout=0)
        except Exception:
            raise RuntimeError("receive transport unavailable") from None
        a = self.authority
        accepted = []
        for message in messages:
            if type(message) is not dict or not isinstance(message.get("id"), str):
                continue
            try:
                if str(uuid.UUID(message["id"])) != message["id"]:
                    continue
            except ValueError:
                continue
            grant = next((g for g, r in self.cfg["routes"].items() if r["receive_endpoint"] == endpoint and r["from"] == message.get("from")), None)
            if grant is None:
                continue
            enc_v = message.get("enc_v", 0)
            if type(enc_v) is not int or enc_v != _ENC_V2:
                continue  # no v1/plaintext downgrade acceptance
            try:
                topic, in_reply_to = validate_message_context(
                    message.get("topic"), message.get("in_reply_to"))
            except ValueError:
                continue
            if not isinstance(message.get("text"), str) or len(message["text"].encode()) > 65536:
                continue
            try:
                enc = json.loads(native_payload(_base.strict_json(message["text"]), _ENC_V2))
            except (ValueError, TypeError):
                continue
            outer_to = message.get("to", self.cfg["endpoints"][endpoint]["peer"])
            if outer_to != self.cfg["endpoints"][endpoint]["peer"]:
                continue
            # Exact-byte same-ID retry: the durable outcome already exists, so
            # reconcile it without re-consulting the snapshot — later route
            # rotation must not erase it. This read is effect-free.
            stable = {k: message.get(k) for k in ("id", "from", "text", "sent_at", "expires_at")}
            stable["topic"] = topic
            stable["in_reply_to"] = in_reply_to
            stable["enc_v"] = _ENC_V2
            if "to" in message:
                stable["to"] = message["to"]
            payload = json.dumps(stable, sort_keys=True)
            with a.authority_lock():
                c = a._connect()
                try:
                    old = c.execute(
                        "SELECT grant_id,payload FROM runtime_inbox WHERE endpoint=? AND msg_id=?",
                        (endpoint, message["id"])).fetchone()
                finally:
                    c.close()
            if old is not None and old != (grant, payload):
                continue  # same-ID collision: refuse, zero effects
            if old is None:
                # Boundary-2 gate: CNS-pinned route/key/home/generation,
                # owner authenticity (real sender-signature verification),
                # and outer/inner context equality — BEFORE cap, journal,
                # or ACK. Any violation skips with zero effects.
                try:
                    self._v2_cns_gate(
                        enc,
                        outer_id=message["id"],
                        outer_from=message["from"],
                        outer_to=outer_to,
                        outer_topic=topic,
                        outer_in_reply_to=in_reply_to,
                    )
                except _cns.CNSResolutionError:
                    continue
            self.enforce_cap(grant)
            with a.authority_lock():
                c = a._connect()
                try:
                    a._begin(c)
                    a._enforce_cap_in_transaction(c, grant)
                    c.execute("COMMIT")
                    a._begin(c)
                    g = a._grant_row(c, grant)
                    if not g or g[2] != "OK" or g[3] is not None:
                        c.execute("ROLLBACK")
                        continue
                    old = c.execute("SELECT grant_id,payload FROM runtime_inbox WHERE endpoint=? AND msg_id=?", (endpoint, message["id"])).fetchone()
                    if old is not None and old != (grant, payload):
                        c.execute("ROLLBACK")
                        continue
                    c.execute("INSERT OR IGNORE INTO runtime_inbox VALUES (?,?,?,?,?)", (endpoint, message["id"], grant, g[1], payload))
                    c.execute("COMMIT")  # durable local acceptance BEFORE relay ack
                    try:
                        ack = self.client(endpoint).ack([message["id"]])
                        if (type(ack) is not dict or not isinstance(ack.get("acked"), list)
                                or not isinstance(ack.get("already_acked"), list)
                                or message["id"] not in ack["acked"] + ack["already_acked"]):
                            raise RuntimeError("relay did not confirm acknowledgement")
                    except Exception:
                        raise RuntimeError("receive persisted; ack uncertain, retry receive") from None
                    accepted.append(message["id"])
                except Exception:
                    a._rollback_quiet(c)
                    raise
                finally:
                    c.close()
        return {"accepted_ids": accepted, "enc_v": _ENC_V2,
                "proof_only": self.cfg["proof_only"]}

    def reconcile(self):
        # v2-only: any durable payload that is not exactly enc_v=2 fails closed.
        a = self.authority
        with a.authority_lock():
            c = a._connect()
            try:
                rows = c.execute("SELECT r.res_id,r.state,p.grant_id,p.msg_id,p.text,p.enc_v FROM runtime_payloads p LEFT JOIN reservations r ON p.msg_id=r.msg_id AND p.grant_id=r.grant_id LEFT JOIN outbox o ON o.msg_id=p.msg_id WHERE (r.state IS NULL OR r.state IN ('inflight','failed-unknown','retry','reserved')) AND (o.state IS NULL OR o.state NOT IN ('sent','released')) AND NOT EXISTS (SELECT 1 FROM ndrs n WHERE n.msg_id=p.msg_id)").fetchall()
            finally:
                c.close()
        results = []
        for res_id, state, grant, mid, text, enc_v in rows:
            if type(enc_v) is not int or enc_v != _ENC_V2:
                raise ValueError("v2 reconcile refuses non-v2 durable payload")
            enc_raw = native_payload(_base.strict_json(text), _ENC_V2)
            enc_obj = json.loads(enc_raw)
            kwargs = {"enc": enc_obj, "enc_v": enc_v}
            # Retain the signed topic/reply context: the durable envelope
            # carries the authoritative ctx, and the send() CNS gate
            # requires outer/inner context equality. Without this, a
            # bare-payload retry via reconcile would fail the gate on
            # context mismatch even when the CNS authority is unchanged.
            _ctx = enc_obj.get("ctx") or {}
            if _ctx.get("topic") is not None:
                kwargs["topic"] = _ctx["topic"]
            if _ctx.get("in_reply_to") is not None:
                kwargs["in_reply_to"] = _ctx["in_reply_to"]
            if res_id is None:
                results.append(self.send(grant, mid, **kwargs))
                continue
            current = a.reservation_row(res_id)
            if current["state"] == "inflight":
                a.reconcile_inflight(res_id)
            current = a.reservation_row(res_id)
            if current["state"] == "failed-unknown":
                try:
                    a.schedule_retry(res_id)
                except a.ReservationError:
                    pass  # re-read/action fence resolves concurrent completion
            results.append(self.send(grant, mid, **kwargs))
        return results
