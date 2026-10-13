"""Candidate-679 enc_v2 policy tests (ENGINEERED, not custody).

Proves the candidate's real enc_v2 operational path against the candidate
relay.py and the candidate client, with focused negative controls:

- v2 envelope accepted on /v1/send, stored enc_v=2, returned on poll.
- v1 and plaintext paths unchanged (regression).
- Strict rejection intact: bool/float/str/future envelope versions rejected;
  no client-supplied enc_v marker is honored (version derived from the
  validated envelope).
- No downgrade of the enc_v{0,1} handshake advertisement gate:
  minter_enc_v/redeemer_enc_v still reject 2/True/1.0.
- Negative control: enc_v=2 through the v1-only federation_adapter fails.
- AdapterV2 carries enc_v=2 end to end and refuses plaintext/v1 downgrade.

Run: python3 -m unittest discover -s tests -p "test_candidate_679*" -v
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import sqlite3
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "clack-client"))

from clack_client import e2ee as ce2ee  # noqa: E402
from clack_client.envelope import native_payload  # noqa: E402
import ed25519  # noqa: E402  (vendored; CNS snapshot signing in fixtures)
import federation_cns as cns  # noqa: E402


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def import_relay(base):
    with mock.patch.dict(os.environ, {"CLACK_RELAY_BASE": str(base)}):
        spec = importlib.util.spec_from_file_location(
            "relay_cand679_" + uuid.uuid4().hex, ROOT / "relay.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


def load_relay(base):
    module = import_relay(base)
    cfg = {"peers": {"alice": "tok-a", "bob": "tok-b"}}
    module.init_db(cfg)
    module.relay_cfg = cfg
    return module


def make_v2_envelope(mid, sender_seed, recipient_seed, sender="peer-x",
                     recipient="peer-y", topic="task.v2", reply=None):
    import nacl.signing

    recipient_x = ce2ee.x25519_scalarmult(
        ce2ee.ed25519_seed_to_x25519_priv(recipient_seed),
        ce2ee._X25519_BASE,
    )
    # The CNS snapshot pins these exact identity/home/generation values;
    # sender/recipient names select the pinned row.
    context = ce2ee.make_context(
        message_id=mid,
        sender=sender,
        recipient=recipient,
        sender_id=V2_PEERS[sender]["identity"],
        recipient_id=V2_PEERS[recipient]["identity"],
        topic=topic,
        in_reply_to=reply,
        sender_home=V2_PEERS[sender]["home"],
        recipient_home=V2_PEERS[recipient]["home"],
        sender_home_generation=V2_PEERS[sender]["generation"],
        recipient_home_generation=V2_PEERS[recipient]["generation"],
    )
    return ce2ee.encrypt_envelope_v2(
        sender_seed, recipient_x, b"candidate-679 v2 payload", context
    )


# --- v2 fixture identities: the CNS snapshot pins these exact values ---
V2_PEERS = {
    "peer-x": {"identity": "agent://peer-x", "home": "clack://home-x",
               "generation": 7},
    "peer-y": {"identity": "agent://peer-y", "home": "clack://home-y",
               "generation": 11},
}


def _cns_peer_route(peer, seed, relay_endpoint, relay_identity_key_id):
    """One CNS route row whose key ids match the fixture keypair.

    relay_endpoint/relay_identity_key_id name the peer's relay per the
    signed CNS authority; the adapter binds its configured transport to
    these values before any client/credential/journal/egress effect.
    """
    import nacl.signing

    pub = bytes(nacl.signing.SigningKey(seed).verify_key)
    x_pub = ce2ee.x25519_scalarmult(
        ce2ee.ed25519_seed_to_x25519_priv(seed), ce2ee._X25519_BASE)
    return {
        "peer": peer,
        "identity": V2_PEERS[peer]["identity"],
        "owner": "Owner of %s" % peer,
        "prime_relay": "prime-relay",
        "home": V2_PEERS[peer]["home"],
        "relay_endpoint": relay_endpoint,
        "relay_identity_key_id": relay_identity_key_id,
        "generation": V2_PEERS[peer]["generation"],
        "signing_key_id": b64u(hashlib.sha256(pub).digest()[:8]),
        "encryption_key_id": b64u(hashlib.sha256(x_pub).digest()[:8]),
    }


def _cns_sign_snapshot(snap, seed):
    body = {k: v for k, v in snap.items() if k != "signature"}
    pub = ed25519._publickey(seed)
    body["issuer_key_id"] = "sha256:" + hashlib.sha256(pub).hexdigest()
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False, allow_nan=False).encode()
    sig = ed25519.sign(seed, cns.SIGNING_DOMAIN + raw)
    snap = dict(body)
    snap["signature"] = {"alg": "Ed25519", "key_id": body["issuer_key_id"],
                         "value": b64u(sig)}
    return snap


def _cns_snapshot_doc(routes, authority_seed):
    snap = {
        "schema": "clack-cns-route-snapshot/v1",
        "version": 1,
        "snapshot_id": str(uuid.uuid4()),
        "issuer": "candidate-679-test-cns",
        "issuer_key_id": "",  # filled by _cns_sign_snapshot
        "sequence": 7,
        "issued_at": int(time.time()) - 60,
        "expires_at": int(time.time()) + 3600,
        "routes": sorted(routes,
                         key=lambda r: (r["identity"].encode(),
                                        r["peer"].encode())),
        "signature": {},
    }
    return _cns_sign_snapshot(snap, authority_seed)


def make_v1_envelope():
    return {
        "v": 1,
        "alg": "x25519-chacha20poly1305",
        "eph": b64u(bytes([1]) * 32),
        "nonce": b64u(bytes([2]) * 12),
        "kid": b64u(bytes([3]) * 8),
        "ct": b64u(bytes([4]) * 32),
    }


class RelayEncV2PolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cand679-relay-", dir="/tmp")
        self.addCleanup(self.temp.cleanup)
        self.relay = load_relay(Path(self.temp.name))
        self.addCleanup(self.relay.conn.close)
        now = time.time()
        a, b = self.relay._hs_pair("alice", "bob")
        self.relay.conn.execute("DELETE FROM handshakes")
        self.relay.conn.execute(
            "INSERT INTO handshakes(a_identity,b_identity,status,created_at,"
            "last_activity) VALUES(?,?,'active',?,?)",
            (a, b, now, now),
        )
        self.relay.conn.commit()
        self.sender_seed = os.urandom(32)
        self.recipient_seed = os.urandom(32)

    def post(self, body, peer="alice"):
        handler = self.relay.Handler.__new__(self.relay.Handler)
        handler.path = "/v1/send"
        handler._require_auth = lambda: peer
        handler._read_json = lambda: body
        replies = []
        handler._json = lambda status, payload: replies.append((status, payload))
        with mock.patch.object(self.relay, "sweep"), mock.patch.object(
            self.relay, "maybe_notify"
        ):
            handler.do_POST()
        self.assertTrue(replies)
        return replies[-1]

    def poll(self, peer="bob"):
        handler = self.relay.Handler.__new__(self.relay.Handler)
        handler.path = "/v1/poll?timeout=0"
        handler._require_auth = lambda: peer
        replies = []
        handler._json = lambda status, payload: replies.append((status, payload))
        with mock.patch.object(self.relay, "sweep"), mock.patch.object(
            self.relay, "maybe_notify"
        ):
            handler.do_GET()
        self.assertTrue(replies)
        return replies[-1]

    def stored_enc_v(self, mid):
        row = self.relay.conn.execute(
            "SELECT enc_v FROM messages WHERE id=?", (mid,)
        ).fetchone()
        return row[0] if row else None

    # --- positive: real enc_v=2 operational path ---

    def test_v2_envelope_accepted_stored_and_polled_as_enc_v2(self):
        mid = str(uuid.uuid4())
        enc = make_v2_envelope(mid, self.sender_seed, self.recipient_seed)
        status, payload = self.post({"id": mid, "to": "bob", "enc": enc})
        self.assertEqual(status, 200, payload)
        self.assertTrue(payload["accepted"])
        self.assertEqual(self.stored_enc_v(mid), 2)
        # The stored text is the canonical envelope JSON; the relay never decrypts.
        text = self.relay.conn.execute(
            "SELECT text FROM messages WHERE id=?", (mid,)
        ).fetchone()[0]
        self.assertEqual(json.loads(text)["v"], 2)
        status, payload = self.poll("bob")
        self.assertEqual(status, 200)
        msgs = payload["messages"] if isinstance(payload, dict) else payload
        got = [m for m in msgs if m["id"] == mid]
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["enc_v"], 2)

    def test_v2_round_trip_decrypts_owner_side(self):
        import nacl.signing

        mid = str(uuid.uuid4())
        plaintext = b"duplex v2 ownership proof"
        recipient_x = ce2ee.x25519_scalarmult(
            ce2ee.ed25519_seed_to_x25519_priv(self.recipient_seed),
            ce2ee._X25519_BASE,
        )
        context = ce2ee.make_context(
            message_id=mid, sender="alice", recipient="bob",
            sender_id="agent://alice", recipient_id="agent://bob",
            topic="task.v2", in_reply_to=None,
            sender_home="clack://home-a", recipient_home="clack://home-b",
            sender_home_generation=3, recipient_home_generation=5,
        )
        enc = ce2ee.encrypt_envelope_v2(
            self.sender_seed, recipient_x, plaintext, context)
        status, _ = self.post({"id": mid, "to": "bob", "enc": enc})
        self.assertEqual(status, 200)
        sender_pub = bytes(nacl.signing.SigningKey(self.sender_seed).verify_key)
        # Recipient verifies sender/context and decrypts from the stored bytes.
        stored = json.loads(self.relay.conn.execute(
            "SELECT text FROM messages WHERE id=?", (mid,)).fetchone()[0])
        recovered = ce2ee.decrypt_envelope_v2(
            self.recipient_seed, stored, sender_pub, context)
        self.assertEqual(recovered, plaintext)

    def test_v1_envelope_still_accepted_as_enc_v1(self):
        mid = str(uuid.uuid4())
        status, payload = self.post({"id": mid, "to": "bob", "enc": make_v1_envelope()})
        self.assertEqual(status, 200, payload)
        self.assertEqual(self.stored_enc_v(mid), 1)

    def test_plaintext_still_stored_as_enc_v0(self):
        mid = str(uuid.uuid4())
        status, payload = self.post({"id": mid, "to": "bob", "text": "plain"})
        self.assertEqual(status, 200, payload)
        self.assertEqual(self.stored_enc_v(mid), 0)

    # --- strict rejection: no client-controlled version marker ---

    def test_body_enc_v_marker_is_ignored_version_comes_from_envelope(self):
        mid = str(uuid.uuid4())
        # A hostile body marker must not change the stored version: the relay
        # derives enc_v from the validated envelope only.
        status, _ = self.post(
            {"id": mid, "to": "bob", "enc": make_v1_envelope(), "enc_v": 99})
        self.assertEqual(status, 200)
        self.assertEqual(self.stored_enc_v(mid), 1)

    def test_non_integer_envelope_versions_rejected(self):
        for bad_v in (True, False, 1.0, 2.0, "1", "2", None, [2], 0, 3, 99):
            mid = str(uuid.uuid4())
            enc = make_v1_envelope()
            enc["v"] = bad_v
            status, payload = self.post({"id": mid, "to": "bob", "enc": enc})
            self.assertEqual(status, 400, (bad_v, payload))
            self.assertEqual(payload["error"], "bad_envelope")
            self.assertIsNone(self.stored_enc_v(mid))

    def test_v2_envelope_with_bad_shape_rejected(self):
        mid = str(uuid.uuid4())
        enc = make_v2_envelope(mid, self.sender_seed, self.recipient_seed)
        enc["sig"] = b64u(bytes([6]) * 32)  # 32 bytes, must be 64
        status, payload = self.post({"id": mid, "to": "bob", "enc": enc})
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "bad_envelope")

    def test_v2_envelope_with_extra_field_rejected(self):
        mid = str(uuid.uuid4())
        enc = make_v2_envelope(mid, self.sender_seed, self.recipient_seed)
        enc["unexpected"] = "field"
        status, payload = self.post({"id": mid, "to": "bob", "enc": enc})
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "bad_envelope")

    def test_v2_envelope_with_wrong_alg_rejected(self):
        mid = str(uuid.uuid4())
        enc = make_v2_envelope(mid, self.sender_seed, self.recipient_seed)
        enc["alg"] = "x25519-chacha20poly1305"  # v1 alg on a v2 envelope
        status, payload = self.post({"id": mid, "to": "bob", "enc": enc})
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "bad_envelope")

    # --- no downgrade of the enc_v{0,1} handshake advertisement gate ---

    def test_handshake_enc_v_gate_still_strict(self):
        self.assertTrue(self.relay._is_strict_enc_v(0))
        self.assertTrue(self.relay._is_strict_enc_v(1))
        for bad in (2, True, False, 1.0, 0.0, "1", None):
            self.assertFalse(self.relay._is_strict_enc_v(bad), bad)

    # --- boundary-1: encrypted branches run the shared TTL/reply checks ---
    # Mercedes reproduction: a valid v1 envelope + ttl=-1 was 200/accepted
    # and persisted already expired; an invalid object in_reply_to also
    # validated. The exact parent method (10ffd1f) rejects bad_ttl and
    # bad_in_reply_to for the encrypted branches too.

    def _assert_send_rejected_unstored(self, body, error):
        mid = body["id"]
        status, payload = self.post(body)
        self.assertEqual(status, 400, (body, payload))
        self.assertEqual(payload["error"], error)
        self.assertIsNone(self.stored_enc_v(mid),
                          "rejected send must not persist")

    def test_v1_envelope_with_bad_ttl_rejected_not_stored(self):
        for bad_ttl in (-1, 0, True, False, "60", None, 2592001, float("inf")):
            mid = str(uuid.uuid4())
            self._assert_send_rejected_unstored(
                {"id": mid, "to": "bob", "enc": make_v1_envelope(),
                 "ttl_secs": bad_ttl},
                "bad_ttl")

    def test_v2_envelope_with_bad_ttl_rejected_not_stored(self):
        for bad_ttl in (-1, 0, True, "60", 2592001):
            mid = str(uuid.uuid4())
            enc = make_v2_envelope(mid, self.sender_seed, self.recipient_seed)
            self._assert_send_rejected_unstored(
                {"id": mid, "to": "bob", "enc": enc, "ttl_secs": bad_ttl},
                "bad_ttl")

    def test_envelope_with_bad_in_reply_to_rejected_not_stored(self):
        for bad_reply in ({"not": "a string"}, 123, ["x"], "x" * 129):
            for enc in (make_v1_envelope(),
                        make_v2_envelope(str(uuid.uuid4()),
                                         self.sender_seed, self.recipient_seed)):
                mid = str(uuid.uuid4())
                self._assert_send_rejected_unstored(
                    {"id": mid, "to": "bob", "enc": enc,
                     "in_reply_to": bad_reply},
                    "bad_in_reply_to")

    def test_envelope_ttl_type_and_range_edges(self):
        # Boundary values: 1 and MAX_TTL accepted; just outside rejected.
        for good_ttl in (1, 60, 60.5, 2592000):
            for enc in (make_v1_envelope(),
                        make_v2_envelope(str(uuid.uuid4()),
                                         self.sender_seed, self.recipient_seed)):
                mid = str(uuid.uuid4())
                status, payload = self.post(
                    {"id": mid, "to": "bob", "enc": enc, "ttl_secs": good_ttl})
                self.assertEqual(status, 200, (good_ttl, payload))
                self.assertTrue(payload["accepted"])
        # Sibling controls: plaintext was always subject to the shared
        # checks; valid envelopes with valid TTL still flow.
        mid = str(uuid.uuid4())
        self._assert_send_rejected_unstored(
            {"id": mid, "to": "bob", "text": "plain", "ttl_secs": -1},
            "bad_ttl")
        mid = str(uuid.uuid4())
        enc = make_v2_envelope(mid, self.sender_seed, self.recipient_seed)
        status, payload = self.post({"id": mid, "to": "bob", "enc": enc})
        self.assertEqual(status, 200, payload)
        self.assertEqual(self.stored_enc_v(mid), 2)


# ---------------------------------------------------------------------------
# Adapter-level gates: v1-only negative control + v2 overlay


def _private(path, obj):
    data = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
    fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def _authority_schema():
    spec = importlib.util.spec_from_file_location(
        "fed_auth_schema_probe_" + uuid.uuid4().hex,
        ROOT / "federation_authority.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module._SCHEMA


class FakeV2SendClient:
    def __init__(self):
        self.send_calls = []

    def send(self, to, msg_id=None, **kwargs):
        self.send_calls.append((to, msg_id, kwargs))
        return (msg_id, True)


class FakeV2PollClient:
    def __init__(self, messages):
        self.messages = list(messages)
        self.ack_calls = []

    def poll(self, timeout=0):
        return list(self.messages)

    def ack(self, ids):
        self.ack_calls.append(list(ids))
        return {"acked": list(ids), "already_acked": []}


class AdapterGateTests(unittest.TestCase):
    """Duplex/restart/reconcile gates for the v2 overlay; negative control
    for the v1-only adapter. Disposable /tmp fixture state only."""

    def make_adapter(self, v2=True, cns_peer_x_endpoint="http://127.0.0.1:19991",
                     cns_peer_x_pin="sha256:" + "00" * 32, stale_grant=False):
        state = tempfile.TemporaryDirectory(prefix="cand679-adapter-", dir="/tmp")
        self.addCleanup(state.cleanup)
        base = Path(state.name)
        _private(base / ".clack-fed-v098-owned.json", {"owned": "candidate-679 test"})
        ndr_key = base / "ndr.key"
        verifier_pub = base / "verifier.pub"
        _private(ndr_key, os.urandom(32))
        _private(verifier_pub, os.urandom(32))
        auth_db = base / "federation-authority.db"
        fd = os.open(str(auth_db), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        c = sqlite3.connect(str(auth_db))
        try:
            c.executescript(_authority_schema())
            now = time.time()
            c.execute(
                "INSERT INTO grants(grant_id,generation,state,tombstone_reason,"
                "last_recheck_verified_at,updated_at) VALUES (?,?,?,?,?,?)",
                ("forward", 1, "OK", None,
                 now - 7200 if stale_grant else now, now),
            )
            c.commit()
        finally:
            c.close()
        bootstrap = base / "bootstrap.json"
        _private(bootstrap, {
            "schema": "clack-federation-bootstrap-reference-v1",
            "purpose": "fixture-proof",
            "approval_ref": "DISPOSABLE TEST ONLY",
            "state_dir": str(base),
        })
        endpoints = {}
        # One endpoint for both directions (the real topology: one peer, one
        # relay). The CNS route for peer-x must name this same relay URL and
        # pin, or the transport-authority seam fails closed.
        for name, port in (("ep", 19991),):
            token = base / (name + "-token.ref")
            key = base / (name + "-key.ref")
            pins = base / (name + "-pins.ref")
            url = "http://127.0.0.1:%d" % port
            _private(token, b"disposable-fixture-token")
            _private(key, os.urandom(32))
            _private(pins, {url: "sha256:" + "00" * 32})
            endpoints[name] = {"url": url, "peer": "peer-x",
                               "token_ref": str(token), "key_ref": str(key),
                               "pin_ref": str(pins)}
        from federation_adapter import SCHEMA

        # v2 fixture keys: the same keypairs feed the CNS snapshot's key ids
        # AND the static pins supplement, so the gate binds real crypto to
        # the signed snapshot. (The v1-only negative control never reads
        # either file.)
        seed_x, seed_y = os.urandom(32), os.urandom(32)
        keys = {"peer-x": seed_x, "peer-y": seed_y}
        if v2:
            import nacl.signing

            pubs = {p: bytes(nacl.signing.SigningKey(s).verify_key)
                    for p, s in keys.items()}
            _private(base / "v2-sender-pins.json", {
                "schema": "clack-federation-v2-pins/v1",
                "peer_verify_keys": {p: b64u(pub) for p, pub in pubs.items()},
                # Operator attestation pin for the configured relay URL: the
                # Ed25519 federation attestation key id. Independent of the
                # endpoint's pin_ref, which stays the native RSA transport
                # identity pin for ClackClient (Zari d8728e50).
                "relay_attestation_pins": {url: "sha256:" + "00" * 32},
            })
            auth_seed = os.urandom(32)
            # The authority key file holds the 32-byte Ed25519 PUBLIC key
            # (verify_snapshot pins sha256 of the file bytes).
            _private(base / "cns-authority.key",
                     ed25519._publickey(auth_seed))
            snap = _cns_snapshot_doc(
                [_cns_peer_route("peer-x", seed_x,
                                cns_peer_x_endpoint, cns_peer_x_pin),
                 _cns_peer_route("peer-y", seed_y,
                                "https://127.0.0.1:19999",
                                "sha256:" + "ab" * 32)],
                auth_seed)
            _private(base / "cns-snapshot.json", snap)
            loaded = cns.load_snapshot(
                str(base / "cns-snapshot.json"),
                str(base / "cns-authority.key"),
                str(base / "cns-routes.db"), now=time.time())
            assert set(loaded["routes"]) == {"peer-x", "peer-y"}, loaded

        cfg = {
            "schema": SCHEMA, "proof_only": True, "state_dir": str(base),
            "bootstrap_ref": str(bootstrap), "ndr_key_ref": str(ndr_key),
            "verifier_pub_ref": str(verifier_pub),
            "verifier_id": "candidate-679-test-verifier",
            "timeout": 3, "partition_cap_s": 3600, "endpoints": endpoints,
            # Two-party route: we are peer-x; we send to peer-y and receive
            # from peer-y. The old loopback (receive from peer-x) could not
            # express a valid v2 envelope (ctx sender != recipient).
            "routes": {"forward": {"send_endpoint": "ep", "to": "peer-y",
                                   "receive_endpoint": "ep", "from": "peer-y"}},
        }
        config = base / "runtime.json"
        _private(config, cfg)
        if v2:
            from federation_e2ee_v2 import AdapterV2

            adapter = AdapterV2(str(config))
        else:
            from federation_adapter import Adapter

            adapter = Adapter(str(config))
        self.addCleanup(adapter.clients.clear)
        return adapter, base, keys

    def v2_envelope(self, keys, mid, sender="peer-x", recipient="peer-y",
                    topic="task.v2", reply=None):
        enc = make_v2_envelope(mid, keys[sender], keys[recipient],
                               sender=sender, recipient=recipient,
                               topic=topic, reply=reply)
        return enc, keys[sender], keys[recipient]

    # --- negative control: the v1-only adapter refuses enc_v=2 ---

    def test_v1_only_adapter_rejects_enc_v2(self):
        adapter, _, keys = self.make_adapter(v2=False)
        adapter.clients["ep"] = FakeV2SendClient()
        mid = str(uuid.uuid4())
        enc, _, _ = self.v2_envelope(keys, mid)
        # native_payload(enc, 2) is valid; the v1-only adapter must still refuse.
        native_payload(enc, 2)
        with self.assertRaises(ValueError) as ctx:
            adapter.send("forward", mid, enc=enc, enc_v=2)
        self.assertIn("v1-only adapter requires enc_v=1", str(ctx.exception))
        self.assertEqual(adapter.clients["ep"].send_calls, [])

    # --- v2 overlay: real enc_v=2, no downgrade ---

    def test_v2_send_refuses_plaintext_and_v1(self):
        adapter, _, _ = self.make_adapter(v2=True)
        adapter.clients["ep"] = FakeV2SendClient()
        mid = str(uuid.uuid4())
        with self.assertRaises(ValueError):
            adapter.send("forward", mid, "plaintext is refused")
        v1 = make_v1_envelope()
        with self.assertRaises(ValueError):
            adapter.send("forward", mid, enc=v1, enc_v=1)
        with self.assertRaises(ValueError):
            adapter.send("forward", mid, enc=v1, enc_v=True)
        self.assertEqual(adapter.clients["ep"].send_calls, [])

    def test_v2_send_journals_and_transports_enc_v2(self):
        adapter, base, keys = self.make_adapter(v2=True)
        fake = FakeV2SendClient()
        adapter.clients["ep"] = fake
        mid = str(uuid.uuid4())
        enc, _, _ = self.v2_envelope(keys, mid)
        result = adapter.send("forward", mid, enc=enc, enc_v=2, topic="task.v2")
        self.assertEqual(result["id"], mid)
        self.assertEqual(result["enc_v"], 2)
        self.assertIn(result["outcome"], ("sent", "already_sent", "held"))
        to, sent_mid, kwargs = fake.send_calls[0]
        self.assertEqual(to, "peer-y")
        self.assertEqual(sent_mid, mid)
        self.assertEqual(kwargs["enc_v"], 2)
        self.assertEqual(kwargs["required_enc_v"], 2)
        # Stable-ID replay: same bytes -> the original outcome is reported
        # without a second wire send (idempotent, no duplication).
        result2 = adapter.send("forward", mid, enc=enc, enc_v=2, topic="task.v2")
        self.assertEqual(result2["outcome"], "already_sent")
        self.assertEqual(len(fake.send_calls), 1)
        # Restart gate: a fresh adapter instance over the same state dir
        # sees the journaled payload and reconciles without duplicating.
        from federation_e2ee_v2 import AdapterV2

        adapter2 = AdapterV2(str(base / "runtime.json"))
        adapter2.clients["ep"] = fake
        self.assertEqual(adapter2.reconcile(), [])

    def test_v2_receive_accepts_real_crypto_v2_only(self):
        # Boundary-2 positive: a real-crypto v2 envelope (nacl-signed by
        # peer-y for peer-x), inner recipient == outer recipient, all CNS
        # bindings intact -> accepted, journaled, ACKed. v1/plaintext skipped.
        adapter, _, keys = self.make_adapter(v2=True)
        mid2 = str(uuid.uuid4())
        enc2, _, _ = self.v2_envelope(keys, mid2, sender="peer-y",
                                      recipient="peer-x")
        raw2 = native_payload(enc2, 2)
        mid1 = str(uuid.uuid4())
        messages = [
            {"id": mid1, "from": "peer-y", "to": "peer-x",
             "text": "plaintext attempt", "enc_v": 0},
            {"id": str(uuid.uuid4()), "from": "peer-y", "to": "peer-x",
             "text": native_payload(make_v1_envelope(), 1), "enc_v": 1},
            {"id": mid2, "from": "peer-y", "to": "peer-x",
             "text": raw2, "enc_v": 2,
             "topic": "task.v2", "in_reply_to": None},
        ]
        fake = FakeV2PollClient(messages)
        adapter.clients["ep"] = fake
        result = adapter.receive("ep")
        # Only the enc_v=2 message is accepted; v1/plaintext are skipped.
        self.assertEqual(result["accepted_ids"], [mid2])
        self.assertEqual(result["enc_v"], 2)
        inbox = adapter.inbox_messages()
        self.assertEqual(len(inbox), 1)
        self.assertEqual(inbox[0]["id"], mid2)
        self.assertEqual(inbox[0]["enc_v"], 2)
        # The transport ACK ran exactly once, for the accepted message.
        self.assertEqual(fake.ack_calls, [[mid2]])

    # --- Boundary-2 negatives: every gate violation -> ZERO effects ---
    # (no inbox row, no ACK call, no egress). Mirrors of Mercedes's probes.

    def _receive_one(self, adapter, message):
        fake = FakeV2PollClient([message])
        adapter.clients["ep"] = fake
        return adapter.receive("ep"), fake

    def _assert_zero_effects(self, adapter, fake, result):
        self.assertEqual(result["accepted_ids"], [])
        self.assertEqual(adapter.inbox_messages(), [])
        self.assertEqual(fake.ack_calls, [])

    def _grant_row(self, base):
        conn = sqlite3.connect(str(base / "federation-authority.db"))
        try:
            return conn.execute(
                "SELECT generation,state,tombstone_reason FROM grants"
                " WHERE grant_id='forward'").fetchone()
        finally:
            conn.close()

    def _payload_row(self, base, mid):
        conn = sqlite3.connect(str(base / "federation-authority.db"))
        try:
            return conn.execute(
                "SELECT msg_id FROM runtime_payloads WHERE msg_id=?",
                (mid,)).fetchone()
        finally:
            conn.close()

    def _reservation_row(self, base, mid):
        conn = sqlite3.connect(str(base / "federation-authority.db"))
        try:
            return conn.execute(
                "SELECT res_id FROM reservations WHERE msg_id=?",
                (mid,)).fetchone()
        finally:
            conn.close()

    def _good_receive_message(self, keys, mid):
        enc, _, _ = self.v2_envelope(keys, mid, sender="peer-y",
                                     recipient="peer-x")
        return ({"id": mid, "from": "peer-y", "to": "peer-x",
                 "text": native_payload(enc, 2), "enc_v": 2,
                 "topic": "task.v2", "in_reply_to": None}, enc)

    def test_v2_receive_rejects_altered_inner_recipient(self):
        # Probe 1: inner recipient_id rewritten to wrong-recipient (no
        # re-sign). The CNS recipient binding must catch it.
        adapter, _, keys = self.make_adapter(v2=True)
        mid = str(uuid.uuid4())
        message, enc = self._good_receive_message(keys, mid)
        enc["ctx"]["recipient_id"] = "agent://wrong-recipient"
        message["text"] = native_payload(enc, 2)
        result, fake = self._receive_one(adapter, message)
        self._assert_zero_effects(adapter, fake, result)

    def test_v2_receive_rejects_generation_mismatch(self):
        # Probe 2: inner recipient_home_generation 999 != CNS generation.
        adapter, _, keys = self.make_adapter(v2=True)
        mid = str(uuid.uuid4())
        message, enc = self._good_receive_message(keys, mid)
        enc["ctx"]["recipient_home_generation"] = 999
        message["text"] = native_payload(enc, 2)
        result, fake = self._receive_one(adapter, message)
        self._assert_zero_effects(adapter, fake, result)

    def test_v2_receive_rejects_zeroed_signature(self):
        # Probe 3: 64 zero bytes for the sender signature. Shape-valid, all
        # bindings intact — only real Ed25519 verification catches it.
        adapter, _, keys = self.make_adapter(v2=True)
        mid = str(uuid.uuid4())
        message, enc = self._good_receive_message(keys, mid)
        enc["sig"] = b64u(bytes(64))
        message["text"] = native_payload(enc, 2)
        result, fake = self._receive_one(adapter, message)
        self._assert_zero_effects(adapter, fake, result)

    def test_v2_receive_rejects_tampered_sender_identity(self):
        # Owner-authenticity: inner sender_id rewritten to an identity the
        # CNS snapshot does not pin for the outer sender.
        adapter, _, keys = self.make_adapter(v2=True)
        mid = str(uuid.uuid4())
        message, enc = self._good_receive_message(keys, mid)
        enc["ctx"]["sender_id"] = "agent://impostor"
        message["text"] = native_payload(enc, 2)
        result, fake = self._receive_one(adapter, message)
        self._assert_zero_effects(adapter, fake, result)

    def test_v2_receive_rejects_outer_inner_id_mismatch(self):
        # Signed ctx.id must equal the observed outer message id.
        adapter, _, keys = self.make_adapter(v2=True)
        mid = str(uuid.uuid4())
        message, _ = self._good_receive_message(keys, mid)
        message["id"] = str(uuid.uuid4())
        result, fake = self._receive_one(adapter, message)
        self._assert_zero_effects(adapter, fake, result)

    def test_v2_receive_missing_cns_snapshot_fails_closed(self):
        # Missing snapshot must not permit work via static cfg routes: the
        # envelope is fully valid, but there is no signed CNS authority.
        # The transport-authority seam fails closed BEFORE any poll — the
        # relay is never contacted and nothing is journaled or acked.
        adapter, base, keys = self.make_adapter(v2=True)
        mid = str(uuid.uuid4())
        message, _ = self._good_receive_message(keys, mid)
        os.remove(base / "cns-routes.db")
        fake = FakeV2PollClient([message])
        adapter.clients["ep"] = fake
        polled = []
        orig_poll = fake.poll

        def spy_poll(timeout=0):
            polled.append(timeout)
            return orig_poll(timeout)

        fake.poll = spy_poll
        with self.assertRaises(ValueError) as ctx:
            adapter.receive("ep")
        self.assertIn("cns_snapshot_unavailable", str(ctx.exception))
        self.assertEqual(polled, [])
        self.assertEqual(adapter.inbox_messages(), [])
        self.assertEqual(fake.ack_calls, [])

    def test_v2_send_rejects_zeroed_signature_before_egress(self):
        # Egress gate: a tampered envelope is refused before journaling and
        # before any wire send.
        adapter, base, keys = self.make_adapter(v2=True)
        fake = FakeV2SendClient()
        adapter.clients["ep"] = fake
        mid = str(uuid.uuid4())
        enc, _, _ = self.v2_envelope(keys, mid)
        enc["sig"] = b64u(bytes(64))
        with self.assertRaises(ValueError):
            adapter.send("forward", mid, enc=enc, enc_v=2, topic="task.v2")
        self.assertEqual(fake.send_calls, [])
        conn = sqlite3.connect(str(base / "federation-authority.db"))
        try:
            row = conn.execute(
                "SELECT msg_id FROM runtime_payloads WHERE msg_id=?",
                (mid,)).fetchone()
        finally:
            conn.close()
        self.assertIsNone(row, "refused send must not journal")

    def test_v2_send_rejects_recipient_mismatch_before_egress(self):
        # Envelope built for peer-x as recipient, but the route sends to
        # peer-y: outer/inner recipient mismatch -> no egress, no journal.
        adapter, base, keys = self.make_adapter(v2=True)
        fake = FakeV2SendClient()
        adapter.clients["ep"] = fake
        mid = str(uuid.uuid4())
        enc, _, _ = self.v2_envelope(keys, mid, sender="peer-y",
                                     recipient="peer-x")
        with self.assertRaises(ValueError):
            adapter.send("forward", mid, enc=enc, enc_v=2, topic="task.v2")
        self.assertEqual(fake.send_calls, [])
        conn = sqlite3.connect(str(base / "federation-authority.db"))
        try:
            row = conn.execute(
                "SELECT msg_id FROM runtime_payloads WHERE msg_id=?",
                (mid,)).fetchone()
        finally:
            conn.close()
        self.assertIsNone(row, "refused send must not journal")

    def test_v2_snapshot_integrity(self):
        adapter, _, _ = self.make_adapter(v2=True)
        snap = adapter.snapshot("gate-test")
        self.assertEqual(snap["integrity"], "ok")
        self.assertTrue(os.path.exists(snap["snapshot"]))

    # --- Defect-1 repair: CNS-selected transport endpoint/pin enforced ---
    # The signed snapshot's relay_endpoint/relay_identity_key_id must match
    # the configured endpoint URL/pin before any client, credential,
    # journal, or egress effect.

    def test_v2_send_refuses_transport_endpoint_mismatch_zero_effects(self):
        # Mercedes's independent repro: the CNS sender route names
        # https://127.0.0.1:19999 pin sha256:ab*32 while the static cfg
        # sends via http://127.0.0.1:19991 pin sha256:00*32. The send must
        # fail closed with zero client/credential/dispatch/new-payload
        # effects.
        adapter, base, keys = self.make_adapter(
            cns_peer_x_endpoint="https://127.0.0.1:19999",
            cns_peer_x_pin="sha256:" + "ab" * 32)
        client_calls = []

        def no_client(endpoint):
            client_calls.append(endpoint)
            raise AssertionError("transport client must not be constructed")

        adapter.client = no_client
        mid = str(uuid.uuid4())
        enc, _, _ = self.v2_envelope(keys, mid)
        with self.assertRaises(ValueError) as ctx:
            adapter.send("forward", mid, enc=enc, enc_v=2, topic="task.v2")
        self.assertIn("relay_pin_mismatch", str(ctx.exception))
        self.assertEqual(client_calls, [])
        self.assertIsNone(self._payload_row(base, mid),
                          "refused send must not journal")
        self.assertIsNone(self._reservation_row(base, mid),
                          "refused send must not reserve")
        self.assertEqual(tuple(self._grant_row(base)), (1, "OK", None))

    def test_v2_send_refuses_transport_pin_mismatch_zero_effects(self):
        # Same seam, pin-only disagreement: the endpoint URL matches the
        # CNS authority but the configured pin does not.
        adapter, base, keys = self.make_adapter(
            cns_peer_x_pin="sha256:" + "ff" * 32)
        client_calls = []

        def no_client(endpoint):
            client_calls.append(endpoint)
            raise AssertionError("transport client must not be constructed")

        adapter.client = no_client
        mid = str(uuid.uuid4())
        enc, _, _ = self.v2_envelope(keys, mid)
        with self.assertRaises(ValueError) as ctx:
            adapter.send("forward", mid, enc=enc, enc_v=2, topic="task.v2")
        self.assertIn("relay_pin_mismatch", str(ctx.exception))
        self.assertEqual(client_calls, [])
        self.assertIsNone(self._payload_row(base, mid),
                          "refused send must not journal")
        self.assertEqual(tuple(self._grant_row(base)), (1, "OK", None))

    def test_v2_send_accepts_matching_transport_endpoint_and_pin(self):
        # Defect-1 positive: the CNS authority names exactly the configured
        # endpoint URL and pin, so the bound send proceeds end to end.
        adapter, base, keys = self.make_adapter()
        route = cns.resolve_route(str(base / "cns-routes.db"), "peer-x")
        self.assertEqual(route["relay_endpoint"], "http://127.0.0.1:19991")
        self.assertEqual(route["relay_identity_key_id"],
                         "sha256:" + "00" * 32)
        fake = FakeV2SendClient()
        adapter.clients["ep"] = fake
        mid = str(uuid.uuid4())
        enc, _, _ = self.v2_envelope(keys, mid)
        result = adapter.send("forward", mid, enc=enc, enc_v=2, topic="task.v2")
        self.assertEqual(result["outcome"], "sent")
        self.assertEqual(len(fake.send_calls), 1)

    def test_v2_receive_refuses_transport_endpoint_mismatch(self):
        # The receive seam shares the route/pin protection: a CNS authority
        # that disagrees with the polled endpoint fails closed before the
        # relay is ever polled.
        adapter, base, keys = self.make_adapter(
            cns_peer_x_endpoint="https://127.0.0.1:19999",
            cns_peer_x_pin="sha256:" + "ab" * 32)
        mid = str(uuid.uuid4())
        message, _ = self._good_receive_message(keys, mid)
        fake = FakeV2PollClient([message])
        adapter.clients["ep"] = fake
        polled = []
        orig_poll = fake.poll

        def spy_poll(timeout=0):
            polled.append(timeout)
            return orig_poll(timeout)

        fake.poll = spy_poll
        with self.assertRaises(ValueError) as ctx:
            adapter.receive("ep")
        self.assertIn("relay_pin_mismatch", str(ctx.exception))
        self.assertEqual(polled, [])
        self.assertEqual(adapter.inbox_messages(), [])
        self.assertEqual(fake.ack_calls, [])

    def test_v2_receive_accepts_matching_transport_endpoint_and_pin(self):
        # Receive positive: the polled endpoint's URL/pin match the CNS
        # authority for the local peer, so the envelope gate decides.
        adapter, base, keys = self.make_adapter()
        mid = str(uuid.uuid4())
        message, _ = self._good_receive_message(keys, mid)
        result, fake = self._receive_one(adapter, message)
        self.assertEqual(result["accepted_ids"], [mid])
        self.assertEqual(fake.ack_calls, [[mid]])

    # --- Defect-2 repair: hostile envelope/CNS validated BEFORE the cap ---
    # Cap enforcement moved to the final action fence. A refused envelope
    # must leave the grant (and all durable state) untouched; a valid
    # envelope on a time-due grant still enforces the cap.

    def test_v2_send_stale_cap_invalid_signature_zero_mutation(self):
        # Mercedes's repro: the grant's cap is independently time-due AND
        # the envelope carries a bad 64-byte signature. The authenticity
        # gate fires first: grant stays OK/gen1, nothing journaled.
        adapter, base, keys = self.make_adapter(stale_grant=True)
        fake = FakeV2SendClient()
        adapter.clients["ep"] = fake
        mid = str(uuid.uuid4())
        enc, _, _ = self.v2_envelope(keys, mid)
        enc["sig"] = b64u(bytes(64))
        with self.assertRaises(ValueError):
            adapter.send("forward", mid, enc=enc, enc_v=2, topic="task.v2")
        self.assertEqual(fake.send_calls, [])
        self.assertIsNone(self._payload_row(base, mid),
                          "refused send must not journal")
        self.assertIsNone(self._reservation_row(base, mid),
                          "refused send must not reserve")
        self.assertEqual(tuple(self._grant_row(base)), (1, "OK", None))

    def test_v2_send_stale_cap_missing_snapshot_zero_mutation(self):
        adapter, base, keys = self.make_adapter(stale_grant=True)
        os.remove(base / "cns-routes.db")
        fake = FakeV2SendClient()
        adapter.clients["ep"] = fake
        mid = str(uuid.uuid4())
        enc, _, _ = self.v2_envelope(keys, mid)
        with self.assertRaises(ValueError) as ctx:
            adapter.send("forward", mid, enc=enc, enc_v=2, topic="task.v2")
        self.assertIn("cns_snapshot_unavailable", str(ctx.exception))
        self.assertEqual(fake.send_calls, [])
        self.assertIsNone(self._payload_row(base, mid),
                          "refused send must not journal")
        self.assertEqual(tuple(self._grant_row(base)), (1, "OK", None))

    def test_v2_send_stale_cap_route_mismatch_zero_mutation(self):
        # Route mismatch (envelope addressed peer-y->peer-x, route sends to
        # peer-y) with a time-due cap: still zero durable mutation.
        adapter, base, keys = self.make_adapter(stale_grant=True)
        fake = FakeV2SendClient()
        adapter.clients["ep"] = fake
        mid = str(uuid.uuid4())
        enc, _, _ = self.v2_envelope(keys, mid, sender="peer-y",
                                     recipient="peer-x")
        with self.assertRaises(ValueError):
            adapter.send("forward", mid, enc=enc, enc_v=2, topic="task.v2")
        self.assertEqual(fake.send_calls, [])
        self.assertIsNone(self._payload_row(base, mid),
                          "refused send must not journal")
        self.assertEqual(tuple(self._grant_row(base)), (1, "OK", None))

    def test_v2_send_stale_cap_valid_envelope_enforces_cap(self):
        # Defect-2 positive: a valid envelope on a time-due grant still gets
        # the cap enforced (OK/gen1 -> CAPPED/gen2) and the send is held at
        # the final action fence — safety retained, ordered after the
        # authenticity gate.
        adapter, base, keys = self.make_adapter(stale_grant=True)
        fake = FakeV2SendClient()
        adapter.clients["ep"] = fake
        mid = str(uuid.uuid4())
        enc, _, _ = self.v2_envelope(keys, mid)
        result = adapter.send("forward", mid, enc=enc, enc_v=2, topic="task.v2")
        self.assertEqual(result["outcome"], "held")
        self.assertEqual(fake.send_calls, [])
        self.assertEqual(tuple(self._grant_row(base)), (2, "CAPPED", None))

    # --- recovery-bypass repair: bare-payload retries must re-run the gate ---

    def _insert_bare_payload(self, base, mid, enc_raw):
        # Simulate Mercedes's probe: payload committed, interrupted before
        # reservation/wire. State: payloads=1, reservations=0, wire=0.
        conn = sqlite3.connect(str(base / "federation-authority.db"))
        try:
            conn.execute(
                "INSERT INTO runtime_payloads(msg_id,grant_id,text,enc_v)"
                " VALUES (?,?,?,2)",
                (mid, "forward", enc_raw))
            conn.commit()
        finally:
            conn.close()

    def _drift_cns_pin(self, base, new_pin):
        # Simulate CNS authority rotation after the payload commit: the
        # signed snapshot now names a different relay identity pin.
        conn = sqlite3.connect(str(base / "cns-routes.db"))
        try:
            conn.execute(
                "UPDATE cns_routes SET relay_identity_key_id=? WHERE peer=?",
                (new_pin, "peer-x"))
            conn.commit()
        finally:
            conn.close()

    def test_v2_retry_bare_payload_pin_drift_fails_closed_zero_dispatch(self):
        # Mercedes's exact probe: identical-ID/envelope retry on a bare
        # payload row must NOT skip the CNS/transport gate. Pin drift ->
        # fail closed, zero client construction, zero dispatch, zero new
        # journal rows beyond the pre-existing bare payload.
        adapter, base, keys = self.make_adapter()
        mid = str(uuid.uuid4())
        reply_id = str(uuid.uuid4())
        enc, _, _ = self.v2_envelope(keys, mid, topic="task.v2",
                                     reply=reply_id)
        from clack_client.envelope import native_payload as _np
        self._insert_bare_payload(base, mid, _np(enc, 2))
        # Authority rotates the pin after the interrupted commit.
        self._drift_cns_pin(base, "sha256:" + "ab" * 32)
        client_calls = []

        def no_client(endpoint):
            client_calls.append(endpoint)
            raise AssertionError("transport client must not be constructed")

        adapter.client = no_client
        with self.assertRaises(ValueError) as ctx:
            adapter.send("forward", mid, enc=enc, enc_v=2,
                         topic="task.v2", in_reply_to=reply_id)
        self.assertIn("relay_pin_mismatch", str(ctx.exception))
        self.assertEqual(client_calls, [],
                         "drifted retry must not construct a client")
        # Bare payload row intact; no reservation created by the refused retry.
        self.assertIsNotNone(self._payload_row(base, mid))
        self.assertIsNone(self._reservation_row(base, mid),
                          "refused retry must not reserve")

    def test_v2_retry_bare_payload_endpoint_drift_fails_closed(self):
        # Same seam, endpoint-URL drift instead of pin drift.
        adapter, base, keys = self.make_adapter()
        mid = str(uuid.uuid4())
        enc, _, _ = self.v2_envelope(keys, mid)
        from clack_client.envelope import native_payload as _np
        self._insert_bare_payload(base, mid, _np(enc, 2))
        conn = sqlite3.connect(str(base / "cns-routes.db"))
        try:
            conn.execute(
                "UPDATE cns_routes SET relay_endpoint=? WHERE peer=?",
                ("https://127.0.0.1:19999", "peer-x"))
            conn.commit()
        finally:
            conn.close()
        adapter.client = lambda ep: (_ for _ in ()).throw(
            AssertionError("transport client must not be constructed"))
        with self.assertRaises(ValueError) as ctx:
            adapter.send("forward", mid, enc=enc, enc_v=2, topic="task.v2")
        self.assertIn("relay_pin_mismatch", str(ctx.exception))
        self.assertIsNone(self._reservation_row(base, mid))

    def test_v2_retry_bare_payload_matching_resume_succeeds(self):
        # No drift: the bare-payload retry re-passes the gate and dispatches
        # exactly once. Signed topic/reply context retained end to end.
        adapter, base, keys = self.make_adapter()
        fake = FakeV2SendClient()
        adapter.clients["ep"] = fake
        mid = str(uuid.uuid4())
        reply_id = str(uuid.uuid4())
        enc, _, _ = self.v2_envelope(keys, mid, topic="task.v2",
                                     reply=reply_id)
        from clack_client.envelope import native_payload as _np
        self._insert_bare_payload(base, mid, _np(enc, 2))
        result = adapter.send("forward", mid, enc=enc, enc_v=2,
                              topic="task.v2", in_reply_to=reply_id)
        self.assertEqual(result["outcome"], "sent")
        self.assertEqual(len(fake.send_calls), 1)
        to, sent_mid, kwargs = fake.send_calls[0]
        self.assertEqual(sent_mid, mid)
        self.assertEqual(kwargs.get("topic"), "task.v2")
        self.assertEqual(kwargs.get("in_reply_to"), reply_id)
        self.assertIsNotNone(self._reservation_row(base, mid))

    def test_v2_retry_completed_no_wire_replay_after_rotation(self):
        # Completed send, then route rotation: the identical retry must
        # return the durable outcome with zero additional wire — rotation
        # must not erase it, and no re-dispatch may occur.
        adapter, base, keys = self.make_adapter()
        fake = FakeV2SendClient()
        adapter.clients["ep"] = fake
        mid = str(uuid.uuid4())
        enc, _, _ = self.v2_envelope(keys, mid)
        result = adapter.send("forward", mid, enc=enc, enc_v=2, topic="task.v2")
        self.assertEqual(result["outcome"], "sent")
        self.assertEqual(len(fake.send_calls), 1)
        # Authority rotates after completion.
        self._drift_cns_pin(base, "sha256:" + "ab" * 32)
        result2 = adapter.send("forward", mid, enc=enc, enc_v=2,
                               topic="task.v2")
        self.assertEqual(result2["outcome"], "already_sent")
        self.assertEqual(len(fake.send_calls), 1,
                         "completed replay must not re-dispatch")

    def test_v2_reconcile_bare_payload_drift_fails_closed(self):
        # The actual reconcile() path — not just direct send() — must also
        # gate a bare-payload retry. Drift -> zero dispatch.
        adapter, base, keys = self.make_adapter()
        mid = str(uuid.uuid4())
        enc, _, _ = self.v2_envelope(keys, mid)
        from clack_client.envelope import native_payload as _np
        self._insert_bare_payload(base, mid, _np(enc, 2))
        self._drift_cns_pin(base, "sha256:" + "ab" * 32)
        adapter.client = lambda ep: (_ for _ in ()).throw(
            AssertionError("transport client must not be constructed"))
        with self.assertRaises(ValueError) as ctx:
            adapter.reconcile()
        self.assertIn("relay_pin_mismatch", str(ctx.exception))
        self.assertIsNone(self._reservation_row(base, mid))

    def test_v2_reconcile_bare_payload_matching_resumes(self):
        # Reconcile on a matching bare payload resumes the send end to end.
        adapter, base, keys = self.make_adapter()
        fake = FakeV2SendClient()
        adapter.clients["ep"] = fake
        mid = str(uuid.uuid4())
        enc, _, _ = self.v2_envelope(keys, mid, topic="task.v2")
        from clack_client.envelope import native_payload as _np
        self._insert_bare_payload(base, mid, _np(enc, 2))
        results = adapter.reconcile()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["outcome"], "sent")
        self.assertEqual(len(fake.send_calls), 1)


if __name__ == "__main__":
    unittest.main()
