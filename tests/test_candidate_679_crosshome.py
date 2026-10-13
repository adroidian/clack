"""Candidate-679 cross-home forwarding tests (ENGINEERED, not custody).

Proves the relay-side missing hop for #679: a sender enrolled ONLY on home A
sending a valid real-crypto v2 envelope to a recipient enrolled ONLY on home B.
Two separate relay stores; each participant local ONLY to its home.

Positive path:
- AdapterV2.send on the A side (real federation grant, real signed-CNS gate,
  real sender Ed25519 signature) -> relay A /v1/send -> durable outbox ->
  relay-to-relay POST /v1/federation/deliver (attested, pinned, CNS-bound) ->
  relay B mailbox -> AdapterV2.receive on the B side (real CNS gate incl.
  signature verification) -> owner-side decrypt_envelope_v2.
- Topic/in_reply_to preserved; return path (B -> A) symmetric.

Negative / fail-closed:
- unknown recipient, canonical-home-is-us, sender home mismatch, tampered
  attestation, pin mismatch, local sender on deliver, attestation for own
  home, v2 ctx mismatch, same-ID unknown-outcome recovery (exactly-once),
  restart reclaim of inflight, duplicate send, ID collision, expiry,
  federation-disabled regression (unknown_peer intact), bad config refuses
  startup, real-socket transport round trip.

Run: python3 -m unittest discover -s tests -p "test_candidate_679_crosshome*" -v
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
import threading
import time
import unittest
import uuid
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "clack-client"))

from clack_client import e2ee as ce2ee  # noqa: E402
import ed25519  # noqa: E402  (vendored; CNS snapshot + relay attestation)
import federation_cns as cns  # noqa: E402


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def import_relay(base):
    with mock.patch.dict(os.environ, {"CLACK_RELAY_BASE": str(base)}):
        spec = importlib.util.spec_from_file_location(
            "relay_crosshome_" + uuid.uuid4().hex, ROOT / "relay.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


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
        "fed_auth_schema_xh_" + uuid.uuid4().hex, ROOT / "federation_authority.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module._SCHEMA


# --- fixture identities -------------------------------------------------
# peer-x lives ONLY on home-a; peer-y lives ONLY on home-b.
PEERS = {
    "peer-x": {"identity": "agent://peer-x", "home": "clack://home-a", "generation": 7},
    "peer-y": {"identity": "agent://peer-y", "home": "clack://home-b", "generation": 11},
}


def _x_pub(seed):
    return ce2ee.x25519_scalarmult(
        ce2ee.ed25519_seed_to_x25519_priv(seed), ce2ee._X25519_BASE)


def _ed_pub(seed):
    import nacl.signing

    return bytes(nacl.signing.SigningKey(seed).verify_key)


def _cns_route(peer, relay_endpoint, relay_pub32, peer_seed):
    ed_pub = _ed_pub(peer_seed)
    return {
        "peer": peer,
        "identity": PEERS[peer]["identity"],
        "owner": "Owner of %s" % peer,
        "prime_relay": "prime-relay",
        "home": PEERS[peer]["home"],
        "relay_endpoint": relay_endpoint,
        "relay_identity_key_id": "sha256:" + hashlib.sha256(relay_pub32).hexdigest(),
        "generation": PEERS[peer]["generation"],
        "signing_key_id": b64u(hashlib.sha256(ed_pub).digest()[:8]),
        "encryption_key_id": b64u(hashlib.sha256(_x_pub(peer_seed)).digest()[:8]),
    }


def _sign_snapshot(snap, authority_seed):
    body = {k: v for k, v in snap.items() if k != "signature"}
    pub = ed25519._publickey(authority_seed)
    body["issuer_key_id"] = "sha256:" + hashlib.sha256(pub).hexdigest()
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False, allow_nan=False).encode()
    sig = ed25519.sign(authority_seed, cns.SIGNING_DOMAIN + raw)
    snap = dict(body)
    snap["signature"] = {"alg": "Ed25519", "key_id": body["issuer_key_id"],
                         "value": b64u(sig)}
    return snap


def _snapshot_doc(routes, authority_seed):
    snap = {
        "schema": "clack-cns-route-snapshot/v1",
        "version": 1,
        "snapshot_id": str(uuid.uuid4()),
        "issuer": "candidate-679-crosshome-test",
        "issuer_key_id": "",
        "sequence": 7,
        "issued_at": int(time.time()) - 60,
        "expires_at": int(time.time()) + 3600,
        "routes": sorted(routes,
                         key=lambda r: (r["identity"].encode(),
                                        r["peer"].encode())),
        "signature": {},
    }
    return _sign_snapshot(snap, authority_seed)


def make_v2_envelope(mid, sender_seed, recipient_seed, sender="peer-x",
                     recipient="peer-y", topic="task.v2", reply=None,
                     plaintext=b"cross-home v2 payload"):
    context = ce2ee.make_context(
        message_id=mid,
        sender=sender,
        recipient=recipient,
        sender_id=PEERS[sender]["identity"],
        recipient_id=PEERS[recipient]["identity"],
        topic=topic,
        in_reply_to=reply,
        sender_home=PEERS[sender]["home"],
        recipient_home=PEERS[recipient]["home"],
        sender_home_generation=PEERS[sender]["generation"],
        recipient_home_generation=PEERS[recipient]["generation"],
    )
    return ce2ee.encrypt_envelope_v2(
        sender_seed, _x_pub(recipient_seed), plaintext, context)


# --- two-home rig ---------------------------------------------------------

class TwoHomeRig:
    """Two relay modules, separate stores, signed CNS, federation enabled."""

    def __init__(self, port_a=19991, port_b=19992):
        self.tmp = tempfile.TemporaryDirectory(prefix="cand679-xhome-", dir="/tmp")
        base = Path(self.tmp.name)
        self.base_a = base / "home-a"
        self.base_b = base / "home-b"
        self.base_a.mkdir()
        self.base_b.mkdir()
        self.port_a = port_a
        self.port_b = port_b
        self.url_a = "http://127.0.0.1:%d" % port_a
        self.url_b = "http://127.0.0.1:%d" % port_b

        # Relay identity seeds (operator-held Ed25519 keys).
        self.relay_seed_a = os.urandom(32)
        self.relay_seed_b = os.urandom(32)
        self.relay_pub_a = ed25519._publickey(self.relay_seed_a)
        self.relay_pub_b = ed25519._publickey(self.relay_seed_b)
        self.seed_file_a = base / "relay-seed-a"
        self.seed_file_b = base / "relay-seed-b"
        _private(self.seed_file_a, self.relay_seed_a)
        _private(self.seed_file_b, self.relay_seed_b)

        # Peer keypairs (sender/recipient crypto).
        self.seed_x = os.urandom(32)
        self.seed_y = os.urandom(32)

        # Signed CNS snapshot: both homes, key ids bound to real relay keys.
        authority_seed = os.urandom(32)
        _private(base / "cns-authority.key", ed25519._publickey(authority_seed))
        snap = _snapshot_doc([
            _cns_route("peer-x", self.url_a, self.relay_pub_a, self.seed_x),
            _cns_route("peer-y", self.url_b, self.relay_pub_b, self.seed_y),
        ], authority_seed)
        _private(base / "cns-snapshot.json", snap)
        self.cns_state_a = str(base / "cns-a.db")
        self.cns_state_b = str(base / "cns-b.db")
        for state in (self.cns_state_a, self.cns_state_b):
            loaded = cns.load_snapshot(
                str(base / "cns-snapshot.json"),
                str(base / "cns-authority.key"), state, now=time.time())
            assert set(loaded["routes"]) == {"peer-x", "peer-y"}

        # Relay modules, each local ONLY to its peer.
        self.mod_a = import_relay(self.base_a)
        self.mod_b = import_relay(self.base_b)
        self._configure(self.mod_a, {"peer-x": "tok-x"}, "clack://home-a",
                        self.cns_state_a, self.seed_file_a)
        self._configure(self.mod_b, {"peer-y": "tok-y"}, "clack://home-b",
                        self.cns_state_b, self.seed_file_b)

        # Hermetic relay-to-relay transport: A's forwarder POSTs straight
        # into B's deliver handler (no sockets). One test below uses the
        # real default HTTP transport against a live server instead.
        self.mod_a._FED_HTTP_POST = self._dispatch_to_b

    def grant(self, mod, sender_home, sender, recipient_home, recipient,
              status="active", note="test grant"):
        """Insert a federation_grants admission row into mod's relay DB
        (Zari delta fix D2, a74bb2b2: cross-home wire acceptance requires
        an explicit maintained grant for the exact tuple)."""
        with mod.db_lock:
            mod.conn.execute(
                "INSERT OR REPLACE INTO federation_grants("
                "sender_home, sender, recipient_home, recipient, status,"
                " created_at, revoked_at, note)"
                " VALUES (?,?,?,?,?,?,NULL,?)",
                (sender_home, sender, recipient_home, recipient, status,
                 time.time(), note),
            )
            mod.conn.commit()

    def _configure(self, mod, peers, own_home, cns_state, seed_file):
        cfg = {
            "peers": peers,
            "federation": {
                "own_home": own_home,
                "cns_state": cns_state,
                "relay_seed_ref": str(seed_file),
                "linked_relays": {
                    self.url_a: b64u(self.relay_pub_a),
                    self.url_b: b64u(self.relay_pub_b),
                },
            },
        }
        mod.relay_cfg = cfg
        mod._init_federation(cfg)
        assert mod._FED is not None
        mod.init_db(cfg)

    def _dispatch_to_b(self, url, body):
        assert url == self.url_b + "/v1/federation/deliver", url
        status, payload = deliver(self.mod_b, body)
        return status, json.dumps(payload).encode("utf-8")

    def close(self):
        for mod in (self.mod_a, self.mod_b):
            try:
                mod.conn.close()
            except Exception:
                pass
        self.tmp.cleanup()

    # -- adapter construction (sender-home grant + CNS authority) ---------
    def make_adapter(self, side):
        """AdapterV2 for side 'a' (peer-x) or 'b' (peer-y), with a real
        federation grant, real CNS snapshot, and real v2 pins."""
        from federation_adapter import SCHEMA

        base = Path(self.tmp.name) / ("adapter-" + side)
        base.mkdir(exist_ok=True)
        os.chmod(str(base), 0o700)
        _private(base / ".clack-fed-v098-owned.json", {"owned": "crosshome test"})
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
                ("forward", 1, "OK", None, now, now),
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
        if side == "a":
            me, other = "peer-x", "peer-y"
            url = self.url_a
            relay_pub = self.relay_pub_a
        else:
            me, other = "peer-y", "peer-x"
            url = self.url_b
            relay_pub = self.relay_pub_b
        ep = "ep-" + side
        token = base / "token.ref"
        key = base / "key.ref"
        pins = base / "pins.ref"
        key_id = "sha256:" + hashlib.sha256(relay_pub).hexdigest()
        _private(token, b"disposable-fixture-token")
        _private(key, os.urandom(32))
        _private(pins, {url: key_id})
        endpoints = {ep: {"url": url, "peer": me, "token_ref": str(token),
                          "key_ref": str(key), "pin_ref": str(pins)}}
        import nacl.signing

        pubs = {"peer-x": bytes(nacl.signing.SigningKey(self.seed_x).verify_key),
                "peer-y": bytes(nacl.signing.SigningKey(self.seed_y).verify_key)}
        _private(base / "v2-sender-pins.json", {
            "schema": "clack-federation-v2-pins/v1",
            "peer_verify_keys": {p: b64u(pub) for p, pub in pubs.items()},
            # Operator attestation pin for this side's relay URL: the
            # Ed25519 federation attestation key id (== the CNS snapshot's
            # relay_identity_key_id). Independent of the endpoint's pin_ref,
            # which stays the native RSA transport identity pin for
            # ClackClient (Zari d8728e50).
            "relay_attestation_pins": {
                url: "sha256:" + hashlib.sha256(relay_pub).hexdigest()},
        })
        cns_state = str(base / "cns-routes.db")
        loaded = cns.load_snapshot(
            str(Path(self.tmp.name) / "cns-snapshot.json"),
            str(Path(self.tmp.name) / "cns-authority.key"),
            cns_state, now=time.time())
        assert set(loaded["routes"]) == {"peer-x", "peer-y"}
        cfg = {
            "schema": SCHEMA, "proof_only": True, "state_dir": str(base),
            "bootstrap_ref": str(bootstrap), "ndr_key_ref": str(ndr_key),
            "verifier_pub_ref": str(verifier_pub),
            "verifier_id": "crosshome-test-verifier",
            "timeout": 3, "partition_cap_s": 3600, "endpoints": endpoints,
            "routes": {"forward": {"send_endpoint": ep, "to": other,
                                  "receive_endpoint": ep, "from": other}},
        }
        config = base / "runtime.json"
        _private(config, cfg)
        from federation_e2ee_v2 import AdapterV2

        adapter = AdapterV2(str(config))
        adapter.clients.clear()
        return adapter, {"me": me, "other": other, "ep": ep, "url": url}


# --- direct handler invocation helpers ------------------------------------

def post_send(mod, body, peer):
    handler = mod.Handler.__new__(mod.Handler)
    handler.path = "/v1/send"
    handler._require_auth = lambda: peer
    handler._read_json = lambda: body
    replies = []
    handler._json = lambda status, payload: replies.append((status, payload))
    with mock.patch.object(mod, "sweep"), mock.patch.object(mod, "maybe_notify"):
        handler.do_POST()
    assert replies
    return replies[-1]


def deliver(mod, body):
    handler = mod.Handler.__new__(mod.Handler)
    handler.path = "/v1/federation/deliver"
    handler._read_json = lambda: body
    handler._client_ip = lambda: "127.0.0.1"
    replies = []
    handler._json = lambda status, payload: replies.append((status, payload))
    handler.do_POST()
    assert replies
    return replies[-1]


def poll(mod, peer):
    handler = mod.Handler.__new__(mod.Handler)
    handler.path = "/v1/poll?timeout=0"
    handler._require_auth = lambda: peer
    replies = []
    handler._json = lambda status, payload: replies.append((status, payload))
    with mock.patch.object(mod, "sweep"), mock.patch.object(mod, "maybe_notify"):
        handler.do_GET()
    assert replies
    return replies[-1]


class DirectRelaySendClient:
    """Carries AdapterV2.send's transport call into the relay module's
    /v1/send handler (auth patched to the local peer)."""

    def __init__(self, mod, peer):
        self.mod = mod
        self.peer = peer
        self.send_calls = []

    def send(self, to, msg_id=None, **kwargs):
        self.send_calls.append((to, msg_id, kwargs))
        body = {"id": msg_id, "to": to, "enc": kwargs.get("enc"),
                "enc_v": kwargs.get("enc_v")}
        if kwargs.get("topic"):
            body["topic"] = kwargs["topic"]
        if kwargs.get("in_reply_to"):
            body["in_reply_to"] = kwargs["in_reply_to"]
        status, payload = post_send(self.mod, body, self.peer)
        assert status == 200, payload
        assert payload.get("accepted") is True, payload
        return (msg_id, True)


class DirectRelayPollClient:
    def __init__(self, mod, peer):
        self.mod = mod
        self.peer = peer
        self.ack_calls = []

    def poll(self, timeout=0):
        status, payload = poll(self.mod, self.peer)
        assert status == 200, payload
        return payload["messages"] if isinstance(payload, dict) else payload

    def ack(self, ids):
        self.ack_calls.append(list(ids))
        return {"acked": list(ids), "already_acked": []}


def outbox_rows(mod):
    with mod.db_lock:
        return mod.conn.execute(
            "SELECT id, sender, recipient, state, attempts, last_error,"
            " dest_origin FROM federation_outbox ORDER BY created_at").fetchall()


def message_rows(mod):
    with mod.db_lock:
        return mod.conn.execute(
            "SELECT id, sender, recipient, topic, in_reply_to, enc_v"
            " FROM messages ORDER BY created_at").fetchall()


# --- test cases -------------------------------------------------------------

class CrossHomeTests(unittest.TestCase):
    def setUp(self):
        self.rig = TwoHomeRig()
        self.addCleanup(self.rig.close)
        # Zari delta fix D2 (a74bb2b2): cross-home wire acceptance now
        # requires an explicit maintained grant for the exact
        # (sender-home, sender, recipient-home, recipient) tuple. All
        # positive sends in this file are authorized; the no-grant and
        # revoked-grant negatives live in test_candidate_679_delta_fix.py.
        self.rig.grant(self.rig.mod_a, "clack://home-a", "peer-x",
                       "clack://home-b", "peer-y")
        self.rig.grant(self.rig.mod_b, "clack://home-b", "peer-y",
                       "clack://home-a", "peer-x")

    def _full_send_a_to_b(self, topic="task.v2", reply=None,
                          plaintext=b"cross-home v2 payload"):
        """AdapterV2 (real grant + CNS gate + real signature) -> relay A."""
        rig = self.rig
        adapter, info = rig.make_adapter("a")
        client = DirectRelaySendClient(rig.mod_a, "peer-x")
        adapter.clients[info["ep"]] = client
        mid = str(uuid.uuid4())
        enc = make_v2_envelope(mid, rig.seed_x, rig.seed_y, topic=topic,
                               reply=reply, plaintext=plaintext)
        result = adapter.send("forward", mid, enc=enc, enc_v=2,
                              topic=topic, in_reply_to=reply)
        self.assertEqual(result["id"], mid)
        self.assertIn(result["outcome"], ("sent", "already_sent", "held"))
        self.assertEqual(len(client.send_calls), 1)
        return mid, enc, adapter, info

    def _send_only(self):
        rig = self.rig
        adapter, info = rig.make_adapter("a")
        adapter.clients[info["ep"]] = DirectRelaySendClient(rig.mod_a, "peer-x")
        mid = str(uuid.uuid4())
        enc = make_v2_envelope(mid, rig.seed_x, rig.seed_y)
        adapter.send("forward", mid, enc=enc, enc_v=2, topic="task.v2")
        return mid, enc, adapter, info

    def _forward_all(self):
        return self.rig.mod_a.federation_forward_pending()

    # --- positive: request ------------------------------------------------

    def test_v2_crosshome_request_end_to_end(self):
        rig = self.rig
        parent = str(uuid.uuid4())
        mid, enc, adapter_a, info_a = self._full_send_a_to_b(
            topic="topic.preserved", reply=parent,
            plaintext=b"duplex v2 cross-home ownership proof")

        # Sender's home: durable outbox row, NO local mailbox row.
        rows = outbox_rows(rig.mod_a)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][1], "peer-x")
        self.assertEqual(rows[0][2], "peer-y")
        self.assertEqual(rows[0][3], "queued")
        self.assertEqual(message_rows(rig.mod_a), [])

        # Forward: relay A -> relay B over the attested channel.
        fwd = self._forward_all()
        self.assertEqual(fwd["forwarded"], 1)
        rows = outbox_rows(rig.mod_a)
        self.assertEqual(rows[0][3], "delivered")

        # Recipient's home: exactly one mailbox row, topic/parent preserved.
        b_rows = message_rows(rig.mod_b)
        self.assertEqual(len(b_rows), 1)
        _id, sender, recipient, topic, in_reply_to, enc_v = b_rows[0]
        self.assertEqual((_id, sender, recipient), (mid, "peer-x", "peer-y"))
        self.assertEqual(topic, "topic.preserved")
        self.assertEqual(in_reply_to, parent)
        self.assertEqual(enc_v, 2)
        # No forwarding state on the recipient's home; no mailbox on A.
        self.assertEqual(outbox_rows(rig.mod_b), [])
        self.assertEqual(message_rows(rig.mod_a), [])

        # B side: AdapterV2.receive (real CNS gate incl. signature
        # verification) -> owner-side decrypt.
        adapter_b, info_b = rig.make_adapter("b")
        adapter_b.clients[info_b["ep"]] = DirectRelayPollClient(
            rig.mod_b, "peer-y")
        received = adapter_b.receive(info_b["ep"])
        self.assertEqual(received["accepted_ids"], [mid])
        inbox = adapter_b.inbox_messages()
        self.assertEqual(len(inbox), 1)
        stored = json.loads(inbox[0]["text"])
        self.assertEqual(stored["v"], 2)
        import nacl.signing

        sender_pub = bytes(nacl.signing.SigningKey(rig.seed_x).verify_key)
        context = ce2ee.make_context(
            message_id=mid, sender="peer-x", recipient="peer-y",
            sender_id="agent://peer-x", recipient_id="agent://peer-y",
            topic="topic.preserved", in_reply_to=parent,
            sender_home="clack://home-a", recipient_home="clack://home-b",
            sender_home_generation=7, recipient_home_generation=11)
        recovered = ce2ee.decrypt_envelope_v2(
            rig.seed_y, stored, sender_pub, context)
        self.assertEqual(recovered, b"duplex v2 cross-home ownership proof")

    # --- positive: return path (B -> A symmetric) --------------------------

    def test_v2_crosshome_return_path(self):
        rig = self.rig

        def dispatch_to_a(url, body):
            self.assertEqual(url, rig.url_a + "/v1/federation/deliver", url)
            status, payload = deliver(rig.mod_a, body)
            return status, json.dumps(payload).encode()

        rig.mod_b._FED_HTTP_POST = dispatch_to_a
        adapter_b, info_b = rig.make_adapter("b")
        adapter_b.clients[info_b["ep"]] = DirectRelaySendClient(
            rig.mod_b, "peer-y")
        mid = str(uuid.uuid4())
        enc = make_v2_envelope(mid, rig.seed_y, rig.seed_x, sender="peer-y",
                               recipient="peer-x", plaintext=b"return leg")
        result = adapter_b.send("forward", mid, enc=enc, enc_v=2,
                                topic="task.v2")
        self.assertEqual(result["id"], mid)
        fwd = rig.mod_b.federation_forward_pending()
        self.assertEqual(fwd["forwarded"], 1)
        a_rows = message_rows(rig.mod_a)
        self.assertEqual(len(a_rows), 1)
        self.assertEqual(a_rows[0][:3], (mid, "peer-y", "peer-x"))
        self.assertEqual(a_rows[0][5], 2)
        self.assertEqual(message_rows(rig.mod_b), [])

    # --- fail-closed negatives --------------------------------------------

    def test_unknown_recipient_fails_closed(self):
        rig = self.rig
        mid = str(uuid.uuid4())
        status, payload = post_send(
            rig.mod_a, {"id": mid, "to": "nobody", "text": "hello"}, "peer-x")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "cns_route_unknown")
        self.assertEqual(outbox_rows(rig.mod_a), [])
        self.assertEqual(message_rows(rig.mod_a), [])
        self.assertEqual(message_rows(rig.mod_b), [])

    def test_canonical_home_is_us_unknown_peer(self):
        # CNS says peer-z's canonical home is home-a, but peer-z is not
        # enrolled on A: honest unknown_peer -- never a forward, never an
        # invented mailbox.
        rig = self.rig
        base = Path(rig.tmp.name)
        authority_seed = os.urandom(32)
        _private(base / "cns2-authority.key", ed25519._publickey(authority_seed))
        snap = _snapshot_doc([
            _cns_route("peer-x", rig.url_a, rig.relay_pub_a, rig.seed_x),
            _cns_route("peer-y", rig.url_b, rig.relay_pub_b, rig.seed_y),
            {"peer": "peer-z", "identity": "agent://peer-z", "owner": "o",
             "prime_relay": "prime-relay", "home": "clack://home-a",
             "relay_endpoint": rig.url_a,
             "relay_identity_key_id": "sha256:" + hashlib.sha256(
                 rig.relay_pub_a).hexdigest(),
             "generation": 1,
             "signing_key_id": b64u(b"12345678"),
             "encryption_key_id": b64u(b"12345678")},
        ], authority_seed)
        _private(base / "cns2-snapshot.json", snap)
        state2 = str(base / "cns2.db")
        cns.load_snapshot(str(base / "cns2-snapshot.json"),
                          str(base / "cns2-authority.key"), state2,
                          now=time.time())
        old = rig.mod_a._FED["cns_state"]
        rig.mod_a._FED["cns_state"] = state2
        try:
            status, payload = post_send(
                rig.mod_a,
                {"id": str(uuid.uuid4()), "to": "peer-z", "text": "hello"},
                "peer-x")
        finally:
            rig.mod_a._FED["cns_state"] = old
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "unknown_peer")
        self.assertEqual(outbox_rows(rig.mod_a), [])

    def test_sender_home_mismatch_fails_closed(self):
        # Rotate the CNS so peer-x's home is elsewhere: A must not forward
        # for a sender it no longer pins to its own home.
        rig = self.rig
        base = Path(rig.tmp.name)
        authority_seed = os.urandom(32)
        _private(base / "cns3-authority.key", ed25519._publickey(authority_seed))
        other_pub = ed25519._publickey(os.urandom(32))
        routes = [
            _cns_route("peer-x", "http://127.0.0.1:19977", other_pub,
                       rig.seed_x),
            _cns_route("peer-y", rig.url_b, rig.relay_pub_b, rig.seed_y),
        ]
        for r in routes:
            if r["peer"] == "peer-x":
                r["home"] = "clack://home-c"
        snap = _snapshot_doc(routes, authority_seed)
        _private(base / "cns3-snapshot.json", snap)
        state3 = str(base / "cns3.db")
        cns.load_snapshot(str(base / "cns3-snapshot.json"),
                          str(base / "cns3-authority.key"), state3,
                          now=time.time())
        old = rig.mod_a._FED["cns_state"]
        rig.mod_a._FED["cns_state"] = state3
        try:
            status, payload = post_send(
                rig.mod_a,
                {"id": str(uuid.uuid4()), "to": "peer-y", "text": "hello"},
                "peer-x")
        finally:
            rig.mod_a._FED["cns_state"] = old
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "federation_sender_home_mismatch")
        self.assertEqual(outbox_rows(rig.mod_a), [])

    def test_v2_context_mismatch_fails_closed(self):
        rig = self.rig
        mid = str(uuid.uuid4())
        enc = make_v2_envelope(mid, rig.seed_x, rig.seed_y,
                               recipient="peer-y")
        status, payload = post_send(
            rig.mod_a, {"id": mid, "to": "peer-y", "enc": enc}, "peer-x")
        self.assertEqual(status, 200)  # control: matched ctx is fine
        # Tamper the envelope's claimed sender: ctx stays structurally
        # valid (sender != recipient) but disagrees with the authenticated
        # outer sender. The relay must not forward a misbound envelope.
        mid2 = str(uuid.uuid4())
        enc2 = make_v2_envelope(mid2, rig.seed_x, rig.seed_y,
                                recipient="peer-y")
        enc2["ctx"] = dict(enc2["ctx"], sender="peer-z")
        status, payload = post_send(
            rig.mod_a, {"id": mid2, "to": "peer-y", "enc": enc2}, "peer-x")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "federation_context_mismatch")
        self.assertEqual(
            [r for r in outbox_rows(rig.mod_a) if r[0] == mid2], [])

    def test_tampered_attestation_rejected(self):
        rig = self.rig
        adapter, info = rig.make_adapter("a")
        adapter.clients[info["ep"]] = DirectRelaySendClient(rig.mod_a, "peer-x")
        mid = str(uuid.uuid4())
        enc = make_v2_envelope(mid, rig.seed_x, rig.seed_y)
        adapter.send("forward", mid, enc=enc, enc_v=2, topic="task.v2")
        real_post = rig.mod_a._FED_HTTP_POST

        def mitm(url, body):
            body = dict(body)
            sig = bytearray(base64.urlsafe_b64decode(
                body["sig"] + "=" * (-len(body["sig"]) % 4)))
            sig[0] ^= 1
            body["sig"] = base64.urlsafe_b64encode(
                bytes(sig)).rstrip(b"=").decode()
            return real_post(url, body)

        rig.mod_a._FED_HTTP_POST = mitm
        try:
            fwd = self._forward_all()
        finally:
            rig.mod_a._FED_HTTP_POST = real_post
        self.assertEqual(fwd["forwarded"], 0)
        rows = outbox_rows(rig.mod_a)
        self.assertEqual(rows[0][3], "rejected")
        self.assertIn("403", rows[0][5])
        self.assertEqual(message_rows(rig.mod_b), [])

    def test_pin_mismatch_fails_closed(self):
        rig = self.rig
        mid, _, _, _ = self._send_only()
        # B pins the WRONG key for A's origin.
        wrong = b64u(ed25519._publickey(os.urandom(32)))
        old = rig.mod_b._FED["linked_relays"][rig.url_a]
        rig.mod_b._FED["linked_relays"][rig.url_a] = wrong
        try:
            fwd = self._forward_all()
        finally:
            rig.mod_b._FED["linked_relays"][rig.url_a] = old
        self.assertEqual(fwd["forwarded"], 0)
        rows = outbox_rows(rig.mod_a)
        self.assertEqual(rows[0][3], "rejected")
        self.assertEqual(message_rows(rig.mod_b), [])

    def test_local_sender_on_deliver_rejected(self):
        rig = self.rig
        # A local peer must use /v1/send; the deliver ingress refuses them.
        mid = str(uuid.uuid4())
        enc = make_v2_envelope(mid, rig.seed_y, rig.seed_x, sender="peer-y",
                               recipient="peer-x")
        payload = json.dumps(enc, sort_keys=True, separators=(",", ":"))
        exp = time.time() + 60
        attest = rig.mod_b._federation_attest_bytes(
            mid, "peer-y", "peer-y", None, None, exp,
            hashlib.sha256(payload.encode()).hexdigest(), 2, "clack://home-b")
        sig = ed25519.sign(rig.relay_seed_b, attest)
        body = {"id": mid, "from": "peer-y", "to": "peer-y", "topic": None,
                "in_reply_to": None, "expires_at": exp,
                "enc": enc, "text": None, "enc_v": 2,
                "from_home": "clack://home-b",
                "relay_pub": b64u(rig.relay_pub_b),
                "nonce": "ab" * 32, "sig": b64u(sig)}
        status, payload = deliver(rig.mod_b, body)
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "federation_local_sender")
        self.assertEqual(message_rows(rig.mod_b), [])

    def test_attestation_for_own_home_rejected(self):
        # A relay must never accept relay attestation for a peer whose
        # canonical home is itself: that peer must use /v1/send locally.
        rig = self.rig
        mid = str(uuid.uuid4())
        enc = make_v2_envelope(mid, rig.seed_x, rig.seed_y)
        payload = json.dumps(enc, sort_keys=True, separators=(",", ":"))
        exp = time.time() + 60
        attest = rig.mod_a._federation_attest_bytes(
            mid, "peer-x", "peer-y", None, None, exp,
            hashlib.sha256(payload.encode()).hexdigest(), 2, "clack://home-a")
        sig = ed25519.sign(rig.relay_seed_a, attest)
        body = {"id": mid, "from": "peer-x", "to": "peer-y", "topic": None,
                "in_reply_to": None, "expires_at": exp,
                "enc": enc, "text": None, "enc_v": 2,
                "from_home": "clack://home-a",
                "relay_pub": b64u(rig.relay_pub_a),
                "nonce": "ab" * 32, "sig": b64u(sig)}
        status, payload = deliver(rig.mod_a, body)
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "federation_local_sender")
        self.assertEqual(message_rows(rig.mod_a), [])

    def test_recipient_not_local_on_deliver_rejected(self):
        # peer-y (home-b, attested by B's key) delivering to A for a
        # recipient A does not host: refused, nothing stored.
        rig = self.rig
        mid = str(uuid.uuid4())
        enc = make_v2_envelope(mid, rig.seed_x, rig.seed_y)
        payload = json.dumps(enc, sort_keys=True, separators=(",", ":"))
        exp = time.time() + 60
        attest = rig.mod_b._federation_attest_bytes(
            mid, "peer-y", "peer-nobody", None, None, exp,
            hashlib.sha256(payload.encode()).hexdigest(), 2, "clack://home-b")
        sig = ed25519.sign(rig.relay_seed_b, attest)
        body = {"id": mid, "from": "peer-y", "to": "peer-nobody",
                "topic": None, "in_reply_to": None, "expires_at": exp,
                "enc": enc, "text": None, "enc_v": 2,
                "from_home": "clack://home-b",
                "relay_pub": b64u(rig.relay_pub_b),
                "nonce": "cd" * 32, "sig": b64u(sig)}
        status, payload = deliver(rig.mod_a, body)
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "federation_recipient_not_local")
        self.assertEqual(message_rows(rig.mod_a), [])

    # --- same-ID unknown-outcome recovery (exactly-once) -------------------

    def test_unknown_outcome_retry_is_idempotent(self):
        rig = self.rig
        mid, _, _, _ = self._send_only()
        calls = {"n": 0}
        real_post = rig.mod_a._FED_HTTP_POST

        def flaky(url, body):
            calls["n"] += 1
            status, raw = real_post(url, body)
            if calls["n"] == 1:
                # The destination processed the POST, then the connection
                # dropped: the outcome is UNKNOWN to the sender.
                raise ConnectionError("dropped after processing")
            return status, raw

        rig.mod_a._FED_HTTP_POST = flaky
        try:
            fwd1 = self._forward_all()
            self.assertEqual(fwd1["forwarded"], 0)
            row = [r for r in outbox_rows(rig.mod_a) if r[0] == mid][0]
            self.assertEqual(row[3], "queued")  # unknown -> requeued
            # B already has the mailbox row from the "dropped" attempt.
            self.assertEqual(len(message_rows(rig.mod_b)), 1)
            # Simulate time passing past the backoff, then retry.
            with rig.mod_a.db_lock:
                rig.mod_a.conn.execute(
                    "UPDATE federation_outbox SET next_attempt_at=? WHERE id=?",
                    (time.time() - 1, mid))
                rig.mod_a.conn.commit()
            fwd2 = self._forward_all()
            self.assertEqual(fwd2["forwarded"], 1)
        finally:
            rig.mod_a._FED_HTTP_POST = real_post
        # Exactly one mailbox row on B despite the retry.
        self.assertEqual(len(message_rows(rig.mod_b)), 1)
        row = [r for r in outbox_rows(rig.mod_a) if r[0] == mid][0]
        self.assertEqual(row[3], "delivered")

    def test_restart_reclaims_inflight_without_duplication(self):
        rig = self.rig
        mid, _, _, _ = self._send_only()
        # Simulate a crash between claim and delivery completion.
        with rig.mod_a.db_lock:
            rig.mod_a.conn.execute(
                "UPDATE federation_outbox SET state='inflight' WHERE id=?",
                (mid,))
            rig.mod_a.conn.commit()
        fwd = self._forward_all()
        self.assertEqual(fwd["forwarded"], 1)
        self.assertEqual(len(message_rows(rig.mod_b)), 1)
        row = [r for r in outbox_rows(rig.mod_a) if r[0] == mid][0]
        self.assertEqual(row[3], "delivered")

    def test_duplicate_send_returns_duplicate(self):
        rig = self.rig
        mid, enc, _, _ = self._send_only()
        # Same bytes, same ID: the original outcome, no second forwarding.
        status, payload = post_send(
            rig.mod_a, {"id": mid, "to": "peer-y", "enc": enc}, "peer-x")
        self.assertEqual(status, 200)
        self.assertTrue(payload.get("duplicate"))
        fwd = self._forward_all()
        self.assertEqual(fwd["forwarded"], 1)
        self.assertEqual(len(message_rows(rig.mod_b)), 1)

    def test_id_collision_rejected(self):
        rig = self.rig
        mid, _, _, _ = self._send_only()
        other = make_v2_envelope(str(uuid.uuid4()), rig.seed_x, rig.seed_y)
        status, payload = post_send(
            rig.mod_a, {"id": mid, "to": "peer-y", "enc": other}, "peer-x")
        self.assertEqual(status, 409)
        self.assertEqual(payload["error"], "id_collision")

    def test_expired_row_never_forwarded(self):
        rig = self.rig
        mid, _, _, _ = self._send_only()
        with rig.mod_a.db_lock:
            rig.mod_a.conn.execute(
                "UPDATE federation_outbox SET expires_at=? WHERE id=?",
                (time.time() - 1, mid))
            rig.mod_a.conn.commit()
        fwd = self._forward_all()
        self.assertEqual(fwd["forwarded"], 0)
        row = [r for r in outbox_rows(rig.mod_a) if r[0] == mid][0]
        self.assertEqual(row[3], "expired")
        self.assertEqual(message_rows(rig.mod_b), [])

    # --- regression: federation disabled keeps unknown_peer ----------------

    def test_federation_disabled_unknown_peer_intact(self):
        base = Path(self.rig.tmp.name) / "plain"
        base.mkdir()
        mod = import_relay(base)
        cfg = {"peers": {"alice": "tok-a", "bob": "tok-b"}}
        mod.relay_cfg = cfg
        mod.init_db(cfg)
        self.addCleanup(lambda: mod.conn.close() if mod.conn else None)
        self.assertIsNone(mod._FED)
        mid = str(uuid.uuid4())
        status, payload = post_send(
            mod, {"id": mid, "to": "peer-y", "text": "hello"}, "alice")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "unknown_peer")

    # --- config validation -------------------------------------------------

    def test_bad_federation_config_refuses_startup(self):
        base = Path(self.rig.tmp.name) / "badcfg"
        base.mkdir()
        mod = import_relay(base)
        self.addCleanup(lambda: mod.conn.close() if mod.conn else None)
        with self.assertRaises(SystemExit):
            mod._init_federation({"federation": {"own_home": "x"}})
        with self.assertRaises(SystemExit):
            mod._init_federation({"federation": {
                "own_home": "clack://home-a",
                "cns_state": "/nonexistent.db",
                "relay_seed_ref": str(self.rig.seed_file_a),
                "linked_relays": {}}})
        # seed file must be mode 0600: create the seed, then force the intended
        # loose mode explicitly — os.open()'s mode arg is masked by the
        # process umask (077 in this harness makes 0o644 come out 0o600),
        # so a post-creation chmod is the only umask-independent fixture.
        loose = base / "loose-seed"
        fd = os.open(str(loose), os.O_CREAT | os.O_WRONLY, 0o600)
        os.write(fd, os.urandom(32))
        os.close(fd)
        os.chmod(str(loose), 0o644)
        with self.assertRaises(SystemExit):
            mod._init_federation({"federation": {
                "own_home": "clack://home-a",
                "cns_state": self.rig.cns_state_a,
                "relay_seed_ref": str(loose),
                "linked_relays": {}}})
        self.assertIsNone(mod._FED)

    # --- real-socket transport smoke test ----------------------------------

    def test_real_http_transport_round_trip(self):
        """The DEFAULT urllib transport delivers to a live B server and
        verifies the destination's response signature."""
        rig = self.rig
        server = ThreadingHTTPServer(("127.0.0.1", 0), rig.mod_b.Handler)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        # Point A's destination at the live server via a fresh snapshot.
        base = Path(rig.tmp.name)
        authority_seed = os.urandom(32)
        _private(base / "cns-live-authority.key",
                 ed25519._publickey(authority_seed))
        live_url_b = "http://127.0.0.1:%d" % port
        snap = _snapshot_doc([
            _cns_route("peer-x", rig.url_a, rig.relay_pub_a, rig.seed_x),
            _cns_route("peer-y", live_url_b, rig.relay_pub_b, rig.seed_y),
        ], authority_seed)
        _private(base / "cns-live-snapshot.json", snap)
        live_state = str(base / "cns-live.db")
        cns.load_snapshot(str(base / "cns-live-snapshot.json"),
                          str(base / "cns-live-authority.key"), live_state,
                          now=time.time())
        old_state = rig.mod_a._FED["cns_state"]
        old_post = rig.mod_a._FED_HTTP_POST
        rig.mod_a._FED["cns_state"] = live_state
        rig.mod_a._FED_HTTP_POST = rig.mod_a._federation_http_post_default
        try:
            mid, _, _, _ = self._send_only()
            fwd = self._forward_all()
        finally:
            rig.mod_a._FED["cns_state"] = old_state
            rig.mod_a._FED_HTTP_POST = old_post
        self.assertEqual(fwd["forwarded"], 1)
        b_rows = message_rows(rig.mod_b)
        self.assertEqual(len(b_rows), 1)
        self.assertEqual(b_rows[0][0], mid)
        row = [r for r in outbox_rows(rig.mod_a) if r[0] == mid][0]
        self.assertEqual(row[3], "delivered")


if __name__ == "__main__":
    unittest.main()
