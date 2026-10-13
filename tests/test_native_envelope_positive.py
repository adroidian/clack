"""Positive functional tests only; synthetic envelopes are NOT real crypto.
No sockets, live state, credentials, profile data or runtime constructor.
All disposable state stays inside this isolated candidate's parent directory.
Auth/pin/network seams are fixture stubs, not authentication acceptance tests.
"""
import base64
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import time
import unittest
import uuid
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "clack-client"))
from federation_adapter import Adapter, init_transport_schema  # noqa: E402
from clack_client.client import ClackClient  # noqa: E402
from clack_client.envelope import native_payload  # noqa: E402
from clack_client.errors import RelayUnreachable  # noqa: E402


def load(name):
    spec = importlib.util.spec_from_file_location("fixture_" + uuid.uuid4().hex, ROOT / name)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def envelope():
    def b(n, char):
        return base64.urlsafe_b64encode(bytes([char]) * n).decode().rstrip("=")
    return {"v": 1, "alg": "x25519-chacha20poly1305", "eph": b(32, 1),
            "nonce": b(12, 2), "kid": b(8, 3), "ct": b(48, 4)}


def envelope_v2(mid):
    def b(n, char):
        return base64.urlsafe_b64encode(bytes([char]) * n).decode().rstrip("=")
    return {
        "v": 2,
        "alg": "x25519-chacha20poly1305+ed25519",
        "eph": b(32, 1),
        "nonce": b(12, 2),
        "kid": b(8, 3),
        "skid": b(8, 4),
        "ctx": {
            "id": mid,
            "sender": "fixture-a",
            "recipient": "fixture-b",
            "sender_id": "agent://fixture-a",
            "recipient_id": "agent://fixture-b",
            "topic": "fixture.v2",
            "in_reply_to": None,
            "sender_home": "clack://fixture-a",
            "recipient_home": "clack://fixture-b",
            "sender_home_generation": 1,
            "recipient_home_generation": 1,
        },
        "ct": b(32, 5),
        "sig": b(64, 6),
    }


def private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


class NativePositiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="offline-native-fixture-", dir=ROOT.parent)
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        # Enforced network prohibition: fail before any socket is constructed.
        self.sockets = mock.patch.object(socket, "socket", side_effect=AssertionError("offline fixture: no sockets"))
        self.sockets.start()
        self.addCleanup(self.sockets.stop)
        self.env = envelope()
        self.mid = str(uuid.uuid4())

    def relay(self):
        with mock.patch.dict(os.environ, {"CLACK_RELAY_BASE": str(self.base / "relay")}):
            r = load("relay.py")
        r.init_db({})
        self.addCleanup(lambda: r.conn.close())
        r.peer_names = {"fixture-a", "fixture-b"}
        now = time.time()
        for p in r.peer_names:
            r.conn.execute("INSERT INTO peers(name,token_hash,created_at) VALUES(?,?,?)", (p, "fixture-only", now))
        r.conn.execute(
            """INSERT INTO handshakes(
                   a_identity,b_identity,status,created_at,last_activity,
                   minter_enc_v,redeemer_enc_v,enc_capable,enc_version)
               VALUES(?,?,'active',?,?,?,?,?,?)""",
            ("fixture-a", "fixture-b", now, now, 1, 1, 1, 1),
        )
        r.conn.commit()
        return r

    def post(self, r, body):
        h = r.Handler.__new__(r.Handler)
        h.path = "/v1/send"
        h._require_auth = lambda: "fixture-a"
        h._read_json = lambda: body
        replies = []
        h._json = lambda status, payload: replies.append((status, payload))
        with mock.patch.object(r, "sweep"), mock.patch.object(r, "maybe_notify"):
            h.do_POST()
        self.assertEqual(replies[-1][0], 200)
        self.assertTrue(replies[-1][1]["accepted"])
        return replies[-1][1]

    def sdk(self):
        c = ClackClient.__new__(ClackClient)
        c.relay_url = "http://fixture.invalid"
        c.token = "synthetic-fixture-token"
        c.peer_name = "fixture-a"
        c.user_agent = "OfflineFixture/1"
        c.timeout = 1
        c._seed = bytes([9]) * 32
        return c

    def adapter(self, a=None):
        if a is None:
            a = load("federation_authority.py")
            state = self.base / "authority"
            state.mkdir(mode=0o700)
            private(self.base / "ndr", bytes([5]) * 32)
            private(self.base / "verifier", bytes([6]) * 32)
            private(state / "federation-authority.db", b"")
            a.configure(str(state), str(self.base / "ndr"), str(self.base / "verifier"), "synthetic-verifier", 3600)
            c = a._connect()
            try:
                now = time.time()
                c.execute("INSERT INTO grants(grant_id,generation,state,tombstone_reason,last_recheck_verified_at,updated_at) VALUES('fixture-grant',1,'OK',NULL,?,?)", (now, now))
                init_transport_schema(c)
            finally:
                c.close()
        # Deliberate fixture assembly; no operational bootstrap/credentials.
        obj = Adapter.__new__(Adapter)
        obj.authority = a
        obj.cfg = {"proof_only": True, "partition_cap_s": 3600,
                   "endpoints": {"send": {"peer": "fixture-a"}, "receive": {"peer": "fixture-b"}},
                   "routes": {"fixture-grant": {"send_endpoint": "send", "to": "fixture-b",
                                               "receive_endpoint": "receive", "from": "fixture-a"}}}
        obj.clients = {}
        return obj

    def query(self, obj, sql, params=()):
        c = obj.authority._connect()
        try:
            return c.execute(sql, params).fetchall()
        finally:
            c.close()

    def authority_snapshot(self, obj):
        with obj.authority.authority_lock():
            c = obj.authority._connect()
            try:
                return tuple(c.iterdump())
            finally:
                c.close()

    def test_additive_journal_migration_preserves_fixture_rows(self):
        import sqlite3
        c = sqlite3.connect(":memory:")
        try:
            c.executescript("CREATE TABLE grants(grant_id TEXT PRIMARY KEY); CREATE TABLE runtime_payloads(msg_id TEXT PRIMARY KEY,grant_id TEXT NOT NULL REFERENCES grants(grant_id),text TEXT NOT NULL);")
            c.execute("INSERT INTO grants VALUES('fixture-grant')")
            c.execute("INSERT INTO runtime_payloads VALUES(?,?,?)", (self.mid, "fixture-grant", "synthetic legacy fixture"))
            init_transport_schema(c)
            init_transport_schema(c)
            self.assertEqual(c.execute("SELECT msg_id,grant_id,text,enc_v FROM runtime_payloads").fetchall(), [(self.mid, "fixture-grant", "synthetic legacy fixture", 0)])
        finally:
            c.close()

    def test_reviewed_shape_and_exact_ciphertext_strings(self):
        raw = native_payload(self.env)
        self.assertEqual(json.loads(raw), self.env)
        for k in ("ct", "eph", "nonce", "kid"):
            self.assertEqual(json.loads(raw)[k], self.env[k])

    def test_sdk_native_send_and_signed_retry_use_same_body(self):
        c = self.sdk()
        calls = []
        def transport(method, url, headers, data, timeout):
            calls.append((headers, data))
            if len(calls) == 1:
                raise RelayUnreachable("synthetic transient delivery uncertainty")
            return 200, json.dumps({"id": self.mid, "accepted": True}).encode()
        with mock.patch("clack_client.client.transport.request", side_effect=transport), mock.patch("clack_client.client.time.sleep"):
            self.assertEqual(c.send("fixture-b", msg_id=self.mid, enc=self.env, enc_v=1), (self.mid, True))
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][1], calls[1][1])
        self.assertNotEqual(calls[0][0]["X-Clack-Nonce"], calls[1][0]["X-Clack-Nonce"])
        body = json.loads(calls[1][1])
        self.assertEqual(body, {"id": self.mid, "to": "fixture-b", "enc": self.env, "enc_v": 1})
        self.assertNotIn("text", body)

    def test_relay_native_send_durable_poll_and_same_id_retry(self):
        r = self.relay()
        body = {"id": self.mid, "to": "fixture-b", "enc": self.env, "enc_v": 1}
        self.post(r, body)
        before = r.conn.execute("SELECT text,enc_v,expires_at FROM messages WHERE id=?", (self.mid,)).fetchone()
        self.assertEqual(before[:2], (native_payload(self.env), 1))
        duplicate = self.post(r, dict(body))
        self.assertTrue(duplicate["duplicate"])
        self.assertEqual(r.conn.execute("SELECT text,enc_v,expires_at FROM messages WHERE id=?", (self.mid,)).fetchone(), before)
        r.conn.close()
        r.init_db({"peers": {"fixture-a": "synthetic-A", "fixture-b": "synthetic-B"}})
        messages = r.fetch_pending("fixture-b", time.time())
        self.assertEqual(len(messages), 1)
        self.assertEqual(json.loads(messages[0]["text"]), self.env)
        self.assertEqual(messages[0]["enc_v"], 1)
        self.assertEqual(messages[0]["text"], native_payload(self.env))
        self.assertEqual((messages[0]["from"], messages[0]["to"]), ("fixture-a", "fixture-b"))

    def test_relay_fetch_returns_native_fields(self):
        r = self.relay()
        reply_to = str(uuid.uuid4())
        self.post(r, {"id": self.mid, "to": "fixture-b", "enc": self.env, "in_reply_to": reply_to})
        h = r.Handler.__new__(r.Handler)
        h.path = "/v1/fetch?in_reply_to=" + reply_to
        h._require_auth = lambda: "fixture-b"
        out = []
        h._json = lambda status, body: out.append((status, body))
        with mock.patch.object(r, "sweep"):
            h.do_GET()
        self.assertEqual(out[-1][0], 200)
        m = out[-1][1]["messages"][0]
        self.assertEqual((json.loads(m["text"]), m["enc_v"]), (self.env, 1))

    def test_adapter_native_outbox_and_terminal_restart_no_replay(self):
        obj = self.adapter()
        calls = []
        client = mock.Mock()
        client.send.side_effect = lambda to, **kw: (calls.append((to, kw)) or (kw["msg_id"], True))
        obj.clients["send"] = client
        self.assertEqual(obj.send("fixture-grant", self.mid, enc=self.env, enc_v=1)["outcome"], "sent")
        self.assertEqual(calls[0], ("fixture-b", {"msg_id": self.mid, "enc": self.env, "enc_v": 1}))
        self.assertEqual(self.query(obj, "SELECT text,enc_v FROM runtime_payloads"), [(native_payload(self.env), 1)])
        self.assertEqual(self.query(obj, "SELECT grant_id,generation,state FROM outbox"), [("fixture-grant", 1, "sent")])
        restarted = self.adapter(obj.authority)
        restarted.clients["send"] = client
        self.assertEqual(restarted.send("fixture-grant", self.mid, enc=self.env)["outcome"], "already_sent")
        self.assertEqual(restarted.reconcile(), [])
        self.assertEqual(len(calls), 1)

    def test_v1_adapter_rejects_v2_before_any_durable_or_transport_mutation(self):
        obj = self.adapter()
        client = mock.Mock()
        client.send.return_value = (self.mid, True)
        obj.clients["send"] = client
        before = self.authority_snapshot(obj)
        with mock.patch.object(obj, "enforce_cap", wraps=obj.enforce_cap) as enforce:
            for marker in (2, None):
                with self.subTest(enc_v=marker):
                    mid = str(uuid.uuid4())
                    kwargs = {} if marker is None else {"enc_v": marker}
                    with self.assertRaisesRegex(ValueError, "v1-only adapter"):
                        obj.send(
                            "fixture-grant",
                            mid,
                            enc=envelope_v2(mid),
                            **kwargs,
                        )
                    self.assertEqual(self.authority_snapshot(obj), before)
        enforce.assert_not_called()
        client.send.assert_not_called()

    def test_adapter_positive_uncertain_delivery_restart_reuses_journal(self):
        obj = self.adapter()
        first = mock.Mock()
        original_calls = []
        def uncertain(to, **kw):
            original_calls.append((to, kw))
            self.assertEqual(self.query(obj, "SELECT text,enc_v FROM runtime_payloads"), [(native_payload(self.env), 1)])
            raise RuntimeError("fixture-only uncertainty")
        first.send.side_effect = uncertain
        obj.clients["send"] = first
        self.assertEqual(obj.send("fixture-grant", self.mid, enc=self.env)["outcome"], "uncertain")
        self.assertEqual(self.query(obj, "SELECT text,enc_v FROM runtime_payloads"), [(native_payload(self.env), 1)])
        restarted = self.adapter(obj.authority)
        calls = []
        second = mock.Mock()
        second.send.side_effect = lambda to, **kw: (calls.append((to, kw)) or (kw["msg_id"], True))
        restarted.clients["send"] = second
        self.assertEqual(restarted.reconcile()[0]["outcome"], "sent")
        self.assertEqual(calls, original_calls)
        self.assertEqual(calls, [("fixture-b", {"msg_id": self.mid, "enc": self.env, "enc_v": 1})])

    def test_adapter_inbox_durable_native_and_positive_redelivery(self):
        obj = self.adapter()
        now = time.time()
        message = {"id": self.mid, "from": "fixture-a", "to": "fixture-b", "topic": None,
                   "text": native_payload(self.env), "enc_v": 1, "in_reply_to": None,
                   "sent_at": now, "expires_at": now + 600}
        client = mock.Mock()
        client.poll.return_value = [message]
        client.ack.return_value = {"acked": [self.mid], "already_acked": []}
        obj.clients["receive"] = client
        self.assertEqual(obj.receive("receive")["accepted_ids"], [self.mid])
        restarted = self.adapter(obj.authority)
        restarted.clients["receive"] = client
        client.poll.return_value = [dict(message, delivery_count=2, redelivered=True)]
        self.assertEqual(restarted.receive("receive")["accepted_ids"], [self.mid])
        self.assertEqual(restarted.inbox_messages(), [message])
        self.assertEqual(self.query(obj, "SELECT grant_id,generation FROM runtime_inbox"), [("fixture-grant", 1)])

    def test_reconcile_rejects_unsupported_durable_version_before_lifecycle(self):
        obj = self.adapter()
        client = mock.Mock()
        client.send.side_effect = RuntimeError("fixture-only uncertainty")
        obj.clients["send"] = client
        self.assertEqual(obj.send("fixture-grant", self.mid, enc=self.env)["outcome"], "uncertain")
        row = self.query(obj, "SELECT res_id FROM reservations WHERE msg_id=?", (self.mid,))
        self.assertEqual(len(row), 1)
        res_id = row[0][0]
        before = obj.authority.reservation_row(res_id)
        self.assertEqual(before["state"], "failed-unknown")
        with obj.authority.authority_lock():
            c = obj.authority._connect()
            try:
                c.execute("UPDATE runtime_payloads SET enc_v=2 WHERE msg_id=?", (self.mid,))
            finally:
                c.close()
        restarted = self.adapter(obj.authority)
        refused = mock.Mock()
        restarted.clients["send"] = refused
        with self.assertRaisesRegex(ValueError, "unsupported durable payload version"):
            restarted.reconcile()
        after = obj.authority.reservation_row(res_id)
        self.assertEqual(
            (after["state"], after["attempt_count"], after["last_error"], after["updated_at"]),
            (before["state"], before["attempt_count"], before["last_error"], before["updated_at"]),
        )
        refused.send.assert_not_called()

    def test_reviewed_owner_crypto_transport_round_trip(self):
        # Reviewed secret-free helper loaded read-only; fixture seed never
        # enters the transport, adapter configuration or wire body.
        import hashlib
        reference = ROOT / "tests" / "fixtures" / "e2ee.py"
        raw = reference.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), "ebe5517464f28b34dc0662ff06ccc9e059039d64f19f6e0f1a6216b41845c90e")
        spec = importlib.util.spec_from_file_location("reviewed_owner_crypto", reference)
        crypto = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(crypto)
        import ed25519
        import secrets
        seed = secrets.token_bytes(32)  # freshly generated disposable owner-only identity
        pub = ed25519._publickey(seed)
        plain = b"synthetic native owner round-trip fixture"
        self.env = crypto.encrypt_envelope("fixture-a", "fixture-b", crypto.ed25519_pub_to_x25519_pub(pub), plain)
        self.test_adapter_sdk_relay_poll_inbox_offline_composition()
        c = __import__("sqlite3").connect(self.base / "authority" / "federation-authority.db")
        try:
            stored = json.loads(c.execute("SELECT payload FROM runtime_inbox").fetchone()[0])
        finally:
            c.close()
        self.assertEqual(stored["enc_v"], 1)
        self.assertEqual(crypto.decrypt_envelope(seed, json.loads(stored["text"]), stored["from"], stored["to"]), plain)

    def test_adapter_sdk_relay_poll_inbox_offline_composition(self):
        r = self.relay()
        sender = self.adapter()
        sdk = self.sdk()
        def transport(method, url, headers, data, timeout):
            body = json.loads(data)
            result = self.post(r, body)
            return 200, json.dumps(result).encode()
        sender.clients["send"] = sdk
        with mock.patch("clack_client.client.transport.request", side_effect=transport):
            self.assertEqual(sender.send("fixture-grant", self.mid, enc=self.env)["outcome"], "sent")
        receiver = self.adapter(sender.authority)
        client = mock.Mock()
        client.poll.return_value = r.fetch_pending("fixture-b", time.time())
        client.ack.return_value = {"acked": [self.mid], "already_acked": []}
        receiver.clients["receive"] = client
        self.assertEqual(receiver.receive("receive")["accepted_ids"], [self.mid])
        stored = receiver.inbox_messages()[0]
        self.assertEqual(json.loads(stored["text"]), self.env)
        self.assertEqual(stored["enc_v"], 1)
        self.assertEqual(stored["text"], native_payload(self.env))


if __name__ == "__main__":
    unittest.main(verbosity=2)
