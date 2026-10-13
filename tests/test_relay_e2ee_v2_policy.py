"""Relay-side v2 context and no-downgrade policy tests."""
from __future__ import annotations

import base64
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
import urllib.parse
import uuid
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


KEY_IDS = {
    "alice": {"signing": b64u(bytes([4]) * 8), "encryption": b64u(bytes([7]) * 8)},
    "bob": {"signing": b64u(bytes([8]) * 8), "encryption": b64u(bytes([3]) * 8)},
}


def trusted_v2_contexts():
    return {
        "alice": {
            "identity": "agent://alice",
            "home": "clack://ex",
            "generation": 3,
            "signing_key_id": KEY_IDS["alice"]["signing"],
            "encryption_key_id": KEY_IDS["alice"]["encryption"],
        },
        "bob": {
            "identity": "agent://bob",
            "home": "clack://omni",
            "generation": 5,
            "signing_key_id": KEY_IDS["bob"]["signing"],
            "encryption_key_id": KEY_IDS["bob"]["encryption"],
        },
    }


def import_relay(base):
    with mock.patch.dict(os.environ, {"CLACK_RELAY_BASE": str(base)}):
        spec = importlib.util.spec_from_file_location(
            "relay_v2_policy_" + uuid.uuid4().hex, ROOT / "relay.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


def load_relay(base):
    module = import_relay(base)
    cfg = {
        "peers": {"alice": "test-a", "bob": "test-b"},
        "e2ee_v2_contexts": trusted_v2_contexts(),
    }
    module.init_db(cfg)
    module.relay_cfg = cfg
    return module


def context(mid, topic="task.v2", reply=None, sender="alice", recipient="bob"):
    return {
        "id": mid,
        "sender": sender,
        "recipient": recipient,
        "sender_id": "agent://" + sender,
        "recipient_id": "agent://" + recipient,
        "topic": topic,
        "in_reply_to": reply,
        "sender_home": "clack://ex",
        "recipient_home": "clack://omni",
        "sender_home_generation": 3,
        "recipient_home_generation": 5,
    }


def v1_envelope():
    return {
        "v": 1,
        "alg": "x25519-chacha20poly1305",
        "eph": b64u(bytes([1]) * 32),
        "nonce": b64u(bytes([2]) * 12),
        "kid": b64u(bytes([3]) * 8),
        "ct": b64u(bytes([4]) * 32),
    }


def v2_envelope(mid, topic="task.v2", reply=None, sender="alice", recipient="bob"):
    return {
        "v": 2,
        "alg": "x25519-chacha20poly1305+ed25519",
        "eph": b64u(bytes([1]) * 32),
        "nonce": b64u(bytes([2]) * 12),
        "kid": KEY_IDS.get(recipient, KEY_IDS["bob"])["encryption"],
        "skid": KEY_IDS.get(sender, KEY_IDS["alice"])["signing"],
        "ctx": context(mid, topic, reply, sender, recipient),
        "ct": b64u(bytes([5]) * 32),
        "sig": b64u(bytes([6]) * 64),
    }


class RelayE2EEV2PolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="relay-v2-policy-", dir=ROOT.parent)
        self.addCleanup(self.temp.cleanup)
        self.relay = load_relay(Path(self.temp.name))
        self.addCleanup(self.relay.conn.close)
        cols = {
            row[1]
            for row in self.relay.conn.execute("PRAGMA table_info(handshakes)")
        }
        self.assertTrue(
            {"minter_enc_v", "redeemer_enc_v", "enc_capable", "enc_version"}
            <= cols
        )

    def set_pair(self, version):
        now = time.time()
        a, b = self.relay._hs_pair("alice", "bob")
        self.relay.conn.execute("DELETE FROM handshakes")
        self.relay.conn.execute(
            """INSERT INTO handshakes(
                   a_identity,b_identity,status,created_at,last_activity,
                   generation,minter_enc_v,redeemer_enc_v,enc_capable,enc_version)
               VALUES(?,?,'active',?,?,0,?,?,?,?)""",
            (a, b, now, now, version, version, 1 if version else 0, version),
        )
        self.relay.conn.commit()

    def post(self, body, peer="alice", relay=None):
        relay = self.relay if relay is None else relay
        handler = relay.Handler.__new__(relay.Handler)
        handler.path = "/v1/send"
        handler._require_auth = lambda: peer
        handler._read_json = lambda: body
        replies = []
        handler._json = lambda status, payload: replies.append((status, payload))
        with mock.patch.object(relay, "sweep"), mock.patch.object(
            relay, "maybe_notify"
        ):
            handler.do_POST()
        self.assertTrue(replies)
        return replies[-1]

    def fetch(self, in_reply_to, *, peer="alice", now=None):
        now = time.time() if now is None else now
        handler = self.relay.Handler.__new__(self.relay.Handler)
        handler.path = "/v1/fetch?in_reply_to=" + in_reply_to
        handler._require_auth = lambda: peer
        replies = []
        handler._json = lambda status, payload: replies.append((status, payload))
        with mock.patch.object(self.relay.time, "time", return_value=now):
            handler.do_GET()
        self.assertTrue(replies)
        return replies[-1]

    @staticmethod
    def database_snapshot(connection):
        return tuple(connection.iterdump())

    def test_handshake_config_rejects_nonfinite_and_nonexact_numbers_atomically(self):
        original = (
            self.relay.HS_MAX_PER_IDENTITY,
            self.relay.HS_EXPIRY_DAYS,
            self.relay.HS_INACTIVITY_DAYS,
            self.relay.MIN_ENCRYPTION_VERSION,
        )

        class IntSubclass(int):
            pass

        class FloatSubclass(float):
            pass

        invalid_values = (
            float("nan"),
            float("inf"),
            float("-inf"),
            10**400,
            IntSubclass(1),
            FloatSubclass(1.0),
            True,
            "1",
            None,
        )
        fields = (
            "max_handshakes_per_identity",
            "handshake_expiry_days",
            "handshake_inactivity_expiry_days",
        )
        try:
            for field in fields:
                for value in invalid_values:
                    with self.subTest(field=field, value=repr(value)):
                        cfg = {
                            "max_handshakes_per_identity": 4,
                            "handshake_expiry_days": 2.0,
                            "handshake_inactivity_expiry_days": 3.0,
                            "minimum_encryption_version": 2,
                        }
                        cfg[field] = value
                        with self.assertRaises(ValueError):
                            self.relay._parse_handshake_knobs(cfg)
                        self.assertEqual(
                            (
                                self.relay.HS_MAX_PER_IDENTITY,
                                self.relay.HS_EXPIRY_DAYS,
                                self.relay.HS_INACTIVITY_DAYS,
                                self.relay.MIN_ENCRYPTION_VERSION,
                            ),
                            original,
                        )
        finally:
            for name, value in zip(
                (
                    "HS_MAX_PER_IDENTITY",
                    "HS_EXPIRY_DAYS",
                    "HS_INACTIVITY_DAYS",
                    "MIN_ENCRYPTION_VERSION",
                ),
                original,
            ):
                setattr(self.relay, name, value)

    def test_config_loader_rejects_nonfinite_json_numbers(self):
        config_path = Path(self.temp.name) / "nonfinite-config.json"
        for literal in ("NaN", "Infinity", "-Infinity", "1e309"):
            with self.subTest(literal=literal):
                config_path.write_text(
                    '{"handshake_expiry_days": %s}' % literal,
                    encoding="utf-8",
                )
                with mock.patch.object(
                    self.relay,
                    "CONFIG_PATH",
                    str(config_path),
                ):
                    with self.assertRaisesRegex(ValueError, "non-finite"):
                        self.relay.load_config()

    def test_request_expiry_and_ttl_values_require_exact_finite_numbers(self):
        class IntSubclass(int):
            pass

        class FloatSubclass(float):
            pass

        invalid_values = (
            float("nan"),
            float("inf"),
            float("-inf"),
            10**400,
            IntSubclass(120),
            FloatSubclass(120.0),
            True,
            "120",
        )

        def call(method_name, body):
            handler = self.relay.Handler.__new__(self.relay.Handler)
            handler._read_json = lambda: body
            replies = []
            handler._json = lambda status, payload: replies.append((status, payload))
            try:
                getattr(handler, method_name)("alice", time.time())
            finally:
                self.relay.conn.execute("DELETE FROM invites")
                self.relay.conn.commit()
            self.assertTrue(replies)
            return replies[-1]

        for value in invalid_values:
            with self.subTest(surface="handshake-exp-days", value=repr(value)):
                status, payload = call(
                    "_handle_handshake_mint",
                    {"exp_days": value, "enc_v": 2},
                )
                self.assertEqual((status, payload.get("error")), (400, "bad_exp_days"))
            with self.subTest(surface="invite-expiry-seconds", value=repr(value)):
                status, payload = call(
                    "_handle_invite_mint",
                    {"expiry_seconds": value},
                )
                self.assertEqual(
                    (status, payload.get("error")),
                    (400, "bad_expiry_seconds"),
                )
            with self.subTest(surface="message-ttl", value=repr(value)):
                error = self.relay.Handler._validate_send(
                    str(uuid.uuid4()),
                    "bob",
                    None,
                    "payload",
                    None,
                    value,
                    "alice",
                )
                self.assertEqual(error, "bad_ttl")

    def test_malformed_persisted_handshake_rows_never_authorize_send(self):
        malformed_cases = (
            ("unknown-status", {"status": "mystery"}),
            ("negative-generation", {"generation": -1}),
            (
                "negotiation-mismatch",
                {"minter_enc_v": 1, "redeemer_enc_v": 2, "enc_version": 2},
            ),
            ("wrong-version-type", {"enc_version": "bogus"}),
            ("infinite-deadline", {"expires_at": float("inf")}),
            ("active-pending-deadline", {"pending_expires_at": time.time() + 600}),
        )
        for label, changes in malformed_cases:
            with self.subTest(label=label):
                self.set_pair(2)
                assignments = ", ".join("%s=?" % field for field in changes)
                self.relay.conn.execute(
                    "UPDATE handshakes SET " + assignments,
                    tuple(changes.values()),
                )
                self.relay.conn.commit()
                mid = str(uuid.uuid4())
                status, payload = self.post(
                    {
                        "id": mid,
                        "to": "bob",
                        "topic": "task.v2",
                        "enc": v2_envelope(mid),
                        "enc_v": 2,
                    }
                )
                self.assertEqual(
                    (status, payload.get("error")),
                    (403, "invalid_handshake_state"),
                )
                self.assertIsNone(
                    self.relay.conn.execute(
                        "SELECT 1 FROM messages WHERE id=?",
                        (mid,),
                    ).fetchone()
                )

    def test_startup_rejects_malformed_persisted_handshake_rows(self):
        base = Path(self.temp.name) / "malformed-startup"
        first = load_relay(base)
        now = time.time()
        a, b = first._hs_pair("alice", "bob")
        first.conn.execute(
            """INSERT INTO handshakes(
                   a_identity,b_identity,status,created_at,last_activity,
                   generation,minter_enc_v,redeemer_enc_v,enc_capable,enc_version)
               VALUES(?,?,'active',?,?,0,2,2,1,2)""",
            (a, b, now, now),
        )
        first.conn.commit()
        first.conn.execute("UPDATE handshakes SET status='mystery'")
        first.conn.commit()
        first.conn.close()

        with self.assertRaisesRegex(ValueError, "invalid persisted handshake"):
            load_relay(base)

    def test_full_schema_capability_mismatch_is_not_repaired_or_authorized_on_restart(self):
        base = Path(self.temp.name) / "full-schema-capability-mismatch"
        first = load_relay(base)
        now = time.time()
        a, b = first._hs_pair("alice", "bob")
        first.conn.execute(
            """INSERT INTO handshakes(
                   a_identity,b_identity,status,created_at,last_activity,
                   generation,minter_enc_v,redeemer_enc_v,enc_capable,enc_version)
               VALUES(?,?,'active',?,?,0,1,1,1,0)""",
            (a, b, now, now),
        )
        first.conn.commit()

        direct_mid = str(uuid.uuid4())
        direct_status, direct = self.post(
            {
                "id": direct_mid,
                "to": "bob",
                "enc": v1_envelope(),
                "enc_v": 1,
            },
            relay=first,
        )
        self.assertEqual(
            (direct_status, direct.get("error")),
            (403, "invalid_handshake_state"),
        )
        self.assertIsNone(
            first.conn.execute(
                "SELECT 1 FROM messages WHERE id=?", (direct_mid,)
            ).fetchone()
        )
        first.conn.close()

        cfg = {
            "peers": {"alice": "test-a", "bob": "test-b"},
            "e2ee_v2_contexts": trusted_v2_contexts(),
        }
        restarted = import_relay(base)
        restart_error = None
        restart_send = None
        restart_mid = str(uuid.uuid4())
        try:
            restarted.init_db(cfg)
        except ValueError as exc:
            restart_error = exc
            # Even if a caller catches the startup exception and manually
            # exposes the half-initialized module, the malformed row remains
            # non-authoritative at the native send boundary.
            restarted.relay_cfg = cfg
            restarted.peer_names = {"alice", "bob"}
            restart_send = self.post(
                {
                    "id": restart_mid,
                    "to": "bob",
                    "enc": v1_envelope(),
                    "enc_v": 1,
                },
                relay=restarted,
            )
        else:
            restarted.relay_cfg = cfg
            restart_send = self.post(
                {
                    "id": restart_mid,
                    "to": "bob",
                    "enc": v1_envelope(),
                    "enc_v": 1,
                },
                relay=restarted,
            )
        finally:
            if restarted.conn is not None:
                restarted.conn.close()

        with sqlite3.connect(base / "relay.db") as check:
            persisted = check.execute(
                "SELECT enc_capable,enc_version FROM handshakes"
                " WHERE a_identity=? AND b_identity=?",
                (a, b),
            ).fetchone()
            restart_message = check.execute(
                "SELECT 1 FROM messages WHERE id=?", (restart_mid,)
            ).fetchone()
        self.assertIsInstance(
            restart_error,
            ValueError,
            "restart accepted malformed full-schema authority; send=%r" % (restart_send,),
        )
        self.assertIn("invalid persisted handshake", str(restart_error))
        self.assertEqual(
            (restart_send[0], restart_send[1].get("error")),
            (403, "invalid_handshake_state"),
        )
        self.assertEqual(persisted, (1, 0))
        self.assertIsNone(restart_message)

    def test_accept_at_max_generation_is_atomic_and_refused(self):
        now = time.time()
        maximum = (1 << 63) - 1
        a, b = self.relay._hs_pair("alice", "bob")
        self.relay.conn.execute(
            """INSERT INTO handshakes(
                   a_identity,b_identity,status,created_at,pending_expires_at,
                   last_activity,redeemer_identity,generation,minter_enc_v,
                   redeemer_enc_v,enc_capable,enc_version)
               VALUES(?,?,'pending',?,?,?,?,?,2,2,0,0)""",
            (a, b, now, now + 600, now, "bob", maximum),
        )
        self.relay.conn.commit()
        before = self.database_snapshot(self.relay.conn)
        handler = self.relay.Handler.__new__(self.relay.Handler)
        handler._read_json = lambda: {
            "handshake_id": self.relay._hs_id(a, b, maximum),
            "enc_v": 2,
        }
        replies = []
        handler._json = lambda status, payload: replies.append((status, payload))

        handler._handle_handshake_accept("bob", now)

        self.assertEqual(
            (replies[-1][0], replies[-1][1].get("error")),
            (409, "handshake_generation_exhausted"),
        )
        self.assertEqual(self.database_snapshot(self.relay.conn), before)

    def test_reconsent_at_max_generation_is_atomic_and_refused(self):
        now = time.time()
        maximum = (1 << 63) - 1
        self.set_pair(2)
        self.relay.conn.execute(
            """UPDATE handshakes
               SET status='revoked', pending_expires_at=NULL,
                   redeemer_identity=NULL, generation=?""",
            (maximum,),
        )
        self.relay.conn.commit()

        handler = self.relay.Handler.__new__(self.relay.Handler)
        replies = []
        handler._json = lambda status, payload: replies.append((status, payload))
        handler._read_json = lambda: {"enc_v": 2}
        handler._handle_handshake_mint("alice", now)
        self.assertEqual(replies[-1][0], 200, replies[-1])
        fragment = urllib.parse.parse_qs(
            urllib.parse.urlsplit(replies[-1][1]["link"]).fragment
        )
        before = self.database_snapshot(self.relay.conn)

        replies.clear()
        handler.headers = {"Authorization": "Bearer fixture"}
        handler._require_auth = lambda: "bob"
        handler._client_ip = lambda: "127.0.0.1"
        handler._read_json = lambda: {
            "h": fragment["h"][0],
            "k": fragment["k"][0],
            "enc_v": 2,
        }
        caught = None
        try:
            handler._handle_handshake_redeem(now + 1)
        except Exception as exc:  # regression captures the pre-fix overflow
            caught = exc

        self.assertIsNone(caught)
        self.assertEqual(
            (replies[-1][0], replies[-1][1].get("error")),
            (409, "handshake_generation_exhausted"),
        )
        self.assertEqual(self.database_snapshot(self.relay.conn), before)

    def test_revoke_at_max_generation_is_atomic_and_refused(self):
        now = time.time()
        maximum = (1 << 63) - 1
        self.set_pair(2)
        self.relay.conn.execute(
            "UPDATE handshakes SET generation=?, via_link_id='fixture-link'",
            (maximum,),
        )
        self.relay.conn.execute(
            """INSERT INTO messages(
                   id,sender,recipient,topic,text,in_reply_to,created_at,
                   expires_at,enc_v,acked_at)
               VALUES(?,?,?,?,?,?,?,?,?,NULL)""",
            (
                str(uuid.uuid4()),
                "alice",
                "bob",
                "fixture.max-generation",
                "fixture payload",
                None,
                now,
                now + 600,
                0,
            ),
        )
        self.relay.conn.commit()
        before = self.database_snapshot(self.relay.conn)

        handler = self.relay.Handler.__new__(self.relay.Handler)
        handler._read_json = lambda: {"peer": "bob"}
        replies = []
        handler._json = lambda status, payload: replies.append((status, payload))
        handler._handle_handshake_revoke("alice", now)

        self.assertEqual(
            (replies[-1][0], replies[-1][1].get("error")),
            (409, "handshake_generation_exhausted"),
        )
        self.assertEqual(self.database_snapshot(self.relay.conn), before)

    def test_hard_expired_active_rows_are_not_live_between_sweeps(self):
        self.set_pair(2)
        now = time.time()
        expired_at = now - 1
        self.relay.conn.execute(
            """UPDATE handshakes
               SET created_at=?, last_activity=?, expires_at=?""",
            (expired_at - 10, expired_at - 5, expired_at),
        )
        self.relay.conn.commit()

        self.assertEqual(self.relay._active_handshake_count("alice"), 0)
        self.assertEqual(self.relay._active_handshake_list("alice"), [])

        handler = self.relay.Handler.__new__(self.relay.Handler)
        replies = []
        handler._json = lambda status, payload: replies.append((status, payload))
        with mock.patch.object(self.relay.time, "time", return_value=now):
            handler._handle_handshakes_list("alice")
        self.assertEqual(replies[-1][0], 200, replies[-1])
        self.assertEqual(replies[-1][1]["handshakes"][0]["status"], "revoked")

    def test_fetch_hides_hard_expired_active_history_when_sweep_is_throttled(self):
        self.set_pair(2)
        reply_to = str(uuid.uuid4())
        mid = str(uuid.uuid4())
        status, sent = self.post(
            {
                "id": mid,
                "to": "bob",
                "topic": "task.v2",
                "in_reply_to": reply_to,
                "enc": v2_envelope(mid, reply=reply_to),
                "enc_v": 2,
            }
        )
        self.assertEqual(status, 200, sent)
        now = time.time()
        self.relay.conn.execute(
            """UPDATE handshakes
               SET created_at=?, last_activity=?, expires_at=?""",
            (now - 100, now - 50, now - 1),
        )
        self.relay.conn.commit()
        self.relay._last_sweep = now

        fetch_status, fetched = self.fetch(reply_to, peer="bob", now=now)

        self.assertEqual(fetch_status, 200, fetched)
        self.assertEqual(fetched["messages"], [])
        self.assertEqual(
            self.relay.conn.execute(
                "SELECT status FROM handshakes"
            ).fetchone()[0],
            "active",
            "the regression must exercise effective expiry, not sweep mutation",
        )

    def test_fetch_fails_closed_on_malformed_active_row_when_sweep_is_throttled(self):
        self.set_pair(2)
        reply_to = str(uuid.uuid4())
        mid = str(uuid.uuid4())
        status, sent = self.post(
            {
                "id": mid,
                "to": "bob",
                "topic": "task.v2",
                "in_reply_to": reply_to,
                "enc": v2_envelope(mid, reply=reply_to),
                "enc_v": 2,
            }
        )
        self.assertEqual(status, 200, sent)
        self.relay.conn.execute("UPDATE handshakes SET enc_version=0")
        self.relay.conn.commit()
        before = self.relay.conn.execute("SELECT * FROM handshakes").fetchone()
        now = time.time()
        self.relay._last_sweep = now

        fetch_status, fetched = self.fetch(reply_to, peer="bob", now=now)

        self.assertEqual(
            (fetch_status, fetched.get("error")),
            (500, "invalid_handshake_state"),
        )
        self.assertNotIn("messages", fetched)
        self.assertEqual(
            self.relay.conn.execute("SELECT * FROM handshakes").fetchone(),
            before,
        )

    def test_fetch_preserves_valid_history_when_sweep_is_throttled(self):
        self.set_pair(2)
        reply_to = str(uuid.uuid4())
        mid = str(uuid.uuid4())
        status, sent = self.post(
            {
                "id": mid,
                "to": "bob",
                "topic": "task.v2",
                "in_reply_to": reply_to,
                "enc": v2_envelope(mid, reply=reply_to),
                "enc_v": 2,
            }
        )
        self.assertEqual(status, 200, sent)
        now = time.time()
        self.relay._last_sweep = now

        fetch_status, fetched = self.fetch(reply_to, peer="bob", now=now)

        self.assertEqual(fetch_status, 200, fetched)
        self.assertEqual([message["id"] for message in fetched["messages"]], [mid])

    def test_malformed_handshake_listing_fails_closed(self):
        self.set_pair(2)
        self.relay.conn.execute("UPDATE handshakes SET status='mystery'")
        self.relay.conn.commit()
        handler = self.relay.Handler.__new__(self.relay.Handler)
        replies = []
        handler._json = lambda status, payload: replies.append((status, payload))
        handler._handle_handshakes_list("alice")
        self.assertEqual(
            (replies[-1][0], replies[-1][1].get("error")),
            (500, "invalid_handshake_state"),
        )

    def test_accept_does_not_launder_malformed_pending_negotiation(self):
        now = time.time()
        a, b = self.relay._hs_pair("alice", "bob")
        self.relay.conn.execute(
            """INSERT INTO handshakes(
                   a_identity,b_identity,status,created_at,pending_expires_at,
                   last_activity,redeemer_identity,generation,minter_enc_v,
                   redeemer_enc_v,enc_capable,enc_version)
               VALUES(?,?,'pending',?,?,?,?,0,99,2,0,0)""",
            (a, b, now, now + 600, now, "bob"),
        )
        self.relay.conn.commit()
        before = self.relay.conn.execute(
            "SELECT * FROM handshakes WHERE a_identity=? AND b_identity=?",
            (a, b),
        ).fetchone()

        handler = self.relay.Handler.__new__(self.relay.Handler)
        handler._read_json = lambda: {
            "handshake_id": self.relay._hs_id(a, b, 0),
            "enc_v": 2,
        }
        replies = []
        handler._json = lambda status, payload: replies.append((status, payload))
        handler._handle_handshake_accept("bob", now)

        self.assertEqual(
            (replies[-1][0], replies[-1][1].get("error")),
            (500, "invalid_handshake_state"),
        )
        self.assertEqual(
            self.relay.conn.execute(
                "SELECT * FROM handshakes WHERE a_identity=? AND b_identity=?",
                (a, b),
            ).fetchone(),
            before,
        )

    def test_v2_context_snapshot_config_is_strict_and_atomic(self):
        base = {
            "peers": {"alice": "test-a", "bob": "test-b"},
            "e2ee_v2_contexts": trusted_v2_contexts(),
        }
        self.assertEqual(
            self.relay._parse_e2ee_v2_contexts(base),
            trusted_v2_contexts(),
        )
        original = self.relay._E2EE_V2_CONTEXTS

        unknown_peer = json.loads(json.dumps(base))
        unknown_peer["e2ee_v2_contexts"]["mallory"] = dict(
            unknown_peer["e2ee_v2_contexts"]["alice"]
        )
        missing_field = json.loads(json.dumps(base))
        del missing_field["e2ee_v2_contexts"]["alice"]["home"]
        duplicate_identity = json.loads(json.dumps(base))
        duplicate_identity["e2ee_v2_contexts"]["bob"]["identity"] = "agent://alice"
        bool_generation = json.loads(json.dumps(base))
        bool_generation["e2ee_v2_contexts"]["alice"]["generation"] = True
        malformed_key_id = json.loads(json.dumps(base))
        malformed_key_id["e2ee_v2_contexts"]["alice"]["signing_key_id"] = "not!base64"

        for name, bad in (
            ("not-an-object", {"peers": base["peers"], "e2ee_v2_contexts": []}),
            ("unknown-peer", unknown_peer),
            ("missing-field", missing_field),
            ("duplicate-identity", duplicate_identity),
            ("bool-generation", bool_generation),
            ("malformed-key-id", malformed_key_id),
        ):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    self.relay._init_e2ee_v2_contexts(bad)
                self.assertIs(self.relay._E2EE_V2_CONTEXTS, original)

    def test_v2_route_snapshot_persists_monotonic_generation(self):
        row = self.relay.conn.execute(
            "SELECT identity,home,generation,signing_key_id,encryption_key_id"
            " FROM e2ee_v2_contexts WHERE peer='alice'"
        ).fetchone()
        self.assertEqual(
            row,
            (
                "agent://alice",
                "clack://ex",
                3,
                KEY_IDS["alice"]["signing"],
                KEY_IDS["alice"]["encryption"],
            ),
        )

        renamed_rollback = trusted_v2_contexts()
        renamed_rollback["alice-new"] = renamed_rollback.pop("alice")
        renamed_rollback["alice-new"]["generation"] = 2
        with self.assertRaisesRegex(ValueError, "generation rollback"):
            self.relay._persist_e2ee_v2_contexts(renamed_rollback)

        renamed_same_generation = trusted_v2_contexts()
        renamed_same_generation["alice-new"] = renamed_same_generation.pop("alice")
        self.relay._persist_e2ee_v2_contexts(renamed_same_generation)
        self.assertIsNone(
            self.relay.conn.execute(
                "SELECT 1 FROM e2ee_v2_contexts WHERE peer='alice'"
            ).fetchone()
        )
        self.assertEqual(
            self.relay.conn.execute(
                "SELECT identity,generation FROM e2ee_v2_contexts"
                " WHERE peer='alice-new'"
            ).fetchone(),
            ("agent://alice", 3),
        )

        lower = trusted_v2_contexts()
        lower["alice"]["generation"] = 2
        with self.assertRaisesRegex(ValueError, "generation rollback"):
            self.relay._persist_e2ee_v2_contexts(lower)

        rewritten = trusted_v2_contexts()
        rewritten["alice"]["home"] = "clack://rewritten-at-same-generation"
        with self.assertRaisesRegex(ValueError, "same generation"):
            self.relay._persist_e2ee_v2_contexts(rewritten)

        advanced = trusted_v2_contexts()
        advanced["alice"]["generation"] = 4
        advanced["alice"]["home"] = "clack://new-ex"
        self.relay._persist_e2ee_v2_contexts(advanced)
        row = self.relay.conn.execute(
            "SELECT identity,home,generation FROM e2ee_v2_contexts WHERE peer='alice'"
        ).fetchone()
        self.assertEqual(row, ("agent://alice", "clack://new-ex", 4))

    def test_v2_pair_refuses_plaintext_and_v1_downgrade(self):
        self.set_pair(2)
        status, out = self.post(
            {"id": str(uuid.uuid4()), "to": "bob", "text": "plaintext"}
        )
        self.assertEqual((status, out.get("error"), out.get("minimum_enc_v")),
                         (400, "encryption_required", 2))
        status, out = self.post(
            {"id": str(uuid.uuid4()), "to": "bob", "enc": v1_envelope(), "enc_v": 1}
        )
        self.assertEqual((status, out.get("error"), out.get("minimum_enc_v")),
                         (400, "encryption_required", 2))

    def test_v2_outer_context_is_bound_and_exact_retry_is_idempotent(self):
        self.set_pair(2)
        mid = str(uuid.uuid4())
        reply = str(uuid.uuid4())
        envelope = v2_envelope(mid, "task.v2", reply)
        body = {
            "id": mid,
            "to": "bob",
            "topic": "task.v2",
            "in_reply_to": reply,
            "enc": envelope,
            "enc_v": 2,
        }
        status, out = self.post(body)
        self.assertEqual(status, 200, out)
        self.assertTrue(out["accepted"])
        row = self.relay.conn.execute(
            "SELECT sender,recipient,topic,in_reply_to,text,enc_v FROM messages WHERE id=?",
            (mid,),
        ).fetchone()
        self.assertEqual(row[:4], ("alice", "bob", "task.v2", reply))
        self.assertEqual(row[5], 2)
        self.assertEqual(json.loads(row[4]), envelope)

        status, duplicate = self.post(dict(body))
        self.assertEqual(status, 200, duplicate)
        self.assertTrue(duplicate["duplicate"])

        changed = json.loads(json.dumps(body))
        changed["enc"]["ct"] = b64u(bytes([9]) * 32)
        status, collision = self.post(changed)
        self.assertEqual((status, collision.get("error")), (409, "id_collision"))

    def test_v2_context_substitution_is_rejected_before_storage(self):
        self.set_pair(2)
        cases = [
            ("topic", "task.outer", "task.signed", None, None, "alice", "bob"),
            (
                "reply",
                "task.v2",
                "task.v2",
                str(uuid.uuid4()),
                str(uuid.uuid4()),
                "alice",
                "bob",
            ),
            ("sender", "task.v2", "task.v2", None, None, "mallory", "bob"),
            ("recipient", "task.v2", "task.v2", None, None, "alice", "carol"),
        ]
        for (
            name,
            outer_topic,
            signed_topic,
            outer_reply,
            signed_reply,
            sender,
            recipient,
        ) in cases:
            with self.subTest(name=name):
                mid = str(uuid.uuid4())
                env = v2_envelope(mid, signed_topic, signed_reply, sender, recipient)
                body = {"id": mid, "to": "bob", "topic": outer_topic,
                        "in_reply_to": outer_reply, "enc": env, "enc_v": 2}
                status, out = self.post(body)
                self.assertEqual((status, out.get("error")), (400, "bad_enc_context"))
                self.assertIsNone(
                    self.relay.conn.execute(
                        "SELECT 1 FROM messages WHERE id=?", (mid,)
                    ).fetchone()
                )

    def test_v2_stable_identity_and_home_context_matches_trusted_snapshot(self):
        self.set_pair(2)
        changes = {
            "sender_id": "agent://mallory",
            "recipient_id": "agent://carol",
            "sender_home": "clack://wrong-ex",
            "recipient_home": "clack://wrong-omni",
            "sender_home_generation": 4,
            "recipient_home_generation": 6,
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                mid = str(uuid.uuid4())
                env = v2_envelope(mid)
                env["ctx"][field] = value
                status, out = self.post(
                    {
                        "id": mid,
                        "to": "bob",
                        "topic": "task.v2",
                        "enc": env,
                        "enc_v": 2,
                    }
                )
                self.assertEqual(
                    (status, out.get("error")),
                    (400, "bad_enc_context"),
                )
                self.assertIsNone(
                    self.relay.conn.execute(
                        "SELECT 1 FROM messages WHERE id=?", (mid,)
                    ).fetchone()
                )

    def test_v2_refuses_missing_trusted_context_snapshot(self):
        self.set_pair(2)
        self.relay._E2EE_V2_CONTEXTS = {}
        mid = str(uuid.uuid4())
        status, out = self.post(
            {
                "id": mid,
                "to": "bob",
                "topic": "task.v2",
                "enc": v2_envelope(mid),
                "enc_v": 2,
            }
        )
        self.assertEqual(
            (status, out.get("error")),
            (400, "e2ee_context_untrusted"),
        )
        self.assertIsNone(
            self.relay.conn.execute(
                "SELECT 1 FROM messages WHERE id=?", (mid,)
            ).fetchone()
        )

    def test_v2_binds_sender_and_recipient_key_ids_to_trusted_snapshot(self):
        self.set_pair(2)
        for field, value in (
            ("skid", b64u(bytes([9]) * 8)),
            ("kid", b64u(bytes([10]) * 8)),
        ):
            with self.subTest(field=field):
                mid = str(uuid.uuid4())
                env = v2_envelope(mid)
                env[field] = value
                status, out = self.post(
                    {
                        "id": mid,
                        "to": "bob",
                        "topic": "task.v2",
                        "enc": env,
                        "enc_v": 2,
                    }
                )
                self.assertEqual(
                    (status, out.get("error")),
                    (400, "bad_enc_key_binding"),
                )
                self.assertIsNone(
                    self.relay.conn.execute(
                        "SELECT 1 FROM messages WHERE id=?", (mid,)
                    ).fetchone()
                )

    def test_exact_retry_survives_trusted_route_rotation(self):
        self.set_pair(2)
        mid = str(uuid.uuid4())
        body = {
            "id": mid,
            "to": "bob",
            "topic": "task.v2",
            "enc": v2_envelope(mid),
            "enc_v": 2,
        }
        status, first = self.post(body)
        self.assertEqual(status, 200, first)
        self.relay._E2EE_V2_CONTEXTS["alice"]["generation"] += 1

        status, duplicate = self.post(body)
        self.assertEqual(status, 200, duplicate)
        self.assertTrue(duplicate["duplicate"])

        new_mid = str(uuid.uuid4())
        stale = dict(body, id=new_mid, enc=v2_envelope(new_mid))
        status, rejected = self.post(stale)
        self.assertEqual(
            (status, rejected.get("error")),
            (400, "bad_enc_context"),
        )

    def test_v2_does_not_normalize_empty_outer_context_fields(self):
        self.set_pair(2)
        for field in ("topic", "in_reply_to"):
            with self.subTest(field=field):
                mid = str(uuid.uuid4())
                body = {
                    "id": mid,
                    "to": "bob",
                    "enc": v2_envelope(mid, topic=None, reply=None),
                    "enc_v": 2,
                    field: "",
                }
                status, out = self.post(body)
                self.assertEqual(
                    (status, out.get("error")),
                    (400, "bad_enc_context"),
                )
                self.assertIsNone(
                    self.relay.conn.execute(
                        "SELECT 1 FROM messages WHERE id=?", (mid,)
                    ).fetchone()
                )

    def test_sender_cannot_use_version_above_negotiated_pair(self):
        self.set_pair(1)
        mid = str(uuid.uuid4())
        status, out = self.post(
            {"id": mid, "to": "bob", "topic": "task.v2",
             "enc": v2_envelope(mid), "enc_v": 2}
        )
        self.assertEqual(
            (status, out.get("error"), out.get("maximum_enc_v")),
            (409, "encryption_version_not_negotiated", 1),
        )

    def test_v1_capable_live_row_migrates_to_enc_version_without_rewrite(self):
        base = Path(self.temp.name) / "legacy-v1"
        base.mkdir()
        legacy = sqlite3.connect(base / "relay.db")
        legacy.executescript(
            """CREATE TABLE handshakes(
                   a_identity TEXT NOT NULL,
                   b_identity TEXT NOT NULL,
                   status TEXT NOT NULL,
                   created_at REAL NOT NULL,
                   pending_expires_at REAL,
                   expires_at REAL,
                   last_activity REAL NOT NULL,
                   via_link_id TEXT,
                   redeemer_identity TEXT,
                   generation INTEGER NOT NULL DEFAULT 0,
                   minter_enc_v INTEGER NOT NULL DEFAULT 0,
                   redeemer_enc_v INTEGER NOT NULL DEFAULT 0,
                   enc_capable INTEGER NOT NULL DEFAULT 0,
                   PRIMARY KEY(a_identity,b_identity));
               INSERT INTO handshakes(
                   a_identity,b_identity,status,created_at,last_activity,
                   minter_enc_v,redeemer_enc_v,enc_capable)
               VALUES('alice','bob','active',1.0,2.0,1,1,1);"""
        )
        legacy.commit()
        legacy.close()

        migrated = load_relay(base)
        self.addCleanup(migrated.conn.close)
        row = migrated.conn.execute(
            "SELECT a_identity,b_identity,status,created_at,last_activity,"
            " minter_enc_v,redeemer_enc_v,enc_capable,enc_version"
            " FROM handshakes"
        ).fetchone()
        self.assertEqual(
            row,
            ("alice", "bob", "active", 1.0, 2.0, 1, 1, 1, 1),
        )

    def test_full_handshake_flow_persists_both_v2_advertisements(self):
        now = time.time()
        handler = self.relay.Handler.__new__(self.relay.Handler)
        replies = []
        handler._json = lambda status, payload: replies.append((status, payload))
        handler._read_json = lambda: {"enc_v": 2}
        handler._handle_handshake_mint("alice", now)
        self.assertEqual(replies[-1][0], 200, replies[-1])
        fragment = urllib.parse.parse_qs(
            urllib.parse.urlsplit(replies[-1][1]["link"]).fragment
        )

        replies.clear()
        handler.headers = {"Authorization": "Bearer fixture"}
        handler._require_auth = lambda: "bob"
        handler._client_ip = lambda: "127.0.0.1"
        handler._read_json = lambda: {
            "h": fragment["h"][0],
            "k": fragment["k"][0],
            "enc_v": 2,
        }
        handler._handle_handshake_redeem(now + 1)
        self.assertEqual(replies[-1][0], 200, replies[-1])
        handshake_id = replies[-1][1]["handshake_id"]

        replies.clear()
        handler._read_json = lambda: {"handshake_id": handshake_id, "enc_v": 2}
        handler._handle_handshake_accept("bob", now + 2)
        self.assertEqual(replies[-1][0], 200, replies[-1])
        self.assertEqual(replies[-1][1]["enc_version"], 2)
        row = self.relay.conn.execute(
            "SELECT minter_enc_v,redeemer_enc_v,enc_capable,enc_version"
            " FROM handshakes"
        ).fetchone()
        self.assertEqual(row, (2, 2, 1, 2))

    def test_accept_refuses_elapsed_hard_expiry_between_sweeps(self):
        now = time.time()
        a, b = self.relay._hs_pair("alice", "bob")
        self.relay.conn.execute(
            """INSERT INTO handshakes(
                   a_identity,b_identity,status,created_at,pending_expires_at,
                   expires_at,last_activity,redeemer_identity,generation,
                   minter_enc_v,redeemer_enc_v,enc_capable,enc_version)
               VALUES(?,?,'pending',?,?,?,?,?,0,2,2,0,0)""",
            (a, b, now - 10, now + 600, now - 1, now - 10, "bob"),
        )
        self.relay.conn.commit()

        handler = self.relay.Handler.__new__(self.relay.Handler)
        handler._read_json = lambda: {
            "handshake_id": self.relay._hs_id(a, b, 0),
            "enc_v": 2,
        }
        replies = []
        handler._json = lambda status, payload: replies.append((status, payload))
        handler._handle_handshake_accept("bob", now)

        self.assertEqual(
            (replies[-1][0], replies[-1][1].get("error")),
            (410, "handshake_expired"),
        )
        self.assertNotEqual(
            self.relay.conn.execute(
                "SELECT status FROM handshakes WHERE a_identity=? AND b_identity=?",
                (a, b),
            ).fetchone()[0],
            "active",
        )

    def test_accept_does_not_report_hard_expired_active_consent_as_live(self):
        now = time.time()
        a, b = self.relay._hs_pair("alice", "bob")
        self.relay.conn.execute(
            """INSERT INTO handshakes(
                   a_identity,b_identity,status,created_at,pending_expires_at,
                   expires_at,last_activity,redeemer_identity,generation,
                   minter_enc_v,redeemer_enc_v,enc_capable,enc_version)
               VALUES(?,?,'active',?,NULL,?,?,NULL,0,2,2,1,2)""",
            (a, b, now - 10, now - 1, now - 10),
        )
        self.relay.conn.commit()

        handler = self.relay.Handler.__new__(self.relay.Handler)
        handler._read_json = lambda: {
            "handshake_id": self.relay._hs_id(a, b, 0),
            "enc_v": 2,
        }
        replies = []
        handler._json = lambda status, payload: replies.append((status, payload))
        handler._handle_handshake_accept("bob", now)

        self.assertEqual(
            (replies[-1][0], replies[-1][1].get("error")),
            (410, "handshake_expired"),
        )

    def test_redeem_hard_expired_pending_starts_fresh_generation_between_sweeps(self):
        now = time.time()
        handler = self.relay.Handler.__new__(self.relay.Handler)
        replies = []
        handler._json = lambda status, payload: replies.append((status, payload))

        def mint():
            replies.clear()
            handler._read_json = lambda: {"enc_v": 2}
            handler._handle_handshake_mint("alice", now)
            self.assertEqual(replies[-1][0], 200, replies[-1])
            return urllib.parse.parse_qs(
                urllib.parse.urlsplit(replies[-1][1]["link"]).fragment
            )

        def redeem(fragment):
            replies.clear()
            handler.headers = {"Authorization": "Bearer fixture"}
            handler._require_auth = lambda: "bob"
            handler._client_ip = lambda: "127.0.0.1"
            handler._read_json = lambda: {
                "h": fragment["h"][0],
                "k": fragment["k"][0],
                "enc_v": 2,
            }
            handler._handle_handshake_redeem(now + 1)
            self.assertEqual(replies[-1][0], 200, replies[-1])
            return replies[-1][1]["handshake_id"]

        old_id = redeem(mint())
        self.assertTrue(old_id.endswith("|0"), old_id)
        expired_at = time.time() - 1
        self.relay.conn.execute(
            """UPDATE handshakes
               SET created_at=?, last_activity=?, expires_at=?,
                   pending_expires_at=?""",
            (expired_at - 10, expired_at - 5, expired_at, time.time() + 600),
        )
        self.relay.conn.commit()

        new_id = redeem(mint())
        self.assertNotEqual(new_id, old_id)
        self.assertTrue(new_id.endswith("|1"), new_id)
        self.assertEqual(
            self.relay.conn.execute(
                "SELECT status,generation FROM handshakes"
            ).fetchone(),
            ("pending", 1),
        )

    def test_fresh_consent_after_expiry_gets_a_new_generation(self):
        now = time.time()
        handler = self.relay.Handler.__new__(self.relay.Handler)
        replies = []
        handler._json = lambda status, payload: replies.append((status, payload))

        def mint(enc_v):
            replies.clear()
            handler._read_json = lambda: {"enc_v": enc_v}
            handler._handle_handshake_mint("alice", now)
            self.assertEqual(replies[-1][0], 200, replies[-1])
            return urllib.parse.parse_qs(
                urllib.parse.urlsplit(replies[-1][1]["link"]).fragment
            )

        def redeem(fragment, enc_v):
            replies.clear()
            handler.headers = {"Authorization": "Bearer fixture"}
            handler._require_auth = lambda: "bob"
            handler._client_ip = lambda: "127.0.0.1"
            handler._read_json = lambda: {
                "h": fragment["h"][0],
                "k": fragment["k"][0],
                "enc_v": enc_v,
            }
            handler._handle_handshake_redeem(now + 1)
            self.assertEqual(replies[-1][0], 200, replies[-1])
            return replies[-1][1]["handshake_id"]

        def accept(handshake_id, enc_v):
            replies.clear()
            handler._read_json = lambda: {
                "handshake_id": handshake_id,
                "enc_v": enc_v,
            }
            handler._handle_handshake_accept("bob", now + 2)
            return replies[-1]

        old_id = redeem(mint(2), 2)
        status, active = accept(old_id, 2)
        self.assertEqual(status, 200, active)
        self.assertEqual(active["enc_version"], 2)

        expired_at = time.time() - 1
        self.relay.conn.execute(
            """UPDATE handshakes
               SET created_at=?, last_activity=?, expires_at=?""",
            (expired_at - 10, expired_at - 5, expired_at),
        )
        self.relay.conn.commit()
        self.relay.HS_EXPIRY_DAYS = 1
        self.relay._last_sweep = 0.0
        self.relay.sweep(time.time())
        self.assertEqual(
            self.relay.conn.execute(
                "SELECT status,generation,enc_version FROM handshakes"
            ).fetchone(),
            ("revoked", 0, 2),
        )

        new_id = redeem(mint(1), 1)
        self.assertNotEqual(new_id, old_id)
        self.assertTrue(new_id.endswith("|1"), new_id)

        status, stale = accept(old_id, 2)
        self.assertEqual((status, stale.get("error")), (409, "stale_generation"))
        status, renewed = accept(new_id, 1)
        self.assertEqual(status, 200, renewed)
        self.assertEqual((renewed["generation"], renewed["enc_version"]), (1, 1))

    def test_accept_negotiates_minimum_and_never_downgrades_active_generation(self):
        now = time.time()
        a, b = self.relay._hs_pair("alice", "bob")
        self.relay.conn.execute(
            """INSERT INTO handshakes(
                   a_identity,b_identity,status,created_at,pending_expires_at,
                   last_activity,redeemer_identity,generation,minter_enc_v)
               VALUES(?,?,'pending',?,?,?,?,0,2)""",
            (a, b, now, now + 600, now, "bob"),
        )
        self.relay.conn.commit()
        hid = self.relay._hs_id(a, b, 0)

        handler = self.relay.Handler.__new__(self.relay.Handler)
        handler._read_json = lambda: {"handshake_id": hid, "enc_v": 2}
        replies = []
        handler._json = lambda status, payload: replies.append((status, payload))
        handler._handle_handshake_accept("bob", now)
        self.assertEqual(replies[-1][0], 200, replies[-1])
        self.assertEqual(replies[-1][1]["enc_version"], 2)

        replies.clear()
        handler._read_json = lambda: {"handshake_id": hid, "enc_v": 1}
        handler._handle_handshake_accept("bob", now + 1)
        self.assertEqual(replies[-1][0], 200, replies[-1])
        self.assertEqual(replies[-1][1]["enc_version"], 2)
        row = self.relay.conn.execute(
            "SELECT minter_enc_v,redeemer_enc_v,enc_version FROM handshakes"
        ).fetchone()
        self.assertEqual(row, (2, 2, 2))


if __name__ == "__main__":
    unittest.main(verbosity=2)
