"""Restart behavior for config-managed peer rows."""

import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class ConfigPeerRestartPreservationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="clack-config-peer-restart-")
        self.addCleanup(self.temp.cleanup)
        with mock.patch.dict(os.environ, {"CLACK_RELAY_BASE": self.temp.name}):
            spec = importlib.util.spec_from_file_location(
                "config_peer_restart_relay", ROOT / "relay.py"
            )
            if spec is None or spec.loader is None:
                raise RuntimeError("relay import spec unavailable")
            self.r = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.r)
        self.addCleanup(lambda: self.r.conn.close())

    def test_restart_refreshes_authority_fields_without_replacing_row(self):
        self.r.init_db({"peers": {"alice": "token-one", "bob": "token-bob"}})
        with self.r.conn:
            self.r.conn.execute(
                "UPDATE peers SET last_poll_at=?, last_send_at=?, display_name=?, "
                "enroll_ip=?, invited_by=? WHERE name='alice'",
                (11.5, 22.5, "Alice", "127.0.0.1", "operator"),
            )
        before = self.r.conn.execute(
            "SELECT rowid, created_at, last_poll_at, last_send_at, display_name, "
            "enroll_ip, invited_by FROM peers WHERE name='alice'"
        ).fetchone()

        # init_db opens a new connection; close the previous one as a real
        # restart would, especially before Windows temporary-directory cleanup.
        self.r.conn.close()
        self.r.init_db({"peers": {"alice": "token-two", "bob": "token-bob"}})

        after = self.r.conn.execute(
            "SELECT rowid, created_at, last_poll_at, last_send_at, display_name, "
            "enroll_ip, invited_by, token_hash, enroll_gate "
            "FROM peers WHERE name='alice'"
        ).fetchone()
        self.assertEqual(after[:7], before)
        self.assertEqual(
            after[7], hashlib.sha256(b"token-two").hexdigest()
        )
        self.assertEqual(after[8], "config")

    def test_config_name_collision_with_enrolled_peer_fails_without_takeover(self):
        self.r.init_db({"peers": {"alice": "token-one"}})
        original_hash = hashlib.sha256(b"dynamic-token").hexdigest()
        with self.r.conn:
            self.r.conn.execute(
                "INSERT INTO peers(name, token_hash, created_at, enroll_gate) "
                "VALUES(?,?,?,?)",
                ("dynamic", original_hash, 123.0, "public"),
            )
        before = self.r.conn.execute(
            "SELECT rowid, token_hash, created_at, enroll_gate "
            "FROM peers WHERE name='dynamic'"
        ).fetchone()

        self.r.conn.close()
        with self.assertRaisesRegex(
            SystemExit, "config-managed peer name collides with an enrolled peer"
        ):
            self.r.init_db(
                {"peers": {"alice": "token-one", "dynamic": "config-token"}}
            )

        after = self.r.conn.execute(
            "SELECT rowid, token_hash, created_at, enroll_gate "
            "FROM peers WHERE name='dynamic'"
        ).fetchone()
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()
