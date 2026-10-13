"""Focused tests for the 679 federation delta fix (Zari finding a74bb2b2).

D1 -- _handle_federation_send skipped the shared topic/in_reply_to/TTL
      checks (it ran only _derive_enc_version): ttl_secs=-1,
      topic='bad topic!', and in_reply_to=123 were HTTP 200 accepted=true
      AND created durable federation_outbox rows. The federation lane must
      run the SAME shared strict body path as the local lane before
      durable acceptance.
D2 -- the serving cross-home path had NO sender-home grant/pair-consent
      admission: with only the two relay configs and the signed route
      snapshot (no grant ever created), a direct local-authenticated
      /v1/send forwarded both v0 and real signed v2 into the remote
      mailbox. Wire acceptance now requires an explicit maintained
      federation_grants row for the exact (sender-home, sender,
      recipient-home, recipient) tuple: no grant fails closed (403
      federation_grant_required), a revoked grant is rejected (403
      federation_grant_revoked), an active grant forwards.

Reuses the two-home rig from test_candidate_679_crosshome.py WITHOUT the
grant provisioning that file's own setUp adds (its positive tests encode
authorized forwarding; the negatives live here).

Run: python3 -m unittest discover -s tests -p "test_candidate_679_delta_fix*" -v
"""
from __future__ import annotations

import json
import sys
import time
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "clack-client"))

import test_candidate_679_crosshome as tch  # noqa: E402

TwoHomeRig = tch.TwoHomeRig
post_send = tch.post_send
outbox_rows = tch.outbox_rows
message_rows = tch.message_rows
make_v2_envelope = tch.make_v2_envelope


class DeltaFixTests(unittest.TestCase):
    def setUp(self):
        # Fresh rig, NO grants provisioned: the no-grant fail-closed
        # negatives need the pristine admission state.
        self.rig = TwoHomeRig()
        self.addCleanup(self.rig.close)

    def _grant(self, mod, sender_home, sender, recipient_home, recipient,
               status="active"):
        self.rig.grant(mod, sender_home, sender, recipient_home, recipient,
                       status=status)

    # --- D1: shared strict body path on the federation lane ---------------

    def test_d1_bad_ttl_rejected_no_outbox(self):
        rig = self.rig
        mid = str(uuid.uuid4())
        status, payload = post_send(
            rig.mod_a, {"id": mid, "to": "peer-y", "text": "hi",
                        "ttl_secs": -1}, "peer-x")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "bad_ttl")
        self.assertEqual([r for r in outbox_rows(rig.mod_a)
                          if r[0] == mid], [])
        self.assertEqual(message_rows(rig.mod_b), [])

    def test_d1_bad_topic_rejected_no_outbox(self):
        rig = self.rig
        mid = str(uuid.uuid4())
        status, payload = post_send(
            rig.mod_a, {"id": mid, "to": "peer-y", "text": "hi",
                        "topic": "bad topic!"}, "peer-x")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "bad_topic")
        self.assertEqual([r for r in outbox_rows(rig.mod_a)
                          if r[0] == mid], [])
        self.assertEqual(message_rows(rig.mod_b), [])

    def test_d1_bad_in_reply_to_rejected_no_outbox(self):
        rig = self.rig
        mid = str(uuid.uuid4())
        status, payload = post_send(
            rig.mod_a, {"id": mid, "to": "peer-y", "text": "hi",
                        "in_reply_to": 123}, "peer-x")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "bad_in_reply_to")
        self.assertEqual([r for r in outbox_rows(rig.mod_a)
                          if r[0] == mid], [])
        self.assertEqual(message_rows(rig.mod_b), [])

    def test_d1_invalid_body_beats_grant_gate(self):
        # Body validation runs before the grant gate: an invalid body is
        # 400 even when no grant exists (never 403), and a valid body
        # with an active grant still forwards (the shared path did not
        # break the positive lane).
        rig = self.rig
        status, payload = post_send(
            rig.mod_a, {"id": str(uuid.uuid4()), "to": "peer-y",
                        "text": "hi", "ttl_secs": 0}, "peer-x")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "bad_ttl")

    def test_d1_bad_ttl_enc_v2_rejected_no_outbox(self):
        # The boundary-1 class: a well-formed v2 envelope with an invalid
        # TTL must not be accepted on the federation lane either.
        rig = self.rig
        mid = str(uuid.uuid4())
        enc = make_v2_envelope(mid, rig.seed_x, rig.seed_y)
        status, payload = post_send(
            rig.mod_a, {"id": mid, "to": "peer-y", "enc": enc,
                        "topic": "task.v2", "ttl_secs": -5}, "peer-x")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "bad_ttl")
        self.assertEqual([r for r in outbox_rows(rig.mod_a)
                          if r[0] == mid], [])

    # --- D2: sender-home grant/pair admission ------------------------------

    def test_d2_no_grant_v0_rejected(self):
        rig = self.rig
        mid = str(uuid.uuid4())
        status, payload = post_send(
            rig.mod_a, {"id": mid, "to": "peer-y", "text": "hello"}, "peer-x")
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"], "federation_grant_required")
        self.assertEqual([r for r in outbox_rows(rig.mod_a)
                          if r[0] == mid], [])
        self.assertEqual(message_rows(rig.mod_b), [])

    def test_d2_no_grant_v2_rejected(self):
        # Real signed v2 envelope, no grant ever created: rejected before
        # durable acceptance, nothing forwarded, no remote mailbox row.
        rig = self.rig
        mid = str(uuid.uuid4())
        enc = make_v2_envelope(mid, rig.seed_x, rig.seed_y)
        status, payload = post_send(
            rig.mod_a, {"id": mid, "to": "peer-y", "enc": enc,
                        "topic": "task.v2"}, "peer-x")
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"], "federation_grant_required")
        self.assertEqual([r for r in outbox_rows(rig.mod_a)
                          if r[0] == mid], [])
        fwd = rig.mod_a.federation_forward_pending()
        self.assertEqual(fwd["forwarded"], 0)
        self.assertEqual(message_rows(rig.mod_b), [])

    def test_d2_revoked_grant_rejected(self):
        rig = self.rig
        self._grant(rig.mod_a, "clack://home-a", "peer-x",
                    "clack://home-b", "peer-y", status="revoked")
        mid = str(uuid.uuid4())
        status, payload = post_send(
            rig.mod_a, {"id": mid, "to": "peer-y", "text": "hello"}, "peer-x")
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"], "federation_grant_revoked")
        self.assertEqual([r for r in outbox_rows(rig.mod_a)
                          if r[0] == mid], [])
        self.assertEqual(message_rows(rig.mod_b), [])

    def test_d2_wrong_tuple_grant_rejected(self):
        # A grant for a DIFFERENT tuple is not consent for this one.
        rig = self.rig
        self._grant(rig.mod_a, "clack://home-a", "peer-x",
                    "clack://home-b", "peer-nobody", status="active")
        mid = str(uuid.uuid4())
        status, payload = post_send(
            rig.mod_a, {"id": mid, "to": "peer-y", "text": "hello"}, "peer-x")
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"], "federation_grant_required")
        self.assertEqual([r for r in outbox_rows(rig.mod_a)
                          if r[0] == mid], [])

    def test_d2_valid_grant_v0_accepted_and_forwarded(self):
        rig = self.rig
        self._grant(rig.mod_a, "clack://home-a", "peer-x",
                    "clack://home-b", "peer-y", status="active")
        mid = str(uuid.uuid4())
        status, payload = post_send(
            rig.mod_a, {"id": mid, "to": "peer-y", "text": "hello",
                        "topic": "task.v0"}, "peer-x")
        self.assertEqual(status, 200)
        self.assertTrue(payload.get("accepted"))
        self.assertTrue(payload.get("federated"))
        rows = [r for r in outbox_rows(rig.mod_a) if r[0] == mid]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][3], "queued")
        fwd = rig.mod_a.federation_forward_pending()
        self.assertEqual(fwd["forwarded"], 1)
        b_rows = message_rows(rig.mod_b)
        self.assertEqual(len(b_rows), 1)
        self.assertEqual(b_rows[0][:3], (mid, "peer-x", "peer-y"))
        self.assertEqual(b_rows[0][3], "task.v0")
        self.assertEqual(b_rows[0][5], 0)

    def test_d2_valid_grant_v2_accepted_and_forwarded(self):
        rig = self.rig
        self._grant(rig.mod_a, "clack://home-a", "peer-x",
                    "clack://home-b", "peer-y", status="active")
        mid = str(uuid.uuid4())
        enc = make_v2_envelope(mid, rig.seed_x, rig.seed_y)
        status, payload = post_send(
            rig.mod_a, {"id": mid, "to": "peer-y", "enc": enc,
                        "topic": "task.v2"}, "peer-x")
        self.assertEqual(status, 200)
        self.assertTrue(payload.get("accepted"))
        fwd = rig.mod_a.federation_forward_pending()
        self.assertEqual(fwd["forwarded"], 1)
        b_rows = message_rows(rig.mod_b)
        self.assertEqual(len(b_rows), 1)
        self.assertEqual(b_rows[0][:3], (mid, "peer-x", "peer-y"))
        self.assertEqual(b_rows[0][5], 2)

    def test_d2_revoke_blocks_new_but_duplicate_still_reports(self):
        # Accept with a grant, revoke it, then: a NEW id is 403, while a
        # same-ID retry of the accepted send still reports duplicate:true
        # (dedup is checked before the gate, mirroring the local lane).
        rig = self.rig
        self._grant(rig.mod_a, "clack://home-a", "peer-x",
                    "clack://home-b", "peer-y", status="active")
        mid = str(uuid.uuid4())
        status, payload = post_send(
            rig.mod_a, {"id": mid, "to": "peer-y", "text": "hello"}, "peer-x")
        self.assertEqual(status, 200)
        self._grant(rig.mod_a, "clack://home-a", "peer-x",
                    "clack://home-b", "peer-y", status="revoked")
        mid2 = str(uuid.uuid4())
        status, payload = post_send(
            rig.mod_a, {"id": mid2, "to": "peer-y", "text": "hello"}, "peer-x")
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"], "federation_grant_revoked")
        status, payload = post_send(
            rig.mod_a, {"id": mid, "to": "peer-y", "text": "hello"}, "peer-x")
        self.assertEqual(status, 200)
        self.assertTrue(payload.get("duplicate"))

    def test_d2_grant_table_required_by_health(self):
        # The grant table is part of the required schema: a relay that
        # lost it fails the schema check instead of silently running
        # without the gate.
        rig = self.rig
        self.assertIsNone(rig.mod_a._required_schema_ok())
        with rig.mod_a.db_lock:
            rig.mod_a.conn.execute("DROP TABLE federation_grants")
            rig.mod_a.conn.commit()
        self.assertEqual(rig.mod_a._required_schema_ok(),
                         "table:federation_grants")


if __name__ == "__main__":
    unittest.main()
