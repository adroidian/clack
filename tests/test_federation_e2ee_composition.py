"""Focused native E2EE-over-Federation composition proof.

The runner owns and tears down two disposable loopback relays. It uses fresh
synthetic principals only and explicitly does not claim an actual agent turn.
"""
from pathlib import Path
import importlib.util
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "reviews" / "run_federation_e2ee_canary.py"
spec = importlib.util.spec_from_file_location("federation_e2ee_canary_" + uuid.uuid4().hex, RUNNER)
if spec is None or spec.loader is None:
    raise RuntimeError("composition canary runner unavailable")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
run_canary = runner.run_canary


class FederationE2EECompositionTests(unittest.TestCase):
    def test_two_relay_signed_e2ee_duplex_restart_reconcile_and_cleanup(self):
        receipt = run_canary()
        self.assertEqual(receipt["status"], "PASS")
        self.assertTrue(receipt["distinct_principals"])
        self.assertEqual(receipt["forward_initial_outcome"], "uncertain")
        self.assertEqual(receipt["forward_reconciled_outcome"], "sent")
        self.assertTrue(receipt["ciphertext_stable_across_reconcile"])
        self.assertTrue(receipt["expiry_stable_across_reconcile"])
        self.assertEqual(receipt["relay_row_counts"], {"forward": 1, "reverse": 1})
        self.assertEqual(receipt["owner_decrypt"]["wrong_principal"], "REFUSED")
        self.assertEqual(receipt["native_fail_closed_pre_wire_cases"], 3)
        self.assertEqual(receipt["unfinished_reservations"], 0)
        self.assertEqual(receipt["semantic_agent_ack"], "NOT_EXERCISED")
        self.assertEqual(receipt["actual_team_agent"], "NOT_EXERCISED")
        self.assertTrue(receipt["cleanup"]["verified"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
