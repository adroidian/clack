"""Static release/onboarding consistency; no credentials or public mutations."""
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "website"


class WebsiteRelease(unittest.TestCase):
    def setUp(self):
        self.discovery = json.loads((SITE / "well-known/clack-relay").read_text())
        self.version = self.discovery["version"]

    def test_recommended_cli_and_selfhost_select_current_release(self):
        relay = (SITE / "relay.html").read_text()
        selfhost = (SITE / "selfhost.html").read_text()
        self.assertIn("ClackRelay-CLI/" + self.version, relay)
        self.assertIn("git clone -b v" + self.version + " ", selfhost)
        self.assertIn("checksum-pinned v" + self.version + " source bundle", selfhost)
        self.assertNotIn("previous v1.1.0 release", selfhost)

    def test_private_invitation_consent_and_authority_are_explicit(self):
        invitation = self.discovery["private_invitations"]
        expected = {
            "bearer_authority": True,
            "share_privately_only": True,
            "prior_recipient_enrollment_required": False,
            "prior_recipient_key_exchange_required": False,
            "target_bound_at_mint": False,
            "first_proved_key_claims": True,
            "get_head_mutates": False,
            "fragment_sent_in_get": False,
            "redeem_result": "pending_only",
            "requires_separate_accept": True,
            "enc_v": 1,
            "plaintext_fallback": False,
        }
        for key, value in expected.items():
            with self.subTest(key=key):
                self.assertEqual(invitation[key], value)
        self.assertLessEqual(invitation["max_url_characters"], 120)
        self.assertEqual(invitation["max_uses"], 1)
        self.assertEqual(self.discovery["receiving"], "manual_unless_harness_has_tested_handler")
        self.assertIs(self.discovery["message_execution_authority"], False)
        self.assertIs(self.discovery["connection_requests"]["already_enrolled"], True)
        self.assertIs(self.discovery["connection_requests"]["bearer_authority"], False)

    def test_live_claims_require_corresponding_verification_flags(self):
        for key in ("deployment_verified", "public_smoke_verified"):
            self.assertIsInstance(self.discovery[key], bool)
        if self.discovery["status"] == "successor_contract":
            self.assertIs(self.discovery["deployment_verified"], False)
            self.assertIs(self.discovery["public_smoke_verified"], False)
        if self.discovery["public_smoke_verified"]:
            self.assertIs(self.discovery["deployment_verified"], True)
            self.assertEqual(self.discovery["status"], "live_release")
            self.assertEqual(self.discovery["verified_harness"], "isolated_linux_hermes")
            self.assertRegex(self.discovery["verification_date"], r"^\d{4}-\d{2}-\d{2}$")
            self.assertIs(self.discovery["external_desktop_harness_tested"], False)
            self.assertIn("Receiving was manual", (SITE / "agent-guide.md").read_text())
            self.assertIn("native Windows/macOS were not qualified", (SITE / "join.html").read_text())

    def test_no_real_private_invitation_in_public_site(self):
        secret_url = re.compile(r"https://[^\s\"'<>]+/i/[A-Za-z0-9_-]{22}#[A-Za-z0-9_-]{43}")
        paths = [path for path in SITE.rglob("*") if path.is_file()
                 and path.suffix in ("", ".html", ".md", ".txt", ".json", ".js")]
        # The agent discovery document is JSON without a filename extension.
        self.assertIn(SITE / "well-known/clack-relay", paths)
        for path in paths:
            with self.subTest(path=path.relative_to(SITE)):
                self.assertIsNone(secret_url.search(path.read_text()))


if __name__ == "__main__":
    unittest.main()
