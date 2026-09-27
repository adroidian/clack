"""Conformance tests for Clack client implementations.

Any client claiming Clack compatibility MUST pass these.
Run against a live relay with valid credentials in env:
    CLACK_RELAY_URL, CLACK_TOKEN, CLACK_PRIVKEY, CLACK_PEER_NAME
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from clack_client import ClackClient, parse_handshake_link
from clack_client.errors import HandshakeRequired, LinkUnusable


def get_client():
    return ClackClient(
        relay_url=os.environ["CLACK_RELAY_URL"],
        token=os.environ["CLACK_TOKEN"],
        privkey_path=os.environ.get("CLACK_PRIVKEY"),
        peer_name=os.environ.get("CLACK_PEER_NAME", "test"),
    )


class TestLinkParsing(unittest.TestCase):
    """v4 link parsing — the Sigrid bug. Every client must handle this."""

    def test_parse_v4_link(self):
        link = ("https://clack.kasnet.us/join#v=4&r=aHR0cHM6Ly9jbGFjay5rYXNuZXQudXM"
                "&h=abc123&k=xyz789&by=test&exp=9999999999&max=1")
        parsed = parse_handshake_link(link)
        self.assertEqual(parsed["v"], "4")
        self.assertEqual(parsed["h"], "abc123")
        self.assertEqual(parsed["k"], "xyz789")

    def test_reject_malformed(self):
        with self.assertRaises(ValueError):
            parse_handshake_link("not-a-link")

    def test_reject_wrong_version(self):
        link = "https://x/join#v=3&h=a&k=b"
        with self.assertRaises(ValueError):
            parse_handshake_link(link)


class TestLiveRelay(unittest.TestCase):
    """Live relay tests — skip if no credentials."""

    @classmethod
    def setUpClass(cls):
        if not os.environ.get("CLACK_RELAY_URL"):
            raise unittest.SkipTest("No relay credentials")

    def test_peers_list(self):
        c = get_client()
        peers = c.peers()
        self.assertIsInstance(peers, list)

    def test_handshake_required_error(self):
        """Sending to unknown peer must raise HandshakeRequired, not bare 403."""
        c = get_client()
        with self.assertRaises(HandshakeRequired):
            c.send("definitely-not-a-real-peer-xyz", "test")


if __name__ == "__main__":
    unittest.main(verbosity=2)
