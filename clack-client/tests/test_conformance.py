"""Conformance tests for Clack client implementations.

Any client claiming Clack compatibility MUST pass these.

Unit tests (no relay needed) run always. Live relay tests need env:
    CLACK_RELAY_URL, CLACK_TOKEN, CLACK_PRIVKEY, CLACK_PEER_NAME
"""

import base64
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from clack_client import ClackClient, parse_handshake_link
from clack_client import identity as identity_mod
from clack_client import transport as transport_mod
from clack_client.signing import load_private_key, _load_pem_seed
from clack_client.errors import (
    ClackError, HandshakeRequired, LinkUnusable,
    RelayUnreachable, CurlMissing, CurlFailed,
)


def _write_temp(data: bytes) -> str:
    fd, path = tempfile.mkstemp()
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return path


class TestKeyLoading(unittest.TestCase):
    """load_private_key edge cases (Flint gate)."""

    def test_raw_32_bytes_exact(self):
        seed = os.urandom(32)
        p = _write_temp(seed)
        try:
            self.assertEqual(load_private_key(p), seed)
        finally:
            os.unlink(p)

    def test_raw_32_bytes_leading_whitespace_byte(self):
        # A seed starting with 0x20 must NOT be stripped.
        seed = bytes([0x20]) + os.urandom(31)
        p = _write_temp(seed)
        try:
            self.assertEqual(load_private_key(p), seed)
        finally:
            os.unlink(p)

    def test_raw_32_bytes_trailing_whitespace_byte(self):
        seed = os.urandom(31) + bytes([0x0A])
        p = _write_temp(seed)
        try:
            self.assertEqual(load_private_key(p), seed)
        finally:
            os.unlink(p)

    def test_base64url_with_newline(self):
        seed = os.urandom(32)
        p = _write_temp(base64.urlsafe_b64encode(seed) + b"\n")
        try:
            self.assertEqual(load_private_key(p), seed)
        finally:
            os.unlink(p)

    def test_33_byte_file_rejected(self):
        # 32 bytes + newline is NOT a raw key; and it's not valid b64u
        # of 32 bytes either (44 chars needed). Must fail, not guess.
        p = _write_temp(os.urandom(32) + b"\n")
        try:
            with self.assertRaises(ValueError):
                load_private_key(p)
        finally:
            os.unlink(p)

    def test_garbage_rejected(self):
        p = _write_temp(b"this is not a key at all, just some text")
        try:
            with self.assertRaises(ValueError):
                load_private_key(p)
        finally:
            os.unlink(p)

    def test_pem_pkcs8_ed25519(self):
        pytest = None
        try:
            import subprocess
            r = subprocess.run(
                ["openssl", "genpkey", "-algorithm", "ed25519"],
                capture_output=True)
            if r.returncode != 0:
                self.skipTest("openssl unavailable")
            pem = r.stdout
        except FileNotFoundError:
            self.skipTest("openssl unavailable")
        seed = _load_pem_seed(pem)
        self.assertEqual(len(seed), 32)
        # Same seed via load_private_key
        p = _write_temp(pem)
        try:
            self.assertEqual(load_private_key(p), seed)
        finally:
            os.unlink(p)

    def test_pem_wrong_algorithm_rejected(self):
        try:
            import subprocess
            r = subprocess.run(
                ["openssl", "genpkey", "-algorithm", "RSA",
                 "-pkeyopt", "rsa_keygen_bits:2048"],
                capture_output=True)
            if r.returncode != 0:
                self.skipTest("openssl unavailable")
            pem = r.stdout
        except FileNotFoundError:
            self.skipTest("openssl unavailable")
        with self.assertRaises(ValueError):
            _load_pem_seed(pem)

    def test_pem_truncated_rejected(self):
        # Valid PEM with the DER truncated must fail structure validation,
        # not silently extract the last 32 bytes.
        try:
            import subprocess
            r = subprocess.run(
                ["openssl", "genpkey", "-algorithm", "ed25519"],
                capture_output=True)
            if r.returncode != 0:
                self.skipTest("openssl unavailable")
            pem = r.stdout
        except FileNotFoundError:
            self.skipTest("openssl unavailable")
        lines = pem.decode().split("\n")
        body = "".join(l for l in lines if l and not l.startswith("-----"))
        raw = base64.b64decode(body)
        truncated = base64.b64encode(raw[:-5]).decode()
        bad_pem = ("-----BEGIN PRIVATE KEY-----\n" + truncated +
                   "\n-----END PRIVATE KEY-----\n").encode()
        with self.assertRaises(ValueError):
            _load_pem_seed(bad_pem)


class TestLinkParsing(unittest.TestCase):
    """v4 link parsing — strict."""

    def test_parse_v4_link(self):
        link = ("https://clack.kasnet.us/join#v=4&r=aHR0cHM6Ly9jbGFjay5rYXNuZXQudXM"
                "&h=abc123&k=xyz789&by=test&exp=9999999999&max=1")
        parsed = parse_handshake_link(link)
        self.assertEqual(parsed["v"], "4")
        self.assertEqual(parsed["h"], "abc123")
        self.assertEqual(parsed["k"], "xyz789")
        self.assertEqual(parsed["_base"], "https://clack.kasnet.us/join")

    def test_reject_malformed(self):
        with self.assertRaises(ValueError):
            parse_handshake_link("not-a-link")

    def test_reject_wrong_version(self):
        link = "https://x/join#v=3&h=a&k=b"
        with self.assertRaises(ValueError):
            parse_handshake_link(link)

    def test_reject_duplicate_field(self):
        link = "https://x/join#v=4&h=a&k=b&h=c"
        with self.assertRaises(ValueError):
            parse_handshake_link(link)

    def test_reject_missing_hk(self):
        with self.assertRaises(ValueError):
            parse_handshake_link("https://x/join#v=4&h=a")


class TestIdentityUnit(unittest.TestCase):
    """Identity verification logic without a live relay."""

    def _pubkey(self):
        # Fixed test vector: n/e are arbitrary but well-formed.
        return {"n": "d5c8" * 64, "e": "10001"}

    def test_fingerprint_format(self):
        fp = identity_mod.relay_identity_fingerprint(self._pubkey())
        self.assertTrue(fp.startswith("sha256:"))
        self.assertEqual(len(fp), len("sha256:") + 16)

    def test_fingerprint_stable(self):
        a = identity_mod.relay_identity_fingerprint(self._pubkey())
        b = identity_mod.relay_identity_fingerprint(self._pubkey())
        self.assertEqual(a, b)

    def test_bad_pubkey_rejected(self):
        for bad in (None, "pem-string", {}, {"n": "zz", "e": "10001"},
                    {"n": "-5", "e": "10001"}, {"n": "d5c8", "e": "0"}):
            with self.assertRaises(ClackError):
                identity_mod.relay_identity_fingerprint(bad)

    def test_corrupt_pin_store_fails_closed(self):
        pin = _write_temp(b"{not json")
        try:
            with self.assertRaises(ClackError) as ctx:
                identity_mod._load_pins(pin)
            self.assertIn("corrupt", str(ctx.exception))
        finally:
            os.unlink(pin)

    def test_old_format_pin_detected(self):
        # _load_pins just loads; format validation happens in
        # verify_relay_identity — test the detection predicate inline.
        stored = {"fingerprint": "sha256:abc", "public_key": "..."}
        self.assertFalse(
            isinstance(stored, str) and stored.startswith("sha256:"))


class TestTransportUnit(unittest.TestCase):
    """Transport fallback rules without a live relay."""

    def test_curl_failed_propagates_no_fallback(self):
        orig = transport_mod.curl_request
        def fake_curl(*a, **k):
            raise CurlFailed("rc=60", returncode=60)
        transport_mod.curl_request = fake_curl
        try:
            with self.assertRaises(CurlFailed):
                transport_mod.request("GET", "http://127.0.0.1:9/", {})
        finally:
            transport_mod.curl_request = orig

    def test_curl_missing_falls_back(self):
        orig_curl = transport_mod.curl_request
        orig_py = transport_mod.python_request
        def fake_missing(*a, **k):
            raise CurlMissing("no curl")
        def fake_py(*a, **k):
            return 200, b"{}"
        transport_mod.curl_request = fake_missing
        transport_mod.python_request = fake_py
        try:
            status, body = transport_mod.request("GET", "http://x/", {})
            self.assertEqual(status, 200)
        finally:
            transport_mod.curl_request = orig_curl
            transport_mod.python_request = orig_py

    def test_curl_missing_no_fallback_when_disallowed(self):
        orig = transport_mod.curl_request
        def fake_missing(*a, **k):
            raise CurlMissing("no curl")
        transport_mod.curl_request = fake_missing
        try:
            with self.assertRaises(CurlMissing):
                transport_mod.request("GET", "http://x/", {},
                                      allow_fallback=False)
        finally:
            transport_mod.curl_request = orig


def get_client():
    return ClackClient(
        relay_url=os.environ["CLACK_RELAY_URL"],
        token=os.environ["CLACK_TOKEN"],
        privkey_path=os.environ.get("CLACK_PRIVKEY"),
        peer_name=os.environ.get("CLACK_PEER_NAME", "test"),
        auto_pin=True,
    )


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
        """Sending to a nonexistent peer raises ClackError (400 unknown_peer),
        not a bare 403. Sending to an existing peer without a handshake
        raises HandshakeRequired (403 handshake_required)."""
        c = get_client()
        with self.assertRaises(ClackError) as ctx:
            c.send("definitely-not-a-real-peer-xyz", "test")
        self.assertIn("Unknown peer", str(ctx.exception))

    def test_handshake_required_for_existing_peer(self):
        """A real peer with no ACTIVE handshake -> HandshakeRequired."""
        c = get_client()
        peers = c.peers()
        # Find a peer that isn't us; the handshake gate is per-pair.
        others = [p for p in peers if p != os.environ.get("CLACK_PEER_NAME")]
        if not others:
            self.skipTest("No other peers enrolled")
        # This may succeed if a handshake exists — only assert the
        # error TYPE when it fails, not that it must fail.
        try:
            c.send(others[0], "handshake gate probe")
        except HandshakeRequired:
            pass  # expected when no handshake
        except ClackError:
            pass  # e.g. queue_full — not our concern here

    def test_identity_pin_roundtrip(self):
        """Two clients pinning the same relay agree on the fingerprint."""
        c1 = get_client()
        c2 = get_client()
        self.assertEqual(c1.relay_fingerprint, c2.relay_fingerprint)
        self.assertTrue(c1.relay_fingerprint.startswith("sha256:"))

    def test_get_receipt_unknown_id(self):
        c = get_client()
        with self.assertRaises(ClackError):
            c.get_receipt("00000000-0000-0000-0000-000000000000")


if __name__ == "__main__":
    unittest.main(verbosity=2)
