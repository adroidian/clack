"""Offline public-request SDK, standalone CLI and MCP contract tests."""
import base64
import contextlib
import copy
import importlib.util
import io
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "clack-client"))
from clack_client import ClackClient
from clack_client.errors import ClackError, RelayUnreachable
from clack_client.requests import parse_request_url


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cli = load_module("request_test_cli", ROOT / "relay-cli.py")
mcp = load_module("request_test_mcp", ROOT / "clack-client/mcp_server/server.py")
ORIGIN = "https://relay.example"
HANDLE = "12345678-abcd-4abc-8abc-123456789abc"
URL = ORIGIN + "/join/" + HANDLE
TARGET = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode()
PENDING = {"handshake_id": HANDLE, "status": "pending"}
BAD_URLS = [
    "https://evil.example/join/" + HANDLE,
    "http://relay.example/join/" + HANDLE,
    "https://relay.example.evil/join/" + HANDLE,
    "https://name@relay.example/join/" + HANDLE,
    "https://name:password@relay.example/join/" + HANDLE,
    URL + "?", URL + "?h=another", URL + "#", URL + "#relay_fp=untrusted",
    URL + "/", URL + "/extra", URL.replace("/join/", "/other/"),
    URL.replace("/join/", "/join//"), URL.replace(HANDLE, HANDLE.upper()),
    URL.replace(HANDLE, HANDLE.replace("-", "")),
    URL.replace(HANDLE, "{" + HANDLE + "}"), URL.replace("abcd", "%61bcd"),
    URL + "\n", " " + URL, URL.replace("relay", "re\tlay"),
    URL.replace("relay.example", "relay.example\\@evil.example"),
    "//relay.example/join/" + HANDLE, "/join/" + HANDLE, HANDLE,
    "https://relay.example:bad/join/" + HANDLE,
    "https://relay.example:65536/join/" + HANDLE,
]


class PublicRequestSDK(unittest.TestCase):
    def setUp(self):
        # No relay lookup, key file, or live credentials; fixed local fixture.
        self.client = ClackClient.__new__(ClackClient)
        self.client.relay_url = ORIGIN
        self.client._seed = bytes(range(32))
        self.client.token = "offline-test-only"
        self.client.peer_name = "alice"
        self.client.user_agent = "offline-test"
        self.client.timeout = 1
        self.client._request = Mock(return_value=PENDING)

    def test_mint_defaults_and_full_response(self):
        response = {"link": URL, "link_id": HANDLE, "exp": 1, "max_uses": 1,
                    "mode": "public_request", "target_identity": TARGET,
                    "inviter_identity": TARGET}
        self.client._request.return_value = response
        self.assertEqual(self.client.mint_handshake_request(TARGET), response)
        self.client._request.assert_called_once_with("POST", "/v1/handshakes/requests",
            {"target_identity": TARGET, "exp_days": 7, "enc_v": 0})
        self.assertNotIn("k", response)

    def test_options(self):
        self.client.mint_handshake_request(TARGET, exp_days=0.5, enc_v=1)
        self.assertEqual(self.client._request.call_args.args[2]["enc_v"], 1)
        self.assertEqual(self.client._request.call_args.args[2]["exp_days"], 0.5)

    def test_bad_options_before_request(self):
        for key in ("bob", TARGET + "=", TARGET[:-1] + "9", "!" * 43, None):
            with self.subTest(key=key), self.assertRaises(ClackError):
                self.client.mint_handshake_request(key)
        for days in (True, 0, -1, float("nan"), float("inf"), "7"):
            with self.subTest(days=days), self.assertRaises(ClackError):
                self.client.mint_handshake_request(TARGET, exp_days=days)
        for version in (True, 1.0, 2, "1"):
            with self.subTest(version=version), self.assertRaises(ClackError):
                self.client.mint_handshake_request(TARGET, enc_v=version)
        self.client._request.assert_not_called()

    def test_redeem_pending_only(self):
        self.assertEqual(self.client.redeem_handshake_request(URL), PENDING)
        self.client._request.assert_called_once_with("POST", "/v1/handshakes/requests/redeem", {"h": HANDLE})
        self.assertEqual(self.client.peer_name, "alice")
        self.assertEqual(self.client.relay_url, ORIGIN)

    def test_url_validation_sdk_and_standalone_agree(self):
        for parser in (parse_request_url, cli.parse_request_url):
            self.assertEqual(parser(URL, ORIGIN), HANDLE)
            self.assertEqual(parser(URL, ORIGIN + "/"), HANDLE)
            for url in BAD_URLS:
                with self.subTest(parser=parser, url=url), self.assertRaises(ValueError):
                    parser(url, ORIGIN)
        for url in BAD_URLS:
            with self.subTest(url=url), self.assertRaises(ClackError):
                self.client.redeem_handshake_request(url)
        self.client._request.assert_not_called()

    def test_new_agent_cannot_use_public_request(self):
        self.client._seed = None
        with self.assertRaisesRegex(ClackError, "v4"):
            self.client.redeem_handshake_request(URL)
        with self.assertRaisesRegex(ClackError, "v4"):
            self.client.mint_handshake_request(TARGET)
        self.client._request.assert_not_called()

    def test_explicit_accept_enc_v_and_legacy_shape(self):
        self.client.accept_handshake(HANDLE)
        self.client._request.assert_called_with("POST", "/v1/handshakes/accept", {"handshake_id": HANDLE})
        self.client.accept_handshake(HANDLE, enc_v=1)
        self.client._request.assert_called_with("POST", "/v1/handshakes/accept", {"handshake_id": HANDLE, "enc_v": 1})
        self.client._request.reset_mock()
        with self.assertRaises(ClackError):
            self.client.accept_handshake(HANDLE, enc_v=True)
        self.client._request.assert_not_called()

    def test_existing_v4_mint_and_redeem_unchanged(self):
        self.client._request.return_value = {"link": "legacy-v4"}
        self.assertEqual(self.client.mint_handshake_link(), "legacy-v4")
        self.client._request.assert_called_with("POST", "/v1/handshakes/mint-link", {})
        self.client._request.return_value = PENDING
        self.assertEqual(self.client.redeem_handshake({"h": HANDLE, "k": "offline-fixture"}), HANDLE)
        self.client._request.assert_called_with("POST", "/v1/handshakes/redeem", {"h": HANDLE, "k": "offline-fixture"})

    def test_signed_transport_non_idempotent(self):
        del self.client._request  # exercise real signer/transport, mocked I/O
        with patch("clack_client.client.transport.request", return_value=(200, json.dumps(PENDING).encode())) as transport:
            self.client.redeem_handshake_request(URL)
        method, url, headers, raw, timeout = transport.call_args.args
        self.assertEqual((method, url), ("POST", ORIGIN + "/v1/handshakes/requests/redeem"))
        self.assertEqual(json.loads(raw), {"h": HANDLE})
        self.assertEqual(headers["X-Clack-Scheme"], "1")
        self.assertIn("X-Clack-Sig", headers)
        with patch("clack_client.client.transport.request", side_effect=RelayUnreachable("offline failure")) as transport:
            with self.assertRaises(RelayUnreachable):
                self.client.redeem_handshake_request(URL)
            self.assertEqual(transport.call_count, 1)


class PublicRequestCLI(unittest.TestCase):
    def setUp(self):
        self.cfg = {"kind": cli.IDENTITY_KIND, "relay_url": ORIGIN,
                    "service_token": "offline-test-only", "peer_name": "alice",
                    "relay_identity_fingerprint": "sha256:offline-test-pin"}

    def run_cli(self, arguments, cfg=None):
        before = copy.deepcopy(self.cfg if cfg is None else cfg)
        with patch.object(sys, "argv", ["relay-cli.py", "--config", "unused-test.json"] + arguments), \
             patch.object(cli, "load_config", return_value=before), \
             patch.object(cli, "signing_seed", return_value=bytes(range(32))), \
             patch.object(cli, "req", return_value=(200, PENDING)) as request, \
             patch.object(cli, "_save_identity_config") as save, \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            result = cli.main()
        self.assertEqual(before, self.cfg if cfg is None else cfg)
        save.assert_not_called()
        return result, request

    def test_standalone_download_needs_no_sdk(self):
        with tempfile.TemporaryDirectory() as directory:
            shutil.copyfile(ROOT / "relay-cli.py", Path(directory) / "relay-cli.py")
            for arguments in (["--help"], ["mint-request", "--help"],
                              ["redeem-request", "--help"], ["accept-handshake", "--help"]):
                result = subprocess.run([sys.executable, "relay-cli.py"] + arguments,
                    cwd=directory, capture_output=True, text=True, timeout=10,
                    env={**os.environ, "PYTHONPATH": ""})
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_mint_parser_defaults(self):
        result, request = self.run_cli(["mint-request", TARGET])
        self.assertEqual(result, 0)
        self.assertEqual(request.call_args.args[2:], ("/v1/handshakes/requests",
            {"target_identity": TARGET, "exp_days": 7, "enc_v": 0}))

    def test_mint_parser_options(self):
        result, request = self.run_cli(["mint-request", TARGET, "--exp-days", "2", "--enc-v", "1"])
        self.assertEqual(result, 0)
        self.assertEqual(request.call_args.args[3]["enc_v"], 1)

    def test_redeem_no_yes_no_auto_accept(self):
        result, request = self.run_cli(["redeem-request", URL])
        self.assertEqual(result, 0)
        request.assert_called_once_with(self.cfg, "POST", "/v1/handshakes/requests/redeem", {"h": HANDLE}, base=ORIGIN)

    def test_explicit_accept(self):
        for version in (0, 1):
            with self.subTest(version=version):
                result, request = self.run_cli(["accept-handshake", HANDLE, "--enc-v", str(version)])
                self.assertEqual(result, 0)
                self.assertEqual(request.call_args.args[2:], ("/v1/handshakes/accept", {"handshake_id": HANDLE, "enc_v": version}))

    def test_accept_omitted_advertisement_matches_sdk_and_mcp(self):
        result, request = self.run_cli(["accept-handshake", HANDLE])
        self.assertEqual(result, 0)
        self.assertEqual(request.call_args.args[2:], ("/v1/handshakes/accept", {"handshake_id": HANDLE}))

    def test_invalid_urls_before_request(self):
        for url in BAD_URLS:
            with self.subTest(url=url):
                result, request = self.run_cli(["redeem-request", url])
                self.assertEqual(result, 1)
                request.assert_not_called()

    def test_configured_origin_override_rejected(self):
        result, request = self.run_cli(["--base-url", "https://evil.example", "redeem-request", URL])
        self.assertEqual(result, 1)
        request.assert_not_called()

    def test_missing_identity_no_enrollment(self):
        result, request = self.run_cli(["redeem-request", URL], {"kind": cli.IDENTITY_KIND, "relay_url": ORIGIN})
        self.assertEqual(result, 1)
        request.assert_not_called()

    def test_missing_pin_no_trust_upgrade(self):
        cfg = dict(self.cfg)
        del cfg["relay_identity_fingerprint"]
        result, request = self.run_cli(["redeem-request", URL], cfg)
        self.assertEqual(result, 1)
        request.assert_not_called()

    def test_public_posts_no_ambiguous_curl_fallback(self):
        with patch.object(cli, "_ensure_origin_verified", return_value="pinned"), \
             patch.object(cli, "sign_headers", return_value={}), \
             patch.object(cli, "_curl_req", side_effect=ConnectionError("offline")) as curl, \
             patch.object(cli, "_open") as urllib_open, \
             patch.dict(os.environ, {"CLACK_USE_CURL": "1"}):
            for path in ("/v1/handshakes/requests", "/v1/handshakes/requests/redeem", "/v1/handshakes/accept"):
                with self.subTest(path=path), self.assertRaisesRegex(RuntimeError, "UNKNOWN"):
                    cli.req(self.cfg, "POST", path, {"h": HANDLE})
                self.assertEqual(curl.call_count, 1)
                curl.reset_mock()
            urllib_open.assert_not_called()

    def test_public_posts_no_urllib_retry(self):
        with patch.object(cli, "_ensure_origin_verified", return_value="pinned"), \
             patch.object(cli, "sign_headers", return_value={}), \
             patch.object(cli, "_open", side_effect=ConnectionError("offline")) as urllib_open, \
             patch.dict(os.environ, {"CLACK_USE_CURL": "0"}):
            for path in ("/v1/handshakes/requests", "/v1/handshakes/requests/redeem", "/v1/handshakes/accept"):
                with self.subTest(path=path), self.assertRaisesRegex(RuntimeError, "UNKNOWN"):
                    cli.req(self.cfg, "POST", path, {"target_identity": TARGET})
                self.assertEqual(urllib_open.call_count, 1)
                urllib_open.reset_mock()


class PublicRequestMCP(unittest.TestCase):
    def test_schemas_and_routing(self):
        schemas = {tool["name"]: tool for tool in mcp.TOOLS}
        self.assertIn("clack_mint_handshake_request", schemas)
        self.assertIn("clack_redeem_handshake_request", schemas)
        self.assertIn("enc_v", schemas["clack_accept_handshake"]["inputSchema"]["properties"])
        client = Mock()
        client.redeem_handshake_request.return_value = PENDING
        with patch.object(mcp, "_get_client", return_value=client):
            mcp.handle_tool("clack_mint_handshake_request", {"target_identity": TARGET})
            client.mint_handshake_request.assert_called_once_with(TARGET, exp_days=7, enc_v=0)
            self.assertEqual(mcp.handle_tool("clack_redeem_handshake_request", {"url": URL}), PENDING)
            client.accept_handshake.assert_not_called()
            mcp.handle_tool("clack_accept_handshake", {"handshake_id": HANDLE, "enc_v": 1})
            client.accept_handshake.assert_called_once_with(HANDLE, enc_v=1)


if __name__ == "__main__":
    unittest.main()
