"""Private invitation CLI/SDK/MCP boundaries; disposable keys, no public I/O."""
import base64
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
import uuid
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "clack-client"))
from clack_client import ClackClient
from clack_client.errors import ClackError, RelayUnreachable
from clack_client.invitations import parse_invitation_url


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def gen_rsa_key(directory):
    """Disposable loopback relay identity; stdlib + openssl, no test imports."""
    pem = str(Path(directory) / "identity.pem")
    der = str(Path(directory) / "identity.der")
    subprocess.run(["openssl", "genrsa", "-out", pem, "2048"],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "rsa", "-in", pem, "-traditional", "-outform", "DER", "-out", der],
                   check=True, capture_output=True)
    raw = Path(der).read_bytes()
    assert raw[0] == 0x30
    offset = 2 + (raw[1] & 0x7f) if raw[1] & 0x80 else 2
    integers = []
    while offset < len(raw):
        assert raw[offset] == 0x02
        length = raw[offset + 1]
        start = offset + 2
        if length & 0x80:
            count = length & 0x7f
            length = int.from_bytes(raw[start:start + count], "big")
            start += count
        integers.append(int.from_bytes(raw[start:start + length], "big"))
        offset = start + length
    _, n, e, d = integers[:4]
    return {"n": format(n, "x"), "e": format(e, "x"), "d": format(d, "x")}


cli = module("new_invitation_cli", ROOT / "relay-cli.py")
mcp = module("new_invitation_mcp", ROOT / "clack-client/mcp_server/server.py")
ORIGIN = "https://relay.example"
HANDLE = uuid.UUID("12345678-abcd-4abc-8abc-123456789abc")
SHORT = base64.urlsafe_b64encode(HANDLE.bytes).rstrip(b"=").decode()
SECRET = base64.urlsafe_b64encode(bytes(range(32))).rstrip(b"=").decode()
INVITER = cli.b64u_encode(cli._publickey(bytes(range(32))))
URL = ORIGIN + "/i/" + SHORT + "#" + SECRET
METADATA = {"mode": "private_invitation", "inviter_identity": INVITER,
            "inviter_name_hint": "alice", "exp": 9999999999}
PENDING = {"handshake_id": str(HANDLE), "status": "pending", "minter_identity": INVITER}


class InvitationParsing(unittest.TestCase):
    def test_strict_sdk_standalone_parity(self):
        bad = [URL + "=", URL + "#", URL + "?", " " + URL, URL + "\n",
               URL.replace("https:", "http:"), URL.replace("https:", "file:"),
               URL.replace("relay.example", "name@relay.example"),
               URL.replace("relay.example", "name:pass@relay.example"),
               URL.replace("relay.example", "relay.example:bad"),
               URL.replace("relay.example", "relay.example:65536"),
               URL.replace("relay.example", "relay.example:"),
               URL.replace("relay.example", "relay.example\\@evil.example"),
               URL.replace("relay", "re\tlay"), URL.replace("/i/", "/%69/"),
               URL.replace("/i/", "/i//"), URL.replace("#", "/#"),
               URL.replace("#", "?x=y#"), URL.replace(SHORT, SHORT[:-1] + "x"),
               URL.replace(SECRET, SECRET[:-1] + "9"),
               URL.replace(SECRET, SECRET + "="), URL.split("#")[0],
               URL.replace("/i/", "/join/"), "/i/" + SHORT + "#" + SECRET]
        for parser in (parse_invitation_url, cli.parse_invitation_url):
            with self.subTest(parser=parser):
                parsed = parser(URL, ORIGIN)
                self.assertEqual(parsed, {"origin": ORIGIN, "h": str(HANDLE),
                                         "k": SECRET, "path": "/i/" + SHORT})
                self.assertEqual(parser(URL), parsed)
                for host in ("127.0.0.1:18998", "localhost", "[::1]:18998"):
                    parser(URL.replace(ORIGIN, "http://" + host))
                for url in bad:
                    with self.subTest(url=url), self.assertRaises(ValueError):
                        parser(url)
                with self.assertRaises(ValueError):
                    parser(URL, "https://other.example")
                with self.assertRaises(ValueError):
                    parser(URL, ORIGIN + "/nested")

    def test_standalone_download_without_sdk(self):
        with tempfile.TemporaryDirectory() as directory:
            shutil.copyfile(ROOT / "relay-cli.py", Path(directory) / "relay-cli.py")
            for args in (["mint-invitation", "--help"], ["redeem", "--help"]):
                result = subprocess.run([sys.executable, "relay-cli.py"] + args,
                    cwd=directory, env={**os.environ, "PYTHONPATH": ""},
                    capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)


class InvitationCLI(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = str(Path(self.temp.name) / "identity.json")
        self.args = SimpleNamespace(config=self.path, link=URL, name="fresh-agent",
                                    yes=True, expect_inviter=INVITER, base_url=None)
        self.seed = bytes(reversed(range(32)))
        self.pub = cli._publickey(self.seed)
        self.calls = []
        self.nonce_number = 0
        self.fail_redeem = False

    def request(self, cfg, method, path, body=None, base=None):
        self.calls.append((copy.deepcopy(cfg), method, path, copy.deepcopy(body), base))
        if method == "GET":
            self.assertEqual(path, "/i/" + SHORT)
            self.assertNotIn("service_token", cfg)
            self.assertNotIn(SECRET, path)
            return 200, METADATA
        durable = cli.load_config(self.path)
        self.assertEqual(durable["identity_pubkey"], cfg["identity_pubkey"])
        self.assertEqual(cli.signing_seed(durable), self.seed)
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(durable["identity_privkey_path"]).st_mode & 0o777, 0o600)
        if path == "/v1/enroll/challenge":
            self.assertEqual(body, {"invite_id": str(HANDLE), "k": SECRET,
                                    "identity_pubkey": cli.b64u_encode(self.pub)})
            self.nonce_number += 1
            return 200, {"gate": "invite", "nonce": cli.b64u_encode(bytes([self.nonce_number]) * 32)}
        self.assertEqual(path, "/v1/handshakes/redeem")
        if "proof" in body:
            nonce = cli.b64u_decode(body["proof"]["nonce"])
            self.assertTrue(cli.verify(self.pub, cli.b64u_decode(body["proof"]["signature"]),
                                       nonce + str(HANDLE).encode() + self.pub))
            self.assertEqual(body["requested_name"], "fresh-agent")
        else:
            self.assertEqual(body, {"h": str(HANDLE), "k": SECRET})
        if self.fail_redeem:
            raise cli.UnknownMutationOutcome("offline lost response")
        return 200, {**PENDING, "service_token": "disposable-token", "peer_name": "fresh-agent"}

    def run_redeem(self):
        with patch.object(cli, "check_relay_identity", return_value="sha256:offline-pin") as check, \
             patch.object(cli, "keygen", return_value=(self.seed, self.pub)) as generate, \
             patch.object(cli, "req", side_effect=self.request), \
             patch("builtins.input", side_effect=AssertionError("unexpected prompt")), \
             contextlib.redirect_stdout(io.StringIO()) as output, \
             contextlib.redirect_stderr(io.StringIO()):
            result = cli.cmd_redeem(self.args)
        return result, check, generate, output.getvalue()

    def test_fresh_durable_private_key_and_pending_only(self):
        result, check, generated, output = self.run_redeem()
        self.assertEqual(result, 0)
        generated.assert_called_once()
        self.assertEqual([row[2] for row in self.calls],
                         ["/i/" + SHORT, "/v1/enroll/challenge", "/v1/handshakes/redeem"])
        saved = cli.load_config(self.path)
        self.assertEqual(saved["peer_name"], "fresh-agent")
        self.assertEqual(saved["service_token"], "disposable-token")
        self.assertIn(INVITER, output)
        self.assertIn("alice", output)
        self.assertIn("Pending only", output)
        self.assertNotIn(SECRET, output)

    def test_unknown_outcome_retains_seed_fresh_nonce_recovery(self):
        self.fail_redeem = True
        self.assertEqual(self.run_redeem()[0], 1)
        initial = cli.load_config(self.path)
        self.assertNotIn("service_token", initial)
        first = self.calls[-1][3]["proof"]["nonce"]
        self.fail_redeem = False
        result, _, generated, _ = self.run_redeem()
        self.assertEqual(result, 0)
        generated.assert_not_called()
        self.assertEqual(cli.signing_seed(cli.load_config(self.path)), self.seed)
        self.assertNotEqual(first, self.calls[-1][3]["proof"]["nonce"])

    def test_existing_identity_keeps_token_no_enrollment(self):
        cfg = {"kind": cli.IDENTITY_KIND, "relay_url": ORIGIN,
               "identity_pubkey": cli.b64u_encode(self.pub), "peer_name": "fresh-agent",
               "service_token": "retained-token", "relay_identity_fingerprint": "sha256:offline-pin"}
        cli._save_identity_config(self.path, cfg, self.seed)
        self.assertEqual(self.run_redeem()[0], 0)
        self.assertEqual([row[2] for row in self.calls], ["/i/" + SHORT, "/v1/handshakes/redeem"])
        self.assertEqual(cli.load_config(self.path)["service_token"], "retained-token")

    def test_consent_required_before_keys_or_mutation(self):
        self.args.expect_inviter = None
        result, check, generated, _ = self.run_redeem()
        self.assertEqual(result, 1)
        check.assert_not_called()
        generated.assert_not_called()
        self.assertFalse(Path(self.path).exists())
        self.assertEqual(self.calls, [])

    def test_short_path_cannot_downgrade_to_legacy_autoaccept(self):
        self.args.link = ORIGIN + "/i/" + SHORT + "#r=" + cli.b64u_encode(ORIGIN.encode()) + "&h=" + str(HANDLE) + "&k=" + SECRET
        result, check, generated, _ = self.run_redeem()
        self.assertEqual(result, 1)
        check.assert_not_called()
        generated.assert_not_called()
        self.assertEqual(self.calls, [])

    def test_no_consent_interactively_means_no_keys_or_mutation(self):
        self.args.yes = False
        with patch.object(cli, "check_relay_identity", return_value="sha256:offline-pin"), \
             patch.object(cli, "keygen") as generate, \
             patch.object(cli, "req", side_effect=self.request), \
             patch("builtins.input", return_value="YES"), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.cmd_redeem(self.args), 1)
        generate.assert_not_called()
        self.assertEqual(len(self.calls), 1)
        self.assertFalse(Path(self.path).exists())

    def test_inviter_mismatch_metadata_only(self):
        self.args.expect_inviter = cli.b64u_encode(self.pub)
        result, _, generated, _ = self.run_redeem()
        self.assertEqual(result, 1)
        generated.assert_not_called()
        self.assertEqual(len(self.calls), 1)
        self.assertFalse(Path(self.path).exists())

    def test_interactive_exact_named_consent(self):
        self.args.yes = False
        with patch.object(cli, "check_relay_identity", return_value="sha256:offline-pin"), \
             patch.object(cli, "keygen", return_value=(self.seed, self.pub)), \
             patch.object(cli, "req", side_effect=self.request), \
             patch("builtins.input", return_value="CONNECT " + INVITER) as consent, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.cmd_redeem(self.args), 0)
        self.assertIn(INVITER, consent.call_args.args[0])

    def test_cross_origin_before_identity_or_credentials(self):
        cfg = {"kind": cli.IDENTITY_KIND, "relay_url": "https://other.example",
               "identity_pubkey": cli.b64u_encode(self.pub), "peer_name": "fresh-agent",
               "service_token": "retained-token", "relay_identity_fingerprint": "sha256:offline-pin"}
        cli._save_identity_config(self.path, cfg, self.seed)
        original = Path(self.path).read_bytes()
        result, check, generated, _ = self.run_redeem()
        self.assertEqual(result, 1)
        check.assert_not_called()
        generated.assert_not_called()
        self.assertEqual(Path(self.path).read_bytes(), original)
        self.assertEqual(self.calls, [])

    def test_pin_mismatch_before_metadata_secret_or_config_change(self):
        cfg = {"kind": cli.IDENTITY_KIND, "relay_url": ORIGIN,
               "identity_pubkey": cli.b64u_encode(self.pub), "relay_identity_fingerprint": "sha256:old"}
        cli._save_identity_config(self.path, cfg, self.seed)
        with patch.object(cli, "fetch_relay_identity", return_value=("sha256:changed", {})), \
             patch.object(cli, "req") as request, \
             contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli.cmd_redeem(self.args)
        request.assert_not_called()
        self.assertEqual(cli.load_config(self.path)["relay_identity_fingerprint"], "sha256:old")

    def test_enrolled_no_pin_fails_before_discovery(self):
        cfg = {"kind": cli.IDENTITY_KIND, "relay_url": ORIGIN,
               "identity_pubkey": cli.b64u_encode(self.pub), "peer_name": "fresh-agent",
               "service_token": "retained-token"}
        cli._save_identity_config(self.path, cfg, self.seed)
        result, check, _, _ = self.run_redeem()
        self.assertEqual(result, 1)
        check.assert_not_called()
        self.assertEqual(self.calls, [])

    def test_mint_defaults_and_unknown_readback_not_second_mint(self):
        cfg = {"kind": cli.IDENTITY_KIND, "relay_url": ORIGIN,
               "service_token": "disposable", "peer_name": "alice",
               "relay_identity_fingerprint": "sha256:offline-pin"}
        args = SimpleNamespace(cmd="mint-invitation", base_url=None, exp_days=7)
        with patch.object(cli, "signing_seed", return_value=self.seed), \
             patch.object(cli, "req", side_effect=[cli.UnknownMutationOutcome("lost"), (200, {"invites": []})]) as request, \
             contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.cmd_public_request(args, cfg), 1)
        self.assertEqual(request.call_args_list[0].args[1:],
                         ("POST", "/v1/handshakes/invitations", {"exp_days": 7, "enc_v": 1}))
        self.assertEqual(request.call_args_list[1].args[1:], ("GET", "/v1/invites/list"))

    def test_transport_mutations_no_replay_or_curl_downgrade(self):
        for path in ("/v1/handshakes/invitations", "/v1/handshakes/redeem", "/v1/enroll/challenge"):
            with self.subTest(path=path), \
                 patch.object(cli, "_ensure_origin_verified", return_value="pinned"), \
                 patch.object(cli, "_curl_req", side_effect=RuntimeError("lost")) as curl, \
                 patch.object(cli, "_open") as python, \
                 patch.dict(os.environ, {"CLACK_USE_CURL": "1"}), \
                 self.assertRaises(cli.UnknownMutationOutcome):
                cli.req({}, "POST", path, {}, base=ORIGIN)
            curl.assert_called_once()
            python.assert_not_called()
            with patch.object(cli, "_ensure_origin_verified", return_value="pinned"), \
                 patch.dict(os.environ, {"CLACK_USE_CURL": "0"}), \
                 patch.object(cli, "_open", side_effect=ConnectionResetError("lost")) as python, \
                 self.assertRaises(cli.UnknownMutationOutcome):
                cli.req({}, "POST", path, {}, base=ORIGIN)
            python.assert_called_once()

    def test_malformed_mutation_response_is_unknown_not_retried(self):
        response = Mock()
        response.status = 200
        response.read.return_value = b"not-json"
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        with patch.object(cli, "_ensure_origin_verified", return_value="pinned"), \
             patch.dict(os.environ, {"CLACK_USE_CURL": "0"}), \
             patch.object(cli, "_open", return_value=response) as request, \
             self.assertRaises(cli.UnknownMutationOutcome):
            cli.req({}, "POST", "/v1/handshakes/invitations", {}, base=ORIGIN)
        request.assert_called_once()


class InvitationSDK(unittest.TestCase):
    def setUp(self):
        self.client = ClackClient.__new__(ClackClient)
        self.client.relay_url = ORIGIN
        self.client.token = "disposable"
        self.client.peer_name = "bob"
        self.client._seed = bytes(range(32))
        self.client.user_agent = "offline-test"
        self.client.timeout = 1
        self.client._request = Mock(return_value=PENDING)

    def test_mint_wire_and_validation(self):
        response = {"mode": "private_invitation", "link": URL, "link_id": str(HANDLE),
                    "max_uses": 1, "inviter_identity": INVITER, "exp": 9999999999}
        self.client._request.return_value = response
        self.assertEqual(self.client.mint_invitation(), response)
        self.client._request.assert_called_once_with("POST", "/v1/handshakes/invitations", {"exp_days": 7, "enc_v": 1})
        self.client._request.reset_mock()
        for days in (True, 0, -1, float("nan"), float("inf"), "7"):
            with self.assertRaises(ClackError):
                self.client.mint_invitation(exp_days=days)
        self.client._request.assert_not_called()

    def test_existing_redeem_metadata_no_secret_auth_and_pending(self):
        before = (self.client.token, self.client.peer_name, self.client._seed)
        with patch("clack_client.client.transport.request", return_value=(200, json.dumps(METADATA).encode())) as request:
            self.assertEqual(self.client.redeem_invitation(URL, confirm=True, expect_inviter=INVITER), PENDING)
        request.assert_called_once_with("GET", ORIGIN + "/i/" + SHORT,
             {"Accept": "application/json", "User-Agent": "offline-test"}, None, 1)
        self.client._request.assert_called_once_with("POST", "/v1/handshakes/redeem", {"h": str(HANDLE), "k": SECRET})
        self.assertEqual((self.client.token, self.client.peer_name, self.client._seed), before)

    def test_consent_origin_and_inviter_fail_closed(self):
        with patch("clack_client.client.transport.request") as request:
            for options in ({}, {"confirm": True}, {"confirm": 1, "expect_inviter": INVITER}):
                with self.assertRaises(ClackError):
                    self.client.redeem_invitation(URL, **options)
            with self.assertRaises(ClackError):
                self.client.redeem_invitation(URL.replace("relay.example", "evil.example"), confirm=True, expect_inviter=INVITER)
            request.assert_not_called()
        with patch("clack_client.client.transport.request", return_value=(200, json.dumps(METADATA).encode())):
            with self.assertRaises(ClackError):
                self.client.redeem_invitation(URL, confirm=True, expect_inviter=SECRET)
        self.client._request.assert_not_called()

    def test_fresh_sdk_refuses_unsafe_implicit_storage(self):
        self.client._seed = None
        with patch("clack_client.client.transport.request") as request, self.assertRaises(ClackError):
            self.client.redeem_invitation(URL, confirm=True, expect_inviter=INVITER)
        request.assert_not_called()

    def test_non_idempotent_transport_and_separate_accept(self):
        del self.client._request
        with patch("clack_client.client.transport.request", side_effect=[
                (200, json.dumps(METADATA).encode()), RelayUnreachable("lost")]) as request:
            with self.assertRaises(RelayUnreachable):
                self.client.redeem_invitation(URL, confirm=True, expect_inviter=INVITER)
        self.assertEqual(request.call_count, 2)
        method, url, headers, data, _ = request.call_args.args
        self.assertEqual((method, url), ("POST", ORIGIN + "/v1/handshakes/redeem"))
        self.assertIn("X-Clack-Sig", headers)
        self.assertEqual(json.loads(data), {"h": str(HANDLE), "k": SECRET})

    def test_list_reconciliation(self):
        self.client.list_invitations()
        self.client._request.assert_called_once_with("GET", "/v1/invites/list", idempotent=True)


class InvitationMCP(unittest.TestCase):
    def test_schemas_and_dispatch_never_accept(self):
        tools = {tool["name"]: tool for tool in mcp.TOOLS}
        self.assertIn("clack_mint_invitation", tools)
        self.assertEqual(tools["clack_redeem_invitation"]["inputSchema"]["required"], ["url", "confirm", "expect_inviter"])
        client = Mock()
        with patch.object(mcp, "_get_client", return_value=client):
            mcp.handle_tool("clack_mint_invitation", {})
            mcp.handle_tool("clack_redeem_invitation", {"url": URL, "confirm": True, "expect_inviter": INVITER})
        client.mint_invitation.assert_called_once_with(exp_days=7)
        client.redeem_invitation.assert_called_once_with(URL, confirm=True, expect_inviter=INVITER)
        client.accept_handshake.assert_not_called()
        client.send.assert_not_called()


class InvitationHTTP(unittest.TestCase):
    """Real loopback relay, RSA pinning, signatures, persisted keys and consent."""
    def setUp(self):
        fixtures = module("new_agent_http_fixtures", ROOT / "tests/test_public_requests.py")
        self.fixture = fixtures.PublicRequestTests(methodName="test_redeem_then_explicit_mutual_consent")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        rsa_key = gen_rsa_key(self.fixture.temp.name)
        self.fixture.r.load_identity_key({"identity_key": rsa_key})
        self.path = str(Path(self.fixture.temp.name) / "fresh.json")
        self.isolated = Path(self.fixture.temp.name) / "standalone"
        self.isolated.mkdir()
        self.downloaded = self.isolated / "clack.py"
        with urllib.request.urlopen(self.fixture.base + "/join/client") as response:
            client_bytes = response.read()
        self.assertEqual(client_bytes, (ROOT / "relay-cli.py").read_bytes())
        self.downloaded.write_bytes(client_bytes)

    def mint(self):
        status, invitation = self.fixture.post("/v1/handshakes/invitations",
                                              {"exp_days": 7, "enc_v": 1}, "alice")
        self.assertEqual(status, 200, invitation)
        return invitation

    def cli_process(self, args, config=None):
        result = subprocess.run([sys.executable, str(self.downloaded),
                                 "--config", config or self.path] + args,
                                capture_output=True, text=True, timeout=30,
                                cwd=self.isolated,
                                env={**os.environ, "CLACK_USE_CURL": "0", "PYTHONPATH": ""})
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def test_fresh_cli_real_http_pending_then_separate_signed_accept(self):
        invitation = self.mint()
        redemption = self.cli_process(["redeem", invitation["link"], "--name", "fresh-agent", "--yes",
                                       "--expect-inviter", self.fixture.pub["alice"]])
        saved = cli.load_config(self.path)
        with patch.dict(os.environ, {"CLACK_USE_CURL": "0"}):
            status, listed = cli.req(saved, "GET", "/v1/handshakes", base=self.fixture.base)
        self.assertEqual(status, 200)
        hs = listed["handshakes"][0]
        with self.fixture.r.db_lock:
            messages = self.fixture.r.conn.execute("SELECT count(*) FROM messages").fetchone()[0]
        self.assertEqual((hs["status"], hs["enc_capable"]), ("pending", 0))
        self.assertEqual(messages, 0)
        self.assertEqual(saved["peer_name"], "fresh-agent")
        self.assertIn('"pending_expires_at":', redemption.stdout)
        self.assertIn('"minter_identity": "' + self.fixture.pub['alice'] + '"', redemption.stdout)
        self.assertNotIn(saved['service_token'], redemption.stdout)
        self.assertNotIn(invitation['link'].split('#', 1)[1], redemption.stdout)
        emitted = next(line.removeprefix('Next command: ') for line in redemption.stdout.splitlines()
                       if line.startswith('Next command: '))
        command = shlex.split(emitted)
        self.assertEqual(command, [sys.executable, str(self.downloaded), '--config', self.path,
                                   'accept-handshake', '--enc-v', '1', '--', hs['handshake_id']])
        accepted = subprocess.run(command, cwd=self.isolated, capture_output=True, text=True,
                                 env={**os.environ, 'CLACK_USE_CURL': '0', 'PYTHONPATH': ''}, timeout=30)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        with patch.dict(os.environ, {"CLACK_USE_CURL": "0"}):
            _, active = cli.req(saved, "GET", "/v1/handshakes", base=self.fixture.base)
        self.assertEqual((active["handshakes"][0]["status"], active["handshakes"][0]["enc_capable"]),
                         ("active", 1))

        # Fresh identity created through the URL can actually exchange useful,
        # correlated encrypted traffic with its named inviter, from the served
        # standalone bytes, not a fixture-provided replacement credential.
        alice_path = str(Path(self.fixture.temp.name) / "alice.json")
        alice_cfg = {"kind": cli.IDENTITY_KIND, "relay_url": self.fixture.base,
                     "service_token": self.fixture.tokens['alice'], "peer_name": 'alice',
                     "identity_pubkey": self.fixture.pub['alice'],
                     "relay_identity_fingerprint": cli.relay_identity_fingerprint(self.fixture.r.relay_identity_info()),
                     "relay_identity_fingerprint_full": cli.relay_identity_fingerprint_full(self.fixture.r.relay_identity_info())}
        cli._save_identity_config(alice_path, alice_cfg, self.fixture.keys['alice'][0])
        protected = [Path(self.path), Path(alice_path),
                     Path(saved['identity_privkey_path']),
                     Path(cli.load_config(alice_path)['identity_privkey_path'])]
        before = {path: path.read_bytes() for path in protected}
        request_id, reply_id = str(uuid.uuid4()), str(uuid.uuid4())
        question = 'What authority does a Clack connection grant?'
        answer = 'Encrypted messaging only; it grants no execution permission.'
        self.cli_process(['send', '--to', 'fresh-agent', '--id', request_id,
                          '--topic', 'onboarding-proof', '--text', question], alice_path)
        received = json.loads(self.cli_process(['poll', '--timeout', '0']).stdout)['messages']
        self.assertEqual([(m['id'], m['text']) for m in received], [(request_id, question)])
        self.cli_process(['ack', '--ids', request_id])
        self.cli_process(['send', '--to', 'alice', '--id', reply_id,
                          '--in-reply-to', request_id, '--topic', 'onboarding-proof', '--text', answer])
        reply = json.loads(self.cli_process(['poll', '--timeout', '0'], alice_path).stdout)['messages']
        self.assertEqual([(m['id'], m['in_reply_to'], m['text']) for m in reply], [(reply_id, request_id, answer)])
        self.cli_process(['ack', '--ids', reply_id], alice_path)
        receipts = json.loads(self.cli_process(['receipts'], alice_path).stdout)['receipts']
        self.assertEqual(next(r for r in receipts if r['id'] == request_id)['state'], 'acked')
        with self.fixture.r.db_lock:
            rows = self.fixture.r.conn.execute('SELECT text,enc_v FROM messages').fetchall()
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(enc_v == 1 and question not in text and answer not in text for text, enc_v in rows))
        self.assertTrue(all(path.read_bytes() == data for path, data in before.items()))

    def test_short_url_honors_pow_and_open_policy_without_prior_enrollment(self):
        for index, gate in enumerate(('pow', 'open'), 1):
            with self.subTest(gate=gate):
                self.fixture.cfg['enrollment'] = gate
                self.fixture.cfg['pow_difficulty'] = 8
                invitation = self.mint()
                path = str(Path(self.fixture.temp.name) / ('fresh-' + gate + '.json'))
                self.cli_process(['redeem', invitation['link'], '--name', 'fresh-' + gate,
                                  '--yes', '--expect-inviter', self.fixture.pub['alice']], path)
                saved = cli.load_config(path)
                self.assertEqual(saved['peer_name'], 'fresh-' + gate)
                self.assertEqual(self.fixture.state(), (3 + index, index, index))
                self.assertEqual(self.fixture.r.conn.execute(
                    'SELECT enroll_gate FROM peers WHERE name=?', (saved['peer_name'],)
                ).fetchone(), (gate,))

    def test_real_name_collision_preserves_seed_and_invite(self):
        invitation = self.mint()
        args = SimpleNamespace(config=self.path, link=invitation["link"], name="bob",
                               yes=True, expect_inviter=self.fixture.pub["alice"], base_url=None)
        with patch.dict(os.environ, {"CLACK_USE_CURL": "0"}), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.cmd_redeem(args), 1)
            before = cli.load_config(self.path)
            self.assertNotIn("service_token", before)
            self.assertEqual(self.fixture.state(), (3, 0, 0))
            args.name = "name-after-collision"
            self.assertEqual(cli.cmd_redeem(args), 0)
        after = cli.load_config(self.path)
        self.assertEqual(after["identity_pubkey"], before["identity_pubkey"])
        self.assertEqual(after["peer_name"], "name-after-collision")
        self.assertEqual(self.fixture.state(), (4, 1, 1))

    def test_cli_mint_and_sdk_existing_recipient_real_http(self):
        fingerprint = cli.check_relay_identity(self.fixture.base, {})
        inviter = {"kind": cli.IDENTITY_KIND, "relay_url": self.fixture.base,
                   "identity_pubkey": self.fixture.pub["alice"], "peer_name": "alice",
                   "service_token": self.fixture.tokens["alice"],
                   "relay_identity_fingerprint": fingerprint}
        cli._save_identity_config(self.path, inviter, self.fixture.keys["alice"][0])
        invitation = json.loads(self.cli_process(["mint-invitation"]).stdout)
        self.assertLessEqual(len(invitation["link"]), 120)
        key_path = str(Path(self.fixture.temp.name) / "bob.key")
        cli._write_key_file(key_path, self.fixture.keys["bob"][0])
        with patch.dict(os.environ, {"CLACK_USE_CURL": "0"}):
            client = ClackClient(self.fixture.base, self.fixture.tokens["bob"], key_path,
                                 "bob", pin_file=str(Path(self.fixture.temp.name) / "pins.json"),
                                 auto_pin=True)
            pending = client.redeem_invitation(invitation["link"], confirm=True,
                                               expect_inviter=self.fixture.pub["alice"])
            self.assertEqual(pending["status"], "pending")
            self.assertEqual(client.list_handshakes()["handshakes"][0]["status"], "pending")
            self.assertNotIn("service_token", pending)
            self.assertEqual(client.token, self.fixture.tokens["bob"])
            active = client.accept_handshake(pending["handshake_id"], enc_v=1)
            self.assertEqual((active["status"], active["enc_capable"]), ("active", 1))
            self.assertEqual(len(client.list_invitations()["invites"]), 0)

    def test_real_ambiguous_claim_recovers_same_identity_with_new_challenge(self):
        invitation = self.mint()
        args = SimpleNamespace(config=self.path, link=invitation["link"], name="recovered-agent",
                               yes=True, expect_inviter=self.fixture.pub["alice"], base_url=None)
        actual_request = cli.req
        nonces = []
        lose_response = True
        def uncertain(cfg, method, path, body=None, base=None):
            result = actual_request(cfg, method, path, body, base)
            if path == "/v1/handshakes/redeem":
                nonces.append(body["proof"]["nonce"])
                if lose_response:
                    raise cli.UnknownMutationOutcome("simulated lost response after real server commit")
            return result
        with patch.dict(os.environ, {"CLACK_USE_CURL": "0"}), \
             patch.object(cli, "req", side_effect=uncertain), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.cmd_redeem(args), 1)
            before = cli.load_config(self.path)
            self.assertNotIn("service_token", before)
            seed = cli.signing_seed(before)
            lose_response = False
            self.assertEqual(cli.cmd_redeem(args), 0)
        after = cli.load_config(self.path)
        self.assertEqual(after["identity_pubkey"], before["identity_pubkey"])
        self.assertEqual(cli.signing_seed(after), seed)
        self.assertEqual(after["peer_name"], "recovered-agent")
        self.assertNotEqual(nonces[0], nonces[1])
        self.assertEqual(self.fixture.state(), (4, 1, 1))
        with self.fixture.r.db_lock:
            self.assertEqual(self.fixture.r.conn.execute("SELECT status FROM handshakes").fetchone()[0], "pending")


if __name__ == "__main__":
    unittest.main()