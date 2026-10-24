"""Real default-curl custody/origin controls; disposable loopback authority only."""
import contextlib
import http.server
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

import test_new_agent_cli as helpers
import test_public_requests as fixtures
from clack_client import transport

cli = helpers.cli
signed = helpers.module("custody_signed_client", helpers.ROOT / "signed_client.py")


class CurlTransportCustody(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.PublicRequestTests("test_redeem_then_explicit_mutual_consent")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.r.load_identity_key({"identity_key": helpers.gen_rsa_key(self.f.temp.name)})
        cfg = {"kind": cli.IDENTITY_KIND, "relay_url": self.f.base,
               "peer_name": "bob", "service_token": self.f.tokens["bob"],
               "identity_pubkey": self.f.pub["bob"],
               "relay_identity_fingerprint": cli.relay_identity_fingerprint(
                   self.f.r.relay_identity_info())}
        path = str(Path(self.f.temp.name) / "existing.json")
        cli._save_identity_config(path, cfg, self.f.keys["bob"][0])
        self.cfg = cli.load_config(path)
        cli._verified_origins.clear()
        self.addCleanup(cli._verified_origins.clear)
        status, invitation = self.f.post("/v1/handshakes/invitations", {"enc_v": 1}, "alice")
        self.assertEqual(status, 200)
        parsed = cli.parse_invitation_url(invitation["link"])
        self.body = {"h": parsed["h"], "k": parsed["k"]}
        self.data = json.dumps(self.body).encode()
        self.headers = {"Authorization": "Bearer " + self.f.tokens["bob"],
                        "Content-Type": "application/json"}
        self.headers.update(cli.sign_headers(self.cfg, "POST", "/v1/handshakes/redeem", self.data))
        self.files = Path(self.f.temp.name) / "transport-files"
        self.files.mkdir()
        self.home = Path(self.f.temp.name) / "home"
        self.home.mkdir()
        self.curl_home = Path(self.f.temp.name) / "curl-home"
        self.curl_home.mkdir()
        self.env = {"HOME": str(self.home), "CURL_HOME": str(self.curl_home),
                    "CLACK_USE_CURL": "1", "NO_PROXY": "127.0.0.1,localhost"}
        self.signed = signed.SignedClient.__new__(signed.SignedClient)
        self.signed.origin = self.f.base  # Test-only disposable loopback origin.
        self.signed.token = self.f.tokens["bob"]
        self.signed.peer_name = "bob"
        self.signed.seed = self.f.keys["bob"][0]

    def invoke(self, kind):
        if kind == "cli":
            return cli._curl_req(self.cfg, "POST", self.f.base + "/v1/handshakes/redeem",
                                 self.headers, self.data, 5)
        if kind == "sdk":
            return transport.curl_request("POST", self.f.base + "/v1/handshakes/redeem",
                                          self.headers, self.data, 5)
        return self.signed._curl_request("/v1/handshakes/redeem", self.body)

    def private_files(self, argv):
        paths = [Path(arg[1:]) for arg in argv if arg.startswith("@")]
        self.assertEqual(len(paths), 2, "body and headers must use private files")
        self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600 for path in paths))
        self.assertFalse(any(self.f.tokens["bob"] in arg for arg in argv),
                         "bearer authority appeared in child argv")
        self.assertFalse(any("X-Clack-Sig:" in arg for arg in argv),
                         "request signature appeared in child argv")
        self.assertFalse(any(self.body["k"] in arg for arg in argv),
                         "claim authority appeared in child argv")
        self.assertIn(argv[1], ("-q", "--disable"))
        self.assertEqual(argv[argv.index("--max-redirs") + 1], "0")
        return paths

    def test_real_default_signed_redemption_has_no_secret_arguments(self):
        observed = []
        run = subprocess.run

        def traced(argv, *args, **kwargs):
            if argv[0] == "curl":
                # Execute the real child before making the custody assertions.
                observed.append((list(argv), [Path(arg[1:]) for arg in argv
                                             if arg.startswith("@")]))
            return run(argv, *args, **kwargs)

        with patch.dict(os.environ, self.env), patch.object(subprocess, "run", side_effect=traced), \
             patch.object(tempfile, "tempdir", str(self.files)):
            status, result = cli.req(self.cfg, "POST", "/v1/handshakes/redeem", self.body)
        self.assertEqual(status, 200)
        self.assertEqual(result["status"], "pending")
        self.assertEqual(self.f.state(), (3, 1, 1))
        self.assertTrue(observed)
        for argv, paths in observed:
            self.assertFalse(any(self.f.tokens["bob"] in arg for arg in argv),
                             "bearer authority appeared in actual child argv")
            self.assertFalse(any("X-Clack-Sig:" in arg for arg in argv),
                             "signature appeared in actual child argv")
            self.assertEqual(len(paths), 2)
            self.assertTrue(all(not path.exists() for path in paths))
        self.assertEqual(list(self.files.iterdir()), [])

    @unittest.skipUnless(Path("/proc/self/cmdline").exists(), "Linux process readback")
    def test_actual_running_default_curl_cmdline_has_no_authority(self):
        entered = threading.Event()
        release = threading.Event()
        real = self.f.r.Handler
        observed = []

        class Held(real):
            def do_POST(self):
                entered.set()
                if not release.wait(10):
                    return
                super().do_POST()

        self.f.server.RequestHandlerClass = Held
        run = subprocess.run

        def traced(argv, *args, **kwargs):
            if argv[0] != "curl":
                return run(argv, *args, **kwargs)
            with subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
                try:
                    self.assertTrue(entered.wait(10), "curl did not reach loopback relay")
                    cmdline = Path("/proc/%d/cmdline" % child.pid).read_bytes()
                    # Retain booleans only, never raw process/credential bytes.
                    observed.append((self.f.tokens["bob"].encode() in cmdline,
                                     b"X-Clack-Sig:" in cmdline,
                                     self.body["k"].encode() in cmdline))
                finally:
                    release.set()
                stdout, stderr = child.communicate(timeout=10)
                return subprocess.CompletedProcess(argv, child.returncode, stdout, stderr)

        with patch.dict(os.environ, self.env), patch.object(subprocess, "run", side_effect=traced):
            status, result = cli.req(self.cfg, "POST", "/v1/handshakes/redeem", self.body)
        self.assertEqual(status, 200)
        self.assertEqual(result["status"], "pending")
        self.assertEqual(observed, [(False, False, False)])

    def test_private_file_setup_failure_cleans_up_before_launch(self):
        chmod = os.chmod
        for kind in ("cli", "sdk", "signed"):
            for fail_at in (1, 2):
                calls = []

                def fail(path, mode):
                    calls.append(True)
                    if len(calls) == fail_at:
                        raise OSError("test protected-file setup failure")
                    return chmod(path, mode)

                with self.subTest(kind=kind, fail_at=fail_at), \
                     patch.object(tempfile, "tempdir", str(self.files)), \
                     patch.object(os, "chmod", side_effect=fail), \
                     patch.object(subprocess, "run") as run, self.assertRaises(OSError):
                    self.invoke(kind)
                run.assert_not_called()
                self.assertEqual(list(self.files.iterdir()), [])

    def test_all_delivered_helpers_private_files_cleanup_on_every_exit(self):
        for kind in ("cli", "sdk", "signed"):
            for outcome in ("success", "launch", "timeout", "exit", "parse", "redirect"):
                seen = []

                def run(argv, *args, **kwargs):
                    seen.extend(self.private_files(argv))
                    if outcome == "launch":
                        raise FileNotFoundError("test missing curl")
                    if outcome == "timeout":
                        raise subprocess.TimeoutExpired("curl", 1)
                    if outcome == "exit":
                        return subprocess.CompletedProcess(argv, 28, b"", b"test timeout")
                    if outcome == "parse":
                        return subprocess.CompletedProcess(argv, 0, b"bad-response", b"")
                    status = b"307 Temporary Redirect" if outcome == "redirect" else b"200 OK"
                    return subprocess.CompletedProcess(argv, 0, b"HTTP/1.1 " + status + b"\r\n\r\n{}", b"")

                with self.subTest(kind=kind, outcome=outcome), \
                     patch.object(subprocess, "run", side_effect=run), \
                     patch.object(tempfile, "tempdir", str(self.files)), \
                     contextlib.redirect_stderr(io.StringIO()):
                    if outcome == "success" or (kind == "sdk" and outcome == "redirect"):
                        self.invoke(kind)
                    else:
                        with self.assertRaises((Exception, SystemExit)):
                            self.invoke(kind)
                self.assertTrue(seen)
                self.assertTrue(all(not path.exists() for path in seen))
                self.assertEqual(list(self.files.iterdir()), [])

    def test_real_curl_ignores_home_and_curl_home_redirect_configs(self):
        received = []

        class Sink(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                received.append(True)  # Never retain or print claim/header bytes.
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

        sink = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Sink)
        thread = threading.Thread(target=sink.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(sink.server_close)
        self.addCleanup(sink.shutdown)
        destination = "http://127.0.0.1:%d/off-origin" % sink.server_port
        real = self.f.r.Handler

        class Redirect(real):
            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                self.send_response(307)
                self.send_header("Location", destination)
                self.send_header("Content-Length", "0")
                self.end_headers()

        self.f.server.RequestHandlerClass = Redirect
        for config in ("clean", "HOME", "CURL_HOME"):
            for home in (self.home, self.curl_home):
                (home / ".curlrc").unlink(missing_ok=True)
            if config != "clean":
                home = self.home if config == "HOME" else self.curl_home
                (home / ".curlrc").write_text("location\n")
            env = dict(self.env)
            if config == "HOME":
                env.pop("CURL_HOME")
            for kind in ("cli", "sdk", "signed", "python"):
                received.clear()
                with self.subTest(config=config, kind=kind), patch.dict(os.environ, env), \
                     contextlib.redirect_stderr(io.StringIO()):
                    # Remove inherited CURL_HOME too: HOME control must really select HOME.
                    if config == "HOME":
                        os.environ.pop("CURL_HOME", None)
                    if kind == "sdk":
                        status, _ = self.invoke(kind)
                        self.assertEqual(status, 307)
                    elif kind == "python":
                        with patch.dict(os.environ, {"CLACK_USE_CURL": "0"}), self.assertRaises(SystemExit):
                            cli.req(self.cfg, "POST", "/v1/handshakes/redeem", self.body)
                    else:
                        with self.assertRaises((ValueError, SystemExit)):
                            self.invoke(kind)
                    self.assertEqual(received, [], "off-origin delivery must never occur")
        self.assertEqual(self.f.state(), (3, 0, 0))

    def test_default_mutation_response_loss_does_not_fallback_or_replay(self):
        real = self.f.r.Handler
        committed = []

        class Lost(real):
            def do_POST(self):
                if self.path != "/v1/handshakes/redeem":
                    return super().do_POST()
                # Exercise actual commit then truncate the HTTP response.
                original = self.wfile
                self.wfile = io.BytesIO()
                try:
                    super().do_POST()
                    committed.append(True)
                finally:
                    self.wfile = original
                self.close_connection = True

        self.f.server.RequestHandlerClass = Lost
        with patch.dict(os.environ, self.env), patch.object(cli, "_open", wraps=cli._open) as python, \
             patch.object(tempfile, "tempdir", str(self.files)), self.assertRaises(cli.UnknownMutationOutcome):
            cli.req(self.cfg, "POST", "/v1/handshakes/redeem", self.body)
        self.assertEqual(committed, [True])
        # _open is used by pin verification, never by a duplicate mutation.
        self.assertTrue(all(call.args[0].get_method() == "GET" for call in python.call_args_list))
        self.assertEqual(self.f.state(), (3, 1, 1))
        self.assertEqual(list(self.files.iterdir()), [])
        self.f.server.RequestHandlerClass = real
        with patch.dict(os.environ, self.env):
            status, recovered = cli.req(self.cfg, "POST", "/v1/handshakes/redeem", self.body)
        self.assertEqual(status, 200)
        self.assertEqual(recovered["status"], "pending")
        self.assertEqual(self.f.state(), (3, 1, 1))


if __name__ == "__main__":
    unittest.main()
