"""Disposable loopback FIXTURE PROOF, never real Labkin dogfood.

Run: env PYTHONPATH= PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
The empty PYTHONPATH is command-scoped to the fixture Python only; the profile
SQLite overlay is not edited. Require Connection.iterdump before starting.
"""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from federation_adapter import Adapter, SCHEMA


def load(path):
    spec = importlib.util.spec_from_file_location("fixture_" + uuid.uuid4().hex, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("fixture source unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def private(path, obj):
    data = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
    fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


class LoopbackRuntimeTests(unittest.TestCase):
    rig: Path
    env: dict
    endpoints: dict
    setup_receipt: str

    def setUpRig(self):
        # Each case owns fresh stock relays. This respects the real relay's
        # 30/min identity-proof limit rather than weakening it for the suite.
        cls = self
        if not hasattr(sqlite3.Connection, "iterdump"):
            raise RuntimeError("fixture Python must expose Connection.iterdump; do not change profile overlay")
        cls.rig = Path(tempfile.mkdtemp(prefix="clack-operational-fixture-", dir="/tmp"))
        ports = []
        sockets = []
        for _ in range(2):
            s = socket.socket()
            s.bind(("127.0.0.1", 0))
            sockets.append(s)
            ports.append(s.getsockname()[1])
        for s in sockets:
            s.close()
        cls.env = dict(os.environ, FED_BASE=str(cls.rig), FED_PORT_A=str(ports[0]), FED_PORT_B=str(ports[1]), PYTHONDONTWRITEBYTECODE="1")
        setup = subprocess.run(["bash", str(REPO / "reviews/rig-setup.sh")], env=cls.env, capture_output=True, text=True)
        if setup.returncode:
            raise RuntimeError("disposable rig setup failed: " + setup.stdout + setup.stderr)
        self.addCleanup(self.tearDownRig)
        cls.setup_receipt = setup.stdout.strip()
        # Existing freshly generated fixture credentials only. Never peers'
        # persona/memory or operational credentials; no secret printed.
        a = json.loads((cls.rig / "client-sender-a.json").read_text())
        b = json.loads((cls.rig / "client-sender-b.json").read_text())
        rb = json.loads((cls.rig / "client-recipient-b.json").read_text())
        relay_a = json.loads((cls.rig / "relay-a/relay-config.json").read_text())
        ra = dict(rb, relay_url=a["relay_url"], service_token=relay_a["peers"][rb["peer_name"]], relay_identity_fingerprint=a["relay_identity_fingerprint"])
        cls.endpoints = {}
        for name, identity in (("sender-a", a), ("sender-b", b), ("recipient-a", ra), ("recipient-b", rb)):
            token = cls.rig / (name + "-token.ref")
            pins = cls.rig / (name + "-pins.ref")
            private(token, identity["service_token"].encode())
            private(pins, {identity["relay_url"]: identity["relay_identity_fingerprint"]})
            cls.endpoints[name] = {"url": identity["relay_url"], "peer": identity["peer_name"], "token_ref": str(token), "key_ref": identity["identity_privkey_path"], "pin_ref": str(pins)}

    def tearDownRig(self):
        cls = self
        result = subprocess.run(["bash", str(REPO / "reviews/rig-teardown.sh")], env=cls.env, capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError("owned fixture teardown failed: " + result.stdout + result.stderr)
        if cls.rig.exists():
            raise RuntimeError("fixture root retained unexpectedly")
        print("FIXTURE PROOF: two stock loopback relays exercised; ownership-verified teardown passed", flush=True)

    def setUp(self):
        self.setUpRig()
        self.state = tempfile.TemporaryDirectory(prefix="clack-adapter-fixture-state-", dir="/tmp")
        self.addCleanup(self.state.cleanup)
        self.base = Path(self.state.name)
        private(self.base / "fixture-proof.json", {"purpose": "fixture-proof", "rig": str(self.rig)})
        os.environ["FED_BASE"] = str(self.base)
        self.fixture = load(REPO / "reviews/fed_driver.py")
        self.fixture.install_grant("forward")
        self.fixture.install_grant("reverse")
        bootstrap = self.base / "bootstrap.json"
        private(bootstrap, {"schema": "clack-federation-bootstrap-reference-v1", "purpose": "fixture-proof", "approval_ref": "DISPOSABLE TEST ONLY", "state_dir": str(self.base)})
        self.cfg = {"schema": SCHEMA, "proof_only": True, "state_dir": str(self.base), "bootstrap_ref": str(bootstrap), "ndr_key_ref": str(self.rig / "federation-ndr.key"), "verifier_pub_ref": str(self.rig / "federation-recheck-verifier.pub"), "verifier_id": "synthetic-recheck-verifier-v1", "timeout": 3, "endpoints": self.endpoints, "routes": {"forward": {"send_endpoint": "sender-b", "to": "test-peer-b", "receive_endpoint": "recipient-b", "from": "test-peer-a"}, "reverse": {"send_endpoint": "recipient-a", "to": "test-peer-a", "receive_endpoint": "sender-a", "from": "test-peer-b"}}}
        self.cfg["partition_cap_s"] = 3600
        self.config = self.base / "runtime.json"
        private(self.config, self.cfg)
        self.adapter = Adapter(str(self.config))


    def mid(self):
        return str(uuid.uuid4())

    def altered(self, mutate):
        cfg = json.loads(json.dumps(self.cfg))
        mutate(cfg)
        path = self.base / ("bad-" + uuid.uuid4().hex + ".json")
        private(path, cfg)
        return str(path)

    def cli(self, *args, expected=0):
        run = subprocess.run([sys.executable, str(REPO / "federation_adapter.py"), "--config", str(self.config), *args], capture_output=True, text=True)
        self.assertEqual(run.returncode, expected, run.stdout + run.stderr)
        return json.loads(run.stdout or run.stderr)

    def wire_count(self, which, mid):
        with sqlite3.connect(self.rig / ("relay-" + which) / "relay.db") as c:
            return c.execute("SELECT count(*) FROM messages WHERE id=?", (mid,)).fetchone()[0]

    def evidence(self, grant) -> dict:
        a = self.adapter.authority
        record = a.read_grant_record(grant)
        public = (self.rig / "federation-recheck-verifier.pub").read_bytes()
        import ed25519
        body = {"schema": "clack-federation-recheck-evidence-v1", "version": 1, "evidence_id": "ev-" + uuid.uuid4().hex, "verifier_id": self.cfg["verifier_id"], "verifier_key_id": "sha256:" + hashlib.sha256(public).hexdigest(), "grant_id": grant, "expected_generation": record["generation"], "prior_state": record["state"], "verdict": "successful", "verified_at": record["last_recheck_verified_at"] + 1}
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
        return dict(body, signature_hex=ed25519.sign((self.rig / "federation-recheck-verifier.key").read_bytes(), b"clack-federation-recheck-evidence/v1\n" + canonical).hex())

    def test_duplex_cli_send_receive_restart(self):
        forward, reverse = self.mid(), self.mid()
        text = self.base / "text.txt"
        private(text, b"DISPOSABLE FIXTURE ONLY duplex")
        self.assertEqual(self.cli("send", "--grant", "forward", "--id", forward, "--text-file", str(text))["outcome"], "sent")
        self.assertEqual(self.cli("send", "--grant", "reverse", "--id", reverse, "--text-file", str(text))["outcome"], "sent")
        self.assertIn(forward, self.cli("receive", "--endpoint", "recipient-b")["accepted_ids"])
        self.assertIn(reverse, self.cli("receive", "--endpoint", "sender-a")["accepted_ids"])
        self.assertEqual(self.cli("status")["inbox_count"], 2)
        self.assertEqual(self.cli("reconcile"), [])
        self.assertEqual(self.wire_count("a", reverse), 1)
        self.assertEqual(self.wire_count("b", forward), 1)

    def test_stable_id_payload_and_grant_binding(self):
        mid = self.mid()
        self.assertEqual(self.adapter.send("forward", mid, "fixture")["outcome"], "sent")
        self.assertEqual(Adapter(str(self.config)).send("forward", mid, "fixture")["outcome"], "already_sent")
        with self.assertRaises(ValueError):
            self.adapter.send("forward", mid, "changed")
        with self.assertRaises(ValueError):
            self.adapter.send("reverse", mid, "fixture")
        self.assertEqual(self.wire_count("b", mid), 1)

    def test_unknown_acceptance_fresh_process_reconciles_same_id(self):
        mid = self.mid()
        client = self.adapter.client("sender-b")
        original = client.send
        def lost(*args, **kwargs):
            original(*args, **kwargs)
            raise RuntimeError("SIMULATED LOST ACCEPTANCE fixture only")
        with mock.patch.object(client, "send", side_effect=lost):
            self.assertEqual(self.adapter.send("forward", mid, "fixture unknown")["outcome"], "uncertain")
        result = self.cli("reconcile")
        self.assertEqual(result[0]["id"], mid)
        self.assertEqual(result[0]["outcome"], "sent")
        self.assertEqual(self.wire_count("b", mid), 1)
        self.assertEqual(self.cli("reconcile"), [])

    def test_hard_post_accept_crash_reconciles(self):
        mid = self.mid()
        script = "from federation_adapter import Adapter; import os,sys; a=Adapter(sys.argv[1]); c=a.client('sender-b'); original=c.send\ndef crash(*args,**kwargs):\n original(*args,**kwargs); os._exit(86)\nc.send=crash\na.send('forward',sys.argv[2],'fixture crash')\n"
        run = subprocess.run([sys.executable, "-c", script, str(self.config), mid], cwd=REPO, capture_output=True)
        self.assertEqual(run.returncode, 86)
        self.assertEqual(self.adapter.authority.outbox_state(mid), "inflight")
        self.assertEqual(self.cli("reconcile")[0]["outcome"], "sent")
        self.assertEqual(self.wire_count("b", mid), 1)

    def test_concurrent_processes_send_once(self):
        mid = self.mid()
        text = self.base / "text.txt"
        private(text, b"fixture concurrency")
        command = [sys.executable, str(REPO / "federation_adapter.py"), "--config", str(self.config), "send", "--grant", "forward", "--id", mid, "--text-file", str(text)]
        children = [subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(2)]
        outcomes = []
        for child in children:
            out, err = child.communicate(timeout=30)
            self.assertEqual(child.returncode, 0, out + err)
            outcomes.append(json.loads(out)["outcome"])
        self.assertEqual(sorted(outcomes), ["already_sent", "sent"])
        self.assertEqual(self.wire_count("b", mid), 1)

    def test_ack_loss_durable_redelivery_no_duplicate(self):
        mid = self.mid()
        self.adapter.send("forward", mid, "fixture ack loss")
        client = self.adapter.client("recipient-b")
        with mock.patch.object(client, "ack", side_effect=RuntimeError("fixture ack loss")):
            with self.assertRaisesRegex(RuntimeError, "persisted"):
                self.adapter.receive("recipient-b")
        self.assertEqual(len(self.adapter.inbox_messages()), 1)
        fresh = Adapter(str(self.config))
        self.assertIn(mid, fresh.receive("recipient-b")["accepted_ids"])
        self.assertEqual(len(fresh.inbox_messages()), 1)

    def test_suspect_hold_and_signed_reopen(self):
        mid = self.mid()
        a = self.adapter.authority
        a.set_grant("forward", "SUSPECT")
        self.assertEqual(self.adapter.send("forward", mid, "fixture hold")["outcome"], "held")
        self.assertEqual(self.wire_count("b", mid), 0)
        self.assertEqual(self.cli("reconcile")[0]["outcome"], "held")
        evidence = self.evidence("forward")
        a.verified_recheck(evidence)
        self.assertEqual(self.cli("reconcile")[0]["outcome"], "sent")
        with self.assertRaises(ValueError):
            a.verified_recheck(evidence)
        self.assertEqual(self.wire_count("b", mid), 1)

    def test_automatic_partition_cap_and_signed_cli_recheck(self):
        a = self.adapter.authority
        with a.authority_lock():
            c = a._connect()
            c.execute("UPDATE grants SET last_recheck_verified_at=? WHERE grant_id='forward'", (time.time() - 4000,))
            c.close()
        mid = self.mid()
        self.assertEqual(self.adapter.send("forward", mid, "fixture automatic cap")["outcome"], "held")
        self.assertEqual(a.read_grant("forward"), "CAPPED")
        self.assertEqual(self.wire_count("b", mid), 0)
        evidence = self.evidence("forward")
        # A legitimate recheck must advance to a current watermark, not just
        # reopen with another expired time. Re-sign the fixture statement.
        evidence.pop("signature_hex")
        evidence["verified_at"] = time.time()
        import ed25519
        canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
        evidence["signature_hex"] = ed25519.sign((self.rig / "federation-recheck-verifier.key").read_bytes(), b"clack-federation-recheck-evidence/v1\n" + canonical).hex()
        path = self.base / "recheck.json"
        private(path, evidence)
        self.assertEqual(self.cli("recheck", "--evidence-file", str(path))["generation"], 3)
        self.cli("recheck", "--evidence-file", str(path), expected=1)
        # CAPPED work has no SUSPECT hold lineage; signed reopen does not
        # launder that old outbox into new authority.
        self.assertEqual(self.adapter.send("forward", mid, "fixture automatic cap")["outcome"], "held")
        fresh = self.mid()
        self.assertEqual(self.adapter.send("forward", fresh, "fixture reopened")["outcome"], "sent")

    def test_unconfirmed_ack_retains_durable_receive(self):
        mid = self.mid()
        self.adapter.send("forward", mid, "fixture unconfirmed ack")
        client = self.adapter.client("recipient-b")
        with mock.patch.object(client, "ack", return_value={"acked": [], "already_acked": [], "unknown": [mid]}):
            with self.assertRaisesRegex(RuntimeError, "persisted"):
                self.adapter.receive("recipient-b")
        self.assertEqual(len(self.adapter.inbox_messages()), 1)
        self.assertIn(mid, Adapter(str(self.config)).receive("recipient-b")["accepted_ids"])

    def test_replaced_state_root_fails_before_writes(self):
        moved = self.base.with_name(self.base.name + "-moved")
        self.base.rename(moved)
        self.base.mkdir(mode=0o700)
        try:
            with self.assertRaisesRegex(RuntimeError, "replaced"):
                self.adapter.authority.read_grant("forward")
            self.assertEqual(list(self.base.iterdir()), [])
        finally:
            self.base.rmdir()
            moved.rename(self.base)

    def test_bad_pin_prevents_credentials_and_wire(self):
        pin = Path(self.endpoints["sender-b"]["pin_ref"])
        original = pin.read_bytes()
        pin.write_text(json.dumps({self.endpoints["sender-b"]["url"]: "sha256:0000000000000000"}))
        from clack_client import transport  # pyright: ignore[reportMissingImports]
        request = transport.request
        credential_requests = []
        def observed(method, url, headers=None, *args, **kwargs):
            if headers and "Authorization" in headers:
                credential_requests.append(method)
            return request(method, url, headers, *args, **kwargs)
        try:
            mid = self.mid()
            with mock.patch.object(transport, "request", side_effect=observed):
                self.assertEqual(self.adapter.send("forward", mid, "fixture wrong pin")["outcome"], "uncertain")
            self.assertEqual(credential_requests, [])
            self.assertEqual(self.wire_count("b", mid), 0)
        finally:
            pin.write_bytes(original)

    def test_receive_fence_no_ack_while_suspect(self):
        mid = self.mid()
        self.adapter.send("forward", mid, "fixture receive fence")
        self.adapter.authority.set_grant("forward", "SUSPECT")
        self.assertEqual(self.adapter.receive("recipient-b")["accepted_ids"], [])
        self.assertEqual(self.adapter.inbox_messages(), [])
        self.assertIn(mid, [m["id"] for m in self.adapter.client("recipient-b").poll(timeout=0)])
        self.adapter.authority.verified_recheck(self.evidence("forward"))
        self.assertIn(mid, self.adapter.receive("recipient-b")["accepted_ids"])

    def test_cap_and_tombstone_fence(self):
        mid = self.mid()
        a = self.adapter.authority
        a.apply_partition_cap("forward", time.time() + 100, 1)
        self.assertEqual(self.adapter.send("forward", mid, "fixture capped")["outcome"], "held")
        self.assertEqual(self.wire_count("b", mid), 0)
        # Revoke on a separate existing fixture grant using the reviewed API.
        a.commit_revoke_batch("fixture-nonce-" + uuid.uuid4().hex, ["reverse"], "fixture revoke")
        other = self.mid()
        self.assertEqual(self.adapter.send("reverse", other, "fixture revoked")["outcome"], "held")
        self.assertEqual(self.wire_count("a", other), 0)
        with self.assertRaises(ValueError):
            a.verified_recheck(self.evidence("reverse"))

    def test_snapshot_integrity_and_nonoverwrite(self):
        result = self.cli("snapshot", "--name", "before")
        self.assertEqual(result["integrity"], "ok")
        snapshot = Path(result["snapshot"])
        self.assertEqual(snapshot.stat().st_mode & 0o777, 0o600)
        with sqlite3.connect(snapshot) as c:
            self.assertEqual(c.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(c.execute("SELECT count(*) FROM grants").fetchone()[0], 2)
        self.cli("snapshot", "--name", "before", expected=1)

    def test_no_fixture_authority_in_operational_mode(self):
        path = self.altered(lambda cfg: cfg.update(proof_only=False))
        with self.assertRaisesRegex(ValueError, "fixture"):
            Adapter(path)
        self.assertFalse(hasattr(self.adapter.authority, "install_grant"))
        self.assertFalse(hasattr(self.adapter.authority, "_run_transport"))
        with self.assertRaises(ValueError):
            self.adapter.authority.action("forward", self.mid(), "fixture")

    def test_config_binding_denies_reroute(self):
        path = self.altered(lambda cfg: cfg["routes"]["forward"].update(send_endpoint="sender-a"))
        with self.assertRaisesRegex(ValueError, "different configuration"):
            Adapter(path)

    def test_bad_permissions_symlinks_and_public_endpoints(self):
        self.config.chmod(0o644)
        with self.assertRaises(ValueError):
            Adapter(str(self.config))
        self.config.chmod(0o600)
        link = self.base / "config-link.json"
        link.symlink_to(self.config)
        with self.assertRaises(ValueError):
            Adapter(str(link))
        path = self.altered(lambda cfg: cfg["endpoints"]["sender-b"].update(url="https://example.com"))
        with self.assertRaises(ValueError):
            Adapter(path)
        path = self.altered(lambda cfg: cfg["endpoints"]["sender-b"].update(url="http://100.100.100.100:8080"))
        with self.assertRaisesRegex(ValueError, "loopback"):
            Adapter(path)

    def test_missing_grant_unknown_config_and_no_secret_errors(self):
        path = self.altered(lambda cfg: cfg["routes"].update(absent=cfg["routes"].pop("forward")))
        with self.assertRaisesRegex(ValueError, "missing"):
            Adapter(path)
        secret = "FIXTURE-SECRET-MUST-NOT-APPEAR"
        path = self.altered(lambda cfg: cfg.update(service_token=secret))
        run = subprocess.run([sys.executable, str(REPO / "federation_adapter.py"), "--config", path, "status"], capture_output=True, text=True)
        self.assertEqual(run.returncode, 1)
        self.assertNotIn(secret, run.stdout + run.stderr)
        with mock.patch.object(self.adapter.client("sender-b"), "send", side_effect=RuntimeError(secret)):
            mid = self.mid()
            self.assertEqual(self.adapter.send("forward", mid, "fixture")["outcome"], "uncertain")
            with sqlite3.connect(self.base / "federation-authority.db") as c:
                self.assertNotIn(secret, "\n".join(c.iterdump()))

    def test_payload_only_crash_checkpoint_reconciles(self):
        mid = self.mid()
        a = self.adapter.authority
        with a.authority_lock():
            c = a._connect()
            c.execute(
                "INSERT INTO runtime_payloads(msg_id,grant_id,text,enc_v) VALUES (?,?,?,0)",
                (mid, "forward", "fixture payload checkpoint"),
            )
            c.close()
        self.assertEqual(self.cli("reconcile")[0]["outcome"], "sent")
        self.assertEqual(self.wire_count("b", mid), 1)


class ReviewedCoreParityTests(unittest.TestCase):
    def test_reviewed_algorithms_retained_exactly(self):
        def functions(path):
            return {n.name: ast.dump(n, include_attributes=False) for n in ast.parse(path.read_text()).body if isinstance(n, ast.FunctionDef)}
        baseline = functions(REPO / "reviews/fed_driver.py")
        core = functions(REPO / "federation_authority.py")
        # Intentional reviewed divergences from the successor6 baseline:
        #   _require_base/action: operational persistent-root binding and
        #     mandatory injected transport (documented at adapter intake).
        #   authority_lock: pinned root identity is rechecked after the
        #     blocking flock acquisition, before any pathname DB open, so a
        #     root replaced during the wait refuses mutation (Flint 685 R2).
        #   apply_partition_cap: trusted clock may be sampled inside the lock
        #     (now=None) and its transition statements are shared verbatim
        #     with the in-fence enforcement helper (Flint 685 R1).
        changed = {"_require_base", "action", "authority_lock", "apply_partition_cap"}
        removed = {"install_grant", "_run_transport", "poll_b_for", "_cli"}
        for name in baseline.keys() - changed - removed:
            self.assertEqual(core[name], baseline[name], name)
        self.assertEqual(set(baseline) - set(core), removed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
