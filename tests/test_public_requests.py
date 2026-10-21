"""Real HTTP/adversarial tests. All keys and tokens are disposable, never printed."""
import concurrent.futures
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import ed25519


class PublicRequestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="clack-public-request-")
        self.addCleanup(self.temp.cleanup)
        with mock.patch.dict(os.environ, {"CLACK_RELAY_BASE": self.temp.name}):
            spec = importlib.util.spec_from_file_location("public_request_relay", ROOT / "relay.py")
            self.r = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.r)
        self.keys = {name: ed25519.keygen() for name in ("alice", "bob", "eve")}
        self.tokens = {name: secrets.token_urlsafe(32) for name in self.keys}
        self.pub = {name: self.r.b64u_encode(pair[1]) for name, pair in self.keys.items()}
        self.cfg = {"peers": self.tokens, "identity_pubkeys": self.pub}
        self.r._init_identity_pubkeys(self.cfg)
        self.r.init_db(self.cfg)
        self.addCleanup(lambda: self.r.conn.close())
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self.r.Handler)
        self.base = "http://127.0.0.1:%d" % self.server.server_port
        self.cfg["base_url"] = self.base
        self.r.relay_cfg = self.cfg
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def prepared(self, path, body, peer="bob", signer=None, signed=True):
        data = json.dumps(body).encode()
        headers = {"Content-Type": "application/json"}
        if peer:
            headers["Authorization"] = "Bearer " + self.tokens[peer]
            if signed:
                nonce = "%d:%s" % (int(time.time()), secrets.token_hex(16))
                msg = ("clack-ed25519-v1\nPOST\n" + path + "\n" + hashlib.sha256(data).hexdigest() + "\n" + nonce).encode()
                sig = ed25519.sign(self.keys[signer or peer][0], msg)
                headers.update({"X-Clack-Scheme": "1", "X-Clack-Key": peer,
                                "X-Clack-Nonce": nonce, "X-Clack-Sig": sig.hex()})
        return urllib.request.Request(self.base + path, data=data, headers=headers, method="POST")

    def execute(self, request):
        try:
            response = urllib.request.urlopen(request, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, json.loads(response.read())

    def post(self, path, body, peer="bob", **options):
        return self.execute(self.prepared(path, body, peer, **options))

    def mint(self, inviter="alice", recipient="bob", enc_v=1):
        status, out = self.post("/v1/handshakes/requests", {"target_identity": self.pub[recipient], "enc_v": enc_v}, inviter)
        self.assertEqual(status, 200)
        self.assertEqual(out["mode"], "public_request")
        self.assertEqual(out["link"], self.base + "/join/" + out["link_id"])
        self.assertNotIn("#", out["link"])
        self.assertNotIn("?", out["link"])
        self.assertNotIn("k", out)
        return out

    def redeem(self, invite, **options):
        return self.post("/v1/handshakes/requests/redeem", {"h": invite["link_id"]}, **options)

    def accept(self, pending, peer="bob", **options):
        return self.post("/v1/handshakes/accept", {"handshake_id": pending["handshake_id"], "enc_v": 1}, peer, **options)

    def state(self):
        with self.r.db_lock:
            return (self.r.conn.execute("SELECT count(*) FROM peers").fetchone()[0],
                    self.r.conn.execute("SELECT count(*) FROM handshakes").fetchone()[0],
                    self.r.conn.execute("SELECT coalesce(sum(uses),0) FROM invites").fetchone()[0])

    def sql(self, query, args=()):
        with self.r.db_lock:
            self.r.conn.execute(query, args)
            self.r.conn.commit()

    def test_url_possession_no_auth_wrong_identity_and_forged_signature(self):
        inv = self.mint()
        before = self.state()
        for options, expected in (({"peer": None}, 401), ({"signed": False}, 401),
                                  ({"peer": "eve"}, 403), ({"signer": "eve"}, 401)):
            with self.subTest(options=options):
                self.assertEqual(self.redeem(inv, **options)[0], expected)
                self.assertEqual(self.state(), before)
        self.assertEqual(self.post("/v1/handshakes/redeem", {"h": inv["link_id"], "k": "not-a-claim"})[0], 403)
        self.assertEqual(self.state(), before)

    def test_redeem_then_explicit_mutual_consent(self):
        inv = self.mint()
        status, pending = self.redeem(inv)
        self.assertEqual(status, 200)
        self.assertEqual(pending["status"], "pending")
        self.assertEqual(pending["minter_identity"], self.pub["alice"])
        self.assertNotIn("service_token", pending)
        self.assertLessEqual(pending["pending_expires_at"], inv["exp"])
        self.assertNotEqual(self.accept(pending, "alice")[0], 200)
        status, active = self.accept(pending)
        self.assertEqual(status, 200)
        self.assertEqual(active["status"], "active")
        self.assertEqual(active["enc_capable"], 1)
        self.assertEqual(self.state(), (3, 1, 1))

    def test_public_handle_probes_cannot_poison_target_cooldown(self):
        inv = self.mint()
        for _ in range(12):
            status, _ = self.post("/v1/handshakes/redeem", {
                "h": inv["link_id"], "k": "arbitrary-nonsecret"}, peer=None)
            self.assertEqual(status, 403)
        for _ in range(5):
            self.assertEqual(self.redeem(inv, peer="eve")[0], 403)
        self.assertEqual(self.redeem(inv)[0], 200)

    def assert_fresh_pending(self, old, fresh, recipient="bob"):
        status, pending = self.redeem(fresh, peer=recipient)
        self.assertEqual(status, 200)
        self.assertEqual(pending["status"], "pending")
        self.assertEqual(pending["via_link_id"], fresh["link_id"])
        self.assertGreater(pending["generation"], old["generation"])
        # Prior signed consent must not activate a different request.
        self.assertNotEqual(self.accept(old)[0], 200)
        self.assertEqual(self.redeem({"link_id": old["via_link_id"]})[0], 403)
        status, active = self.accept(pending, peer=recipient)
        self.assertEqual(status, 200)
        self.assertEqual(active["via_link_id"], fresh["link_id"])
        self.assertEqual(active["status"], "active")
        self.assertEqual(active["enc_capable"], 1)
        self.assertEqual(self.state(), (3, 1, 2))

    def test_revoked_pending_replaced_by_fresh_same_direction_request(self):
        inv = self.mint()
        _, old = self.redeem(inv)
        self.assertEqual(self.post("/v1/invites/revoke", {"invite_id": inv["link_id"]}, "alice")[0], 200)
        self.assert_fresh_pending(old, self.mint())
        self.assertEqual(self.redeem(inv)[0], 403)

    def test_revoked_pending_replaced_by_fresh_reverse_direction_request(self):
        inv = self.mint()
        _, old = self.redeem(inv)
        self.assertEqual(self.post("/v1/invites/revoke", {"invite_id": inv["link_id"]}, "alice")[0], 200)
        self.assert_fresh_pending(old, self.mint(inviter="bob", recipient="alice"), recipient="alice")

    def test_expired_backing_request_replaced_without_waiting_for_pending_sweep(self):
        inv = self.mint()
        _, old = self.redeem(inv)
        self.sql("UPDATE invites SET exp=? WHERE invite_id=?", (time.time() - 1, inv["link_id"]))
        self.assert_fresh_pending(old, self.mint())

    def test_new_capable_request_supersedes_unrevoked_incapable_pending(self):
        inv = self.mint(enc_v=0)
        _, old = self.redeem(inv)
        fresh = self.mint(enc_v=1)
        self.assert_fresh_pending(old, fresh)
        # The consumed superseded request cannot displace the new ceremony.
        status, still_active = self.redeem(fresh)
        self.assertEqual(status, 200)
        self.assertEqual(still_active["via_link_id"], fresh["link_id"])

    def test_replacement_generation_limit_fails_without_consuming_fresh_request(self):
        inv = self.mint()
        self.assertEqual(self.redeem(inv)[0], 200)
        self.sql("UPDATE handshakes SET generation=?", (2**63 - 1,))
        fresh = self.mint()
        status, out = self.redeem(fresh)
        self.assertEqual((status, out["error"]), (409, "generation_exhausted"))
        self.assertEqual(self.state(), (3, 1, 1))
        self.assertEqual(self.r.conn.execute("SELECT via_link_id,generation FROM handshakes").fetchone(),
                         (inv["link_id"], 2**63 - 1))

    def test_collision_shaped_probes_on_both_legacy_routes_cannot_poison_target(self):
        inv = self.mint()
        collision = "public:bob:" + inv["link_id"]
        for path, body in (
            ("/v1/handshakes/redeem", {"h": collision, "k": "nonsecret"}),
            ("/v1/invites/redeem", {"invite_id": collision, "secret": "nonsecret"}),
        ):
            for _ in range(12):
                self.assertIn(self.post(path, body, peer=None)[0], (403, 404, 429))
        self.assertEqual(self.redeem(inv)[0], 200)

    def test_source_limit_still_charges_legacy_probes_of_public_request(self):
        inv = self.mint()
        statuses = [self.post("/v1/handshakes/redeem", {
            "h": inv["link_id"], "k": "nonsecret"}, peer=None)[0] for _ in range(31)]
        self.assertEqual(statuses[:30], [403] * 30)
        self.assertEqual(statuses[-1], 429)

    def test_public_requests_never_create_enrollment_challenges_or_reveal_transition(self):
        inv = self.mint()
        count = lambda: self.r.conn.execute("SELECT count(*) FROM enroll_challenges").fetchone()[0]
        before = count()
        missing = self.post("/v1/enroll/challenge", {"invite_id": "00000000-0000-4000-8000-000000000000"}, peer=None)
        active = self.post("/v1/enroll/challenge", {"invite_id": inv["link_id"]}, peer=None)
        self.assertEqual(active, missing)
        self.assertEqual(count(), before)
        self.assertEqual(self.redeem(inv)[0], 200)
        redeemed = self.post("/v1/enroll/challenge", {"invite_id": inv["link_id"]}, peer=None)
        self.assertEqual(redeemed, active)
        self.assertEqual(count(), before)
        self.assertEqual(self.post("/v1/invites/revoke", {"invite_id": inv["link_id"]}, "alice")[0], 200)
        self.assertEqual(self.post("/v1/enroll/challenge", {"invite_id": inv["link_id"]}, peer=None), active)
        self.assertEqual(count(), before)

    def test_denial_rechecked_after_fast_path_before_idempotency(self):
        inv = self.mint()
        self.assertEqual(self.redeem(inv)[0], 200)
        original = self.r.caller_identity
        count = 0
        def invalidate(peer):
            nonlocal count
            count += 1
            if count == 2:
                self.sql("UPDATE invites SET revoked=1 WHERE invite_id=?", (inv["link_id"],))
            return original(peer)
        with mock.patch.object(self.r, "caller_identity", side_effect=invalidate):
            self.assertEqual(self.redeem(inv)[0], 403)
        self.assertEqual(self.state(), (3, 1, 1))

    def test_replay_exact_signed_request_rejected_and_resigned_retry_idempotent(self):
        inv = self.mint()
        request = self.prepared("/v1/handshakes/requests/redeem", {"h": inv["link_id"]})
        status, first = self.execute(request)
        self.assertEqual(status, 200)
        self.assertEqual(self.execute(request)[0], 401)
        status, second = self.redeem(inv)
        self.assertEqual(status, 200)
        self.assertEqual(first["handshake_id"], second["handshake_id"])
        self.assertEqual(first["pending_expires_at"], second["pending_expires_at"])
        self.assertEqual(self.state(), (3, 1, 1))

    def test_double_redemption_race_exactly_one_use_one_pending(self):
        inv = self.mint()
        barrier = threading.Barrier(2)
        def run():
            barrier.wait()
            return self.redeem(inv)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: run(), range(2)))
        self.assertEqual([r[0] for r in results], [200, 200])
        self.assertEqual(results[0][1]["handshake_id"], results[1][1]["handshake_id"])
        self.assertEqual(self.state(), (3, 1, 1))

    def test_inviter_denial_before_and_after_redemption(self):
        inv = self.mint()
        self.assertEqual(self.post("/v1/invites/revoke", {"invite_id": inv["link_id"]}, "eve")[0], 403)
        status, pending = self.redeem(inv)
        self.assertEqual(status, 200)
        self.assertEqual(self.post("/v1/invites/revoke", {"invite_id": inv["link_id"]}, "alice")[0], 200)
        self.assertNotEqual(self.accept(pending)[0], 200)
        self.assertEqual(self.redeem(inv)[0], 403)
        self.assertEqual(self.state(), (3, 1, 1))

    def test_expiry_before_redeem_and_accept(self):
        inv = self.mint()
        status, pending = self.redeem(inv)
        self.assertEqual(status, 200)
        self.sql("UPDATE invites SET exp=? WHERE invite_id=?", (time.time() - 1, inv["link_id"]))
        self.assertEqual(self.redeem(inv)[0], 403)
        self.assertNotEqual(self.accept(pending)[0], 200)

    def test_pending_deadline_and_pair_denial_cannot_be_resurrected(self):
        inv = self.mint()
        _, pending = self.redeem(inv)
        self.sql("UPDATE handshakes SET pending_expires_at=?", (time.time() - 1,))
        self.assertNotEqual(self.accept(pending)[0], 200)
        self.assertEqual(self.redeem(inv)[0], 403)
        # Separate fresh request allows new consent; revoking pair then
        # permanently rejects redemption/accept of that same request.
        inv = self.mint()
        _, pending = self.redeem(inv)
        self.assertEqual(self.post("/v1/handshakes/revoke", {"peer": "bob"}, "alice")[0], 200)
        self.assertEqual(self.redeem(inv)[0], 403)
        self.assertNotEqual(self.accept(pending)[0], 200)

    def test_public_routes_and_accept_never_use_trusted_proxy_exemption(self):
        with mock.patch.object(self.r.Handler, "_internal_trusted_source", return_value=True):
            self.assertEqual(self.post("/v1/handshakes/requests", {"target_identity": self.pub["bob"]}, "alice", signed=False)[0], 401)
            inv = self.mint()
            self.assertEqual(self.redeem(inv, signed=False)[0], 401)
            _, pending = self.redeem(inv)
            self.assertEqual(self.accept(pending, signed=False)[0], 401)
            self.assertEqual(self.accept(pending)[0], 200)

    def test_landing_preview_get_head_all_formats_has_no_effect(self):
        inv = self.mint()
        def snapshot():
            return tuple(tuple(self.r.conn.execute("SELECT * FROM " + table))
                         for table in self.r.REQUIRED_TABLES)
        before = snapshot()
        for method in ("GET", "HEAD"):
            for accept in ("text/html", "text/plain", "application/json"):
                req = urllib.request.Request(inv["link"], method=method, headers={"Accept": accept})
                with urllib.request.urlopen(req) as response:
                    self.assertEqual(response.status, 200)
                    content = response.read().decode()
                    if method == "GET":
                        self.assertIn("Public request URL", content)
                        self.assertNotIn("<script", content)
        self.assertEqual(snapshot(), before)
        self.assertEqual(self.state(), (3, 0, 0))

    def test_known_canonical_target_only_and_no_inline_enrollment(self):
        for target in (None, {}, "bob", self.pub["bob"] + "=", self.pub["alice"], self.r.b64u_encode(ed25519.keygen()[1])):
            status, _ = self.post("/v1/handshakes/requests", {"target_identity": target}, "alice")
            self.assertEqual(status, 400)
        inv = self.mint()
        self.assertEqual(self.post("/v1/handshakes/requests/redeem", {"h": inv["link_id"], "requested_name": "new-agent"})[0], 400)
        self.assertEqual(self.state(), (3, 0, 0))

    def test_legacy_v4_still_mints_redeems_accepts(self):
        status, legacy = self.post("/v1/handshakes/mint-link", {"enc_v": 1}, "alice")
        self.assertEqual(status, 200)
        fields = urllib.parse.parse_qs(urllib.parse.urlsplit(legacy["link"]).fragment)
        self.assertEqual(fields["v"], ["4"])
        # Filtering public request rows must not remove the v4 inline
        # enrollment challenge path used by existing onboarding clients.
        self.assertEqual(self.post("/v1/enroll/challenge", {
            "invite_id": fields["h"][0]}, peer=None)[0], 200)
        status, pending = self.post("/v1/handshakes/redeem", {"h": fields["h"][0], "k": fields["k"][0]})
        self.assertEqual(status, 200)
        self.assertEqual(self.accept(pending)[0], 200)
        self.assertEqual(self.redeem({"link_id": legacy["link_id"]})[0], 403)

    def test_downloaded_standalone_cli_handshake_and_encrypted_roundtrip(self):
        # Download the actual candidate-served client into an otherwise empty
        # runtime. Real relay identity verification, signatures and E2EE; no
        # mocked transport, pin verification or acceptance.
        home = Path(self.temp.name)
        pem = home / "relay-test-key.pem"
        subprocess.run(["openssl", "genrsa", "-out", str(pem), "2048"],
                       capture_output=True, check=True)
        key_text = subprocess.run(["openssl", "rsa", "-in", str(pem), "-text", "-noout"],
                                  capture_output=True, text=True, check=True).stdout
        def grab(label):
            section = key_text.split(label + ":", 1)[1]
            first = section.splitlines()[0].strip()
            if first:
                return int(re.search(r"0x([0-9a-fA-F]+)", first).group(1), 16)
            chunks = []
            for line in section.splitlines()[1:]:
                if not re.fullmatch(r"[0-9a-fA-F:]+", line.strip()):
                    break
                chunks.append(line.strip().replace(":", ""))
            return int("".join(chunks), 16)
        self.r.id_n, self.r.id_e, self.r.id_d = grab("modulus"), grab("publicExponent"), grab("privateExponent")
        downloaded = home / "isolated"
        downloaded.mkdir()
        with urllib.request.urlopen(self.base + "/join/client") as response:
            client_bytes = response.read()
        cli = downloaded / "clack.py"
        cli.write_bytes(client_bytes)
        self.assertEqual(client_bytes, (ROOT / "relay-cli.py").read_bytes())
        spec = importlib.util.spec_from_file_location("public_request_cli", cli)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        configs = {}
        for name in ("alice", "bob"):
            configs[name] = home / (name + ".json")
            cfg = {"kind": module.IDENTITY_KIND, "relay_url": self.base,
                   "service_token": self.tokens[name], "peer_name": name,
                   "identity_pubkey": self.pub[name],
                   "relay_identity_fingerprint": module.relay_identity_fingerprint(self.r.relay_identity_info()),
                   "relay_identity_fingerprint_full": module.relay_identity_fingerprint_full(self.r.relay_identity_info())}
            module._save_identity_config(str(configs[name]), cfg, self.keys[name][0])
        protected = list(configs.values()) + [Path(json.loads(path.read_text())["identity_privkey_path"])
                                               for path in configs.values()]
        before = {path: path.read_bytes() for path in protected}
        def command(name, *args):
            env = {k: v for k, v in os.environ.items() if not k.startswith("CLACK_")}
            result = subprocess.run([sys.executable, str(cli), "--config", str(configs[name]), *args],
                                    cwd=downloaded, env=env, capture_output=True, text=True, timeout=40)
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout
        inv = json.loads(command("alice", "mint-request", "--enc-v", "1", "--", self.pub["bob"]))
        pending = json.loads(command("bob", "redeem-request", inv["link"]))
        self.assertEqual(pending["status"], "pending")
        active = json.loads(command("bob", "accept-handshake", "--enc-v", "1", "--", pending["handshake_id"]))
        self.assertEqual(active["status"], "active")
        # Omission is no advertisement, not an implicit enc_v=0 downgrade.
        repeated = json.loads(command("bob", "accept-handshake", "--", pending["handshake_id"]))
        self.assertEqual(repeated["enc_capable"], 1)
        explicit_zero = json.loads(command("bob", "accept-handshake", "--enc-v", "0", "--", pending["handshake_id"]))
        self.assertEqual(explicit_zero["enc_capable"], 0)
        restored = json.loads(command("bob", "accept-handshake", "--enc-v", "1", "--", pending["handshake_id"]))
        self.assertEqual(restored["enc_capable"], 1)
        for sender, target, message in (("alice", "bob", "public request encrypted hello"),
                                        ("bob", "alice", "public request encrypted reply")):
            command(sender, "send", "--to", target, "--text", message)
            self.assertIn(message, command(target, "poll", "--timeout", "0"))
        rows = list(self.r.conn.execute("SELECT text,enc_v FROM messages"))
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row[1] == 1 and "public request encrypted" not in row[0] for row in rows))
        self.assertTrue(all(path.read_bytes() == data for path, data in before.items()))

    def test_additive_migration_restart_health_and_no_stored_claim(self):
        # Build a predecessor schema by removing ONLY our added column before
        # rerunning the existing migration path. No live DB is used.
        status, legacy = self.post("/v1/handshakes/mint-link", {}, "alice")
        self.assertEqual(status, 200)
        previous = self.r.conn.execute(
            "SELECT invite_id,secret_hash,inviter_identity,uses FROM invites"
        ).fetchone()
        self.sql("INSERT INTO messages(id,sender,recipient,text,created_at,expires_at)"
                 " VALUES('migration-fixture','alice','bob','synthetic',?,?)",
                 (time.time(), time.time() + 3600))
        self.sql("ALTER TABLE invites DROP COLUMN target_identity")
        self.assertIsNotNone(self.r._required_schema_ok())
        self.r.conn.close()
        self.r.init_db(self.cfg)
        self.assertIsNone(self.r._required_schema_ok())
        self.assertEqual(self.r.conn.execute(
            "SELECT invite_id,secret_hash,inviter_identity,uses FROM invites"
            " WHERE invite_id=?", (legacy["link_id"],)
        ).fetchone(), previous)
        self.assertEqual(self.r.conn.execute("SELECT text FROM messages WHERE id='migration-fixture'").fetchone(), ("synthetic",))
        inv = self.mint()
        _, pending = self.redeem(inv)
        before = self.r.conn.execute("SELECT secret_hash,target_identity,uses FROM invites WHERE invite_id=?",
                                     (inv["link_id"],)).fetchone()
        self.assertEqual(before, ("", self.pub["bob"], 1))
        self.r.conn.close()
        self.r.init_db(self.cfg)
        self.assertEqual(self.redeem(inv)[1]["pending_expires_at"], pending["pending_expires_at"])
        self.assertEqual(self.accept(pending)[0], 200)


if __name__ == "__main__":
    unittest.main()
