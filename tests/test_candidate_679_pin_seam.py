#!/usr/bin/env python3
"""Pin-seam regression tests (Zari verdict d8728e50).

The seam: federation_e2ee_v2.AdapterV2._v2_transport_binding required the
endpoint's pin_ref value to equal the CNS relay_identity_key_id
(sha256 of the full 32-byte Ed25519 relay attestation key), while the
inherited Adapter.client() builds a real ClackClient whose
identity.verify_relay_identity requires the SAME pin_ref value to be the
native RSA transport fingerprint (sha256 of the 16-hex RSA identity-domain
digest). One value can never satisfy both: Ed25519 pin passes the adapter
binding but fails the client's PIN MISMATCH; RSA pin passes the client's
fresh-nonce proof but fails the adapter's relay_pin_mismatch.

The fix separates the two pins: the endpoint's pin_ref stays the native
RSA transport identity pin (verified by ClackClient over the real
/v1/identity fresh-nonce challenge), and the operator's Ed25519 federation
attestation pin lives in the v2 supplement's relay_attestation_pins,
bound against the CNS snapshot by _v2_transport_binding.

These tests exercise the REAL boundary, unmocked where it matters: a real
relay.py process on loopback, a real AdapterV2, and a real ClackClient
performing the genuine /v1/identity challenge-response over HTTP.
"""
import base64
import hashlib
import importlib.util
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid
from pathlib import Path
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "clack-client"))

import ed25519  # noqa: E402  (vendored)
import federation_cns as cns  # noqa: E402
from clack_client.client import ClackClient  # noqa: E402
from clack_client.errors import ClackError  # noqa: E402
from clack_client.identity import relay_identity_fingerprint  # noqa: E402


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _der_ints(der):
    assert der[0] == 0x30
    i = 2
    if der[1] & 0x80:
        nlen = der[1] & 0x7F
        i = 2 + nlen
    out = []
    while i < len(der):
        assert der[i] == 0x02
        j = i + 1
        ln = der[j]
        j += 1
        if ln & 0x80:
            nlen = ln & 0x7F
            ln = int.from_bytes(der[j:j + nlen], "big")
            j += nlen
        out.append(int.from_bytes(der[j:j + ln], "big"))
        i = j + ln
    return out


def gen_rsa_key(d):
    pem = os.path.join(d, "identity.pem")
    der = os.path.join(d, "identity.der")
    subprocess.run(["openssl", "genrsa", "-out", pem, "2048"],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "rsa", "-in", pem, "-traditional",
                    "-outform", "DER", "-out", der],
                   check=True, capture_output=True)
    with open(der, "rb") as f:
        _ver, n, e, dd = _der_ints(f.read())[:4]
    return {"n": format(n, "x"), "e": format(e, "x"), "d": format(dd, "x")}


def _private(path, obj):
    data = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
    fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def _cns_sign_snapshot(snap, seed):
    body = {k: v for k, v in snap.items() if k != "signature"}
    pub = ed25519._publickey(seed)
    body["issuer_key_id"] = "sha256:" + hashlib.sha256(pub).hexdigest()
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False, allow_nan=False).encode()
    sig = ed25519.sign(seed, cns.SIGNING_DOMAIN + raw)
    snap = dict(body)
    snap["signature"] = {"alg": "Ed25519", "key_id": body["issuer_key_id"],
                         "value": b64u(sig)}
    return snap


def _peer_route(peer, seed, endpoint, key_id):
    import nacl.signing
    from clack_client import e2ee as ce2ee
    pub = bytes(nacl.signing.SigningKey(seed).verify_key)
    x_pub = ce2ee.x25519_scalarmult(ce2ee.ed25519_seed_to_x25519_priv(seed),
                                    ce2ee._X25519_BASE)
    return {
        "peer": peer, "identity": "agent://" + peer, "owner": "o",
        "prime_relay": "prime-relay", "home": "clack://home-" + peer[-1],
        "relay_endpoint": endpoint, "relay_identity_key_id": key_id,
        "generation": 7,
        "signing_key_id": b64u(hashlib.sha256(pub).digest()[:8]),
        "encryption_key_id": b64u(hashlib.sha256(x_pub).digest()[:8]),
    }


class PinSeamTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="pinseam-679-", dir="/tmp")
        cls.addClassCleanup(cls.tmp.cleanup)
        # --- real relay process on loopback with a real RSA identity key ---
        relay_dir = Path(cls.tmp.name) / "relay"
        relay_dir.mkdir()
        with __import__("socket").socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        assert port != 18802
        rsa_key = gen_rsa_key(str(relay_dir))
        cfg = {"port": port, "bind": "127.0.0.1", "peers": {},
               "identity_key": rsa_key}
        with open(relay_dir / "relay-config.json", "w") as f:
            json.dump(cfg, f)
        logf = open(relay_dir / "srv.log", "a")
        cls._srv_log = logf
        env = dict(os.environ, CLACK_RELAY_BASE=str(relay_dir))
        cls.srv = subprocess.Popen([sys.executable, str(ROOT / "relay.py")],
                                   env=env, stdout=logf, stderr=subprocess.STDOUT)
        cls.url = "http://127.0.0.1:%d" % port
        for _ in range(60):
            if cls.srv.poll() is not None:
                raise RuntimeError("scratch relay exited during startup")
            try:
                with urllib.request.urlopen(cls.url + "/health",
                                            timeout=2) as r:
                    if r.status == 200:
                        break
            except Exception:
                pass
            time.sleep(0.25)
        else:
            raise RuntimeError("scratch relay did not start")
        cls.addClassCleanup(cls._stop_relay)
        # --- the relay's REAL pins: RSA transport fingerprint + Ed25519 ---
        nonce = "cd" * 32
        with urllib.request.urlopen(cls.url + "/v1/identity?nonce=" + nonce,
                                    timeout=10) as r:
            ident = json.load(r)
        cls.rsa_fingerprint = relay_identity_fingerprint(ident["public_key"])
        assert re.match(r"^sha256:[0-9a-f]{16}$", cls.rsa_fingerprint)
        cls.relay_ed_pub = ed25519._publickey(os.urandom(32))
        cls.attestation_key_id = ("sha256:"
                                  + hashlib.sha256(cls.relay_ed_pub).hexdigest())
        assert cls.rsa_fingerprint != cls.attestation_key_id

    @classmethod
    def _stop_relay(cls):
        if cls.srv.poll() is None:
            cls.srv.terminate()
            try:
                cls.srv.wait(timeout=10)
            except Exception:
                cls.srv.kill()
        cls._srv_log.close()

    def make_adapter(self, pin_value, attestation_pins):
        """AdapterV2 rig with pin_ref=pin_value and the given supplement
        relay_attestation_pins map. Both pins are REAL values from the live
        scratch relay."""
        base = Path(tempfile.mkdtemp(prefix="pinseam-adapter-", dir="/tmp"))
        self.addCleanup(__import__("shutil").rmtree, str(base),
                        ignore_errors=True)
        os.chmod(str(base), 0o700)
        _private(base / ".clack-fed-v098-owned.json",
                 {"owned": "pin-seam test"})
        ndr_key = base / "ndr.key"
        verifier_pub = base / "verifier.pub"
        _private(ndr_key, os.urandom(32))
        _private(verifier_pub, os.urandom(32))
        spec = importlib.util.spec_from_file_location(
            "fed_auth_schema_pinseam_" + uuid.uuid4().hex,
            str(ROOT / "federation_authority.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        auth_db = base / "federation-authority.db"
        fd = os.open(str(auth_db), os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        c = sqlite3.connect(str(auth_db))
        try:
            c.executescript(mod._SCHEMA)
            now = time.time()
            c.execute("INSERT INTO grants(grant_id,generation,state,"
                      "tombstone_reason,last_recheck_verified_at,updated_at)"
                      " VALUES (?,?,?,?,?,?)",
                      ("forward", 1, "OK", None, now, now))
            c.commit()
        finally:
            c.close()
        _private(base / "bootstrap.json", {
            "schema": "clack-federation-bootstrap-reference-v1",
            "purpose": "fixture-proof",
            "approval_ref": "DISPOSABLE TEST ONLY",
            "state_dir": str(base),
        })
        token = base / "token.ref"
        key = base / "key.ref"
        pins = base / "pins.ref"
        _private(token, b"disposable-fixture-token")
        _private(key, os.urandom(32))
        _private(pins, {self.url: pin_value})
        endpoints = {"ep": {"url": self.url, "peer": "peer-x",
                            "token_ref": str(token), "key_ref": str(key),
                            "pin_ref": str(pins)}}
        import nacl.signing
        seed_x, seed_y = os.urandom(32), os.urandom(32)
        pubs = {p: bytes(nacl.signing.SigningKey(s).verify_key)
                for p, s in (("peer-x", seed_x), ("peer-y", seed_y))}
        _private(base / "v2-sender-pins.json", {
            "schema": "clack-federation-v2-pins/v1",
            "peer_verify_keys": {p: b64u(pub) for p, pub in pubs.items()},
            "relay_attestation_pins": attestation_pins,
        })
        auth_seed = os.urandom(32)
        _private(base / "cns-authority.key", ed25519._publickey(auth_seed))
        snap = {
            "schema": "clack-cns-route-snapshot/v1", "version": 1,
            "snapshot_id": str(uuid.uuid4()), "issuer": "pin-seam-test",
            "issuer_key_id": "", "sequence": 7,
            "issued_at": int(time.time()) - 60,
            "expires_at": int(time.time()) + 3600,
            "routes": sorted([
                _peer_route("peer-x", seed_x, self.url,
                            self.attestation_key_id),
                _peer_route("peer-y", seed_y, self.url,
                            self.attestation_key_id),
            ], key=lambda r: (r["identity"].encode(), r["peer"].encode())),
            "signature": {},
        }
        snap = _cns_sign_snapshot(snap, auth_seed)
        _private(base / "cns-snapshot.json", snap)
        loaded = cns.load_snapshot(str(base / "cns-snapshot.json"),
                                   str(base / "cns-authority.key"),
                                   str(base / "cns-routes.db"), now=time.time())
        assert set(loaded["routes"]) == {"peer-x", "peer-y"}, loaded
        from federation_adapter import SCHEMA
        cfg = {
            "schema": SCHEMA, "proof_only": True, "state_dir": str(base),
            "bootstrap_ref": str(base / "bootstrap.json"),
            "ndr_key_ref": str(ndr_key),
            "verifier_pub_ref": str(verifier_pub),
            "verifier_id": "pin-seam-test",
            "timeout": 5, "partition_cap_s": 3600, "endpoints": endpoints,
            "routes": {"forward": {"send_endpoint": "ep", "to": "peer-y",
                                   "receive_endpoint": "ep",
                                   "from": "peer-y"}},
        }
        _private(base / "runtime.json", cfg)
        from federation_e2ee_v2 import AdapterV2
        adapter = AdapterV2(str(base / "runtime.json"))
        self.addCleanup(adapter.clients.clear)
        route = cns.resolve_route(str(base / "cns-routes.db"), "peer-x")
        return adapter, route, base

    # --- positive: both pins pass their respective checks at once ---------
    def test_both_pins_pass_simultaneously(self):
        adapter, route, _ = self.make_adapter(
            self.rsa_fingerprint, {self.url: self.attestation_key_id})
        # The adapter binding uses the Ed25519 attestation pin...
        adapter._v2_transport_binding("ep", route)
        # ...and the REAL client verifies the RSA transport pin over HTTP.
        client = adapter.client("ep")
        self.assertIsInstance(client, ClackClient)
        self.assertEqual(client.relay_fingerprint, self.rsa_fingerprint)

    def test_both_pins_pass_after_adapter_restart(self):
        # Rebuilding the adapter from the same config re-verifies both pins.
        a1, route, base = self.make_adapter(
            self.rsa_fingerprint, {self.url: self.attestation_key_id})
        a1._v2_transport_binding("ep", route)
        a1.client("ep")
        from federation_e2ee_v2 import AdapterV2
        a2 = AdapterV2(str(base / "runtime.json"))
        self.addCleanup(a2.clients.clear)
        route2 = cns.resolve_route(str(base / "cns-routes.db"), "peer-x")
        a2._v2_transport_binding("ep", route2)
        self.assertEqual(a2.client("ep").relay_fingerprint,
                         self.rsa_fingerprint)

    # --- negative: wrong Ed25519 attestation pin fails closed -------------
    def test_wrong_attestation_pin_fails_closed_zero_client_calls(self):
        wrong = "sha256:" + hashlib.sha256(os.urandom(32)).hexdigest()
        adapter, route, _ = self.make_adapter(
            self.rsa_fingerprint, {self.url: wrong})
        client_calls = []
        orig_client = adapter.client

        def recording_client(endpoint):
            client_calls.append(endpoint)
            return orig_client(endpoint)

        adapter.client = recording_client
        with self.assertRaises(cns.CNSResolutionError) as ctx:
            adapter._v2_transport_binding("ep", route)
        self.assertIn(cns.RELAY_PIN_MISMATCH, str(ctx.exception))
        self.assertEqual(client_calls, [],
                         "attestation failure must precede any client effect")

    # --- negative: missing attestation pin fails closed -------------------
    def test_missing_attestation_pin_fails_closed_zero_client_calls(self):
        adapter, route, _ = self.make_adapter(
            self.rsa_fingerprint, {"http://127.0.0.1:1": self.attestation_key_id})
        client_calls = []
        orig_client = adapter.client

        def recording_client(endpoint):
            client_calls.append(endpoint)
            return orig_client(endpoint)

        adapter.client = recording_client
        with self.assertRaises(cns.CNSResolutionError) as ctx:
            adapter._v2_transport_binding("ep", route)
        self.assertIn(cns.RELAY_PIN_MISMATCH, str(ctx.exception))
        self.assertEqual(client_calls, [])

    # --- negative: wrong RSA transport pin fails the client PIN check -----
    def test_wrong_rsa_pin_fails_client_pin_mismatch(self):
        adapter, route, _ = self.make_adapter(
            "sha256:" + "00" * 8, {self.url: self.attestation_key_id})
        # The attestation binding itself is fine (right Ed25519 pin)...
        adapter._v2_transport_binding("ep", route)
        # ...but the real client rejects the wrong RSA pin after the
        # genuine fresh-nonce identity proof over HTTP. adapter.client()
        # wraps the identity failure fail-closed.
        with self.assertRaises(RuntimeError) as ctx:
            adapter.client("ep")
        self.assertIn("pinned transport unavailable", str(ctx.exception))
        cause = ctx.exception.__context__  # "from None" suppresses chaining
        self.assertIsInstance(cause, ClackError)
        self.assertIn("PIN MISMATCH", str(cause))

    # --- negative: supplement without the attestation map is rejected -----
    def test_supplement_missing_attestation_map_rejected_at_construction(self):
        base = Path(tempfile.mkdtemp(prefix="pinseam-badsupp-", dir="/tmp"))
        self.addCleanup(__import__("shutil").rmtree, str(base),
                        ignore_errors=True)
        os.chmod(str(base), 0o700)
        _private(base / ".clack-fed-v098-owned.json",
                 {"owned": "pin-seam test"})
        ndr_key = base / "ndr.key"
        verifier_pub = base / "verifier.pub"
        _private(ndr_key, os.urandom(32))
        _private(verifier_pub, os.urandom(32))
        spec = importlib.util.spec_from_file_location(
            "fed_auth_schema_pinseam_bad_" + uuid.uuid4().hex,
            str(ROOT / "federation_authority.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        auth_db = base / "federation-authority.db"
        fd = os.open(str(auth_db), os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        c = sqlite3.connect(str(auth_db))
        try:
            c.executescript(mod._SCHEMA)
            now = time.time()
            c.execute("INSERT INTO grants(grant_id,generation,state,"
                      "tombstone_reason,last_recheck_verified_at,updated_at)"
                      " VALUES (?,?,?,?,?,?)",
                      ("forward", 1, "OK", None, now, now))
            c.commit()
        finally:
            c.close()
        _private(base / "bootstrap.json", {
            "schema": "clack-federation-bootstrap-reference-v1",
            "purpose": "fixture-proof",
            "approval_ref": "DISPOSABLE TEST ONLY",
            "state_dir": str(base),
        })
        token = base / "token.ref"
        key = base / "key.ref"
        pins = base / "pins.ref"
        _private(token, b"disposable-fixture-token")
        _private(key, os.urandom(32))
        _private(pins, {self.url: self.rsa_fingerprint})
        import nacl.signing
        seed = os.urandom(32)
        # Deliberately OLD schema: no relay_attestation_pins key.
        _private(base / "v2-sender-pins.json", {
            "schema": "clack-federation-v2-pins/v1",
            "peer_verify_keys": {
                "peer-x": b64u(bytes(nacl.signing.SigningKey(seed).verify_key))},
        })
        from federation_adapter import SCHEMA
        cfg = {
            "schema": SCHEMA, "proof_only": True, "state_dir": str(base),
            "bootstrap_ref": str(base / "bootstrap.json"),
            "ndr_key_ref": str(ndr_key),
            "verifier_pub_ref": str(verifier_pub),
            "verifier_id": "pin-seam-test",
            "timeout": 5, "partition_cap_s": 3600,
            "endpoints": {"ep": {"url": self.url, "peer": "peer-x",
                                 "token_ref": str(token),
                                 "key_ref": str(key),
                                 "pin_ref": str(pins)}},
            "routes": {"forward": {"send_endpoint": "ep", "to": "peer-y",
                                   "receive_endpoint": "ep",
                                   "from": "peer-y"}},
        }
        _private(base / "runtime.json", cfg)
        from federation_e2ee_v2 import AdapterV2
        with self.assertRaises(ValueError):
            AdapterV2(str(base / "runtime.json"))


if __name__ == "__main__":
    main()
