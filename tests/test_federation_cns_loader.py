"""Signed-static CNS loader tests (ENGINEERED, not custody).

Covers the required private tests from kns-cns-seam-contract-v1.json
against federation_cns.py:

- static signed CNS route succeeds with KNS disabled
- matching optional KNS hint does not alter selected authority bytes
- attacker relayEndpoint / primeRelay hints -> kns_cns_mismatch with zero
  socket creation (socket.socket is monkeypatched to raise)
- malformed hint -> kns_hint_invalid
- unknown peer, invalid signature, stale snapshot, sequence rollback,
  same-sequence byte change, generation rollback, same-generation rewrite
  each fail closed
- omission from a higher-sequence snapshot disables new work while the
  high-water row is retained
- v2 envelope <-> CNS route binding (e2ee_v2_context_untrusted)

Run: python3 -m unittest discover -s tests -p "test_federation_cns*" -v
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import ed25519  # noqa: E402
import federation_cns as cns  # noqa: E402
from federation_cns import CNSResolutionError  # noqa: E402


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


NOW = 1780000000


def make_keypair():
    seed, pub = ed25519.keygen()
    return seed, pub


def _key_id(prefix, peer):
    raw = (prefix.encode() + b"-" + peer.encode()).ljust(8, b"0")[:8]
    return b64u(raw)


def route(peer, identity, generation=3, **over):
    r = {
        "peer": peer,
        "identity": identity,
        "owner": "Owner of %s" % peer,
        "prime_relay": "prime-relay",
        "home": "clack://home-%s" % peer,
        "relay_endpoint": "https://127.0.0.1:19999",
        "relay_identity_key_id": "sha256:" + "ab" * 32,
        "generation": generation,
        "signing_key_id": _key_id("sign", peer),
        "encryption_key_id": _key_id("enc", peer),
    }
    r.update(over)
    return r


def sign_snapshot(snap, seed):
    body = {k: v for k, v in snap.items() if k != "signature"}
    pub = ed25519._publickey(seed)
    body["issuer_key_id"] = "sha256:" + hashlib.sha256(pub).hexdigest()
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False, allow_nan=False).encode()
    sig = ed25519.sign(seed, cns.SIGNING_DOMAIN + raw)
    snap = dict(body)
    snap["signature"] = {
        "alg": "Ed25519",
        "key_id": body["issuer_key_id"],
        "value": b64u(sig),
    }
    return snap


def snapshot(routes, seed, sequence=7, issued_at=NOW - 60,
             expires_at=NOW + 3600):
    snap = {
        "schema": "clack-cns-route-snapshot/v1",
        "version": 1,
        "snapshot_id": str(uuid.uuid4()),
        "issuer": "cns-test-authority",
        "issuer_key_id": "",  # filled by sign_snapshot
        "sequence": sequence,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "routes": sorted(
            routes,
            key=lambda r: (r["identity"].encode(), r["peer"].encode())),
        "signature": {},
    }
    return sign_snapshot(snap, seed)


class CNSLoaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cand679-cns-", dir="/tmp")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.seed, self.pub = make_keypair()
        self.key_path = str(self.base / "authority.pub")
        self._write(self.key_path, self.pub)
        self.snap_path = str(self.base / "snapshot.json")
        self.state_path = str(self.base / "cns-state.db")

    def _write(self, path, data):
        if isinstance(data, str):
            data = data.encode()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)

    def write_snapshot(self, snap):
        if os.path.exists(self.snap_path):
            os.unlink(self.snap_path)
        self._write(self.snap_path, json.dumps(snap).encode())

    def load(self, snap, now=NOW):
        self.write_snapshot(snap)
        return cns.load_snapshot(self.snap_path, self.key_path,
                                 self.state_path, now=now)

    def base_routes(self):
        return [route("alice", "agent://alice"), route("bob", "agent://bob")]

    # --- positive path ---

    def test_static_signed_snapshot_loads_with_kns_disabled(self):
        result = self.load(snapshot(self.base_routes(), self.seed))
        self.assertEqual(result["sequence"], 7)
        self.assertFalse(result["replayed"])
        routes = result["routes"]
        self.assertEqual(set(routes), {"alice", "bob"})
        alice = routes["alice"]
        self.assertEqual(alice["identity"], "agent://alice")
        self.assertEqual(alice["generation"], 3)
        ctx = cns.route_context(alice)
        self.assertEqual(ctx, {
            "identity": "agent://alice",
            "home": "clack://home-alice",
            "generation": 3,
            "signing_key_id": alice["signing_key_id"],
            "encryption_key_id": alice["encryption_key_id"],
        })

    def test_resolve_route_returns_exactly_one_active_route(self):
        self.load(snapshot(self.base_routes(), self.seed))
        resolved = cns.resolve_route(self.state_path, "alice")
        self.assertEqual(resolved["peer"], "alice")
        self.assertEqual(resolved["identity"], "agent://alice")

    def test_matching_kns_hint_does_not_alter_authority_bytes(self):
        self.load(snapshot(self.base_routes(), self.seed))
        before = cns.resolve_route(self.state_path, "alice")
        hint = {
            "agent": "alice",
            "primeRelay": "prime-relay",
            "relayEndpoint": "https://127.0.0.1:19999",
            "status": "observability only",
            "source": "test",
        }
        after = cns.resolve_route(self.state_path, "alice", kns_hint=hint)
        self.assertEqual(before, after)

    # --- KNS stays OFF: hostile hints fail closed with zero sockets ---

    def test_attacker_relay_endpoint_hint_fails_closed_no_sockets(self):
        self.load(snapshot(self.base_routes(), self.seed))
        hint = {
            "agent": "alice",
            "primeRelay": "prime-relay",
            "relayEndpoint": "https://203.0.113.9:8443",
            "status": "x",
            "source": "attacker",
        }
        with mock.patch.object(socket, "socket",
                               side_effect=AssertionError("socket created")):
            with self.assertRaises(CNSResolutionError) as ctx:
                cns.resolve_route(self.state_path, "alice", kns_hint=hint)
        self.assertEqual(ctx.exception.code, cns.KNS_CNS_MISMATCH)

    def test_attacker_prime_relay_hint_fails_closed(self):
        self.load(snapshot(self.base_routes(), self.seed))
        hint = {"agent": "alice", "primeRelay": "evil-relay",
                "relayEndpoint": "https://127.0.0.1:19999",
                "status": "x", "source": "attacker"}
        with self.assertRaises(CNSResolutionError) as ctx:
            cns.resolve_route(self.state_path, "alice", kns_hint=hint)
        self.assertEqual(ctx.exception.code, cns.KNS_CNS_MISMATCH)

    def test_hint_agent_mismatch_fails_closed(self):
        self.load(snapshot(self.base_routes(), self.seed))
        hint = {"agent": "mallory", "primeRelay": "prime-relay",
                "relayEndpoint": "https://127.0.0.1:19999",
                "status": "x", "source": "t"}
        with self.assertRaises(CNSResolutionError) as ctx:
            cns.resolve_route(self.state_path, "alice", kns_hint=hint)
        self.assertEqual(ctx.exception.code, cns.KNS_CNS_MISMATCH)

    def test_malformed_hint_extra_field_fails_closed(self):
        self.load(snapshot(self.base_routes(), self.seed))
        hint = {"agent": "alice", "primeRelay": "prime-relay",
                "relayEndpoint": "https://127.0.0.1:19999",
                "status": "x", "source": "t", "evil": "field"}
        with self.assertRaises(CNSResolutionError) as ctx:
            cns.resolve_route(self.state_path, "alice", kns_hint=hint)
        self.assertEqual(ctx.exception.code, cns.KNS_HINT_INVALID)

    def test_no_code_path_derives_authority_from_kns(self):
        # The loader module has no socket import or socket use at all.
        import inspect

        source = inspect.getsource(cns)
        self.assertNotIn("import socket", source)
        self.assertNotIn("socket.", source)

    # --- snapshot validation failures ---

    def test_unknown_peer_fails_closed(self):
        self.load(snapshot(self.base_routes(), self.seed))
        with self.assertRaises(CNSResolutionError) as ctx:
            cns.resolve_route(self.state_path, "mallory")
        self.assertEqual(ctx.exception.code, cns.CNS_ROUTE_UNKNOWN)

    def test_bad_short_name_fails_closed(self):
        self.load(snapshot(self.base_routes(), self.seed))
        for bad in ("Alice", "../x", "", "a" * 65):
            with self.assertRaises(CNSResolutionError) as ctx:
                cns.resolve_route(self.state_path, bad)
            self.assertEqual(ctx.exception.code, cns.CNS_ROUTE_UNKNOWN, bad)

    def test_invalid_signature_fails_closed(self):
        snap = snapshot(self.base_routes(), self.seed)
        snap["signature"]["value"] = b64u(os.urandom(64))
        with self.assertRaises(CNSResolutionError) as ctx:
            self.load(snap)
        self.assertEqual(ctx.exception.code, cns.CNS_SNAPSHOT_INVALID)

    def test_wrong_authority_key_fails_closed(self):
        _, other_pub = make_keypair()
        other_key = str(self.base / "other.pub")
        self._write(other_key, other_pub)
        self.write_snapshot(snapshot(self.base_routes(), self.seed))
        with self.assertRaises(CNSResolutionError) as ctx:
            cns.load_snapshot(self.snap_path, other_key, self.state_path, now=NOW)
        self.assertEqual(ctx.exception.code, cns.CNS_SNAPSHOT_INVALID)

    def test_stale_snapshot_fails_closed(self):
        snap = snapshot(self.base_routes(), self.seed,
                        issued_at=NOW - 7200, expires_at=NOW - 600)
        with self.assertRaises(CNSResolutionError) as ctx:
            self.load(snap)
        self.assertEqual(ctx.exception.code, cns.CNS_SNAPSHOT_INVALID)

    def test_future_issued_at_fails_closed(self):
        snap = snapshot(self.base_routes(), self.seed, issued_at=NOW + 600)
        with self.assertRaises(CNSResolutionError) as ctx:
            self.load(snap)
        self.assertEqual(ctx.exception.code, cns.CNS_SNAPSHOT_INVALID)

    def test_excessive_lifetime_fails_closed(self):
        snap = snapshot(self.base_routes(), self.seed,
                        expires_at=NOW + 604800 + 1)
        with self.assertRaises(CNSResolutionError) as ctx:
            self.load(snap)
        self.assertEqual(ctx.exception.code, cns.CNS_SNAPSHOT_INVALID)

    def test_duplicate_json_keys_rejected(self):
        raw = b'{"schema": "clack-cns-route-snapshot/v1", "schema": "x"}'
        self._write(self.snap_path, raw)
        with self.assertRaises(CNSResolutionError) as ctx:
            cns.load_snapshot(self.snap_path, self.key_path,
                              self.state_path, now=NOW)
        self.assertEqual(ctx.exception.code, cns.CNS_SNAPSHOT_INVALID)

    def test_unknown_top_level_field_rejected(self):
        snap = snapshot(self.base_routes(), self.seed)
        snap["unknown"] = 1
        # Re-sign so the failure is the shape check, not the signature.
        snap = sign_snapshot(
            {k: v for k, v in snap.items() if k != "signature"}, self.seed)
        snap["unknown"] = 1
        with self.assertRaises(CNSResolutionError) as ctx:
            self.load(snap)
        self.assertEqual(ctx.exception.code, cns.CNS_SNAPSHOT_INVALID)

    def test_bool_sequence_and_float_issued_at_rejected(self):
        for mutate in (lambda s: s.update(sequence=True),
                       lambda s: s.update(issued_at=float(NOW - 60))):
            snap = snapshot(self.base_routes(), self.seed)
            mutate(snap)
            snap = sign_snapshot(
                {k: v for k, v in snap.items() if k != "signature"}, self.seed)
            with self.assertRaises(CNSResolutionError) as ctx:
                self.load(snap)
            self.assertEqual(ctx.exception.code, cns.CNS_SNAPSHOT_INVALID)

    def test_missing_snapshot_file_fails_closed(self):
        with self.assertRaises(CNSResolutionError) as ctx:
            cns.load_snapshot(str(self.base / "nope.json"), self.key_path,
                              self.state_path, now=NOW)
        self.assertEqual(ctx.exception.code, cns.CNS_SNAPSHOT_UNAVAILABLE)

    # --- monotonicity ---

    def test_sequence_rollback_rejected(self):
        self.load(snapshot(self.base_routes(), self.seed, sequence=7))
        with self.assertRaises(CNSResolutionError) as ctx:
            self.load(snapshot(self.base_routes(), self.seed, sequence=6))
        self.assertEqual(ctx.exception.code, cns.CNS_SNAPSHOT_INVALID)

    def test_same_sequence_identical_bytes_replays_cleanly(self):
        snap = snapshot(self.base_routes(), self.seed, sequence=7)
        first = self.load(snap)
        self.assertFalse(first["replayed"])
        # Same sequence but a different snapshot_id signs different bytes.
        with self.assertRaises(CNSResolutionError) as ctx:
            self.load(snapshot(self.base_routes(), self.seed, sequence=7))
        self.assertEqual(ctx.exception.code, cns.CNS_SNAPSHOT_INVALID)
        # Byte-identical replay is accepted without mutation.
        again = self.load(snap)
        self.assertTrue(again["replayed"])

    def test_same_sequence_different_bytes_rejected(self):
        self.load(snapshot(self.base_routes(), self.seed, sequence=7))
        other = snapshot(self.base_routes(), self.seed, sequence=7)
        with self.assertRaises(CNSResolutionError) as ctx:
            self.load(other)
        self.assertEqual(ctx.exception.code, cns.CNS_SNAPSHOT_INVALID)

    def test_generation_rollback_rejected(self):
        self.load(snapshot(self.base_routes(), self.seed, sequence=7))
        routes = [route("alice", "agent://alice", generation=2),
                  route("bob", "agent://bob")]
        with self.assertRaises(CNSResolutionError) as ctx:
            self.load(snapshot(routes, self.seed, sequence=8))
        self.assertEqual(ctx.exception.code, cns.CNS_SNAPSHOT_INVALID)

    def test_same_generation_rewrite_rejected(self):
        self.load(snapshot(self.base_routes(), self.seed, sequence=7))
        routes = [route("alice", "agent://alice", generation=3,
                        home="clack://moved"),
                  route("bob", "agent://bob")]
        with self.assertRaises(CNSResolutionError) as ctx:
            self.load(snapshot(routes, self.seed, sequence=8))
        self.assertEqual(ctx.exception.code, cns.CNS_SNAPSHOT_INVALID)

    def test_higher_generation_may_rotate_endpoint_and_keys(self):
        self.load(snapshot(self.base_routes(), self.seed, sequence=7))
        routes = [route("alice", "agent://alice", generation=4,
                        relay_endpoint="https://127.0.0.1:19998",
                        encryption_key_id=b64u(b"newkey00"),
                        signing_key_id=b64u(b"newsign0")),
                  route("bob", "agent://bob")]
        result = self.load(snapshot(routes, self.seed, sequence=8))
        self.assertEqual(result["routes"]["alice"]["generation"], 4)
        self.assertEqual(result["routes"]["alice"]["relay_endpoint"],
                         "https://127.0.0.1:19998")

    def test_omission_disables_new_work_but_retains_high_water(self):
        self.load(snapshot(self.base_routes(), self.seed, sequence=7))
        result = self.load(snapshot([route("bob", "agent://bob")], self.seed,
                                    sequence=8))
        self.assertEqual(set(result["routes"]), {"bob"})
        with self.assertRaises(CNSResolutionError) as ctx:
            cns.resolve_route(self.state_path, "alice")
        self.assertEqual(ctx.exception.code, cns.CNS_ROUTE_UNKNOWN)
        # High-water row retained for rollback detection / reconciliation.
        conn = __import__("sqlite3").connect(self.state_path)
        try:
            row = conn.execute(
                "SELECT generation, disabled FROM cns_routes WHERE identity=?",
                ("agent://alice",)).fetchone()
        finally:
            conn.close()
        self.assertEqual(row, (3, 1))

    # --- v2 envelope <-> CNS route binding ---

    def _v2_envelope_for(self, route_row, mutate=None):
        enc = {
            "v": 2,
            "alg": "x25519-chacha20poly1305+ed25519",
            "eph": b64u(bytes([1]) * 32),
            "nonce": b64u(bytes([2]) * 12),
            "kid": route_row["encryption_key_id"],
            "skid": route_row["signing_key_id"],
            "ctx": {
                "id": str(uuid.uuid4()),
                "sender": "alice",
                "recipient": "alice",
                "sender_id": "agent://alice",
                "recipient_id": route_row["identity"],
                "topic": "task.v2",
                "in_reply_to": None,
                "sender_home": "clack://home-alice",
                "recipient_home": route_row["home"],
                "sender_home_generation": 3,
                "recipient_home_generation": route_row["generation"],
            },
            "ct": b64u(bytes([5]) * 32),
            "sig": b64u(bytes([6]) * 64),
        }
        if mutate:
            mutate(enc)
        return enc

    def test_envelope_matching_route_is_trusted(self):
        self.load(snapshot(self.base_routes(), self.seed))
        resolved = cns.resolve_route(self.state_path, "alice")
        self.assertIsNone(
            cns.check_envelope_against_route(
                self._v2_envelope_for(resolved), resolved))

    def test_envelope_with_wrong_kid_is_untrusted(self):
        self.load(snapshot(self.base_routes(), self.seed))
        resolved = cns.resolve_route(self.state_path, "alice")
        enc = self._v2_envelope_for(
            resolved, lambda e: e.update(kid=b64u(b"wrongkid")))
        with self.assertRaises(CNSResolutionError) as ctx:
            cns.check_envelope_against_route(enc, resolved)
        self.assertEqual(ctx.exception.code, cns.E2EE_V2_CONTEXT_UNTRUSTED)

    def test_envelope_with_stale_generation_is_untrusted(self):
        self.load(snapshot(self.base_routes(), self.seed))
        resolved = cns.resolve_route(self.state_path, "alice")
        enc = self._v2_envelope_for(
            resolved,
            lambda e: e["ctx"].update(recipient_home_generation=2))
        with self.assertRaises(CNSResolutionError) as ctx:
            cns.check_envelope_against_route(enc, resolved)
        self.assertEqual(ctx.exception.code, cns.E2EE_V2_CONTEXT_UNTRUSTED)


if __name__ == "__main__":
    unittest.main()
