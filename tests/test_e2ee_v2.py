"""E2EE v2 security and client-contract tests.

These tests intentionally specify behavior that the v1 primitive and the
3883 transport-only candidate do not provide.
"""
from __future__ import annotations

from collections import UserDict
import copy
import json
from pathlib import Path
import sys
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "clack-client"))

import ed25519  # noqa: E402
from clack_client import e2ee  # noqa: E402
from clack_client.client import ClackClient  # noqa: E402
from clack_client.envelope import native_payload  # noqa: E402
from clack_client.errors import ClackError  # noqa: E402


class E2EEV2Tests(unittest.TestCase):
    def setUp(self):
        self.sender_seed, self.sender_pub = ed25519.keygen()
        self.recipient_seed, self.recipient_pub = ed25519.keygen()
        self.recipient_xpub = e2ee.ed25519_pub_to_x25519_pub(self.recipient_pub)
        self.message_id = str(uuid.uuid4())
        self.reply_id = str(uuid.uuid4())
        self.context = e2ee.make_context(
            message_id=self.message_id,
            sender="fixture-a",
            recipient="fixture-b",
            sender_id="agent://fixture-a",
            recipient_id="agent://fixture-b",
            topic="task.e2ee",
            in_reply_to=self.reply_id,
            sender_home="clack://ex",
            recipient_home="clack://omni",
            sender_home_generation=7,
            recipient_home_generation=9,
        )
        self.plaintext = b"authenticated private payload"

    def envelope(self):
        return e2ee.encrypt_envelope_v2(
            self.sender_seed,
            self.recipient_xpub,
            self.plaintext,
            self.context,
        )

    def test_round_trip_verifies_sender_and_context(self):
        envelope = self.envelope()
        self.assertIsNone(e2ee.validate_envelope(envelope))
        self.assertEqual(envelope["v"], 2)
        self.assertEqual(envelope["ctx"], self.context)
        self.assertEqual(
            e2ee.decrypt_envelope_v2(
                self.recipient_seed,
                envelope,
                self.sender_pub,
                self.context,
            ),
            self.plaintext,
        )
        self.assertEqual(json.loads(e2ee.serialize_envelope(envelope)), envelope)
        self.assertEqual(len(e2ee.envelope_digest(envelope)), 64)

    def test_wrong_sender_key_is_rejected(self):
        envelope = self.envelope()
        _, wrong_pub = ed25519.keygen()
        with self.assertRaises(e2ee.DecryptError):
            e2ee.decrypt_envelope_v2(
                self.recipient_seed, envelope, wrong_pub, self.context
            )

    def test_relay_cannot_forge_claimed_sender(self):
        envelope = self.envelope()
        attacker_seed, _ = ed25519.keygen()
        forged = e2ee.encrypt_envelope_v2(
            attacker_seed,
            self.recipient_xpub,
            b"relay forgery",
            self.context,
        )
        with self.assertRaises(e2ee.DecryptError):
            e2ee.decrypt_envelope_v2(
                self.recipient_seed, forged, self.sender_pub, self.context
            )
        self.assertNotEqual(envelope["sig"], forged["sig"])

    def test_every_context_field_is_authenticated(self):
        changes = {
            "id": str(uuid.uuid4()),
            "sender": "fixture-mallory",
            "recipient": "fixture-c",
            "sender_id": "agent://mallory",
            "recipient_id": "agent://fixture-c",
            "topic": "task.other",
            "in_reply_to": str(uuid.uuid4()),
            "sender_home": "clack://other-ex",
            "recipient_home": "clack://other-omni",
            "sender_home_generation": 8,
            "recipient_home_generation": 10,
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                forged = copy.deepcopy(self.envelope())
                forged["ctx"][field] = value
                with self.assertRaises(e2ee.DecryptError):
                    e2ee.decrypt_envelope_v2(
                        self.recipient_seed,
                        forged,
                        self.sender_pub,
                        forged["ctx"],
                    )

    def test_outer_context_substitution_is_rejected(self):
        envelope = self.envelope()
        for field, value in (
            ("id", str(uuid.uuid4())),
            ("topic", "task.substituted"),
            ("in_reply_to", str(uuid.uuid4())),
            ("recipient_home", "clack://wrong-home"),
            ("recipient_home_generation", 10),
        ):
            with self.subTest(field=field):
                expected = dict(self.context)
                expected[field] = value
                with self.assertRaisesRegex(e2ee.DecryptError, "context mismatch"):
                    e2ee.decrypt_envelope_v2(
                        self.recipient_seed,
                        envelope,
                        self.sender_pub,
                        expected,
                    )

    def test_ciphertext_and_header_tampering_is_rejected(self):
        envelope = self.envelope()
        replacements = {
            "eph": e2ee.b64u_encode(bytes([1]) * 32),
            "nonce": e2ee.b64u_encode(bytes([2]) * 12),
            "kid": e2ee.b64u_encode(bytes([3]) * 8),
            "skid": e2ee.b64u_encode(bytes([4]) * 8),
            "ct": e2ee.b64u_encode(bytes([5]) * 32),
            "sig": e2ee.b64u_encode(bytes([6]) * 64),
        }
        for field, value in replacements.items():
            with self.subTest(field=field):
                tampered = dict(envelope)
                tampered[field] = value
                with self.assertRaises(e2ee.DecryptError):
                    e2ee.decrypt_envelope_v2(
                        self.recipient_seed,
                        tampered,
                        self.sender_pub,
                        self.context,
                    )

    def test_new_id_replay_fails_but_exact_wire_is_stable(self):
        envelope = self.envelope()
        wire = e2ee.serialize_envelope(envelope)
        self.assertEqual(e2ee.serialize_envelope(json.loads(wire)), wire)
        replay_context = dict(self.context)
        replay_context["id"] = str(uuid.uuid4())
        with self.assertRaises(e2ee.DecryptError):
            e2ee.decrypt_envelope_v2(
                self.recipient_seed,
                envelope,
                self.sender_pub,
                replay_context,
            )

    def test_context_encoding_is_collision_safe(self):
        first = dict(self.context, sender="ab", recipient="c")
        second = dict(self.context, sender="a", recipient="bc")
        self.assertNotEqual(
            e2ee.canonical_context_bytes(first),
            e2ee.canonical_context_bytes(second),
        )
        third = dict(self.context, topic=None, in_reply_to=self.reply_id)
        fourth = dict(self.context, topic=self.reply_id, in_reply_to=None)
        self.assertNotEqual(
            e2ee.canonical_context_bytes(third),
            e2ee.canonical_context_bytes(fourth),
        )

    def test_malformed_unicode_uses_bounded_context_errors(self):
        for field in (
            "sender",
            "recipient",
            "sender_id",
            "recipient_id",
            "sender_home",
            "recipient_home",
        ):
            with self.subTest(field=field):
                malformed = dict(self.context)
                malformed[field] = "broken-\ud800-value"
                expected_error = "bad context %s" % field

                self.assertEqual(
                    e2ee.validate_context(malformed),
                    expected_error,
                )
                with self.assertRaisesRegex(ValueError, expected_error):
                    e2ee.canonical_context_bytes(malformed)

                malformed_envelope = self.envelope()
                malformed_envelope["ctx"] = malformed
                with self.assertRaisesRegex(e2ee.DecryptError, expected_error):
                    e2ee.decrypt_envelope_v2(
                        self.recipient_seed,
                        malformed_envelope,
                        self.sender_pub,
                        malformed,
                    )

                with self.assertRaisesRegex(e2ee.DecryptError, expected_error):
                    e2ee.decrypt_envelope_v2(
                        self.recipient_seed,
                        self.envelope(),
                        self.sender_pub,
                        malformed,
                    )

    def test_native_payload_keeps_v1_and_accepts_exact_v2(self):
        v1 = e2ee.encrypt_envelope(
            "fixture-a", "fixture-b", self.recipient_xpub, b"legacy"
        )
        self.assertEqual(json.loads(native_payload(v1, 1)), v1)
        v2 = self.envelope()
        self.assertEqual(json.loads(native_payload(v2, 2)), v2)
        with self.assertRaises(ValueError):
            native_payload(v2, 1)
        with self.assertRaises(ValueError):
            native_payload(dict(v2, unexpected="field"), 2)

    def test_client_binds_outer_fields_to_v2_context(self):
        envelope = self.envelope()
        client = ClackClient.__new__(ClackClient)
        client.peer_name = "fixture-a"
        captured = []

        def request(method, path, body=None, idempotent=False):
            captured.append((method, path, body, idempotent))
            return {"id": self.message_id, "accepted": True}

        client._request = request
        self.assertEqual(
            client.send("fixture-b", enc=envelope, enc_v=2, required_enc_v=2),
            (self.message_id, True),
        )
        body = captured[0][2]
        self.assertEqual(body["id"], self.context["id"])
        self.assertEqual(body["topic"], self.context["topic"])
        self.assertEqual(body["in_reply_to"], self.context["in_reply_to"])
        self.assertEqual(body["enc_v"], 2)
        self.assertNotIn("text", body)

        with self.assertRaises(ClackError):
            client.send(
                "fixture-b",
                topic="task.wrong",
                enc=envelope,
                enc_v=2,
                required_enc_v=2,
            )
        with self.assertRaises(ClackError):
            client.send("fixture-b", "plaintext", required_enc_v=2)

    def test_client_rejects_hostile_envelope_keys_before_callbacks(self):
        callbacks = []

        class HostileKey(str):
            def __hash__(self):
                callbacks.append("hash")
                return super().__hash__()

            def __eq__(self, other):
                callbacks.append("eq")
                return super().__eq__(other)

        envelope = self.envelope()
        version = envelope.pop("v")
        envelope[HostileKey("v")] = version
        callbacks.clear()

        client = ClackClient.__new__(ClackClient)
        client.peer_name = "fixture-a"
        client._request = lambda *args, **kwargs: self.fail(
            "hostile envelope reached transport"
        )
        with self.assertRaises(ClackError):
            client.send("fixture-b", enc=envelope, required_enc_v=2)
        self.assertEqual(callbacks, [])

    def test_client_does_not_normalize_explicit_empty_outer_context(self):
        context = dict(self.context, topic=None, in_reply_to=None)
        envelope = e2ee.encrypt_envelope_v2(
            self.sender_seed,
            self.recipient_xpub,
            self.plaintext,
            context,
        )
        client = ClackClient.__new__(ClackClient)
        client.peer_name = "fixture-a"
        client._request = lambda *args, **kwargs: self.fail(
            "mismatched outer context reached transport"
        )

        with self.assertRaisesRegex(ClackError, "topic/context mismatch"):
            client.send("fixture-b", topic="", enc=envelope, required_enc_v=2)
        with self.assertRaisesRegex(ClackError, "reply/context mismatch"):
            client.send(
                "fixture-b",
                in_reply_to="",
                enc=envelope,
                required_enc_v=2,
            )

    def test_client_rejects_hostile_outer_authority_strings_before_callbacks(self):
        callbacks = []

        class HostileString(str):
            def __eq__(self, other):
                callbacks.append(("eq", str(self), other))
                return True

            def __ne__(self, other):
                callbacks.append(("ne", str(self), other))
                return False

        envelope = self.envelope()
        other_id = str(uuid.uuid4())
        cases = (
            ("recipient", {"to": HostileString("carol")}),
            ("message-id", {"msg_id": HostileString(other_id)}),
            ("topic", {"topic": HostileString("task.wrong")}),
            ("reply", {"in_reply_to": HostileString(other_id)}),
            ("sender", {"peer_name": HostileString("mallory")}),
        )

        for label, override in cases:
            with self.subTest(label=label):
                callbacks.clear()
                reached = []
                client = ClackClient.__new__(ClackClient)
                client.peer_name = override.get(
                    "peer_name", self.context["sender"]
                )
                client._request = lambda *args, **kwargs: reached.append(
                    (args, kwargs)
                ) or {"id": self.message_id, "accepted": True}
                kwargs = {
                    "to": override.get("to", self.context["recipient"]),
                    "enc": envelope,
                    "enc_v": 2,
                    "required_enc_v": 2,
                }
                for field in ("msg_id", "topic", "in_reply_to"):
                    if field in override:
                        kwargs[field] = override[field]
                with self.assertRaises(ClackError):
                    client.send(**kwargs)
                self.assertEqual(callbacks, [])
                self.assertEqual(reached, [])

    def test_v1_decryptor_rejects_v2_shaped_algorithm_confusion(self):
        legacy_plaintext = b"v1 ciphertext must remain v1"
        envelope = e2ee.encrypt_envelope(
            "alice",
            "bob",
            self.recipient_xpub,
            legacy_plaintext,
        )
        envelope.update(
            {
                "v": e2ee.ENC_VERSION_V2,
                "alg": e2ee.ENC_ALG_V2,
                "skid": e2ee.b64u_encode(
                    e2ee.signing_pubkey_id(self.sender_pub)
                ),
                "ctx": dict(self.context),
                "sig": e2ee.b64u_encode(bytes(64)),
            }
        )
        # The generic relay validator is deliberately shape-only. The concrete
        # decrypt entry point must still refuse the wrong protocol version.
        self.assertIsNone(e2ee.validate_envelope(envelope))
        with self.assertRaises(e2ee.DecryptError):
            e2ee.decrypt_envelope(
                self.recipient_seed,
                envelope,
                "alice",
                "bob",
            )

    def test_context_and_envelope_reject_hostile_mapping_shapes_without_callbacks(self):
        mapping_callbacks = []

        class HostileContext(UserDict):
            def keys(self):
                mapping_callbacks.append("keys")
                return super().keys()

            def __iter__(self):
                mapping_callbacks.append("iter")
                return super().__iter__()

            def __getitem__(self, key):
                mapping_callbacks.append("getitem")
                return super().__getitem__(key)

        hostile_context = HostileContext(self.context)
        with self.assertRaisesRegex(ValueError, "context must be an object"):
            e2ee.encrypt_envelope_v2(
                self.sender_seed,
                self.recipient_xpub,
                self.plaintext,
                hostile_context,
            )
        self.assertEqual(mapping_callbacks, [])

        key_callbacks = []

        class HostileKey(str):
            def __hash__(self):
                key_callbacks.append("hash")
                return super().__hash__()

            def __eq__(self, other):
                key_callbacks.append("eq")
                return super().__eq__(other)

        hostile_key = HostileKey("id")
        context_with_hostile_key = dict(self.context)
        message_id = context_with_hostile_key.pop("id")
        context_with_hostile_key[hostile_key] = message_id
        key_callbacks.clear()
        self.assertEqual(
            e2ee.validate_context(context_with_hostile_key),
            "bad context field set",
        )
        self.assertEqual(key_callbacks, [])

        envelope_with_hostile_key = self.envelope()
        version = envelope_with_hostile_key.pop("v")
        envelope_with_hostile_key[HostileKey("v")] = version
        key_callbacks.clear()
        self.assertEqual(
            e2ee.validate_envelope(envelope_with_hostile_key),
            "bad envelope field set",
        )
        self.assertEqual(key_callbacks, [])

    def test_decrypt_rejects_hostile_envelope_keys_and_algorithms_without_callbacks(self):
        callbacks = []

        class HostileKey(str):
            def __hash__(self):
                callbacks.append("hash")
                return super().__hash__()

            def __eq__(self, other):
                callbacks.append("eq")
                return super().__eq__(other)

        hostile_key_envelope = self.envelope()
        version = hostile_key_envelope.pop("v")
        hostile_key_envelope[HostileKey("v")] = version
        callbacks.clear()
        with self.assertRaisesRegex(e2ee.DecryptError, "bad v2 envelope field set"):
            e2ee.decrypt_envelope_v2(
                self.recipient_seed,
                hostile_key_envelope,
                self.sender_pub,
                self.context,
            )
        self.assertEqual(callbacks, [])

        class HostileAlgorithm(str):
            def __ne__(self, other):
                callbacks.append("ne")
                return False

            def __eq__(self, other):
                callbacks.append("eq")
                return True

        hostile_algorithm_envelope = self.envelope()
        hostile_algorithm_envelope["alg"] = HostileAlgorithm("not-v2")
        callbacks.clear()
        with self.assertRaisesRegex(e2ee.DecryptError, "unsupported algorithm"):
            e2ee.decrypt_envelope_v2(
                self.recipient_seed,
                hostile_algorithm_envelope,
                self.sender_pub,
                self.context,
            )
        self.assertEqual(callbacks, [])

        callbacks.clear()
        with self.assertRaisesRegex(ValueError, "field set/algorithm invalid"):
            native_payload(hostile_algorithm_envelope, 2)
        self.assertEqual(callbacks, [])

    def test_new_client_advertises_v2_during_every_handshake_step(self):
        client = ClackClient.__new__(ClackClient)
        client.peer_name = "fixture-a"
        calls = []
        responses = [
            {"link": "https://relay.invalid/join#v=4&r=eA&h=h&k=k"},
            {"handshake_id": "a|b|0"},
            {"handshake_id": "a|b|0", "status": "active", "enc_version": 2},
        ]

        def request(method, path, body=None, **kwargs):
            calls.append((method, path, body, kwargs))
            return responses.pop(0)

        client._request = request
        client.mint_handshake_link()
        client.redeem_handshake({"h": "h", "k": "k"})
        client.accept_handshake("a|b|0")
        self.assertEqual([call[2].get("enc_v") for call in calls], [2, 2, 2])

        invalid_calls = (
            lambda: client.mint_handshake_link(enc_v=True),
            lambda: client.redeem_handshake({"h": "h", "k": "k"}, enc_v=True),
            lambda: client.accept_handshake("a|b|0", enc_v=True),
        )
        for invalid_call in invalid_calls:
            with self.assertRaises(ClackError):
                invalid_call()


if __name__ == "__main__":
    unittest.main(verbosity=2)
