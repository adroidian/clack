#!/usr/bin/env python3
"""Unit tests for e2ee.py: RFC vectors + envelope round-trip + tamper cases."""
import os
import sys
import json

sys.path.insert(0, os.path.expanduser("~/workspace/clack-relay"))
import e2ee
import ed25519

PASS = 0
FAIL = 0


def ok(name):
    global PASS
    PASS += 1
    print("ok   %s" % name)


def bad(name, why):
    global FAIL
    FAIL += 1
    print("FAIL %s -- %s" % (name, why))


def check(name, cond, why=""):
    if cond:
        ok(name)
    else:
        bad(name, why)


# --- RFC 7748 section 6.1 X25519 vectors (authoritative, from the RFC) ------
alice_priv = bytes.fromhex(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
alice_pub = bytes.fromhex(
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
bob_priv = bytes.fromhex(
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
bob_pub = bytes.fromhex(
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
shared = bytes.fromhex(
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
base9 = (9).to_bytes(32, "little")
check("rfc7748 X25519(a,9)",
      e2ee.x25519_scalarmult(alice_priv, base9) == alice_pub, "mismatch")
check("rfc7748 X25519(b,9)",
      e2ee.x25519_scalarmult(bob_priv, base9) == bob_pub, "mismatch")
check("rfc7748 shared secret a->B",
      e2ee.x25519_scalarmult(alice_priv, bob_pub) == shared, "mismatch")
check("rfc7748 shared secret b->A agrees",
      e2ee.x25519_scalarmult(bob_priv, alice_pub) == shared, "mismatch")

# --- RFC 8439 section 2.3.2 ChaCha20 block vector (authoritative) -------------
key = bytes(range(32))
nonce = bytes.fromhex("000000090000004a00000000")
block = e2ee._chacha20_block(key, 1, nonce)
check("rfc8439 chacha20 block",
      block.hex() == "10f1e7e4d13b5915500fdd1fa32071c4"
                     "c7d1f4c733c068030422aa9ac3d46c4e"
                     "d2826446079faa0914c2d705d98b02a2"
                     "b5129cd1de164eb9cbd083e8a2503c4e",
      block.hex()[:32])

# --- RFC 8439 appendix A.5 AEAD decryption vector (authoritative) ------------
# Exercises the full AEAD path (ChaCha20 + one-time-key gen + Poly1305)
# as a known-answer test.
a5_key = bytes.fromhex("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0")
a5_nonce = bytes.fromhex("000000000102030405060708")
a5_aad = bytes.fromhex("f33388860000000000004e91")
a5_ct = bytes.fromhex(
    "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb2"
    "4c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf"
    "332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c855"
    "9797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4"
    "b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523e"
    "af4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a"
    "0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a10"
    "49e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29"
    "a6ad5cb4022b02709b")
a5_tag = bytes.fromhex("eead9d67890cbb22392336fea1851f38")
a5_pt_start = b"Internet-Drafts are draft documents"
try:
    pt = e2ee.aead_decrypt(a5_key, a5_nonce, a5_ct, a5_tag, a5_aad)
    check("rfc8439 A.5 aead decrypt tag ok + pt prefix",
          pt[:len(a5_pt_start)] == a5_pt_start and len(pt) == 265,
          repr(pt[:40]))
except Exception as e:  # noqa: BLE001
    bad("rfc8439 A.5 aead decrypt", repr(e))

# --- RFC 8439 appendix A.4 test vector 1: Poly1305 one-time key gen -----------
check("rfc8439 A.4 one-time key",
      e2ee._chacha20_block(bytes(32), 0, bytes(12))[:32].hex()
      == "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7",
      "mismatch")

# --- RFC 8439 appendix A.3 test vector 4: standalone Poly1305 -----------------
poly_key = bytes.fromhex("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0")
poly_msg = (b"'Twas brillig, and the slithy toves\n"
            b"Did gyre and gimble in the wabe:\n"
            b"All mimsy were the borogoves,\n"
            b"And the mome raths outgrabe.")
check("rfc8439 A.3 poly1305",
      e2ee.poly1305_mac(poly_msg, poly_key).hex() == "4541669a7eaaee61e708dc7cbcc5eb62",
      e2ee.poly1305_mac(poly_msg, poly_key).hex())

# --- HKDF-SHA256 RFC 5869 test case 1 ----------------------------------------
ikm = bytes.fromhex("0b" * 22)
hkdf_salt = bytes.fromhex("000102030405060708090a0b0c")
hkdf_info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
hkdf_okm = e2ee.hkdf_sha256(ikm, hkdf_info, 42, hkdf_salt)
check("rfc5869 hkdf case 1",
      hkdf_okm.hex() == "3cb25f25faacd57a90434f64d0362f2a"
                        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                        "34007208d5b887185865",
      hkdf_okm.hex()[:32])

# --- Ed25519 -> X25519 conversion identity -----------------------------------
seed, pub = ed25519.keygen()
x_priv = e2ee.ed25519_seed_to_x25519_priv(seed)
x_pub_from_priv = e2ee.x25519_scalarmult(x_priv, e2ee._X25519_BASE)
x_pub_from_pub = e2ee.ed25519_pub_to_x25519_pub(pub)
check("ed25519->x25519 conversion identity",
      x_pub_from_priv == x_pub_from_pub, "conversion mismatch")

# --- Envelope round-trip ------------------------------------------------------
sender, recip = "alice", "bob"
r_seed, r_pub = ed25519.keygen()
r_xpub = e2ee.ed25519_pub_to_x25519_pub(r_pub)
msgs = [b"hello bob", b"", b"x" * 5000, "unicode: \U0001F600 \xe9".encode("utf-8")]
for i, m in enumerate(msgs):
    env = e2ee.encrypt_envelope(sender, recip, r_xpub, m)
    check("envelope shape %d" % i, e2ee.validate_envelope(env) is None,
          e2ee.validate_envelope(env))
    check("envelope fields %d" % i,
          set(env) == {"v", "alg", "eph", "nonce", "kid", "ct"}
          and env["v"] == 1 and env["alg"] == "x25519-chacha20poly1305")
    pt = e2ee.decrypt_envelope(r_seed, env, sender, recip)
    check("envelope round-trip %d" % i, pt == m)
    # canonical serialization parses back identically
    s = e2ee.serialize_envelope(env)
    check("envelope canonical json %d" % i, json.loads(s) == env)
    check("envelope fits TEXT_MAX %d" % i, len(s) <= 65536)

# Ephemeral uniqueness: same plaintext -> different envelopes
e1 = e2ee.encrypt_envelope(sender, recip, r_xpub, b"same")
e2 = e2ee.encrypt_envelope(sender, recip, r_xpub, b"same")
check("ephemeral uniqueness",
      e1["eph"] != e2["eph"] and e1["ct"] != e2["ct"])

# --- Tamper / wrong-key cases ---------------------------------------------------
env = e2ee.encrypt_envelope(sender, recip, r_xpub, b"secret msg")
raw = bytearray(e2ee.b64u_decode(env["ct"]))
raw[0] ^= 1
env2 = dict(env)
env2["ct"] = e2ee.b64u_encode(bytes(raw))
try:
    e2ee.decrypt_envelope(r_seed, env2, sender, recip)
    bad("tampered ct rejected", "decrypted anyway")
except e2ee.DecryptError:
    ok("tampered ct rejected")

env3 = dict(env)
rawn = bytearray(e2ee.b64u_decode(env3["nonce"]))
rawn[0] ^= 1
env3["nonce"] = e2ee.b64u_encode(bytes(rawn))
try:
    e2ee.decrypt_envelope(r_seed, env3, sender, recip)
    bad("tampered nonce rejected", "decrypted anyway")
except e2ee.DecryptError:
    ok("tampered nonce rejected")

# Wrong recipient seed -> kid mismatch
w_seed, _ = ed25519.keygen()
try:
    e2ee.decrypt_envelope(w_seed, env, sender, recip)
    bad("wrong seed rejected", "decrypted anyway")
except e2ee.DecryptError:
    ok("wrong seed rejected")

# Swapped sender/recipient names -> HKDF info differs -> auth fails
try:
    e2ee.decrypt_envelope(r_seed, env, recip, sender)
    bad("swapped names rejected", "decrypted anyway")
except e2ee.DecryptError:
    ok("swapped names rejected")

# --- validate_envelope malformed inputs ---------------------------------------
for name, bad_env in [
    ("non-dict", "nope"),
    ("bad version", dict(env, v=2)),
    ("bad alg", dict(env, alg="rot13")),
    ("short eph", dict(env, eph=e2ee.b64u_encode(b"short"))),
    ("short nonce", dict(env, nonce=e2ee.b64u_encode(b"short"))),
    ("short kid", dict(env, kid=e2ee.b64u_encode(b"short"))),
    ("empty ct", dict(env, ct=e2ee.b64u_encode(b""))),
    ("bad b64", dict(env, ct="!!!not-b64!!!")),
    ("missing field", {k: v for k, v in env.items() if k != "ct"}),
]:
    check("validate rejects %s" % name,
          e2ee.validate_envelope(bad_env) is not None)

# --- GAP 3a: all-zero shared secret must fail closed -------------------------
# Encrypt with all-zero recipient public key -> must raise, not derive key
try:
    e2ee.encrypt_envelope("alice", "bob", b"\x00" * 32, b"secret")
    bad("all-zero peer key encrypt rejected", "encrypted anyway")
except ValueError as ex:
    check("all-zero peer key encrypt rejected", "all-zero" in str(ex).lower())

# Decrypt path: craft envelope with all-zero eph key.
# Use a real recipient keypair so kid checks pass, but eph=zeros forces
# all-zero shared secret.
r_seed2, r_pub2 = ed25519.keygen()
r_xpub2 = e2ee.ed25519_pub_to_x25519_pub(r_pub2)
env2 = e2ee.encrypt_envelope("alice", "bob2", r_xpub2, b"hello")
env2["eph"] = e2ee.b64u_encode(b"\x00" * 32)
try:
    e2ee.decrypt_envelope(r_seed2, env2, "alice", "bob2")
    bad("all-zero eph decrypt rejected", "decrypted anyway")
except e2ee.DecryptError as ex:
    check("all-zero eph decrypt rejected", "all-zero" in str(ex).lower())

print("----\npass=%d fail=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
