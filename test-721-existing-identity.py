#!/usr/bin/env python3
"""#721: downloaded-client existing-identity branch regression tests.

Bug (pinned artifact: private-relay /join/client, SHA256
3cf20b37184a4f72f5a11f59eecd781e0e783bc618a6ffc544a1caacabf2f109):
when an already-enrolled identity re-redeems, the relay answers WITHOUT
service_token and the client crashed with KeyError: 'service_token'
(relay-cli.py cmd_redeem v3, _redeem_v4_handshake, cmd_enroll).

Contract under test (fix in relay-cli.py::_apply_enrollment_response):
- fresh inline (response carries service_token): store token/name -- green.
- existing identity (response omits service_token, cfg has token+name):
  retain existing name/key/token and proceed (accept, hello, save).
- neither: fail closed (return 1), never a bare KeyError.
- safeguards preserved: no new keypair generated (local key file
  byte-identical), TOFU fingerprint pin retained, relay_url kept,
  display_name/name never overwritten by a tokenless response.

Tests run offline against a fake relay (monkeypatched req) and a
byte-exact fixture of the downloaded client (documents pre-fix crash).
"""
import builtins
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
from types import SimpleNamespace

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE = os.path.join(
    HERE, "tests", "fixtures",
    "downloaded-client-3cf20b37184a4f72f5a11f59eecd781e0e783bc618a6ffc544a1caacabf2f109.py")
FIXTURE_SHA256 = ("3cf20b37184a4f72f5a11f59eecd781e0e783bc618a6ffc544a1caacabf2f109")
CLIENT = os.path.join(HERE, "relay-cli.py")
RELAY_URL = "https://clack.kasnet.us"
FP = "FP123PIN"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def make_identity_config(mod, tmpdir, enrolled=True):
    """Build a saved identity config. enrolled=False -> fresh keygen config."""
    seed, pub = mod.keygen()
    cfg = {
        "kind": "clack-identity-v1",
        "relay_url": RELAY_URL,
        "identity_pubkey": mod.b64u_encode(pub),
        "user_agent": "Test/0.0",
        "relay_identity_fingerprint": FP,
    }
    if enrolled:
        cfg["service_token"] = "OLD_TOKEN"
        cfg["peer_name"] = "ned"
        cfg["display_name"] = "Ned"
    path = os.path.join(tmpdir, "identity.json")
    mod._save_identity_config(path, cfg, seed)
    return path, cfg, seed, pub


class FakeRelay:
    """Offline relay: challenge -> redeem -> accept -> hello(send)."""

    def __init__(self, mod, redeem_response):
        self.mod = mod
        self.redeem_response = redeem_response
        self.calls = []
        self.bodies = []  # (path, body) for round-2 substitution checks

    def req(self, cfg, method, path, body=None, base=None):
        self.calls.append((method, path))
        self.bodies.append((path, body))
        if path.endswith("/v1/enroll/challenge"):
            return 200, {"gate": "open",
                         "nonce": self.mod.b64u_encode(os.urandom(16))}
        if path.endswith("/v1/handshakes/redeem"):
            return 200, dict(self.redeem_response)
        if path.endswith("/v1/handshakes/accept"):
            return 200, {"status": "active", "peer": "minter_peer"}
        if path.endswith("/v1/send"):
            return 200, {"accepted": True}
        raise AssertionError("unexpected request %s %s" % (method, path))

    def paths(self):
        return [p for _, p in self.calls]

    def last_body(self, path_suffix):
        """Most recent request body sent to a path ending in path_suffix."""
        for path, body in reversed(self.bodies):
            if path.endswith(path_suffix):
                return body
        return None


def run_redeem(mod, cfg_path, cfg, fake, seed, pub, input_fn=None):
    args = SimpleNamespace(config=cfg_path)
    f = {"h": "linkid", "k": "secret",
         "r": mod.b64u_encode(RELAY_URL.encode()),
         "exp": "1893456000", "v": 4, "by": "minter_peer"}
    orig_input = builtins.input
    builtins.input = (input_fn if input_fn is not None
                      else (lambda prompt="": ""))  # guest name
    old_req = mod.req
    mod.req = fake.req
    try:
        return mod._redeem_v4_handshake(args, cfg, f, RELAY_URL, FP,
                                        seed, pub)
    finally:
        builtins.input = orig_input
        mod.req = old_req


def load_saved(mod, cfg_path):
    return mod.load_config(cfg_path)


RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print("%s %s %s" % ("PASS" if cond else "FAIL", name,
                        ("-- " + detail) if detail and not cond else ""))


def main():
    # 0. fixture is the pinned artifact
    check("fixture-sha256-pinned",
          sha256_file(FIXTURE) == FIXTURE_SHA256,
          sha256_file(FIXTURE))

    old = load_module("dl_old", FIXTURE)   # pre-fix downloaded client
    new = load_module("dl_new", CLIENT)    # fixed relay-cli.py
    check("fix-helper-present", hasattr(new, "_apply_enrollment_response"))

    redeem_existing = {"identity": "id" + "0" * 60,
                       "peer_name": "ned", "display_name": "Ned",
                       "handshake_id": "hs-1", "status": "pending",
                       "minter_name_hint": "minter_peer",
                       "enrollment": "existing"}  # NO service_token

    # 1. pre-fix client crashes on the existing-identity branch
    with tempfile.TemporaryDirectory() as td:
        cfg_path, cfg, seed, pub = make_identity_config(old, td, True)
        fake = FakeRelay(old, redeem_existing)
        try:
            run_redeem(old, cfg_path, cfg, fake, seed, pub)
            check("prefix-client-crashes", False, "no exception raised")
        except KeyError as e:
            check("prefix-client-crashes", str(e) == "'service_token'",
                  "raised %r" % (e,))

    # 2. fixed client: existing identity retains name/key/token, proceeds
    with tempfile.TemporaryDirectory() as td:
        cfg_path, cfg, seed, pub = make_identity_config(new, td, True)
        key_before = open(cfg["identity_privkey_path"], "rb").read()
        pub_before = cfg["identity_pubkey"]
        fake = FakeRelay(new, redeem_existing)
        rc = run_redeem(new, cfg_path, cfg, fake, seed, pub)
        saved = load_saved(new, cfg_path)
        key_after = open(saved["identity_privkey_path"], "rb").read()
        check("existing-rc0", rc == 0, "rc=%r" % rc)
        check("existing-token-retained",
              saved.get("service_token") == "OLD_TOKEN",
              repr(saved.get("service_token")))
        check("existing-name-retained", saved.get("peer_name") == "ned",
              repr(saved.get("peer_name")))
        check("existing-key-untouched",
              key_after == key_before and saved["identity_pubkey"] == pub_before)
        check("existing-pin-retained",
              saved.get("relay_identity_fingerprint") == FP,
              repr(saved.get("relay_identity_fingerprint")))
        check("existing-relay-url", saved.get("relay_url") == RELAY_URL,
              repr(saved.get("relay_url")))
        check("existing-proceeds",
              "/v1/handshakes/accept" in fake.paths()
              and "/v1/send" in fake.paths(),
              str(fake.paths()))

    # 3. fresh inline stays green: token+name stored from the response
    with tempfile.TemporaryDirectory() as td:
        cfg_path, cfg, seed, pub = make_identity_config(new, td, False)
        fresh = dict(redeem_existing)
        fresh.update({"service_token": "NEW_TOKEN", "peer_name": "ned",
                      "enrollment": "fresh"})
        fake = FakeRelay(new, fresh)
        rc = run_redeem(new, cfg_path, cfg, fake, seed, pub)
        saved = load_saved(new, cfg_path)
        check("fresh-rc0", rc == 0, "rc=%r" % rc)
        check("fresh-token-stored", saved.get("service_token") == "NEW_TOKEN",
              repr(saved.get("service_token")))
        check("fresh-name-stored", saved.get("peer_name") == "ned",
              repr(saved.get("peer_name")))

    # 4. fail closed: no token anywhere -> return 1, no KeyError
    with tempfile.TemporaryDirectory() as td:
        cfg_path, cfg, seed, pub = make_identity_config(new, td, False)
        fake = FakeRelay(new, redeem_existing)
        rc = run_redeem(new, cfg_path, cfg, fake, seed, pub)
        check("fail-closed-rc1", rc == 1, "rc=%r" % rc)
        check("fail-closed-no-accept",
              "/v1/handshakes/accept" not in fake.paths(),
              str(fake.paths()))

    # 5. helper unit: collision safeguard -- tokenless response carrying a
    #    DIFFERENT peer_name must NOT overwrite the enrolled name
    cfg = {"service_token": "OLD_TOKEN", "peer_name": "ned"}
    out = {"peer_name": "mallory", "identity": "x"}
    ok = new._apply_enrollment_response(cfg, out, "redeem")
    check("helper-collision", ok and cfg["peer_name"] == "ned"
          and cfg["service_token"] == "OLD_TOKEN",
          json.dumps(cfg))

    # 6. helper unit: fresh token wins, missing peer_name fails closed
    cfg = {}
    check("helper-fresh",
          new._apply_enrollment_response(
              cfg, {"service_token": "T", "peer_name": "n"}, "redeem")
          and cfg["service_token"] == "T" and cfg["peer_name"] == "n",
          json.dumps(cfg))
    cfg = {}
    check("helper-fresh-no-name-fails-closed",
          not new._apply_enrollment_response(
              cfg, {"service_token": "T"}, "redeem")
          and "service_token" not in cfg)

    # 7. helper unit: nothing to fall back on fails closed
    cfg = {}
    check("helper-nothing-fails-closed",
          not new._apply_enrollment_response(cfg, {"peer_name": "n"},
                                             "enroll"))

    # ---- round 2: independent-acceptance fixes (#721 NO_GO verdict) ----

    # 8. fix 1: existing authenticated identity redeems with NO name
    # prompt (input must never be called), no requested_name in the
    # redeem body, identity retained.
    def boom_input(prompt=""):
        raise AssertionError("name prompt invoked on existing identity")

    with tempfile.TemporaryDirectory() as td:
        cfg_path, cfg, seed, pub = make_identity_config(new, td, True)
        fake = FakeRelay(new, redeem_existing)
        rc = run_redeem(new, cfg_path, cfg, fake, seed, pub,
                        input_fn=boom_input)
        saved = load_saved(new, cfg_path)
        redeem_body = fake.last_body("/v1/handshakes/redeem")
        check("r2-existing-no-prompt", rc == 0, "rc=%r" % rc)
        check("r2-existing-no-requested-name",
              redeem_body is not None
              and "requested_name" not in redeem_body,
              json.dumps(redeem_body))
        check("r2-existing-identity-retained",
              saved.get("service_token") == "OLD_TOKEN"
              and saved.get("peer_name") == "ned",
              json.dumps({k: saved.get(k)
                          for k in ("service_token", "peer_name")}))
        # 8b. fix 4 (round 3 / test02): existing authenticated identity
        # must NOT call /v1/enroll/challenge at all -- redeem is the first
        # call and accept follows it directly. (A /v1/send hello may follow
        # accept when the redeem response names a messageable minter.)
        check("r2-existing-no-challenge",
              "/v1/enroll/challenge" not in fake.paths()
              and fake.paths()[:2] == ["/v1/handshakes/redeem",
                                       "/v1/handshakes/accept"],
              json.dumps(fake.paths()))
        check("r2-existing-redeem-no-proof",
              redeem_body is not None and "proof" not in redeem_body,
              json.dumps(redeem_body))
        # 8c. fix 5 (round 4 / Zari ACTION_CONTINUATION): authoritative
        # handler derives an authenticated redeemer's identity from
        # caller_identity(peer), never from the body. Exact contract body
        # is {h, k} -- no identity_pubkey.
        check("r2-existing-redeem-exact-hk",
              redeem_body == {"h": "linkid", "k": "secret"},
              json.dumps(redeem_body))

    # 9. fix 1: fresh identities still get the name prompt (prompt is the
    # fresh-enrollment path, not an existing-identity regression).
    with tempfile.TemporaryDirectory() as td:
        cfg_path, cfg, seed, pub = make_identity_config(new, td, False)
        fresh = dict(redeem_existing)
        fresh.update({"service_token": "NEW_TOKEN", "peer_name": "alice",
                      "enrollment": "fresh"})
        fake = FakeRelay(new, fresh)
        prompts = []
        rc = run_redeem(new, cfg_path, cfg, fake, seed, pub,
                        input_fn=lambda prompt="": prompts.append(prompt)
                        or "alice")
        saved = load_saved(new, cfg_path)
        redeem_body = fake.last_body("/v1/handshakes/redeem")
        check("r2-fresh-prompt-used", rc == 0 and len(prompts) == 1,
              "rc=%r prompts=%r" % (rc, prompts))
        check("r2-fresh-requested-name-sent",
              (redeem_body or {}).get("requested_name") == "alice",
              json.dumps(redeem_body))
        check("r2-fresh-name-stored", saved.get("peer_name") == "alice",
              repr(saved.get("peer_name")))

    # 10. fix 2, fresh path: silent server substitution fails LOUDLY
    cfg = {}
    out = {"service_token": "T", "peer_name": "mallory"}
    check("r2-fresh-mismatch-fails-loud",
          not new._apply_enrollment_response(cfg, out, "redeem",
                                             requested_name="ned")
          and "service_token" not in cfg,
          json.dumps(cfg))
    # matching requested name -> success, stored
    cfg = {}
    out = {"service_token": "T", "peer_name": "ned"}
    check("r2-fresh-match-ok",
          new._apply_enrollment_response(cfg, out, "redeem",
                                         requested_name="ned")
          and cfg["peer_name"] == "ned" and cfg["service_token"] == "T",
          json.dumps(cfg))

    # 11. fix 2, existing-identity path: requested name != enrolled name
    # fails LOUDLY (never silently dropped); match -> retain.
    cfg = {"service_token": "OLD_TOKEN", "peer_name": "ned"}
    out = {"peer_name": "ned", "identity": "x"}  # tokenless: existing path
    check("r2-existing-mismatch-fails-loud",
          not new._apply_enrollment_response(cfg, out, "redeem",
                                             requested_name="mallory")
          and cfg["peer_name"] == "ned",
          json.dumps(cfg))
    cfg = {"service_token": "OLD_TOKEN", "peer_name": "ned"}
    check("r2-existing-match-ok",
          new._apply_enrollment_response(cfg, out, "redeem",
                                         requested_name="ned")
          and cfg["peer_name"] == "ned"
          and cfg["service_token"] == "OLD_TOKEN",
          json.dumps(cfg))

    # 12. fix 2, end-to-end: fresh redeem where the relay substitutes a
    # different name than the one typed -> rc 1, no accept, no overwrite.
    with tempfile.TemporaryDirectory() as td:
        cfg_path, cfg, seed, pub = make_identity_config(new, td, False)
        swap = dict(redeem_existing)
        swap.update({"service_token": "NEW_TOKEN", "peer_name": "mallory",
                     "enrollment": "fresh"})
        fake = FakeRelay(new, swap)
        rc = run_redeem(new, cfg_path, cfg, fake, seed, pub,
                        input_fn=lambda prompt="": "alice")
        check("r2-redeem-substitution-rc1", rc == 1, "rc=%r" % rc)
        check("r2-redeem-substitution-no-accept",
              "/v1/handshakes/accept" not in fake.paths(),
              str(fake.paths()))

    # 13. fix 3: pin change mid-process invalidates the cached level and
    # forces re-verification -- never trusted on the stale level.
    new._verified_origins.clear()
    fetch_calls = []
    presented = {"fp": "PIN_A"}

    def fake_fetch(url, cfg=None):
        fetch_calls.append(url)
        return presented["fp"], None

    old_fetch = new.fetch_relay_identity
    new.fetch_relay_identity = fake_fetch
    try:
        cfg3 = {"relay_identity_fingerprint": "PIN_A"}
        check("r2-pin-first-verify",
              new._ensure_origin_verified(RELAY_URL, cfg3) == "pinned"
              and len(fetch_calls) == 1,
              "calls=%d" % len(fetch_calls))
        check("r2-pin-cache-hit",
              new._ensure_origin_verified(RELAY_URL, cfg3) == "pinned"
              and len(fetch_calls) == 1,
              "calls=%d" % len(fetch_calls))
        # pin changed mid-process (redeem/enroll TOFU pinned a new fp):
        # the cache must NOT serve the old level; it re-verifies.
        cfg3["relay_identity_fingerprint"] = "PIN_B"
        presented["fp"] = "PIN_B"
        check("r2-pin-change-reverifies",
              new._ensure_origin_verified(RELAY_URL, cfg3) == "pinned"
              and len(fetch_calls) == 2,
              "calls=%d" % len(fetch_calls))
        # changed pin against a relay still presenting the OLD pin:
        # fail closed (exit), never silently pass.
        cfg3["relay_identity_fingerprint"] = "PIN_C"
        try:
            new._ensure_origin_verified(RELAY_URL, cfg3)
            check("r2-pin-change-mismatch-aborts", False,
                  "no SystemExit raised")
        except SystemExit:
            check("r2-pin-change-mismatch-aborts", True)
        check("r2-pin-change-mismatch-refetched", len(fetch_calls) == 3,
              "calls=%d" % len(fetch_calls))
    finally:
        new.fetch_relay_identity = old_fetch
        new._verified_origins.clear()

    fails = [n for n, ok, _ in RESULTS if not ok]
    print("\n%d/%d passed" % (len(RESULTS) - len(fails), len(RESULTS)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
