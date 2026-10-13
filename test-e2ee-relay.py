#!/usr/bin/env python3
"""test-e2ee-relay.py -- end-to-end tests for E2EE encrypted envelopes.

Covers the relay plumbing (relay.py) and CLI helpers (relay-cli.py):

  Phase 1: capability negotiation matrix
    - mint(enc_v=1) + accept(enc_v=1) -> enc_capable=1
    - mint(enc_v=1) + accept()        -> enc_capable=0
    - mint()        + accept(enc_v=1) -> enc_capable=0
    - mint(enc_v=1) + accept(enc_v=1) then re-accept(enc_v=1) on an
      already-active pair upgrades a 0-capable pair to 1 without
      re-handshaking
  Phase 2: encrypted round-trip
    - alice encrypts for bob (e2ee.encrypt_envelope), POSTs {enc}
    - relay stores canonical JSON in text with enc_v=1 (DB assertion:
      the relay never decrypts -- text column holds the envelope)
    - bob polls, gets enc_v=1, decrypts, plaintext matches
  Phase 3: mixed plaintext + encrypted operation
    - plaintext and encrypted messages coexist; poll returns both with
      correct enc_v flags
  Phase 4: handshake gate still enforced
    - encrypted send with no handshake -> 403 handshake_required
  Phase 5: revoked handshake
    - encrypted send after revoke -> 403 handshake_revoked
  Phase 6: malformed envelopes rejected
    - 400 bad_envelope: missing field, bad b64, enc+text both present,
      enc not a dict, oversized envelope
  Phase 7: require_encrypted operator flag
    - plaintext send -> 400 encryption_required; encrypted send works
  Phase 8: CLI helpers (relay-cli.py)
    - _e2ee_encrypt_for encrypts when enc_capable, falls back otherwise
    - _e2ee_decrypt_poll_messages decrypts in place, surfaces failures

Runs its relay on port 18806 (scratch port; never touches 18802).
"""
import base64
import hashlib
import json
import os
import secrets
import signal
import socket as _s
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

RELAY = os.path.expanduser("~/workspace/clack-relay/relay.py")
CLI = os.path.expanduser("~/workspace/clack-relay/relay-cli.py")
PORT = 18806
BASE = "http://127.0.0.1:%d" % PORT
SIGN_SCHEME = "clack-ed25519-v1"

sys.path.insert(0, os.path.expanduser("~/workspace/clack-relay"))
import e2ee


def b64u_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64u_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class Ident:
    """Ed25519 identity. Keygen/sign via openssl (instant); the relay
    verifies with its vendored pure-python verifier (interop checked)."""

    def __init__(self, tmpd, tag):
        self._tmpd = tmpd
        self._pem = os.path.join(tmpd, "id_%s.pem" % tag)
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ed25519", "-out", self._pem],
            check=True, capture_output=True,
        )
        der = subprocess.run(
            ["openssl", "pkey", "-in", self._pem, "-outform", "DER"],
            check=True, capture_output=True,
        ).stdout
        self.seed = der[-32:]
        pubder = subprocess.run(
            ["openssl", "pkey", "-in", self._pem, "-pubout", "-outform", "DER"],
            check=True, capture_output=True,
        ).stdout
        self.pub = pubder[-32:]
        self.pub_b64 = b64u_encode(self.pub)

    def sign(self, msg):
        tag = uuid.uuid4().hex
        mf = os.path.join(self._tmpd, "m%s.bin" % tag)
        sf = mf + ".sig"
        with open(mf, "wb") as f:
            f.write(msg)
        subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-inkey", self._pem,
             "-rawin", "-in", mf, "-out", sf],
            check=True, capture_output=True,
        )
        with open(sf, "rb") as f:
            sig = f.read()
        os.unlink(mf)
        os.unlink(sf)
        return sig


class Client:
    """Authenticated API client for one peer."""

    def __init__(self, name, ident, token):
        self.name = name
        self.ident = ident
        self.token = token

    def req(self, method, path, body=None, auth=True):
        data = json.dumps(body).encode() if body is not None else b""
        headers = {"Content-Type": "application/json"}
        if auth:
            nonce = "%d:%s" % (int(time.time()), secrets.token_hex(16))
            canon = ("%s\n%s\n%s\n%s\n%s" % (
                SIGN_SCHEME, method.upper(), path,
                hashlib.sha256(data).hexdigest(), nonce)).encode()
            sig = self.ident.sign(canon)
            headers.update({
                "Authorization": "Bearer " + self.token,
                "X-Clack-Scheme": "1",
                "X-Clack-Key": self.name,
                "X-Clack-Nonce": nonce,
                "X-Clack-Sig": sig.hex(),
            })
        rq = urllib.request.Request(
            BASE + path,
            data=data if method != "GET" else None,
            headers=headers, method=method,
        )
        try:
            with urllib.request.urlopen(rq, timeout=30) as r:
                return r.status, json.loads(r.read().decode() or "{}")
        except urllib.error.HTTPError as e:
            raw = e.read().decode() or "{}"
            try:
                return e.code, json.loads(raw)
            except ValueError:
                return e.code, {"_raw": raw}


def parse_link(link):
    frag = link.split("#", 1)[1]
    return dict(urllib.parse.parse_qsl(frag))


import urllib.parse

# ---------------------------------------------------------------- harness

TMPD = tempfile.mkdtemp(prefix="e2ee-test-")
DB_PATH = os.path.join(TMPD, "relay.db")
PASS = []
FAIL = []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name + (" -- " + str(detail) if detail and not cond else ""))
    if not cond and detail:
        print("     detail: %s" % (detail,))


def db():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def write_config(extra=None):
    cfg = {
        "port": PORT,
        "bind": "127.0.0.1",
        "base_url": BASE,
        "peers": {"e2e_alice": A_TOKEN, "e2e_bob": B_TOKEN,
                  "e2e_carol": C_TOKEN, "e2e_dave": D_TOKEN},
        "identity_pubkeys": {"e2e_alice": A_IDENT.pub_b64,
                             "e2e_bob": B_IDENT.pub_b64,
                             "e2e_carol": C_IDENT.pub_b64,
                             "e2e_dave": D_IDENT.pub_b64},
        "enrollment": "invite,pow",
        "pow_difficulty": 8,
    }
    if extra:
        cfg.update(extra)
    with open(os.path.join(TMPD, "relay-config.json"), "w") as f:
        json.dump(cfg, f)
    os.chmod(os.path.join(TMPD, "relay-config.json"), 0o600)


SRV = None


def start_relay():
    global SRV
    if SRV is not None:
        raise AssertionError("relay already running")
    env = dict(os.environ, CLACK_RELAY_BASE=TMPD)
    log = open(os.path.join(TMPD, "srv.log"), "ab")
    SRV = subprocess.Popen([sys.executable, RELAY], env=env,
                           stdout=log, stderr=subprocess.STDOUT)
    for _ in range(80):
        try:
            with _s.create_connection(("127.0.0.1", PORT), timeout=1):
                pass
            rq = urllib.request.Request(BASE + "/health")
            with urllib.request.urlopen(rq, timeout=5) as r:
                if r.status == 200:
                    return
        except OSError:
            pass
        time.sleep(0.25)
    raise RuntimeError("relay did not start")


def stop_relay():
    global SRV
    if SRV is not None:
        SRV.terminate()
        try:
            SRV.wait(timeout=10)
        except subprocess.TimeoutExpired:
            SRV.kill()
        SRV = None


def mint_link(client, enc_v=None):
    body = {"max_uses": 1, "exp_days": 7}
    if enc_v is not None:
        body["enc_v"] = enc_v
    code, out = client.req("POST", "/v1/handshakes/mint-link", body)
    assert code == 200, out
    return parse_link(out["link"])


def redeem(client, frag):
    # Authenticated redeem (client already enrolled): {h, k}.
    return client.req("POST", "/v1/handshakes/redeem",
                      {"h": frag["h"], "k": frag["k"]})


def accept(client, handshake_id, enc_v=None):
    body = {"handshake_id": handshake_id}
    if enc_v is not None:
        body["enc_v"] = enc_v
    return client.req("POST", "/v1/handshakes/accept", body)


def make_pair(minter, redeemer, minter_enc_v=None, redeemer_enc_v=None):
    """Full mint->redeem->accept. Returns (handshake_id, enc_capable)."""
    frag = mint_link(minter, enc_v=minter_enc_v)
    code, out = redeem(redeemer, frag)
    assert code == 200, out
    hid = out["handshake_id"]
    code, acc = accept(redeemer, hid, enc_v=redeemer_enc_v)
    assert code == 200, acc
    return hid, acc.get("enc_capable")


def encrypt_for(sender_ident, sender_name, recip_ident, recip_name, text):
    recip_x = e2ee.ed25519_pub_to_x25519_pub(recip_ident.pub)
    return e2ee.encrypt_envelope(sender_name, recip_name, recip_x,
                                 text.encode("utf-8"))


# ---------------------------------------------------------------- main
try:
    _probe = _s.create_connection(("127.0.0.1", PORT), timeout=2)
    _probe.close()
    print("port %d busy; aborting" % PORT)
    sys.exit(2)
except OSError:
    pass

A_IDENT = Ident(TMPD, "alice")
B_IDENT = Ident(TMPD, "bob")
C_IDENT = Ident(TMPD, "carol")
D_IDENT = Ident(TMPD, "dave")
A_TOKEN = "tok-alice-test"
B_TOKEN = "tok-bob-test"
C_TOKEN = "tok-carol-test"
D_TOKEN = "tok-dave-test"
write_config()

try:
    start_relay()
    A = Client("e2e_alice", A_IDENT, A_TOKEN)
    B = Client("e2e_bob", B_IDENT, B_TOKEN)
    C = Client("e2e_carol", C_IDENT, C_TOKEN)
    D = Client("e2e_dave", D_IDENT, D_TOKEN)

    # Migration assertions.
    c = db()
    msg_cols = [r[1] for r in c.execute("PRAGMA table_info(messages)").fetchall()]
    check("migration: messages.enc_v", "enc_v" in msg_cols)
    hs_cols = [r[1] for r in c.execute("PRAGMA table_info(handshakes)").fetchall()]
    check("migration: handshakes.enc_capable", "enc_capable" in hs_cols)
    check("migration: handshakes.minter_enc_v", "minter_enc_v" in hs_cols)
    check("migration: handshakes.redeemer_enc_v", "redeemer_enc_v" in hs_cols)
    inv_cols = [r[1] for r in c.execute("PRAGMA table_info(invites)").fetchall()]
    check("migration: invites.minter_enc_v", "minter_enc_v" in inv_cols)
    c.close()

    print("== phase 1: capability negotiation ==")
    # 1a: both advertise -> capable.
    hid_ab, cap_ab = make_pair(A, B, minter_enc_v=1, redeemer_enc_v=1)
    check("cap: mint(1)+accept(1) -> enc_capable=1", cap_ab == 1, cap_ab)
    # 1b: minter only -> not capable.
    hid_ac, cap_ac = make_pair(A, C, minter_enc_v=1, redeemer_enc_v=None)
    check("cap: mint(1)+accept() -> enc_capable=0", cap_ac == 0, cap_ac)
    # 1c: redeemer only -> not capable.
    hid_ad, cap_ad = make_pair(A, D, minter_enc_v=None, redeemer_enc_v=1)
    check("cap: mint()+accept(1) -> enc_capable=0", cap_ad == 0, cap_ad)
    # 1d: idempotent re-accept upgrade: C's pair is 0-capable (minter
    # advertised, redeemer didn't); C re-accepts with enc_v=1 -> upgrades
    # to 1 without re-handshaking.
    code, acc = accept(C, hid_ac, enc_v=1)
    check("cap: re-accept(1) upgrades 0->1",
          code == 200 and acc.get("enc_capable") == 1, acc)
    # 1d2: D's pair has no minter advertisement; D re-accepts with enc_v=1
    # -> stays 0 (AND requires both).
    code, acc = accept(D, hid_ad, enc_v=1)
    check("cap: re-accept(1) w/o minter ad stays 0",
          code == 200 and acc.get("enc_capable") == 0, acc)
    # 1e: bad enc_v rejected.
    code, out = A.req("POST", "/v1/handshakes/mint-link",
                      {"max_uses": 1, "enc_v": 2})
    check("cap: mint enc_v=2 -> 400 bad_enc_v",
          code == 400 and out.get("error") == "bad_enc_v", out)
    code, out = accept(B, hid_ab, enc_v="yes")
    check("cap: accept enc_v='yes' -> 400 bad_enc_v",
          code == 400 and out.get("error") == "bad_enc_v", out)
    # 1f: /v1/handshakes exposes enc_capable.
    code, out = B.req("GET", "/v1/handshakes")
    caps = {h.get("peer_name_hint"): h.get("enc_capable")
            for h in out.get("handshakes", [])}
    check("cap: handshakes list exposes enc_capable",
          caps.get("e2e_alice") == 1, caps)

    print("== phase 2: encrypted round-trip ==")
    env = encrypt_for(A_IDENT, "e2e_alice", B_IDENT, "e2e_bob",
                      "hello bob, this is secret")
    mid = str(uuid.uuid4())
    code, out = A.req("POST", "/v1/send",
                      {"id": mid, "to": "e2e_bob", "enc": env})
    check("e2e send accepted", code == 200 and out.get("accepted"), out)
    # Relay stores canonical JSON in text with enc_v=1; it never decrypts.
    c = db()
    row = c.execute("SELECT text, enc_v FROM messages WHERE id=?",
                    (mid,)).fetchone()
    stored = json.loads(row["text"])
    check("relay stores enc_v=1", row["enc_v"] == 1, row["enc_v"])
    check("relay stores canonical envelope JSON",
          stored.get("v") == 1 and stored.get("alg") == "x25519-chacha20poly1305"
          and "ct" in stored, stored.keys())
    check("relay cannot read plaintext",
          "hello bob" not in row["text"], None)
    c.close()
    # Bob polls and decrypts.
    code, out = B.req("GET", "/v1/poll?timeout=1")
    msgs = [m for m in out.get("messages", []) if m["id"] == mid]
    check("bob receives the message", len(msgs) == 1, len(msgs))
    check("poll marks enc_v=1", msgs[0].get("enc_v") == 1, msgs[0])
    bob_env = json.loads(msgs[0]["text"])
    bob_pt = e2ee.decrypt_envelope(B_IDENT.seed, bob_env,
                                   "e2e_alice", "e2e_bob")
    check("bob decrypts to original plaintext",
          bob_pt == b"hello bob, this is secret", repr(bob_pt)[:60])
    # Wrong recipient cannot decrypt.
    try:
        e2ee.decrypt_envelope(C_IDENT.seed, bob_env, "e2e_alice", "e2e_carol")
        check("third party cannot decrypt", False, "decrypted!")
    except e2ee.DecryptError:
        check("third party cannot decrypt", True)

    print("== phase 3: mixed plaintext + encrypted ==")
    mid_pt = str(uuid.uuid4())
    code, _ = A.req("POST", "/v1/send",
                    {"id": mid_pt, "to": "e2e_bob", "text": "plain hello"})
    check("plaintext send still works", code == 200, code)
    mid_e2 = str(uuid.uuid4())
    env2 = encrypt_for(A_IDENT, "e2e_alice", B_IDENT, "e2e_bob", "secret 2")
    code, _ = A.req("POST", "/v1/send",
                    {"id": mid_e2, "to": "e2e_bob", "enc": env2})
    check("encrypted send works alongside", code == 200, code)
    code, out = B.req("GET", "/v1/poll?timeout=1")
    got = {m["id"]: m.get("enc_v") for m in out.get("messages", [])}
    check("mixed poll: plaintext enc_v=0", got.get(mid_pt) == 0, got)
    check("mixed poll: encrypted enc_v=1", got.get(mid_e2) == 1, got)
    # /v1/fetch also carries enc_v.
    code, out = B.req("GET", "/v1/fetch?in_reply_to=" + mid_pt)
    check("fetch carries enc_v field",
          code == 200 and all("enc_v" in m for m in out.get("messages", [])),
          out)

    print("== phase 4: handshake gate still enforced ==")
    # Dave has NO handshake with carol: encrypted send must 403.
    env_dc = encrypt_for(D_IDENT, "e2e_dave", C_IDENT, "e2e_carol", "sneaky")
    code, out = D.req("POST", "/v1/send",
                      {"id": str(uuid.uuid4()), "to": "e2e_carol",
                       "enc": env_dc})
    check("encrypted send w/o handshake -> 403 handshake_required",
          code == 403 and out.get("error") == "handshake_required", out)

    print("== phase 5: revoked handshake ==")
    code, out = A.req("POST", "/v1/handshakes/revoke", {"peer": "e2e_bob"})
    check("revoke ok", code == 200, out)
    env_ab2 = encrypt_for(A_IDENT, "e2e_alice", B_IDENT, "e2e_bob", "after revoke")
    code, out = A.req("POST", "/v1/send",
                      {"id": str(uuid.uuid4()), "to": "e2e_bob", "enc": env_ab2})
    check("encrypted send post-revoke -> 403 handshake_revoked",
          code == 403 and out.get("error") == "handshake_revoked", out)

    print("== phase 6: malformed envelopes rejected ==")
    base_env = encrypt_for(A_IDENT, "e2e_alice", C_IDENT, "e2e_carol", "x")
    def bad_send(enc, text=None, note=""):
        body = {"id": str(uuid.uuid4()), "to": "e2e_carol"}
        if enc is not None:
            body["enc"] = enc
        if text is not None:
            body["text"] = text
        code, out = A.req("POST", "/v1/send", body)
        check("malformed: %s -> 400 bad_envelope" % note,
              code == 400 and out.get("error") == "bad_envelope",
              (code, out))
    m1 = dict(base_env); del m1["ct"]
    bad_send(m1, note="missing ct")
    m2 = dict(base_env); m2["ct"] = "!!!not-b64!!!"
    bad_send(m2, note="bad b64")
    bad_send("just a string", note="enc not a dict")
    bad_send(base_env, text="also text", note="enc+text both present")
    m3 = dict(base_env); m3["v"] = 2
    bad_send(m3, note="wrong version")

    print("== phase 7: require_encrypted flag ==")
    stop_relay()
    write_config({"require_encrypted": True})
    start_relay()
    code, out = A.req("POST", "/v1/send",
                      {"id": str(uuid.uuid4()), "to": "e2e_carol",
                       "text": "plaintext under require_encrypted"})
    check("plaintext -> 400 encryption_required",
          code == 400 and out.get("error") == "encryption_required", out)
    env_ac = encrypt_for(A_IDENT, "e2e_alice", C_IDENT, "e2e_carol",
                         "encrypted is fine")
    code, out = A.req("POST", "/v1/send",
                      {"id": str(uuid.uuid4()), "to": "e2e_carol",
                       "enc": env_ac})
    check("encrypted send works under require_encrypted",
          code == 200 and out.get("accepted"), out)
    # Bad flag value refuses startup (strict config).
    stop_relay()
    write_config({"require_encrypted": "yes"})
    try:
        start_relay()
        check("require_encrypted='yes' refuses startup", False, "started!")
    except RuntimeError:
        check("require_encrypted='yes' refuses startup", True)
    finally:
        # start_relay leaves a dead Popen in SRV on failure; clear it.
        stop_relay()
    write_config()
    start_relay()

    print("== phase 8: CLI helpers ==")
    import importlib.util
    spec = importlib.util.spec_from_file_location("relay_cli", CLI)
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    # Build a CLI-style config for alice (identity seed + peer name + token).
    cli_cfg = {
        "kind": "clack-identity-v1",
        "peer_name": "e2e_alice",
        "identity_privkey": b64u_encode(A_IDENT.seed),
        "service_token": A_TOKEN,
        "base_url": BASE,
        "relay_identity_fingerprint": "skip",
    }
    # Monkeypatch req to route through our authed Clients (by peer_name).
    clients_by_name = {"e2e_alice": A, "e2e_bob": B, "e2e_carol": C,
                       "e2e_dave": D}
    def fake_req(cfg, method, path, body=None, base=None):
        c = clients_by_name.get(cfg.get("peer_name"))
        return c.req(method, path, body)
    cli.req = fake_req
    try:
        env_cli, reason = cli._e2ee_encrypt_for(cli_cfg, "e2e_carol",
                                               "cli secret", BASE)
        check("CLI encrypts when enc_capable",
              env_cli is not None and env_cli.get("v") == 1,
              reason)
        # Round-trip through the relay: send via CLI helper, poll, decrypt.
        mid_cli = str(uuid.uuid4())
        code, out = A.req("POST", "/v1/send",
                          {"id": mid_cli, "to": "e2e_carol", "enc": env_cli})
        check("CLI envelope accepted by relay", code == 200, out)
        code, out = C.req("GET", "/v1/poll?timeout=1")
        msgs = [m for m in out.get("messages", []) if m["id"] == mid_cli]
        check("carol receives CLI-encrypted message", len(msgs) == 1)
        cli_cfg_c = dict(cli_cfg, peer_name="e2e_carol",
                         identity_privkey=b64u_encode(C_IDENT.seed),
                         service_token=C_TOKEN)
        cli._e2ee_decrypt_poll_messages(cli_cfg_c, msgs)
        check("CLI decrypts poll message",
              msgs[0].get("text") == "cli secret"
              and msgs[0].get("was_encrypted") is True, msgs[0])
        # Fallback: dave has no capable pair with carol -> plaintext reason.
        env_d, reason_d = cli._e2ee_encrypt_for(
            dict(cli_cfg, peer_name="e2e_dave",
                 identity_privkey=b64u_encode(D_IDENT.seed),
                 service_token=D_TOKEN),
            "e2e_carol", "hi", BASE)
        check("CLI falls back when not enc_capable",
              env_d is None and reason_d, reason_d)
        # GAP 3b: pair IS enc_capable but encryption fails -> must raise
        # E2EEError (fail closed), never fall back to plaintext.
        _real_encrypt = cli.e2ee.encrypt_envelope
        def _boom(*a, **k):
            raise RuntimeError("simulated crypto failure")
        cli.e2ee.encrypt_envelope = _boom
        try:
            cli._e2ee_encrypt_for(cli_cfg, "e2e_carol", "hi", BASE)
            check("CLI raises when enc_capable but encrypt fails", False,
                  "returned instead of raising")
        except cli.E2EEError as ex:
            check("CLI raises when enc_capable but encrypt fails", True)
        except Exception as ex:
            check("CLI raises when enc_capable but encrypt fails", False,
                  "wrong exception: %r" % ex)
        finally:
            cli.e2ee.encrypt_envelope = _real_encrypt
        # Decrypt failure surfaces distinctly.
        bad_msg = {"id": "x", "from": "e2e_alice", "enc_v": 1,
                   "text": json.dumps(dict(env_cli, ct="AAAA"))}
        cli._e2ee_decrypt_poll_messages(cli_cfg_c, [bad_msg])
        check("CLI decrypt failure sets decrypt_error",
              "decrypt_error" in bad_msg, bad_msg)
    finally:
        pass  # cli.req was monkeypatched; no restore needed (test ends)

finally:
    stop_relay()

print("----")
print("pass=%d fail=%d" % (len(PASS), len(FAIL)))
if FAIL:
    print("FAILURES:")
    for f in FAIL:
        print("  - %s" % f)
    sys.exit(1)
