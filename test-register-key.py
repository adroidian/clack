#!/usr/bin/env python3
"""v0.2.17 self-service Ed25519 key registration tests (scratch only, never live).

Spins up an isolated relay (temp dir, CLACK_TEST_PORT or 18996) and covers:
  - POST /v1/register-key: token-only registration succeeds (signature-exempt)
  - invalid / missing pubkey -> 400 (bad_pubkey / pubkey_required)
  - missing / bad token -> 401
  - rotation overwrites and reports rotated=true; same-key re-register -> false
  - relay-config.json actually persisted (config-managed peer)
  - PEM SPKI accepted and normalized to canonical raw b64u
  - key survives relay restart (config-managed peer re-read from config)
  - a signed request works after registration (upgrade_required -> 200)
  - handshake redeem accepts optional `pubkey` (raw or PEM) and binds at
    enrollment; redeem without any key still -> 400 bad_identity
  - CLI `register-key` subcommand: legacy token config -> keygen + register
"""
import base64
import hashlib
import importlib.util
import json
import os
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
RELAY_PY = os.path.join(HERE, "relay.py")
CLI = os.path.join(HERE, "relay-cli.py")
PORT = int(os.environ.get("CLACK_TEST_PORT", "18996"))
BASE = "http://127.0.0.1:%d" % PORT

PASS = 0
FAIL = 0


def check(cond, label, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("ok   %s" % label, flush=True)
    else:
        FAIL += 1
        print("FAIL %s -- %s" % (label, detail), flush=True)


def b64u_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64u_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def pem_of_spki(raw32):
    der = bytes.fromhex("302a300506032b6570032100") + raw32
    b64 = base64.b64encode(der).decode("ascii")
    lines = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return "-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n" % lines


_spec = importlib.util.spec_from_file_location("relay_cli", CLI)
_rc = importlib.util.module_from_spec(_spec)
sys.argv = ["relay-cli.py"]
_spec.loader.exec_module(_rc)

_spec2 = importlib.util.spec_from_file_location("relay_mod", RELAY_PY)
_rm = importlib.util.module_from_spec(_spec2)
_spec2.loader.exec_module(_rm)

TMPD = tempfile.mkdtemp(prefix="clack-regkey-test-")
SRV = None

TOKPEER_TOKEN = "regkey-test-token-tokpeer-001"
MINTER_TOKEN = "regkey-test-token-minter-002"
CLIPEER_TOKEN = "regkey-test-token-clipeer-003"

KEYS = {}  # name -> (seed, pub, pub_b64)


def fresh_key(name):
    seed, pub = _rc.keygen()
    KEYS[name] = (seed, pub, b64u_encode(pub))
    return KEYS[name]


def sign_headers(name, method, path, body, nonce=None):
    seed, _, _ = KEYS[name]
    if nonce is None:
        nonce = "%d:%s" % (int(time.time()), secrets.token_hex(16))
    canon = ("clack-ed25519-v1\n" + method.upper() + "\n" + path + "\n"
             + hashlib.sha256(body).hexdigest() + "\n" + nonce).encode()
    return {"X-Clack-Scheme": "1", "X-Clack-Key": name,
            "X-Clack-Nonce": nonce,
            "X-Clack-Sig": _rc.sign(seed, canon).hex()}


def call(token, method, path, body=None, peer=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method)
    if token:
        r.add_header("Authorization", "Bearer " + token)
    if data is not None:
        r.add_header("Content-Type", "application/json")
    if peer is not None:
        for k, v in sign_headers(peer, method, path, data or b"").items():
            r.add_header(k, v)
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {}


def db_peer_key(name):
    con = sqlite3.connect(os.path.join(TMPD, "relay.db"))
    try:
        row = con.execute(
            "SELECT identity_pubkey FROM peers WHERE name=?", (name,)).fetchone()
        return row[0] if row else None
    finally:
        con.close()


def config_pubkeys():
    with open(os.path.join(TMPD, "relay-config.json")) as f:
        return json.load(f).get("identity_pubkeys", {})


def _der_ints(der):
    ints = []
    i = 0

    def read_len(j):
        n = der[j]
        j += 1
        if n & 0x80:
            k = n & 0x7F
            n = int.from_bytes(der[j:j + k], "big")
            j += k
        return n, j
    assert der[i] == 0x30
    i += 1
    _, i = read_len(i)
    while i < len(der):
        assert der[i] == 0x02
        i += 1
        ln, i = read_len(i)
        ints.append(int.from_bytes(der[i:i + ln], "big"))
        i += ln
    return ints


def _gen_rsa_identity_key(tmpd):
    pem = os.path.join(tmpd, "test-id.pem")
    der = os.path.join(tmpd, "test-id.der")
    subprocess.run(["openssl", "genrsa", "-out", pem, "1024"],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "rsa", "-in", pem, "-traditional",
                    "-outform", "DER", "-out", der],
                   check=True, capture_output=True)
    with open(der, "rb") as f:
        _ver, n, e, d = _der_ints(f.read())[:4]
    return {"n": format(n, "x"), "e": format(e, "x"), "d": format(d, "x")}


def write_config(extra_pubkeys=None):
    global IDKEY
    pubkeys = {"minter": KEYS["minter"][2]}
    if extra_pubkeys:
        pubkeys.update(extra_pubkeys)
    IDKEY = _gen_rsa_identity_key(TMPD)
    cfg = {"port": PORT,
           "peers": {"tokpeer": TOKPEER_TOKEN,
                     "minter": MINTER_TOKEN,
                     "clipeer": CLIPEER_TOKEN},
           "identity_pubkeys": pubkeys,
           "enrollment": "invite,open", "pow_difficulty": 8,
           "identity_key": IDKEY}
    with open(os.path.join(TMPD, "relay-config.json"), "w") as f:
        json.dump(cfg, f)


def start_relay():
    global SRV
    log = open(os.path.join(TMPD, "srv.log"), "a")
    SRV = subprocess.Popen(
        [sys.executable, RELAY_PY],
        env=dict(os.environ, CLACK_RELAY_BASE=TMPD),
        stdout=log, stderr=subprocess.STDOUT)
    for _ in range(40):
        if SRV.poll() is not None:
            raise RuntimeError("scratch relay exited during startup")
        try:
            with urllib.request.urlopen(BASE + "/health", timeout=2) as r:
                if json.loads(r.read().decode()).get("version") == _rm.VERSION:
                    return
        except Exception:
            pass
        time.sleep(0.25)
    raise RuntimeError("scratch relay did not start")


def stop_relay():
    global SRV
    if SRV and SRV.poll() is None:
        SRV.terminate()
        try:
            SRV.wait(timeout=5)
        except Exception:
            SRV.kill()
    SRV = None
    for _ in range(40):
        try:
            urllib.request.urlopen(BASE + "/health", timeout=2).close()
        except Exception:
            break
        time.sleep(0.25)


# ------------------------------------------------------------- phase 1: setup
print("== phase 1: setup ==", flush=True)
import socket as _s
try:
    _probe = _s.create_connection(("127.0.0.1", PORT), timeout=2)
    _probe.close()
    raise RuntimeError("port %d busy: a stale scratch relay is running" % PORT)
except (ConnectionRefusedError, OSError):
    pass
fresh_key("minter")
fresh_key("tokpeer")
write_config()
start_relay()
check(_rm.VERSION == "0.2.17", "relay reports v0.2.17", _rm.VERSION)

# tokpeer starts token-only: signed requests must 401 upgrade_required.
# (tokpeer's key exists locally but is not registered yet)
code, out = call(TOKPEER_TOKEN, "GET", "/v1/peers", peer="tokpeer")
check(code == 401 and out.get("error") == "upgrade_required",
      "token-only peer gets 401 upgrade_required pre-registration",
      "%s %s" % (code, out))

# ------------------------------------------------- phase 2: register-key core
print("== phase 2: register-key ==", flush=True)
seed_a, pub_a, b64_a = KEYS["tokpeer"]

# 2a. token-only registration succeeds, signature-exempt (no sig headers sent)
code, out = call(TOKPEER_TOKEN, "POST", "/v1/register-key",
                 {"pubkey": b64_a})
check(code == 200 and out.get("registered") is True
      and out.get("peer") == "tokpeer" and out.get("rotated") is False,
      "token-only registration 200, rotated=false", "%s %s" % (code, out))
check(db_peer_key("tokpeer") == b64_a, "DB row carries the key")

# 2b. signed requests now work (upgrade path complete)
code, out = call(TOKPEER_TOKEN, "GET", "/v1/peers", peer="tokpeer")
check(code == 200 and "tokpeer" in out.get("peers", []),
      "signed request works after registration", "%s" % code)

# 2c. missing / bad pubkey -> 400
code, out = call(TOKPEER_TOKEN, "POST", "/v1/register-key", {})
check(code == 400 and out.get("error") == "pubkey_required",
      "missing pubkey -> 400 pubkey_required", "%s %s" % (code, out))
code, out = call(TOKPEER_TOKEN, "POST", "/v1/register-key",
                 {"pubkey": "not-a-key"})
check(code == 400 and out.get("error") == "bad_pubkey",
      "garbage pubkey -> 400 bad_pubkey", "%s %s" % (code, out))
code, out = call(TOKPEER_TOKEN, "POST", "/v1/register-key",
                 {"pubkey": b64u_encode(b"short")})
check(code == 400 and out.get("error") == "bad_pubkey",
      "wrong-length pubkey -> 400 bad_pubkey", "%s %s" % (code, out))
code, out = call(TOKPEER_TOKEN, "POST", "/v1/register-key",
                 {"pubkey": "-----BEGIN PUBLIC KEY-----\nZm9v\n-----END PUBLIC KEY-----"})
check(code == 400 and out.get("error") == "bad_pubkey",
      "malformed PEM -> 400 bad_pubkey", "%s %s" % (code, out))

# 2d. auth failures -> 401
code, out = call(None, "POST", "/v1/register-key", {"pubkey": b64_a})
check(code == 401, "no token -> 401", "%s %s" % (code, out))
code, out = call("wrong-token", "POST", "/v1/register-key", {"pubkey": b64_a})
check(code == 401, "bad token -> 401", "%s %s" % (code, out))

# 2e. rotation overwrites, reports rotated=true; same-key -> false
seed_b, pub_b, b64_b = fresh_key("tokpeer_b")
code, out = call(TOKPEER_TOKEN, "POST", "/v1/register-key",
                 {"pubkey": b64_b})
check(code == 200 and out.get("rotated") is True,
      "rotation reports rotated=true", "%s %s" % (code, out))
check(db_peer_key("tokpeer") == b64_b, "DB row now carries rotated key")
code, out = call(TOKPEER_TOKEN, "POST", "/v1/register-key",
                 {"pubkey": b64_b})
check(code == 200 and out.get("rotated") is False,
      "same-key re-register reports rotated=false", "%s %s" % (code, out))

# 2f. old key no longer verifies; new key does
code, _ = call(TOKPEER_TOKEN, "GET", "/v1/peers", peer="tokpeer")
check(code == 401, "old key rejected after rotation", "%s" % code)
KEYS["tokpeer"] = (seed_b, pub_b, b64_b)
code, out = call(TOKPEER_TOKEN, "GET", "/v1/peers", peer="tokpeer")
check(code == 200, "new key verifies after rotation", "%s" % code)

# ------------------------------------------------- phase 3: PEM normalization
print("== phase 3: PEM ==", flush=True)
seed_c, pub_c, b64_c = fresh_key("tokpeer_c")
pem_c = pem_of_spki(pub_c)
code, out = call(TOKPEER_TOKEN, "POST", "/v1/register-key",
                 {"pubkey": pem_c})
check(code == 200 and out.get("registered") is True
      and out.get("rotated") is True,
      "PEM SPKI accepted", "%s %s" % (code, out))
check(db_peer_key("tokpeer") == b64_c,
      "PEM normalized to canonical raw b64u in DB", db_peer_key("tokpeer"))
KEYS["tokpeer"] = (seed_c, pub_c, b64_c)
code, _ = call(TOKPEER_TOKEN, "GET", "/v1/peers", peer="tokpeer")
check(code == 200, "PEM-registered key verifies", "%s" % code)

# ------------------------------------------------- phase 4: config persistence
print("== phase 4: persistence ==", flush=True)
check(config_pubkeys().get("tokpeer") == b64_c,
      "relay-config.json persisted identity_pubkeys.tokpeer")

# restart: config-managed peer rows are rebuilt from config -- the key
# must survive.
stop_relay()
start_relay()
check(db_peer_key("tokpeer") == b64_c,
      "key survives restart via config re-read")
code, _ = call(TOKPEER_TOKEN, "GET", "/v1/peers", peer="tokpeer")
check(code == 200, "signed request works after restart", "%s" % code)

# ------------------------------------------------- phase 5: redeem with pubkey
print("== phase 5: redeem-with-pubkey ==", flush=True)


def parse_link(link):
    frag = link.split("#", 1)[1]
    q = urllib.parse.parse_qs(frag, keep_blank_values=True)
    return {k: (q.get(k) or [None])[0] for k in ("h", "k")}


# minter (signed) mints a handshake link
code, out = call(MINTER_TOKEN, "POST", "/v1/handshakes/mint-link",
                 {"max_uses": 2, "exp_days": 7}, peer="minter")
check(code == 200 and out.get("link"), "mint-link 200", "%s" % code)
frag = parse_link(out["link"])

# fresh identity redeems carrying `pubkey` (PEM form, proving normalization)
# instead of `identity_pubkey`
seed_n, pub_n = _rc.keygen()
b64_n = b64u_encode(pub_n)
code, ch = call(None, "POST", "/v1/enroll/challenge", {"invite_id": frag["h"]})
check(code == 200 and ch.get("gate") == "invite", "invite challenge 200",
      "%s %s" % (code, ch))
presented = b64u_decode(ch["nonce"])
sig = _rc.sign(seed_n, presented + frag["h"].encode() + pub_n)
code, out = call(None, "POST", "/v1/handshakes/redeem", {
    "h": frag["h"], "k": frag["k"],
    "pubkey": pem_of_spki(pub_n),
    "proof": {"nonce": ch["nonce"],
              "signature": b64u_encode(sig)},
})
check(code == 200 and out.get("peer_name"), "redeem with pubkey 200",
      "%s %s" % (code, str(out)[:160]))
new_peer = out.get("peer_name")
check(db_peer_key(new_peer) == b64_n,
      "redeem bound the pubkey at enrollment (normalized)",
      db_peer_key(new_peer))

# redeem with NEITHER pubkey nor identity_pubkey still 400s
seed_m, pub_m = _rc.keygen()
code, ch = call(None, "POST", "/v1/enroll/challenge", {"invite_id": frag["h"]})
presented = b64u_decode(ch["nonce"])
sig = _rc.sign(seed_m, presented + frag["h"].encode() + pub_m)
code, out = call(None, "POST", "/v1/handshakes/redeem", {
    "h": frag["h"], "k": frag["k"],
    "proof": {"nonce": ch["nonce"],
              "signature": b64u_encode(sig)},
})
check(code == 400 and out.get("error") == "bad_identity",
      "redeem without any key -> 400 bad_identity", "%s %s" % (code, out))

# redeem with BOTH pubkey and identity_pubkey disagreeing -> 400 key_mismatch
seed_x, pub_x = _rc.keygen()
seed_y, pub_y = _rc.keygen()
code, ch = call(None, "POST", "/v1/enroll/challenge", {"invite_id": frag["h"]})
presented = b64u_decode(ch["nonce"])
sig = _rc.sign(seed_x, presented + frag["h"].encode() + pub_x)
code, out = call(None, "POST", "/v1/handshakes/redeem", {
    "h": frag["h"], "k": frag["k"],
    "pubkey": b64u_encode(pub_x),
    "identity_pubkey": b64u_encode(pub_y),
    "proof": {"nonce": ch["nonce"],
              "signature": b64u_encode(sig)},
})
check(code == 400 and out.get("error") == "key_mismatch",
      "redeem with mismatched pubkey+identity_pubkey -> 400 key_mismatch",
      "%s %s" % (code, out))

# redeem with BOTH agreeing (same key, different encodings) succeeds
code, ch = call(None, "POST", "/v1/enroll/challenge", {"invite_id": frag["h"]})
presented = b64u_decode(ch["nonce"])
sig = _rc.sign(seed_x, presented + frag["h"].encode() + pub_x)
code, out = call(None, "POST", "/v1/handshakes/redeem", {
    "h": frag["h"], "k": frag["k"],
    "pubkey": b64u_encode(pub_x),
    "identity_pubkey": pem_of_spki(pub_x),
    "proof": {"nonce": ch["nonce"],
              "signature": b64u_encode(sig)},
})
check(code == 200 and out.get("peer_name"),
      "redeem with agreeing pubkey+identity_pubkey 200",
      "%s %s" % (code, str(out)[:120]))

# ------------------------------------------------- phase 6: CLI register-key
print("== phase 6: CLI register-key ==", flush=True)
clid = tempfile.mkdtemp(prefix="clack-cli-regkey-")
cfgp = os.path.join(clid, "cli.json")
with open(cfgp, "w") as f:
    json.dump({"peers": {"clipeer": CLIPEER_TOKEN}, "base_url": BASE,
               "relay_identity_fingerprint":
               _rc.relay_identity_fingerprint(IDKEY)}, f)
r = subprocess.run(
    [sys.executable, CLI, "--config", cfgp, "--peer", "clipeer",
     "register-key", "--key-path", os.path.join(clid, "cli.key")],
    capture_output=True, text=True, timeout=60)
check(r.returncode == 0 and "registered signing key" in r.stdout,
      "CLI register-key exit 0", r.stderr[-200:] + r.stdout[-200:])
cfg = json.load(open(cfgp))
check(cfg.get("kind") == "clack-identity-v1"
      and cfg.get("peer_name") == "clipeer"
      and cfg.get("identity_pubkey"),
      "CLI converted legacy config to identity config with pubkey")
check(oct(os.stat(cfg["identity_privkey_path"]).st_mode & 0o777) == "0o600",
      "CLI private key file mode 600")
check(db_peer_key("clipeer") == cfg["identity_pubkey"],
      "CLI-registered key in relay DB")

stop_relay()
print("PASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
