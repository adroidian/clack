#!/usr/bin/env python3
"""Ed25519 key registration security tests (scratch only, never live).

Spins up an isolated relay (temp dir, CLACK_TEST_PORT or 18996) and covers:
  - first registration succeeds with Bearer auth when no valid key exists
  - unsigned same-key/replacement attempts fail without mutating stored state
  - a proposed/new-key signature cannot authorize its own replacement
  - the current stored key can authorize rotation, binding the proposed body
  - same-key re-registration requires and accepts the current-key signature
  - a replayed signed registration and fresh-nonce stale-key GET/POST are
    rejected with exact config-byte/relevant-table no-mutation
  - concurrent rotations signed by one old key allow exactly one winner, with
    a deterministic no-lock negative control and winner restart readback
  - duplicate identity collisions, live/concurrent operator config drift, and
    injected DB/config/storage faults either restore exact prior authority or
    enter a tested fail-stop/restart path without overwriting operator bytes
  - all public runtime identity writers are fail-stopped with mutation-capable
    post-restart controls, and demonstrably share the registration lock
  - trusted-network signature exemption cannot bypass register-key
  - invalid / missing pubkey -> 400 (bad_pubkey / pubkey_required)
  - missing / bad token -> 401
  - relay-config.json actually persisted (config-managed peer)
  - PEM SPKI accepted and normalized to canonical raw b64u
  - the authorized new key survives relay restart
  - a signed request works after registration (upgrade_required -> 200)
  - handshake redeem accepts optional `pubkey` (raw or PEM) and binds at
    enrollment; redeem without any key still -> 400 bad_identity
  - CLI `register-key`: durable pre-send candidate custody; lost-200 and visible
    503 reconciliation without retry; invalid-runtime recovery; exact response
    key binding; safe quarantine; strict path/type/alias and 0600 enforcement;
    and accepted-server fault recovery at every journal/key/config publication
    boundary through a fresh-module restart model
"""
import base64
import builtins
import hashlib
import importlib.util
import json
import multiprocessing
import os
import queue
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import threading
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


def direct_cli_args(config_path, peer=None, key_path=None, base_url=None):
    return type("RegisterKeyArgs", (), {
        "config": config_path,
        "peer": peer,
        "base_url": base_url,
        "key_path": key_path,
    })()


def fresh_cli_module(tag):
    spec = importlib.util.spec_from_file_location("relay_cli_" + tag, CLI)
    module = importlib.util.module_from_spec(spec)
    old_argv = sys.argv
    try:
        sys.argv = ["relay-cli.py"]
        spec.loader.exec_module(module)
    finally:
        sys.argv = old_argv
    return module


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
_ORIG_REGISTRATION_DB_UPDATE = _rm._registration_db_update
_ORIG_REGISTRATION_DB_COMMIT = _rm._registration_db_commit

TMPD = tempfile.mkdtemp(prefix="clack-regkey-test-")
SRV = None
INPROC_SERVER = None
INPROC_THREAD = None

TOKPEER_TOKEN = "regkey-test-token-tokpeer-001"
MINTER_TOKEN = "regkey-test-token-minter-002"
CLIPEER_TOKEN = "regkey-test-token-clipeer-003"
LOCKPEER_TOKEN = "regkey-test-token-lockpeer-004"
FAILPEER_TOKEN = "regkey-test-token-failpeer-005"
UNCERTAINPEER_TOKEN = "regkey-test-token-uncertainpeer-006"
DRIFTPEER_TOKEN = "regkey-test-token-driftpeer-007"
REVOKEDPEER_TOKEN = "regkey-test-token-revokedpeer-008"
DROPPEER_TOKEN = "regkey-test-token-droppeer-009"
INVALIDPEER_TOKEN = "regkey-test-token-invalidpeer-010"

KEYS = {}  # name -> (seed, pub, pub_b64)


def fresh_key(name):
    seed, pub = _rc.keygen()
    KEYS[name] = (seed, pub, b64u_encode(pub))
    return KEYS[name]


def sign_headers(peer, method, path, body, nonce=None, signer=None):
    seed, _, _ = KEYS[signer or peer]
    if nonce is None:
        nonce = "%d:%s" % (int(time.time()), secrets.token_hex(16))
    canon = ("clack-ed25519-v1\n" + method.upper() + "\n" + path + "\n"
             + hashlib.sha256(body).hexdigest() + "\n" + nonce).encode()
    return {"X-Clack-Scheme": "1", "X-Clack-Key": peer,
            "X-Clack-Nonce": nonce,
            "X-Clack-Sig": _rc.sign(seed, canon).hex()}


def call(token, method, path, body=None, peer=None, signer=None,
         signature_body=None, signature_nonce=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method)
    if token:
        r.add_header("Authorization", "Bearer " + token)
    if data is not None:
        r.add_header("Content-Type", "application/json")
    if peer is not None:
        signed_data = (json.dumps(signature_body).encode()
                       if signature_body is not None else (data or b""))
        for k, v in sign_headers(peer, method, path, signed_data,
                                 nonce=signature_nonce,
                                 signer=signer).items():
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


def db_peer_present(name):
    con = sqlite3.connect(os.path.join(TMPD, "relay.db"))
    try:
        return con.execute(
            "SELECT 1 FROM peers WHERE name=?", (name,)
        ).fetchone() is not None
    finally:
        con.close()


def db_identity_owner(pub_b64):
    con = sqlite3.connect(os.path.join(TMPD, "relay.db"))
    try:
        row = con.execute(
            "SELECT name FROM peers WHERE identity_pubkey=?", (pub_b64,)
        ).fetchone()
        return row[0] if row else None
    finally:
        con.close()


def config_pubkeys():
    with open(os.path.join(TMPD, "relay-config.json")) as f:
        return json.load(f).get("identity_pubkeys", {})


def authority_snapshot():
    """Exact public config bytes plus every register-key-relevant DB row."""
    config_path = os.path.join(TMPD, "relay-config.json")
    with open(config_path, "rb") as f:
        config_bytes = f.read()
    con = sqlite3.connect(os.path.join(TMPD, "relay.db"))
    try:
        peers = con.execute(
            "SELECT rowid, name, token_hash, created_at, identity_pubkey, "
            "invited_by, display_name, enroll_gate, enroll_ip, last_poll_at, "
            "last_send_at FROM peers ORDER BY rowid"
        ).fetchall()
        nonces = con.execute(
            "SELECT nonce, peer, expires_at FROM seen_nonces ORDER BY nonce"
        ).fetchall()
    finally:
        con.close()
    candidates = tuple(sorted(
        name for name in os.listdir(TMPD)
        if ".register-key-" in name and name.endswith(".tmp")
    ))
    return {
        "config_bytes": config_bytes,
        "peers": peers,
        "seen_nonces": nonces,
        "config_candidates": candidates,
    }


def identity_surface_snapshot():
    """Exact config plus all durable DB rows touched by public identity writers."""
    config_path = os.path.join(TMPD, "relay-config.json")
    with open(config_path, "rb") as f:
        config_bytes = f.read()
    con = sqlite3.connect(os.path.join(TMPD, "relay.db"))
    try:
        dump = tuple(con.iterdump())
    finally:
        con.close()
    candidates = tuple(sorted(
        name for name in os.listdir(TMPD)
        if ".register-key-" in name and name.endswith(".tmp")
    ))
    return config_bytes, dump, candidates


def check_authority_unchanged(before, label):
    after = authority_snapshot()
    check(after == before, label,
          "before=%r after=%r" % (before, after))


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
    pubkeys = {"minter": KEYS["minter"][2],
               "lockpeer": KEYS["lockpeer"][2],
               "failpeer": KEYS["failpeer"][2]}
    if extra_pubkeys:
        pubkeys.update(extra_pubkeys)
    IDKEY = _gen_rsa_identity_key(TMPD)
    cfg = {"port": PORT,
           "peers": {"tokpeer": TOKPEER_TOKEN,
                     "minter": MINTER_TOKEN,
                     "clipeer": CLIPEER_TOKEN,
                     "lockpeer": LOCKPEER_TOKEN,
                     "failpeer": FAILPEER_TOKEN,
                     "uncertainpeer": UNCERTAINPEER_TOKEN,
                     "driftpeer": DRIFTPEER_TOKEN,
                     "revokedpeer": REVOKEDPEER_TOKEN,
                     "droppeer": DROPPEER_TOKEN,
                     "invalidpeer": INVALIDPEER_TOKEN},
           "identity_pubkeys": pubkeys,
           # Keep loopback out of the trusted-network signature exemption so
           # this scratch suite exercises real signature verification.
           "internal_trusted_nets": ["192.0.2.0/24"],
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


def start_inprocess_relay():
    """Start an imported loopback relay so fault seams can be patched safely."""
    global INPROC_SERVER, INPROC_THREAD
    if INPROC_SERVER is not None or (SRV and SRV.poll() is None):
        raise RuntimeError("another scratch relay is already running")
    if _rm.conn is not None:
        try:
            _rm.conn.close()
        except Exception:
            pass
        _rm.conn = None
    cfg_path = os.path.join(TMPD, "relay-config.json")
    db_path = os.path.join(TMPD, "relay.db")
    with open(cfg_path, "rb") as f:
        cfg_raw = f.read()
    cfg = json.loads(cfg_raw.decode("utf-8"))
    _rm.BASE = TMPD
    _rm.CONFIG_PATH = cfg_path
    _rm.DB_PATH = db_path
    _rm._capture_registration_config_baseline(cfg_raw)
    _rm.relay_cfg = cfg
    _rm.db_lock = threading.Lock()
    _rm.registration_lock = threading.Lock()
    _rm._registration_fail_stop_lock = threading.Lock()
    _rm._registration_fail_stop_reason = None
    _rm._REGISTER_KEY_BEFORE_LOCK_HOOK = None
    _rm._REGISTER_KEY_AFTER_AUTH_HOOK = None
    _rm._ENROLLMENT_BEFORE_IDENTITY_LOCK_HOOK = None
    _rm._CONFIG_REPLACE = os.replace
    _rm._CONFIG_FSYNC = os.fsync
    _rm._registration_db_update = _ORIG_REGISTRATION_DB_UPDATE
    _rm._registration_db_commit = _ORIG_REGISTRATION_DB_COMMIT
    _rm._peer_key_valid = {}
    _rm.rate_hits = {}
    _rm.auth_fail_hits = {}
    _rm._sweep_last_error = None
    _rm._init_reserved_names(cfg)
    _rm._init_identity_pubkeys(cfg)
    _rm._init_peer_hashes(cfg)
    _rm._parse_handshake_knobs(cfg)
    _rm.load_identity_key(cfg)
    _rm._init_federation(cfg)
    _rm.init_db(cfg)
    INPROC_SERVER = _rm.ThreadingHTTPServer(("127.0.0.1", PORT), _rm.Handler)
    INPROC_THREAD = threading.Thread(
        target=INPROC_SERVER.serve_forever,
        name="register-key-inprocess-relay",
        daemon=True,
    )
    INPROC_THREAD.start()
    for _ in range(40):
        try:
            with urllib.request.urlopen(BASE + "/health", timeout=2) as r:
                if json.loads(r.read().decode()).get("version") == _rm.VERSION:
                    return
        except Exception:
            pass
        time.sleep(0.1)
    raise RuntimeError("in-process scratch relay did not start")


def stop_inprocess_relay():
    global INPROC_SERVER, INPROC_THREAD
    if INPROC_SERVER is not None:
        INPROC_SERVER.shutdown()
        INPROC_SERVER.server_close()
    if INPROC_THREAD is not None:
        INPROC_THREAD.join(timeout=10)
    INPROC_SERVER = None
    INPROC_THREAD = None
    if _rm.conn is not None:
        with _rm.db_lock:
            _rm.conn.close()
            _rm.conn = None


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
fresh_key("lockpeer")
fresh_key("failpeer")
KEYS["tokpeer_a"] = KEYS["tokpeer"]
write_config()
start_relay()
check(_rm.VERSION == "1.1.0", "relay reports v1.1.0", _rm.VERSION)

# tokpeer starts token-only: signed requests must 401 upgrade_required.
# (tokpeer's key exists locally but is not registered yet)
code, out = call(TOKPEER_TOKEN, "GET", "/v1/peers", peer="tokpeer")
check(code == 401 and out.get("error") == "upgrade_required",
      "token-only peer gets 401 upgrade_required pre-registration",
      "%s %s" % (code, out))

# ------------------------------------------------- phase 2: register-key core
print("== phase 2: register-key ==", flush=True)
seed_a, pub_a, b64_a = KEYS["tokpeer"]

# 2a. First registration succeeds without signature because no valid key exists.
code, out = call(TOKPEER_TOKEN, "POST", "/v1/register-key",
                 {"pubkey": b64_a})
check(code == 200 and out.get("registered") is True
      and out.get("peer") == "tokpeer" and out.get("rotated") is False
      and out.get("identity_pubkey") == b64_a,
      "first registration echoes the exact canonical accepted key",
      "%s %s" % (code, out))
check(db_peer_key("tokpeer") == b64_a, "DB row carries the key")
check(config_pubkeys().get("tokpeer") == b64_a,
      "first registration persisted the key")

# 2b. signed requests now work (upgrade path complete)
code, out = call(TOKPEER_TOKEN, "GET", "/v1/peers", peer="tokpeer")
check(code == 200 and "tokpeer" in out.get("peers", []),
      "signed request works after registration", "%s" % code)

# 2c. Authenticated malformed requests still fail without mutation.
before = authority_snapshot()
code, out = call(TOKPEER_TOKEN, "POST", "/v1/register-key", {},
                 peer="tokpeer")
check(code == 400 and out.get("error") == "pubkey_required",
      "missing pubkey -> 400 pubkey_required", "%s %s" % (code, out))
check_authority_unchanged(before, "missing-pubkey rejection preserves exact authority state")
before = authority_snapshot()
code, out = call(TOKPEER_TOKEN, "POST", "/v1/register-key",
                 {"pubkey": "not-a-key"}, peer="tokpeer")
check(code == 400 and out.get("error") == "bad_pubkey",
      "garbage pubkey -> 400 bad_pubkey", "%s %s" % (code, out))
check_authority_unchanged(before, "garbage-pubkey rejection preserves exact authority state")
before = authority_snapshot()
code, out = call(TOKPEER_TOKEN, "POST", "/v1/register-key",
                 {"pubkey": b64u_encode(b"short")}, peer="tokpeer")
check(code == 400 and out.get("error") == "bad_pubkey",
      "wrong-length pubkey -> 400 bad_pubkey", "%s %s" % (code, out))
check_authority_unchanged(before, "short-pubkey rejection preserves exact authority state")
before = authority_snapshot()
code, out = call(TOKPEER_TOKEN, "POST", "/v1/register-key",
                 {"pubkey": "-----BEGIN PUBLIC KEY-----\nZm9v\n-----END PUBLIC KEY-----"},
                 peer="tokpeer")
check(code == 400 and out.get("error") == "bad_pubkey",
      "malformed PEM -> 400 bad_pubkey", "%s %s" % (code, out))
check_authority_unchanged(before, "malformed-PEM rejection preserves exact authority state")

# 2d. auth failures -> 401
before = authority_snapshot()
code, out = call(None, "POST", "/v1/register-key", {"pubkey": b64_a})
check(code == 401, "no token -> 401", "%s %s" % (code, out))
check_authority_unchanged(before, "missing-token rejection preserves exact authority state")
before = authority_snapshot()
code, out = call("wrong-token", "POST", "/v1/register-key", {"pubkey": b64_a})
check(code == 401, "bad token -> 401", "%s %s" % (code, out))
check_authority_unchanged(before, "bad-token rejection preserves exact authority state")

# 2e. Even same-key re-registration needs the current-key signature.
before = authority_snapshot()
code, out = call(TOKPEER_TOKEN, "POST", "/v1/register-key",
                 {"pubkey": b64_a})
check(code == 401 and out.get("error") == "missing_signature",
      "unsigned same-key re-registration rejected",
      "%s %s" % (code, out))
check_authority_unchanged(before, "unsigned same-key rejection preserves exact authority state")

# 2f. Bearer-only replacement must fail and preserve the current key.
seed_b, pub_b, b64_b = fresh_key("tokpeer_b")
before = authority_snapshot()
code, out = call(TOKPEER_TOKEN, "POST", "/v1/register-key",
                 {"pubkey": b64_b})
check(code == 401 and out.get("error") == "missing_signature",
      "unsigned replacement rejected", "%s %s" % (code, out))
check_authority_unchanged(before, "unsigned replacement preserves exact authority state")

# 2g. The proposed/new key cannot authorize its own installation.
before = authority_snapshot()
code, out = call(TOKPEER_TOKEN, "POST", "/v1/register-key",
                 {"pubkey": b64_b}, peer="tokpeer", signer="tokpeer_b")
check(code == 401 and out.get("error") == "bad_signature",
      "new-key signature rejected", "%s %s" % (code, out))
check_authority_unchanged(before, "wrong-key rejection preserves exact authority state")

# 2h. Even a current-key signature fails if the proposed body is changed.
_, _, b64_tampered = fresh_key("tokpeer_tampered")
before = authority_snapshot()
code, out = call(TOKPEER_TOKEN, "POST", "/v1/register-key",
                 {"pubkey": b64_tampered}, peer="tokpeer",
                 signer="tokpeer_a", signature_body={"pubkey": b64_b})
check(code == 401 and out.get("error") == "bad_signature",
      "current-key signature binds the proposed-key body",
      "%s %s" % (code, out))
check_authority_unchanged(before, "body-tamper rejection preserves exact authority state")

# 2i. The current/old key authorizes rotation; the body binds b64_b.
code, out = call(TOKPEER_TOKEN, "POST", "/v1/register-key",
                 {"pubkey": b64_b}, peer="tokpeer", signer="tokpeer_a")
check(code == 200 and out.get("rotated") is True
      and out.get("identity_pubkey") == b64_b,
      "old-key-signed rotation echoes the exact accepted key",
      "%s %s" % (code, out))
check(db_peer_key("tokpeer") == b64_b
      and config_pubkeys().get("tokpeer") == b64_b,
      "authorized rotation updates DB and config")
KEYS["tokpeer"] = (seed_b, pub_b, b64_b)

# 2j. Same-key re-registration succeeds only when signed by the current key.
same_key_nonce = "%d:%s" % (int(time.time()), secrets.token_hex(16))
code, out = call(TOKPEER_TOKEN, "POST", "/v1/register-key",
                 {"pubkey": b64_b}, peer="tokpeer",
                 signature_nonce=same_key_nonce)
check(code == 200 and out.get("rotated") is False
      and out.get("identity_pubkey") == b64_b,
      "same-key response echoes the exact current key",
      "%s %s" % (code, out))
check(db_peer_key("tokpeer") == b64_b
      and config_pubkeys().get("tokpeer") == b64_b,
      "signed same-key re-registration preserves current key")

# 2k. Replaying that exact signed request is rejected without mutation.
before = authority_snapshot()
code, out = call(TOKPEER_TOKEN, "POST", "/v1/register-key",
                 {"pubkey": b64_b}, peer="tokpeer",
                 signature_nonce=same_key_nonce)
check(code == 401 and out.get("error") == "replay",
      "replayed signed same-key registration rejected",
      "%s %s" % (code, out))
check_authority_unchanged(before, "replay rejection preserves exact authority state")

# 2l. Stop the process relay and run deterministic ThreadingHTTPServer races
# keys. The registration lock must let exactly one old-key signature win; the
# second request is stale as soon as the first key is durable.
stop_relay()
start_inprocess_relay()
race_keys = [fresh_key("tokpeer_race_1"), fresh_key("tokpeer_race_2")]
race_results = [None, None]
race_barrier = threading.Barrier(3)
server_arrival_barrier = threading.Barrier(2)
_rm._REGISTER_KEY_BEFORE_LOCK_HOOK = \
    lambda: server_arrival_barrier.wait(timeout=10)


def race_rotate(index):
    try:
        race_barrier.wait(timeout=10)
        race_results[index] = call(
            TOKPEER_TOKEN, "POST", "/v1/register-key",
            {"pubkey": race_keys[index][2]}, peer="tokpeer",
            signer="tokpeer_b")
    except Exception as exc:
        race_results[index] = (None, {"exception": repr(exc)})


race_threads = [threading.Thread(target=race_rotate, args=(i,))
                for i in range(2)]
for thread in race_threads:
    thread.start()
race_barrier.wait(timeout=10)
for thread in race_threads:
    thread.join(timeout=30)
_rm._REGISTER_KEY_BEFORE_LOCK_HOOK = None
check(all(not thread.is_alive() for thread in race_threads),
      "concurrent rotations both completed", repr(race_results))
race_winners = [i for i, result in enumerate(race_results)
                if result and result[0] == 200]
race_losers = [i for i, result in enumerate(race_results)
               if result and result[0] == 401
               and result[1].get("error") == "bad_signature"]
check(len(race_winners) == 1 and len(race_losers) == 1,
      "concurrent old-key rotations allow exactly one winner",
      repr(race_results))
winner = race_winners[0] if len(race_winners) == 1 else None
winner_b64 = race_keys[winner][2] if winner is not None else None
check(winner_b64 is not None
      and db_peer_key("tokpeer") == winner_b64
      and config_pubkeys().get("tokpeer") == winner_b64,
      "concurrent winner is durable in DB and config",
      "winner=%r db=%r config=%r" % (
          winner_b64, db_peer_key("tokpeer"),
          config_pubkeys().get("tokpeer")))
if winner is not None:
    KEYS["tokpeer"] = race_keys[winner]

# Negative control: remove only registration_lock in the imported scratch
# relay, then force both workers to finish old-key authorization before either
# may store. The exact-one-winner oracle must detect the modeled production bug
# (both requests return 200). Production lock and hooks are restored before any
# subsequent assertion.
class _NoRegistrationLock:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


negative_keys = [fresh_key("lockpeer_nolock_1"),
                 fresh_key("lockpeer_nolock_2")]
negative_results = [None, None]
negative_client_barrier = threading.Barrier(3)
negative_auth_barrier = threading.Barrier(2)
production_registration_lock = _rm.registration_lock
_rm.registration_lock = _NoRegistrationLock()
_rm._REGISTER_KEY_AFTER_AUTH_HOOK = \
    lambda: negative_auth_barrier.wait(timeout=10)


def negative_rotate(index):
    try:
        negative_client_barrier.wait(timeout=10)
        negative_results[index] = call(
            LOCKPEER_TOKEN, "POST", "/v1/register-key",
            {"pubkey": negative_keys[index][2]}, peer="lockpeer")
    except Exception as exc:
        negative_results[index] = (None, {"exception": repr(exc)})


negative_threads = [threading.Thread(target=negative_rotate, args=(i,))
                    for i in range(2)]
try:
    for thread in negative_threads:
        thread.start()
    negative_client_barrier.wait(timeout=10)
    for thread in negative_threads:
        thread.join(timeout=30)
finally:
    _rm._REGISTER_KEY_AFTER_AUTH_HOOK = None
    _rm.registration_lock = production_registration_lock
negative_successes = [result for result in negative_results
                      if result and result[0] == 200]
check(all(not thread.is_alive() for thread in negative_threads)
      and len(negative_successes) == 2,
      "no-lock negative control deterministically produces two winners",
      repr(negative_results))
check(len(negative_successes) != 1,
      "exact-one-winner oracle rejects the no-lock control",
      repr(negative_results))
negative_final = db_peer_key("lockpeer")
negative_final_index = next(
    (i for i, key in enumerate(negative_keys) if key[2] == negative_final), None)
check(negative_final_index is not None
      and config_pubkeys().get("lockpeer") == negative_final,
      "negative-control scratch stores converge on one final key",
      "db=%r config=%r" % (negative_final,
                             config_pubkeys().get("lockpeer")))
if negative_final_index is not None:
    KEYS["lockpeer"] = negative_keys[negative_final_index]

# 2m. A real relay restart must preserve the exact race winner before any
# later rotation can mask the result.
stop_inprocess_relay()
start_relay()
check(winner_b64 is not None
      and db_peer_key("tokpeer") == winner_b64
      and config_pubkeys().get("tokpeer") == winner_b64,
      "concurrent winner remains identical in DB/config after restart",
      "winner=%r db=%r config=%r" % (
          winner_b64, db_peer_key("tokpeer"),
          config_pubkeys().get("tokpeer")))

# The immediately stale pre-race key fails on both a read and a fresh-nonce
# register-key POST; every rejected call preserves exact authority state.
before = authority_snapshot()
code, _ = call(TOKPEER_TOKEN, "GET", "/v1/peers",
               peer="tokpeer", signer="tokpeer_b")
check(code == 401, "stale pre-race key rejected on GET", "%s" % code)
check_authority_unchanged(before, "stale-key GET preserves exact authority state")
_, _, stale_post_b64 = fresh_key("tokpeer_stale_post")
before = authority_snapshot()
code, out = call(TOKPEER_TOKEN, "POST", "/v1/register-key",
                 {"pubkey": stale_post_b64}, peer="tokpeer",
                 signer="tokpeer_b")
check(code == 401 and out.get("error") == "bad_signature",
      "fresh-nonce stale-key POST rejected",
      "%s %s" % (code, out))
check_authority_unchanged(before, "stale-key POST preserves exact authority state")
code, out = call(TOKPEER_TOKEN, "GET", "/v1/peers", peer="tokpeer")
check(code == 200, "concurrent winner verifies after restart", "%s" % code)

# A real unique-index collision must be caught before config publication. The
# minter key is already owned by another row.
before = authority_snapshot()
code, out = call(TOKPEER_TOKEN, "POST", "/v1/register-key",
                 {"pubkey": KEYS["minter"][2]}, peer="tokpeer")
check(code == 409 and out.get("error") == "identity_in_use",
      "duplicate identity key -> 409 identity_in_use",
      "%s %s" % (code, out))
check_authority_unchanged(before, "duplicate-key rejection preserves exact authority state")
stop_relay()
start_relay()
check(db_peer_key("tokpeer") == winner_b64
      and config_pubkeys().get("tokpeer") == winner_b64,
      "duplicate-key rejection cannot poison restart",
      "db=%r config=%r" % (db_peer_key("tokpeer"),
                             config_pubkeys().get("tokpeer")))

# A live operator config edit is newer authority than this process's startup
# snapshot. Registration must fail closed before DB/nonce mutation and preserve
# the operator's exact bytes (including a peer revocation and opaque marker).
config_path = os.path.join(TMPD, "relay-config.json")
with open(config_path, "rb") as f:
    operator_source = json.loads(f.read().decode("utf-8"))
operator_source["peers"].pop("revokedpeer")
operator_source["operator_marker"] = {
    "purpose": "byte-exact registration drift regression",
    "revocation": "revokedpeer",
}
operator_bytes = (json.dumps(operator_source, indent=3, sort_keys=True)
                  + "\n").encode("utf-8")
with open(config_path, "wb") as f:
    f.write(operator_bytes)
    f.flush()
    os.fsync(f.fileno())
parent_fd = os.open(TMPD, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(parent_fd)
finally:
    os.close(parent_fd)
drift_before = authority_snapshot()
_, _, drift_candidate = fresh_key("driftpeer_candidate")
code, out = call(DRIFTPEER_TOKEN, "POST", "/v1/register-key",
                 {"pubkey": drift_candidate})
check(code == 409 and out.get("error") == "config_changed_restart_required",
      "registration rejects live config drift pending restart",
      "%s %s" % (code, out))
check_authority_unchanged(
    drift_before,
    "drift rejection preserves revocation bytes, DB rows, and nonce state",
)
check(not config_pubkeys().get("driftpeer")
      and db_peer_key("driftpeer") is None,
      "drift rejection creates no DB/config key split")
stop_relay()
start_relay()
with open(config_path, "rb") as f:
    restarted_operator_bytes = f.read()
check(restarted_operator_bytes == operator_bytes
      and not db_peer_present("revokedpeer"),
      "restart applies revocation without rewriting operator bytes")

# Explicitly trust loopback for ordinary traffic, restart, then prove that the
# register-key special route still demands the current-key signature.
stop_relay()
with open(config_path, "rb") as f:
    trusted_original_config = f.read()
trusted_cfg = json.loads(trusted_original_config.decode("utf-8"))
trusted_cfg["internal_trusted_nets"] = ["127.0.0.1/32"]
with open(config_path, "w", encoding="utf-8") as f:
    json.dump(trusted_cfg, f, indent=2)
    f.write("\n")
start_relay()
_, _, trusted_bypass_b64 = fresh_key("tokpeer_trusted_bypass")
before = authority_snapshot()
code, out = call(TOKPEER_TOKEN, "POST", "/v1/register-key",
                 {"pubkey": trusted_bypass_b64})
check(code == 401 and out.get("error") == "missing_signature",
      "trusted-network exemption cannot bypass register-key",
      "%s %s" % (code, out))
check_authority_unchanged(before, "trusted-network rejection preserves exact authority state")
stop_relay()
with open(config_path, "wb") as f:
    f.write(trusted_original_config)
start_relay()
check(db_peer_key("tokpeer") == winner_b64,
      "trusted-network test restart retains winner", db_peer_key("tokpeer"))

# ---------------------------------------------- phase 3: injected storage faults
print("== phase 3: transactional faults ==", flush=True)
stop_relay()
start_inprocess_relay()

# Inject a real operator revocation while registration is staging its fsynced
# candidate (not merely before the request). The post-stage digest check must
# roll back DB state, consume no nonce, preserve the operator's exact bytes,
# and require restart instead of overwriting from stale process memory.
concurrent_drift_key = fresh_key("driftpeer_concurrent_candidate")
concurrent_drift_before = authority_snapshot()
concurrent_operator_bytes = {"value": None}
concurrent_edit_done = {"value": False}


def edit_config_during_stage(fd):
    real_result = os.fsync(fd)
    if not concurrent_edit_done["value"]:
        config_path = os.path.join(TMPD, "relay-config.json")
        with open(config_path, "rb") as f:
            current = json.loads(f.read().decode("utf-8"))
        current["peers"].pop("failpeer", None)
        current.get("identity_pubkeys", {}).pop("failpeer", None)
        current["concurrent_registration_marker"] = \
            "operator edit must remain byte-exact"
        raw = (json.dumps(current, indent=4, sort_keys=True)
               + "\n").encode("utf-8")
        replacement = config_path + ".operator-edit"
        with open(replacement, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(replacement, config_path)
        dir_fd = os.open(TMPD, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        concurrent_operator_bytes["value"] = raw
        concurrent_edit_done["value"] = True
    return real_result


_rm._CONFIG_FSYNC = edit_config_during_stage
try:
    code, out = call(DRIFTPEER_TOKEN, "POST", "/v1/register-key",
                     {"pubkey": concurrent_drift_key[2]})
finally:
    _rm._CONFIG_FSYNC = os.fsync
concurrent_drift_after = authority_snapshot()
check(code == 409 and out.get("error") == "config_changed_restart_required"
      and concurrent_edit_done["value"],
      "concurrent staged config edit rejects registration",
      "%s %s edited=%r" % (code, out, concurrent_edit_done["value"]))
check(concurrent_drift_after["config_bytes"]
          == concurrent_operator_bytes["value"]
      and concurrent_drift_after["peers"]
          == concurrent_drift_before["peers"]
      and concurrent_drift_after["seen_nonces"]
          == concurrent_drift_before["seen_nonces"]
      and not concurrent_drift_after["config_candidates"]
      and db_peer_key("driftpeer") is None,
      "concurrent revocation bytes survive with no DB/nonce split",
      "before=%r after=%r" % (
          concurrent_drift_before, concurrent_drift_after))
stop_inprocess_relay()
start_inprocess_relay()
with open(os.path.join(TMPD, "relay-config.json"), "rb") as f:
    concurrent_restart_bytes = f.read()
check(concurrent_restart_bytes == concurrent_operator_bytes["value"]
      and not db_peer_present("failpeer"),
      "restart applies concurrent revocation without rewriting marker bytes")

# DB update failure occurs after nonce reservation but before commit: both must
# roll back, including the nonce row and staged-file set.
_, _, db_fault_b64 = fresh_key("tokpeer_db_fault")
before = authority_snapshot()


def fail_db_update(db, peer, pub_b64):
    raise sqlite3.OperationalError("injected registration update fault")


_rm._registration_db_update = fail_db_update
try:
    code, out = call(TOKPEER_TOKEN, "POST", "/v1/register-key",
                     {"pubkey": db_fault_b64}, peer="tokpeer")
finally:
    _rm._registration_db_update = _ORIG_REGISTRATION_DB_UPDATE
check(code == 500 and out.get("error") == "storage_failed",
      "injected DB update fault is caught", "%s %s" % (code, out))
check_authority_unchanged(before, "DB update fault preserves exact authority state")

# Commit-then-raise models an unknown SQLite commit outcome. Compensation must
# restore the old key and delete the nonce before returning the caught error.
_, _, db_commit_fault_b64 = fresh_key("tokpeer_db_commit_fault")
before = authority_snapshot()


def commit_then_fail(db):
    db.commit()
    raise sqlite3.OperationalError("injected post-commit fault")


_rm._registration_db_commit = commit_then_fail
try:
    code, out = call(TOKPEER_TOKEN, "POST", "/v1/register-key",
                     {"pubkey": db_commit_fault_b64}, peer="tokpeer")
finally:
    _rm._registration_db_commit = _ORIG_REGISTRATION_DB_COMMIT
check(code == 500 and out.get("error") == "storage_failed",
      "unknown DB commit outcome is compensated", "%s %s" % (code, out))
check_authority_unchanged(before, "DB commit fault preserves exact authority state")

# Temp-file fsync failure occurs while the SQLite transaction is still open.
_, _, stage_fault_b64 = fresh_key("tokpeer_stage_fault")
before = authority_snapshot()


def fail_fsync(_fd):
    raise OSError("injected temp fsync fault")


_rm._CONFIG_FSYNC = fail_fsync
try:
    code, out = call(TOKPEER_TOKEN, "POST", "/v1/register-key",
                     {"pubkey": stage_fault_b64}, peer="tokpeer")
finally:
    _rm._CONFIG_FSYNC = os.fsync
check(code == 500 and out.get("error") == "storage_failed",
      "injected config staging fault is caught", "%s %s" % (code, out))
check_authority_unchanged(before, "config staging fault preserves exact authority state")

# Replace failure happens after DB commit. The compensation transaction must
# restore key + nonce, leaving exact config bytes and no temp residue.
_, _, replace_fault_b64 = fresh_key("tokpeer_replace_fault")
before = authority_snapshot()


def fail_replace(_src, _dst):
    raise OSError("injected config replace fault")


_rm._CONFIG_REPLACE = fail_replace
try:
    code, out = call(TOKPEER_TOKEN, "POST", "/v1/register-key",
                     {"pubkey": replace_fault_b64}, peer="tokpeer")
finally:
    _rm._CONFIG_REPLACE = os.replace
check(code == 500 and out.get("error") == "persist_failed",
      "pre-publication config replace fault is compensated",
      "%s %s" % (code, out))
check_authority_unchanged(before, "config replace fault preserves exact authority state")

# Every runtime _enroll_identity_locked call site uses the shared guard, and a
# real open-enrollment request demonstrably blocks at that guard while a
# registration transition owns registration_lock.
with open(RELAY_PY, encoding="utf-8") as f:
    relay_source = f.read()
check(relay_source.count("with _EnrollmentIdentityLocks():") == 3,
      "all three enrollment identity writers use the shared lock guard")
enroll_seed, enroll_pub = _rc.keygen()
enroll_b64 = b64u_encode(enroll_pub)
code, enroll_challenge = call(None, "POST", "/v1/enroll/challenge", {})
check(code == 200 and enroll_challenge.get("gate") == "open",
      "open enrollment challenge for lock serialization test",
      "%s %s" % (code, enroll_challenge))
enroll_nonce = b64u_decode(enroll_challenge["nonce"])
enroll_sig = _rc.sign(enroll_seed, enroll_nonce + enroll_pub)
enroll_body = {
    "identity_pubkey": enroll_b64,
    "name": "serialized-enroll",
    "proof": {"nonce": enroll_challenge["nonce"],
              "signature": b64u_encode(enroll_sig)},
}
enrollment_reached_lock = threading.Event()
enrollment_result = [None]
_rm._ENROLLMENT_BEFORE_IDENTITY_LOCK_HOOK = enrollment_reached_lock.set
_rm.registration_lock.acquire()


def blocked_enrollment():
    enrollment_result[0] = call(None, "POST", "/v1/enroll", enroll_body)


enrollment_thread = threading.Thread(target=blocked_enrollment)
try:
    enrollment_thread.start()
    reached = enrollment_reached_lock.wait(timeout=10)
    check(reached and enrollment_thread.is_alive()
          and db_identity_owner(enroll_b64) is None,
          "enrollment identity writer blocks behind registration_lock",
          "reached=%r alive=%r owner=%r" % (
              reached, enrollment_thread.is_alive(),
              db_identity_owner(enroll_b64)))
finally:
    _rm.registration_lock.release()
    enrollment_thread.join(timeout=30)
    _rm._ENROLLMENT_BEFORE_IDENTITY_LOCK_HOOK = None
check(not enrollment_thread.is_alive()
      and enrollment_result[0]
      and enrollment_result[0][0] == 200
      and db_identity_owner(enroll_b64) == "serialized-enroll",
      "blocked enrollment commits after registration lock releases",
      repr(enrollment_result))

# Prepare valid, mutation-capable bodies for every public identity-writing
# surface before the fail-stop latch is set. The exact same bodies are retried
# successfully after restart, so a 503 cannot pass merely because the fixtures
# were malformed or incapable of creating an identity.
public_enroll_seed, public_enroll_pub = _rc.keygen()
public_enroll_b64 = b64u_encode(public_enroll_pub)
code, public_enroll_ch = call(None, "POST", "/v1/enroll/challenge", {})
public_enroll_nonce = b64u_decode(public_enroll_ch.get("nonce", ""))
public_enroll_body = {
    "identity_pubkey": public_enroll_b64,
    "name": "failstop-open-control",
    "proof": {
        "nonce": public_enroll_ch.get("nonce"),
        "signature": b64u_encode(_rc.sign(
            public_enroll_seed, public_enroll_nonce + public_enroll_pub)),
    },
}
check(code == 200 and public_enroll_ch.get("gate") == "open",
      "prepared valid open-enrollment fail-stop fixture",
      "%s %s" % (code, public_enroll_ch))

code, legacy_mint = call(
    MINTER_TOKEN, "POST", "/v1/invites/mint",
    {"expiry_seconds": 3600, "max_uses": 1}, peer="minter")
legacy_qs = urllib.parse.parse_qs(
    legacy_mint.get("link", "#").split("#", 1)[-1],
    keep_blank_values=True)
legacy_iid = legacy_mint.get("invite_id")
legacy_secret = (legacy_qs.get("k") or [None])[0]
legacy_seed, legacy_pub = _rc.keygen()
legacy_b64 = b64u_encode(legacy_pub)
legacy_ch_code, legacy_ch = call(
    None, "POST", "/v1/invites/challenge", {"invite_id": legacy_iid})
legacy_nonce = b64u_decode(legacy_ch.get("nonce", ""))
legacy_body = {
    "invite_id": legacy_iid,
    "secret": legacy_secret,
    "identity_pubkey": legacy_b64,
    "name": "failstop-invite-control",
    "proof": {
        "nonce": legacy_ch.get("nonce"),
        "signature": b64u_encode(_rc.sign(
            legacy_seed,
            legacy_nonce + legacy_iid.encode("utf-8") + legacy_pub)),
    },
}
check(code == 200 and legacy_iid and legacy_secret
      and legacy_ch_code == 200,
      "prepared valid legacy-invite fail-stop fixture",
      "%s %s / %s %s" % (code, legacy_mint, legacy_ch_code, legacy_ch))

code, handshake_mint = call(
    MINTER_TOKEN, "POST", "/v1/handshakes/mint-link",
    {"max_uses": 1, "exp_days": 7}, peer="minter")
handshake_qs = urllib.parse.parse_qs(
    handshake_mint.get("link", "#").split("#", 1)[-1],
    keep_blank_values=True)
handshake_id = (handshake_qs.get("h") or [None])[0]
handshake_secret = (handshake_qs.get("k") or [None])[0]
handshake_seed, handshake_pub = _rc.keygen()
handshake_b64 = b64u_encode(handshake_pub)
handshake_ch_code, handshake_ch = call(
    None, "POST", "/v1/enroll/challenge", {"invite_id": handshake_id})
handshake_nonce = b64u_decode(handshake_ch.get("nonce", ""))
handshake_body = {
    "h": handshake_id,
    "k": handshake_secret,
    "identity_pubkey": handshake_b64,
    "name": "failstop-handshake-control",
    "proof": {
        "nonce": handshake_ch.get("nonce"),
        "signature": b64u_encode(_rc.sign(
            handshake_seed,
            handshake_nonce + handshake_id.encode("utf-8") + handshake_pub)),
    },
}
check(code == 200 and handshake_id and handshake_secret
      and handshake_ch_code == 200
      and handshake_ch.get("gate") == "invite",
      "prepared valid handshake-redeem fail-stop fixture",
      "%s %s / %s %s" % (
          code, handshake_mint, handshake_ch_code, handshake_ch))

# The CLI must retain its exact candidate when the relay makes the DB/config
# update visible but returns 503 because parent-directory fsync is uncertain.
uncertain_dir = tempfile.mkdtemp(prefix="clack-cli-503-")
uncertain_cfgp = os.path.join(uncertain_dir, "legacy.json")
uncertain_keyp = os.path.join(uncertain_dir, "identity.key")
uncertain_pending = uncertain_cfgp + ".register-key.pending"
uncertain_legacy_cfg = {
    "peers": {"uncertainpeer": UNCERTAINPEER_TOKEN},
    "base_url": BASE,
    "relay_identity_fingerprint": _rc.relay_identity_fingerprint(IDKEY),
}
with open(uncertain_cfgp, "w", encoding="utf-8") as f:
    json.dump(uncertain_legacy_cfg, f)
real_fsync = os.fsync
fsync_calls = {"count": 0}


def fail_parent_fsync(fd):
    fsync_calls["count"] += 1
    if fsync_calls["count"] == 2:
        raise OSError("injected parent directory fsync fault")
    return real_fsync(fd)


original_cli_req = _rc.req
uncertain_requests = []


def record_uncertain_req(*args, **kwargs):
    uncertain_requests.append((args[1], args[2]))
    return original_cli_req(*args, **kwargs)


old_use_curl = os.environ.get("CLACK_USE_CURL")
os.environ["CLACK_USE_CURL"] = "0"
_rm._CONFIG_FSYNC = fail_parent_fsync
_rc.req = record_uncertain_req
try:
    uncertain_rc = _rc.cmd_register_key(
        direct_cli_args(uncertain_cfgp, peer="uncertainpeer",
                        key_path=uncertain_keyp),
        dict(uncertain_legacy_cfg),
    )
finally:
    _rc.req = original_cli_req
    _rm._CONFIG_FSYNC = os.fsync
    if old_use_curl is None:
        os.environ.pop("CLACK_USE_CURL", None)
    else:
        os.environ["CLACK_USE_CURL"] = old_use_curl
uncertain_journal = _rc._load_register_key_journal(
    uncertain_pending, uncertain_cfgp)
uncertain_candidate = uncertain_journal["identity_pubkey"]
check(uncertain_rc == 1
      and uncertain_requests == [("POST", "/v1/register-key")]
      and uncertain_journal["phase"] == "requesting",
      "503-after-publication sends once and retains a requesting journal",
      "rc=%r requests=%r phase=%r" % (
          uncertain_rc, uncertain_requests, uncertain_journal.get("phase")))
check((os.stat(uncertain_pending).st_mode & 0o777) == 0o600
      and b64u_encode(_rc._publickey(
          b64u_decode(uncertain_journal["identity_seed"])))
          == uncertain_candidate,
      "retained 503 journal is mode-0600 and recovery-capable")
after_post_replace = authority_snapshot()
check(db_peer_key("uncertainpeer") == uncertain_candidate
      and config_pubkeys().get("uncertainpeer") == uncertain_candidate
      and not after_post_replace["config_candidates"],
      "503-after-publication leaves one exact visible server candidate",
      "db=%r config=%r" % (
          db_peer_key("uncertainpeer"),
          config_pubkeys().get("uncertainpeer")))
code, health = call(None, "GET", "/health")
check(code == 503 and health.get("check") == "registration_fail_stop",
      "fail-stop is visible through health", "%s %s" % (code, health))

blocked_before = authority_snapshot()
code, out = call(TOKPEER_TOKEN, "POST", "/v1/register-key",
                 {"pubkey": winner_b64}, peer="tokpeer")
check(code == 503 and out.get("error") == "registration_fail_stop",
      "fail-stop blocks register-key", "%s %s" % (code, out))
check_authority_unchanged(
    blocked_before, "fail-stop register-key rejection preserves authority")

public_writers = (
    ("open enrollment", "/v1/enroll", public_enroll_body,
     public_enroll_b64),
    ("legacy invite redemption", "/v1/invites/redeem", legacy_body,
     legacy_b64),
    ("handshake redemption", "/v1/handshakes/redeem", handshake_body,
     handshake_b64),
)
for writer_label, writer_path, writer_body, writer_pub in public_writers:
    writer_before = identity_surface_snapshot()
    code, out = call(None, "POST", writer_path, writer_body)
    writer_after = identity_surface_snapshot()
    check(code == 503 and out.get("error") == "registration_fail_stop"
          and db_identity_owner(writer_pub) is None,
          "fail-stop blocks public %s identity writer" % writer_label,
          "%s %s owner=%r" % (code, out, db_identity_owner(writer_pub)))
    check(writer_after == writer_before,
          "fail-stop preserves every durable surface for %s" % writer_label,
          "before/after differ")

# Restart is the recovery boundary. A fresh CLI module must issue only the
# read-only status query, recover the exact retained seed, and publish local
# key+config without repeating register-key.
stop_inprocess_relay()
start_relay()
reconcile_cli = fresh_cli_module("reconcile_503")
reconcile_calls = []
reconcile_req = reconcile_cli.req


def record_reconcile_req(*args, **kwargs):
    reconcile_calls.append((args[1], args[2]))
    return reconcile_req(*args, **kwargs)


old_use_curl = os.environ.get("CLACK_USE_CURL")
os.environ["CLACK_USE_CURL"] = "0"
reconcile_cli.req = record_reconcile_req
try:
    uncertain_cfg = reconcile_cli.load_config(uncertain_cfgp)
    reconcile_rc = reconcile_cli.cmd_register_key(
        direct_cli_args(uncertain_cfgp, peer="uncertainpeer",
                        key_path=uncertain_keyp),
        uncertain_cfg,
    )
finally:
    if old_use_curl is None:
        os.environ.pop("CLACK_USE_CURL", None)
    else:
        os.environ["CLACK_USE_CURL"] = old_use_curl
with open(uncertain_cfgp, encoding="utf-8") as f:
    uncertain_published_cfg = json.load(f)
with open(uncertain_keyp, "rb") as f:
    uncertain_published_seed = b64u_decode(f.read().strip().decode("ascii"))
check(reconcile_rc == 0
      and reconcile_calls == [("GET", "/v1/register-key/status")]
      and not os.path.lexists(uncertain_pending),
      "restart reconciliation publishes without retrying register-key",
      "rc=%r calls=%r pending=%r" % (
          reconcile_rc, reconcile_calls, os.path.lexists(uncertain_pending)))
check(uncertain_published_cfg.get("identity_pubkey") == uncertain_candidate
      and b64u_encode(reconcile_cli._publickey(uncertain_published_seed))
          == uncertain_candidate
      and (os.stat(uncertain_cfgp).st_mode & 0o777) == 0o600
      and (os.stat(uncertain_keyp).st_mode & 0o777) == 0o600,
      "restart reconciliation publishes exact candidate with private modes")
check(db_peer_key("uncertainpeer") == uncertain_candidate
      and config_pubkeys().get("uncertainpeer") == uncertain_candidate,
      "restart reconciles 503 server state without DB/config split")

# The same requests rejected above now succeed, proving each fixture was
# mutation-capable and that restart, rather than a malformed body, was the
# boundary blocking the identity writers.
for writer_label, writer_path, writer_body, writer_pub in public_writers:
    code, out = call(None, "POST", writer_path, writer_body)
    check(code == 200 and db_identity_owner(writer_pub) is not None,
          "post-restart positive control mutates %s" % writer_label,
          "%s %s owner=%r" % (code, out, db_identity_owner(writer_pub)))

check(db_peer_key("tokpeer") == winner_b64
      and config_pubkeys().get("tokpeer") == winner_b64,
      "all compensated tokpeer faults survive restart unchanged")

# ------------------------------------------------- phase 4: PEM normalization
print("== phase 4: PEM ==", flush=True)
seed_c, pub_c, b64_c = fresh_key("tokpeer_c")
pem_c = pem_of_spki(pub_c)
code, out = call(TOKPEER_TOKEN, "POST", "/v1/register-key",
                 {"pubkey": pem_c}, peer="tokpeer")
check(code == 200 and out.get("registered") is True
      and out.get("rotated") is True
      and out.get("identity_pubkey") == b64_c,
      "PEM SPKI response echoes canonical raw b64u",
      "%s %s" % (code, out))
check(db_peer_key("tokpeer") == b64_c,
      "PEM normalized to canonical raw b64u in DB", db_peer_key("tokpeer"))
KEYS["tokpeer"] = (seed_c, pub_c, b64_c)
code, _ = call(TOKPEER_TOKEN, "GET", "/v1/peers", peer="tokpeer")
check(code == 200, "PEM-registered key verifies", "%s" % code)

# ------------------------------------------------- phase 5: config persistence
print("== phase 5: persistence ==", flush=True)
check(config_pubkeys().get("tokpeer") == b64_c,
      "relay-config.json persisted identity_pubkeys.tokpeer")

# restart: config-managed peer rows are rebuilt from config -- the key
# must survive.
stop_relay()
start_relay()
check(db_peer_key("tokpeer") == b64_c,
      "authorized new key survives restart via config re-read")
code, _ = call(TOKPEER_TOKEN, "GET", "/v1/peers", peer="tokpeer")
check(code == 200, "signed request works after restart", "%s" % code)

# ------------------------------------------------- phase 6: redeem with pubkey
print("== phase 6: redeem-with-pubkey ==", flush=True)


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

# ------------------------------------------------- phase 7: CLI register-key
print("== phase 7: CLI register-key ==", flush=True)
clid = tempfile.mkdtemp(prefix="clack-cli-regkey-")
cfgp = os.path.join(clid, "cli.json")
with open(cfgp, "w") as f:
    json.dump({"peers": {"clipeer": CLIPEER_TOKEN}, "base_url": BASE,
               "relay_identity_fingerprint":
               _rc.relay_identity_fingerprint(IDKEY)}, f)
r = subprocess.run(
    [sys.executable, CLI, "--config", cfgp, "--peer", "clipeer",
     "register-key", "--key-path", os.path.join(clid, "cli.key")],
    capture_output=True, text=True, timeout=60,
    env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1", CLACK_USE_CURL="0"))
check(r.returncode == 0 and "registered signing key" in r.stdout,
      "CLI register-key exit 0", r.stderr[-200:] + r.stdout[-200:])
cfg = json.load(open(cfgp))
check(cfg.get("kind") == "clack-identity-v1"
      and cfg.get("peer_name") == "clipeer"
      and cfg.get("identity_pubkey"),
      "CLI converted legacy config to identity config with pubkey")
check((os.stat(cfg["identity_privkey_path"]).st_mode & 0o777) == 0o600
      and (os.stat(cfgp).st_mode & 0o777) == 0o600,
      "CLI private key and config modes are 0600")
check(db_peer_key("clipeer") == cfg["identity_pubkey"],
      "CLI-registered key in relay DB")

# Re-running the CLI exercises the existing-key path. req() must naturally
# sign the same-key registration with the current private key.
r2 = subprocess.run(
    [sys.executable, CLI, "--config", cfgp, "register-key"],
    capture_output=True, text=True, timeout=60,
    env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1", CLACK_USE_CURL="0"))
check(r2.returncode == 0 and "registered signing key" in r2.stdout
      and "(rotated)" not in r2.stdout,
      "CLI signs existing-key same-key re-registration",
      r2.stderr[-200:] + r2.stdout[-200:])
check(db_peer_key("clipeer") == cfg["identity_pubkey"],
      "CLI re-registration preserves current relay key")

# A malformed non-NULL runtime key is not an established signing authority.
# Bearer bootstrap must recover it, and the response semantics must describe
# bootstrap (rotated=false) while echoing the exact accepted candidate.
con = sqlite3.connect(os.path.join(TMPD, "relay.db"))
try:
    con.execute(
        "UPDATE peers SET identity_pubkey=? WHERE name=?",
        ("invalid-runtime-key", "invalidpeer"),
    )
    con.commit()
finally:
    con.close()
invalid_dir = tempfile.mkdtemp(prefix="clack-cli-invalid-runtime-")
invalid_cfgp = os.path.join(invalid_dir, "legacy.json")
invalid_keyp = os.path.join(invalid_dir, "identity.key")
invalid_legacy_cfg = {
    "peers": {"invalidpeer": INVALIDPEER_TOKEN},
    "base_url": BASE,
    "relay_identity_fingerprint": _rc.relay_identity_fingerprint(IDKEY),
}
with open(invalid_cfgp, "w", encoding="utf-8") as f:
    json.dump(invalid_legacy_cfg, f)
invalid_responses = []
original_cli_req = _rc.req


def capture_invalid_runtime_response(*args, **kwargs):
    result = original_cli_req(*args, **kwargs)
    invalid_responses.append((args[1], args[2], result))
    return result


old_use_curl = os.environ.get("CLACK_USE_CURL")
os.environ["CLACK_USE_CURL"] = "0"
_rc.req = capture_invalid_runtime_response
try:
    invalid_rc = _rc.cmd_register_key(
        direct_cli_args(invalid_cfgp, peer="invalidpeer",
                        key_path=invalid_keyp),
        dict(invalid_legacy_cfg),
    )
finally:
    _rc.req = original_cli_req
    if old_use_curl is None:
        os.environ.pop("CLACK_USE_CURL", None)
    else:
        os.environ["CLACK_USE_CURL"] = old_use_curl
with open(invalid_cfgp, encoding="utf-8") as f:
    invalid_identity_cfg = json.load(f)
invalid_response = invalid_responses[0][2] if invalid_responses else (None, {})
check(invalid_rc == 0 and len(invalid_responses) == 1
      and invalid_response[0] == 200
      and invalid_response[1].get("registered") is True
      and invalid_response[1].get("rotated") is False
      and invalid_response[1].get("peer") == "invalidpeer"
      and invalid_response[1].get("identity_pubkey")
          == invalid_identity_cfg.get("identity_pubkey"),
      "invalid-runtime bearer bootstrap accepts and echoes exact candidate",
      "rc=%r responses=%r cfg=%r" % (
          invalid_rc, invalid_responses, invalid_identity_cfg))
check(db_peer_key("invalidpeer") == invalid_identity_cfg.get("identity_pubkey")
      and config_pubkeys().get("invalidpeer")
          == invalid_identity_cfg.get("identity_pubkey"),
      "invalid-runtime bootstrap converges DB and config")

# Simulate a dropped 200 after the real relay has committed. The client sees an
# unknown transport outcome, sends exactly once, and retains the exact seed.
# A fresh module (process-restart model) reconciles with one GET and no POST.
drop_dir = tempfile.mkdtemp(prefix="clack-cli-lost-200-")
drop_cfgp = os.path.join(drop_dir, "legacy.json")
drop_keyp = os.path.join(drop_dir, "identity.key")
drop_pending = drop_cfgp + ".register-key.pending"
drop_legacy_cfg = {
    "peers": {"droppeer": DROPPEER_TOKEN},
    "base_url": BASE,
    "relay_identity_fingerprint": _rc.relay_identity_fingerprint(IDKEY),
}
with open(drop_cfgp, "w", encoding="utf-8") as f:
    json.dump(drop_legacy_cfg, f)
drop_dispatches = []


def lose_success_response(*args, **kwargs):
    result = original_cli_req(*args, **kwargs)
    drop_dispatches.append((args[1], args[2], result[0]))
    if args[1:3] == ("POST", "/v1/register-key") and result[0] == 200:
        raise _rc.UnknownMutationOutcome("injected lost 200 after commit")
    return result


old_use_curl = os.environ.get("CLACK_USE_CURL")
os.environ["CLACK_USE_CURL"] = "0"
_rc.req = lose_success_response
try:
    drop_rc = _rc.cmd_register_key(
        direct_cli_args(drop_cfgp, peer="droppeer", key_path=drop_keyp),
        dict(drop_legacy_cfg),
    )
finally:
    _rc.req = original_cli_req
    if old_use_curl is None:
        os.environ.pop("CLACK_USE_CURL", None)
    else:
        os.environ["CLACK_USE_CURL"] = old_use_curl
drop_journal = _rc._load_register_key_journal(drop_pending, drop_cfgp)
drop_candidate = drop_journal["identity_pubkey"]
check(drop_rc == 1
      and drop_dispatches == [("POST", "/v1/register-key", 200)]
      and drop_journal.get("phase") == "requesting"
      and db_peer_key("droppeer") == drop_candidate
      and config_pubkeys().get("droppeer") == drop_candidate,
      "lost 200 dispatches once and retains the accepted exact candidate",
      "rc=%r dispatches=%r journal=%r" % (
          drop_rc, drop_dispatches, drop_journal))
check((os.stat(drop_pending).st_mode & 0o777) == 0o600
      and b64u_encode(_rc._publickey(
          b64u_decode(drop_journal["identity_seed"]))) == drop_candidate
      and not os.path.lexists(drop_keyp),
      "lost-200 pending journal alone remains recovery-capable")

drop_restart_cli = fresh_cli_module("lost_200_restart")
drop_restart_req = drop_restart_cli.req
drop_reconcile_calls = []


def capture_drop_reconcile(*args, **kwargs):
    drop_reconcile_calls.append((args[1], args[2]))
    return drop_restart_req(*args, **kwargs)


old_use_curl = os.environ.get("CLACK_USE_CURL")
os.environ["CLACK_USE_CURL"] = "0"
drop_restart_cli.req = capture_drop_reconcile
try:
    drop_reconcile_rc = drop_restart_cli.cmd_register_key(
        direct_cli_args(drop_cfgp, peer="droppeer", key_path=drop_keyp),
        drop_restart_cli.load_config(drop_cfgp),
    )
finally:
    if old_use_curl is None:
        os.environ.pop("CLACK_USE_CURL", None)
    else:
        os.environ["CLACK_USE_CURL"] = old_use_curl
with open(drop_cfgp, encoding="utf-8") as f:
    drop_identity_cfg = json.load(f)
with open(drop_keyp, "rb") as f:
    drop_seed = b64u_decode(f.read().strip().decode("ascii"))
check(drop_reconcile_rc == 0
      and drop_reconcile_calls == [("GET", "/v1/register-key/status")]
      and not os.path.lexists(drop_pending),
      "lost-200 restart reconciles without a second POST",
      "rc=%r calls=%r" % (drop_reconcile_rc, drop_reconcile_calls))
check(drop_identity_cfg.get("identity_pubkey") == drop_candidate
      and b64u_encode(drop_restart_cli._publickey(drop_seed)) == drop_candidate,
      "lost-200 restart publishes the exact retained candidate")


def local_tree_snapshot(root):
    snap = {}
    for parent, dirs, files in os.walk(root):
        dirs.sort()
        for name in sorted(files):
            path = os.path.join(parent, name)
            rel = os.path.relpath(path, root)
            with open(path, "rb") as f:
                data = f.read()
            snap[rel] = (os.stat(path).st_mode & 0o777, data)
    return snap


def local_snapshot_bytes(snapshot):
    return {name: value[1] for name, value in snapshot.items()}


# Existing identity: configured public key must be derived from the seed. A
# mismatch is rejected before req(). Existing private artifacts are still
# corrected from 0644 to 0600 and fsynced; their content is unchanged.
mismatch_dir = tempfile.mkdtemp(prefix="clack-cli-mismatch-")
mismatch_cfgp = os.path.join(mismatch_dir, "identity.json")
mismatch_keyp = os.path.join(mismatch_dir, "identity.key")
mismatch_seed, mismatch_pub = _rc.keygen()
_, other_pub = _rc.keygen()
with open(mismatch_keyp, "w", encoding="utf-8") as f:
    f.write(b64u_encode(mismatch_seed) + "\n")
os.chmod(mismatch_keyp, 0o644)
mismatch_cfg = {
    "kind": _rc.IDENTITY_KIND,
    "relay_url": BASE,
    "peer_name": "mismatch-peer",
    "service_token": "local-test-token",
    "identity_pubkey": b64u_encode(other_pub),
    "identity_privkey_path": mismatch_keyp,
}
with open(mismatch_cfgp, "w", encoding="utf-8") as f:
    json.dump(mismatch_cfg, f)
os.chmod(mismatch_cfgp, 0o644)
network_calls = []
original_cli_req = _rc.req
_rc.req = lambda *a, **k: network_calls.append((a, k)) or (599, {})
before_local = local_tree_snapshot(mismatch_dir)
try:
    direct_rc = _rc.cmd_register_key(direct_cli_args(mismatch_cfgp),
                                     dict(mismatch_cfg))
finally:
    _rc.req = original_cli_req
check(direct_rc == 1 and not network_calls,
      "CLI seed/pubkey mismatch fails before network")
mismatch_after = local_tree_snapshot(mismatch_dir)
check(local_snapshot_bytes(mismatch_after) == local_snapshot_bytes(before_local)
      and all(mode == 0o600 for mode, _data in mismatch_after.values()),
      "CLI mismatch preserves bytes and corrects private modes to 0600")

# Missing and malformed seeds on an existing identity must not be replaced.
for case_name, key_payload in (("missing", None), ("malformed", b"not-a-seed\n")):
    case_dir = tempfile.mkdtemp(prefix="clack-cli-%s-seed-" % case_name)
    case_cfgp = os.path.join(case_dir, "identity.json")
    case_keyp = os.path.join(case_dir, "identity.key")
    seed, pub = _rc.keygen()
    case_cfg = {
        "kind": _rc.IDENTITY_KIND,
        "relay_url": BASE,
        "peer_name": "seed-%s-peer" % case_name,
        "service_token": "local-test-token",
        "identity_pubkey": b64u_encode(pub),
        "identity_privkey_path": case_keyp,
    }
    with open(case_cfgp, "w", encoding="utf-8") as f:
        json.dump(case_cfg, f)
    os.chmod(case_cfgp, 0o644)
    if key_payload is not None:
        with open(case_keyp, "wb") as f:
            f.write(key_payload)
        os.chmod(case_keyp, 0o644)
    before_local = local_tree_snapshot(case_dir)
    network_calls = []
    _rc.req = lambda *a, **k: network_calls.append((a, k)) or (599, {})
    try:
        direct_rc = _rc.cmd_register_key(direct_cli_args(case_cfgp),
                                         dict(case_cfg))
    finally:
        _rc.req = original_cli_req
    check(direct_rc == 1 and not network_calls,
          "CLI existing identity with %s seed fails before network" % case_name)
    case_after = local_tree_snapshot(case_dir)
    check(local_snapshot_bytes(case_after) == local_snapshot_bytes(before_local)
          and all(mode == 0o600 for mode, _data in case_after.values()),
          "CLI existing identity with %s seed preserves bytes and corrects modes"
          % case_name)

# A 200 is not acceptance unless it binds registered=true, the requested peer,
# and the exact canonical candidate. A mismatched response key retains the
# recovery journal and publishes neither key nor identity config.
mismatch_response_dir = tempfile.mkdtemp(prefix="clack-cli-response-mismatch-")
mismatch_response_cfgp = os.path.join(mismatch_response_dir, "legacy.json")
mismatch_response_keyp = os.path.join(mismatch_response_dir, "identity.key")
mismatch_response_pending = mismatch_response_cfgp + ".register-key.pending"
mismatch_response_cfg = {
    "peers": {"response-peer": "local-test-token"},
    "base_url": BASE,
    "relay_identity_fingerprint": _rc.relay_identity_fingerprint(IDKEY),
}
with open(mismatch_response_cfgp, "w", encoding="utf-8") as f:
    json.dump(mismatch_response_cfg, f)
os.chmod(mismatch_response_cfgp, 0o600)
with open(mismatch_response_cfgp, "rb") as f:
    mismatch_response_base = f.read()
_, wrong_response_pub = _rc.keygen()
wrong_response_b64 = b64u_encode(wrong_response_pub)
mismatch_response_calls = []


def mismatched_acceptance(*args, **kwargs):
    mismatch_response_calls.append((args[1], args[2], args[3]))
    return 200, {
        "registered": True,
        "peer": "response-peer",
        "rotated": False,
        "identity_pubkey": wrong_response_b64,
    }


_rc.req = mismatched_acceptance
try:
    mismatch_response_rc = _rc.cmd_register_key(
        direct_cli_args(mismatch_response_cfgp, peer="response-peer",
                        key_path=mismatch_response_keyp),
        dict(mismatch_response_cfg),
    )
finally:
    _rc.req = original_cli_req
mismatch_response_journal = _rc._load_register_key_journal(
    mismatch_response_pending, mismatch_response_cfgp)
sent_candidate = mismatch_response_calls[0][2]["pubkey"]
check(mismatch_response_rc == 1 and len(mismatch_response_calls) == 1
      and sent_candidate == mismatch_response_journal["identity_pubkey"]
      and sent_candidate != wrong_response_b64,
      "CLI rejects 200 whose echoed key differs from the candidate",
      "rc=%r calls=%r" % (
          mismatch_response_rc, mismatch_response_calls))
with open(mismatch_response_cfgp, "rb") as f:
    mismatch_response_after = f.read()
check(mismatch_response_after == mismatch_response_base
      and not os.path.lexists(mismatch_response_keyp)
      and os.path.lexists(mismatch_response_pending)
      and (os.stat(mismatch_response_pending).st_mode & 0o777) == 0o600,
      "response-key mismatch retains exact pending candidate only")

# A definite rejection is safe to retire only after status proves the exact
# candidate is not current. Preserve it in a mode-0600 quarantine for operator
# inspection rather than deleting the only recovery seed.
reject_dir = tempfile.mkdtemp(prefix="clack-cli-definite-reject-")
reject_cfgp = os.path.join(reject_dir, "legacy.json")
reject_keyp = os.path.join(reject_dir, "identity.key")
reject_pending = reject_cfgp + ".register-key.pending"
reject_cfg = {
    "peers": {"reject-peer": "local-test-token"},
    "base_url": BASE,
    "relay_identity_fingerprint": _rc.relay_identity_fingerprint(IDKEY),
}
with open(reject_cfgp, "w", encoding="utf-8") as f:
    json.dump(reject_cfg, f)
os.chmod(reject_cfgp, 0o600)
with open(reject_cfgp, "rb") as f:
    reject_base = f.read()
reject_calls = []
reject_candidate = {"value": None}


def definite_rejection(*args, **kwargs):
    method, path = args[1], args[2]
    reject_calls.append((method, path))
    if method == "POST":
        reject_candidate["value"] = args[3]["pubkey"]
        return 401, {"error": "bad_signature"}
    return 200, {
        "registered": False,
        "peer": "reject-peer",
        "identity_pubkey": None,
    }


_rc.req = definite_rejection
try:
    reject_rc = _rc.cmd_register_key(
        direct_cli_args(reject_cfgp, peer="reject-peer", key_path=reject_keyp),
        dict(reject_cfg),
    )
finally:
    _rc.req = original_cli_req
rejected_names = [
    name for name in os.listdir(reject_dir)
    if name.startswith(os.path.basename(reject_pending) + ".rejected-")
]
rejected_path = (os.path.join(reject_dir, rejected_names[0])
                 if len(rejected_names) == 1 else None)
rejected_journal = (
    _rc._load_register_key_journal(rejected_path, reject_cfgp)
    if rejected_path else {})
with open(reject_cfgp, "rb") as f:
    reject_after = f.read()
check(reject_rc == 1
      and reject_calls == [
          ("POST", "/v1/register-key"),
          ("GET", "/v1/register-key/status"),
      ]
      and not os.path.lexists(reject_pending)
      and len(rejected_names) == 1,
      "definite rejection quarantines only after absent status proof",
      "rc=%r calls=%r names=%r" % (reject_rc, reject_calls, rejected_names))
check(rejected_journal.get("identity_pubkey") == reject_candidate["value"]
      and b64u_encode(_rc._publickey(
          b64u_decode(rejected_journal.get("identity_seed", ""))))
          == reject_candidate["value"]
      and (os.stat(rejected_path).st_mode & 0o777) == 0o600
      and reject_after == reject_base
      and not os.path.lexists(reject_keyp),
      "quarantine retains exact rejected candidate without publishing it")

# Unsafe config/key/pending destinations are rejected before any network call.
# This covers lexical aliases, hardlink aliases, symlinks, directories, and a
# FIFO as a representative non-regular file. No test opens the FIFO.
path_safety_cases = (
    "same-file-alias",
    "hardlink-alias",
    "key-symlink",
    "key-directory",
    "key-fifo",
    "config-symlink",
    "config-directory",
    "config-fifo",
    "pending-symlink",
    "pending-directory",
    "pending-fifo",
)
for safety_case in path_safety_cases:
    safety_dir = tempfile.mkdtemp(prefix="clack-cli-path-%s-" % safety_case)
    safety_cfg = {
        "peers": {"path-peer": "local-test-token"},
        "base_url": BASE,
        "relay_identity_fingerprint": _rc.relay_identity_fingerprint(IDKEY),
    }
    safety_real_cfgp = os.path.join(safety_dir, "real-config.json")
    with open(safety_real_cfgp, "w", encoding="utf-8") as f:
        json.dump(safety_cfg, f)
    os.chmod(safety_real_cfgp, 0o600)
    safety_cfgp = safety_real_cfgp
    safety_keyp = os.path.join(safety_dir, "identity.key")
    safety_pending = safety_cfgp + ".register-key.pending"
    if safety_case == "same-file-alias":
        safety_keyp = safety_cfgp
    elif safety_case == "hardlink-alias":
        os.link(safety_cfgp, safety_keyp)
    elif safety_case == "key-symlink":
        target = os.path.join(safety_dir, "key-target")
        with open(target, "wb") as f:
            f.write(b"unchanged-target\n")
        os.chmod(target, 0o600)
        os.symlink(target, safety_keyp)
    elif safety_case == "key-directory":
        os.mkdir(safety_keyp)
    elif safety_case == "key-fifo":
        os.mkfifo(safety_keyp, 0o600)
    elif safety_case.startswith("config-"):
        safety_cfgp = os.path.join(safety_dir, "unsafe-config.json")
        safety_pending = safety_cfgp + ".register-key.pending"
        if safety_case == "config-symlink":
            os.symlink(safety_real_cfgp, safety_cfgp)
        elif safety_case == "config-directory":
            os.mkdir(safety_cfgp)
        else:
            os.mkfifo(safety_cfgp, 0o600)
    elif safety_case.startswith("pending-"):
        if safety_case == "pending-symlink":
            pending_target = os.path.join(safety_dir, "pending-target")
            with open(pending_target, "wb") as f:
                f.write(b"unchanged-pending-target\n")
            os.chmod(pending_target, 0o600)
            os.symlink(pending_target, safety_pending)
        elif safety_case == "pending-directory":
            os.mkdir(safety_pending)
        else:
            os.mkfifo(safety_pending, 0o600)
    with open(safety_real_cfgp, "rb") as f:
        safety_before = f.read()
    safety_network = []
    _rc.req = lambda *a, **k: safety_network.append((a, k)) or (599, {})
    try:
        safety_rc = _rc.cmd_register_key(
            direct_cli_args(safety_cfgp, peer="path-peer",
                            key_path=safety_keyp),
            dict(safety_cfg),
        )
    finally:
        _rc.req = original_cli_req
    with open(safety_real_cfgp, "rb") as f:
        safety_after = f.read()
    check(safety_rc == 1 and not safety_network
          and safety_after == safety_before,
          "unsafe %s destination rejected before network" % safety_case,
          "rc=%r network=%r" % (safety_rc, safety_network))

# Existing 0644 private artifacts are corrected to 0600 and fsynced. A valid
# exact response is accepted even if its informational rotated flag is true;
# candidate equality, peer, registered=true, and boolean shape are authoritative.
mode_dir = tempfile.mkdtemp(prefix="clack-cli-mode-correction-")
mode_cfgp = os.path.join(mode_dir, "legacy.json")
mode_keyp = os.path.join(mode_dir, "identity.key")
mode_pending = mode_cfgp + ".register-key.pending"
mode_cfg = {
    "peers": {"mode-peer": "local-test-token"},
    "base_url": BASE,
    "relay_identity_fingerprint": _rc.relay_identity_fingerprint(IDKEY),
}
with open(mode_cfgp, "w", encoding="utf-8") as f:
    json.dump(mode_cfg, f)
old_mode_seed, _old_mode_pub = _rc.keygen()
with open(mode_keyp, "w", encoding="ascii") as f:
    f.write(b64u_encode(old_mode_seed) + "\n")
os.chmod(mode_cfgp, 0o644)
os.chmod(mode_keyp, 0o644)
mode_calls = []
mode_candidate = {"value": None}


def accept_mode_candidate(*args, **kwargs):
    mode_calls.append((args[1], args[2]))
    candidate = args[3]["pubkey"]
    mode_candidate["value"] = candidate
    return 200, {
        "registered": True,
        "peer": "mode-peer",
        "rotated": True,
        "identity_pubkey": candidate,
    }


_rc.req = accept_mode_candidate
try:
    mode_rc = _rc.cmd_register_key(
        direct_cli_args(mode_cfgp, peer="mode-peer", key_path=mode_keyp),
        dict(mode_cfg),
    )
finally:
    _rc.req = original_cli_req
with open(mode_cfgp, encoding="utf-8") as f:
    mode_identity_cfg = json.load(f)
with open(mode_keyp, "rb") as f:
    mode_seed = b64u_decode(f.read().strip().decode("ascii"))
check(mode_rc == 0 and mode_calls == [("POST", "/v1/register-key")]
      and mode_identity_cfg.get("identity_pubkey") == mode_candidate["value"]
      and b64u_encode(_rc._publickey(mode_seed)) == mode_candidate["value"],
      "exact acceptance publishes candidate independent of rotated value",
      "rc=%r calls=%r" % (mode_rc, mode_calls))
check((os.stat(mode_cfgp).st_mode & 0o777) == 0o600
      and (os.stat(mode_keyp).st_mode & 0o777) == 0o600
      and not os.path.lexists(mode_pending),
      "accepted existing 0644 artifacts are durably corrected to 0600")

# After server acceptance, inject a fault at every journal/key/config staging,
# file-fsync, replace, post-replace, and directory-fsync boundary. Every case
# must leave the old or exact new artifact (never torn bytes), plus a mode-0600
# recovery journal holding the only accepted seed. A fresh module then performs
# one status GET and completes publication without a second POST.
publication_boundaries = []
for publication_label in ("key", "config"):
    for publication_boundary in (
            "before_stage_open", "after_stage_write", "before_file_fsync",
            "before_replace", "after_replace", "before_dir_fsync"):
        publication_boundaries.append(
            (publication_label + ":" + publication_boundary, 1))
for publication_boundary in (
        "before_stage_open", "after_stage_write", "before_file_fsync",
        "before_replace", "after_replace", "before_dir_fsync"):
    # prepared, requesting, then accepted: fail the third journal publication.
    publication_boundaries.append(("journal:" + publication_boundary, 3))

for boundary_index, (boundary_event, boundary_ordinal) in enumerate(
        publication_boundaries):
    boundary_dir = tempfile.mkdtemp(
        prefix="clack-cli-publish-%02d-" % boundary_index)
    boundary_cfgp = os.path.join(boundary_dir, "legacy.json")
    boundary_keyp = os.path.join(boundary_dir, "identity.key")
    boundary_pending = boundary_cfgp + ".register-key.pending"
    boundary_peer = "fault-peer-%02d" % boundary_index
    boundary_cfg = {
        "peers": {boundary_peer: "local-test-token"},
        "base_url": BASE,
        "relay_identity_fingerprint": _rc.relay_identity_fingerprint(IDKEY),
    }
    with open(boundary_cfgp, "w", encoding="utf-8") as f:
        json.dump(boundary_cfg, f)
    os.chmod(boundary_cfgp, 0o600)
    old_boundary_seed, _old_boundary_pub = _rc.keygen()
    old_boundary_key_bytes = (
        b64u_encode(old_boundary_seed) + "\n").encode("ascii")
    with open(boundary_keyp, "wb") as f:
        f.write(old_boundary_key_bytes)
    os.chmod(boundary_keyp, 0o600)
    with open(boundary_cfgp, "rb") as f:
        old_boundary_config_bytes = f.read()
    boundary_counts = {"seen": 0}
    boundary_calls = []
    accepted_server_key = {"value": None}

    def fail_publication_boundary(event, expected=boundary_event,
                                  ordinal=boundary_ordinal):
        if event == expected:
            boundary_counts["seen"] += 1
            if boundary_counts["seen"] == ordinal:
                raise OSError("injected local publication fault at " + event)

    def accept_boundary_candidate(*args, **kwargs):
        boundary_calls.append((args[1], args[2]))
        candidate = args[3]["pubkey"]
        accepted_server_key["value"] = candidate
        return 200, {
            "registered": True,
            "peer": boundary_peer,
            "rotated": False,
            "identity_pubkey": candidate,
        }

    _rc._LOCAL_PUBLICATION_HOOK = fail_publication_boundary
    _rc.req = accept_boundary_candidate
    try:
        boundary_rc = _rc.cmd_register_key(
            direct_cli_args(boundary_cfgp, peer=boundary_peer,
                            key_path=boundary_keyp),
            dict(boundary_cfg),
        )
    finally:
        _rc.req = original_cli_req
        _rc._LOCAL_PUBLICATION_HOOK = None
    boundary_journal = _rc._load_register_key_journal(
        boundary_pending, boundary_cfgp)
    boundary_candidate = boundary_journal["identity_pubkey"]
    boundary_target_config = _rc._blob_decode(
        boundary_journal["target_config_bytes"], "target_config_bytes")
    boundary_candidate_key = (
        boundary_journal["identity_seed"] + "\n").encode("ascii")
    with open(boundary_cfgp, "rb") as f:
        boundary_config_after_fault = f.read()
    with open(boundary_keyp, "rb") as f:
        boundary_key_after_fault = f.read()
    boundary_temps = [
        name for name in os.listdir(boundary_dir) if name.endswith(".tmp")
    ]
    check(boundary_rc == 1
          and boundary_counts["seen"] == boundary_ordinal
          and boundary_calls == [("POST", "/v1/register-key")]
          and accepted_server_key["value"] == boundary_candidate,
          "accepted-server fault reached %s exactly once" % boundary_event,
          "rc=%r seen=%r calls=%r" % (
              boundary_rc, boundary_counts, boundary_calls))
    check((os.stat(boundary_pending).st_mode & 0o777) == 0o600
          and b64u_encode(_rc._publickey(
              b64u_decode(boundary_journal["identity_seed"])))
              == boundary_candidate
          and boundary_config_after_fault in (
              old_boundary_config_bytes, boundary_target_config)
          and boundary_key_after_fault in (
              old_boundary_key_bytes, boundary_candidate_key)
          and not boundary_temps,
          "fault at %s preserves old/new atomic artifacts and exact seed"
          % boundary_event,
          "temps=%r config_len=%d key_len=%d" % (
              boundary_temps, len(boundary_config_after_fault),
              len(boundary_key_after_fault)))

    boundary_restart = fresh_cli_module(
        "publish_%02d_%s" % (
            boundary_index,
            boundary_event.replace(":", "_")))
    recovery_calls = []

    def boundary_status(*args, **kwargs):
        recovery_calls.append((args[1], args[2]))
        return 200, {
            "registered": True,
            "peer": boundary_peer,
            "identity_pubkey": boundary_candidate,
        }

    boundary_restart.req = boundary_status
    boundary_recovery_rc = boundary_restart.cmd_register_key(
        direct_cli_args(boundary_cfgp, peer=boundary_peer,
                        key_path=boundary_keyp),
        boundary_restart.load_config(boundary_cfgp),
    )
    with open(boundary_cfgp, "rb") as f:
        recovered_config_bytes = f.read()
    with open(boundary_keyp, "rb") as f:
        recovered_key_bytes = f.read()
    check(boundary_recovery_rc == 0
          and recovery_calls == [("GET", "/v1/register-key/status")]
          and recovered_config_bytes == boundary_target_config
          and recovered_key_bytes == boundary_candidate_key
          and not os.path.lexists(boundary_pending)
          and (os.stat(boundary_cfgp).st_mode & 0o777) == 0o600
          and (os.stat(boundary_keyp).st_mode & 0o777) == 0o600,
          "restart recovers atomically after %s without POST" % boundary_event,
          "rc=%r calls=%r pending=%r" % (
              boundary_recovery_rc, recovery_calls,
              os.path.lexists(boundary_pending)))

# If journal retirement itself fails after exact artifact readback, phase
# "published" remains a safe restart marker. The next invocation retires it
# without any network request.
retire_dir = tempfile.mkdtemp(prefix="clack-cli-retire-fault-")
retire_cfgp = os.path.join(retire_dir, "legacy.json")
retire_keyp = os.path.join(retire_dir, "identity.key")
retire_pending = retire_cfgp + ".register-key.pending"
retire_cfg = {
    "peers": {"retire-peer": "local-test-token"},
    "base_url": BASE,
    "relay_identity_fingerprint": _rc.relay_identity_fingerprint(IDKEY),
}
with open(retire_cfgp, "w", encoding="utf-8") as f:
    json.dump(retire_cfg, f)
os.chmod(retire_cfgp, 0o600)
retire_candidate = {"value": None}


def accept_retire_candidate(*args, **kwargs):
    candidate = args[3]["pubkey"]
    retire_candidate["value"] = candidate
    return 200, {
        "registered": True,
        "peer": "retire-peer",
        "rotated": False,
        "identity_pubkey": candidate,
    }


def fail_journal_retire(event):
    if event == "journal:before_retire":
        raise OSError("injected journal retirement fault")


_rc.req = accept_retire_candidate
_rc._LOCAL_PUBLICATION_HOOK = fail_journal_retire
try:
    retire_rc = _rc.cmd_register_key(
        direct_cli_args(retire_cfgp, peer="retire-peer",
                        key_path=retire_keyp),
        dict(retire_cfg),
    )
finally:
    _rc.req = original_cli_req
    _rc._LOCAL_PUBLICATION_HOOK = None
retire_journal = _rc._load_register_key_journal(retire_pending, retire_cfgp)
check(retire_rc == 0 and retire_journal.get("phase") == "published"
      and retire_journal.get("identity_pubkey") == retire_candidate["value"],
      "retirement fault retains verified published journal",
      "rc=%r journal=%r" % (retire_rc, retire_journal))
retire_restart = fresh_cli_module("retire_restart")
retire_network = []
retire_restart.req = lambda *a, **k: retire_network.append((a, k)) or (599, {})
retire_restart_rc = retire_restart.cmd_register_key(
    direct_cli_args(retire_cfgp, peer="retire-peer", key_path=retire_keyp),
    retire_restart.load_config(retire_cfgp),
)
check(retire_restart_rc == 0 and not retire_network
      and not os.path.lexists(retire_pending),
      "published-journal restart retires locally with zero network calls",
      "rc=%r network=%r" % (retire_restart_rc, retire_network))

# Independent SPEC regressions: operation serialization, config CAS, TOFU
# ordering, and external hardlinks (including outside sibling aliases).
SPEC_PIN = _rc.relay_identity_fingerprint(IDKEY)


def spec_legacy_config(peer, token):
    return {
        "peers": {peer: token},
        "base_url": BASE,
        "relay_identity_fingerprint": SPEC_PIN,
    }


def atomic_operator_write(path, data):
    candidate = path + ".operator"
    with open(candidate, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(candidate, 0o600)
    os.replace(candidate, path)


# A is paused after dispatch. B is a separately loaded module and must fail
# before generation, status reconciliation, or publication. A then models a
# lost 200 and its potentially accepted seed must remain in the live journal.
serialize_dir = tempfile.mkdtemp(prefix="clack-cli-serialize-")
serialize_cfgp = os.path.join(serialize_dir, "legacy.json")
serialize_keyp = os.path.join(serialize_dir, "identity.key")
serialize_pending = serialize_cfgp + ".register-key.pending"
serialize_cfg = spec_legacy_config("serialize-peer", "serialize-token")
with open(serialize_cfgp, "w", encoding="utf-8") as f:
    json.dump(serialize_cfg, f)
os.chmod(serialize_cfgp, 0o600)
serialize_a = fresh_cli_module("serialize_a")
serialize_b = fresh_cli_module("serialize_b")
serialize_inflight = threading.Event()
serialize_release = threading.Event()
serialize_a_result = []
serialize_a_candidate = {"value": None}
serialize_b_calls = []
serialize_b_keygens = []
serialize_b_real_keygen = serialize_b.keygen


def serialize_a_req(*args, **kwargs):
    method, path, body = args[1], args[2], args[3]
    if (method, path) != ("POST", "/v1/register-key"):
        raise AssertionError("unexpected A request %s %s" % (method, path))
    serialize_a_candidate["value"] = body["pubkey"]
    serialize_inflight.set()
    if not serialize_release.wait(timeout=10):
        raise RuntimeError("serialization release timeout")
    raise serialize_a.UnknownMutationOutcome("synthetic accepted response loss")


def serialize_b_req(*args, **kwargs):
    method, path = args[1], args[2]
    serialize_b_calls.append((method, path))
    if (method, path) == ("GET", "/v1/register-key/status"):
        return 200, {
            "registered": True,
            "peer": "serialize-peer",
            "identity_pubkey": b64u_encode(b"x" * 32),
        }
    raise AssertionError("unexpected B request %s %s" % (method, path))


def serialize_b_keygen():
    serialize_b_keygens.append(True)
    return serialize_b_real_keygen()


serialize_a.req = serialize_a_req
serialize_b.req = serialize_b_req
serialize_b.keygen = serialize_b_keygen
serialize_args = direct_cli_args(
    serialize_cfgp, peer="serialize-peer", key_path=serialize_keyp)
serialize_thread = threading.Thread(
    target=lambda: serialize_a_result.append(
        serialize_a.cmd_register_key(serialize_args, dict(serialize_cfg))),
    daemon=True,
)
serialize_thread.start()
serialize_ready = serialize_inflight.wait(timeout=10)
tofu_during_pending_blocked = False
tofu_during_pending_before = open(serialize_cfgp, "rb").read()
try:
    serialize_a._persist_tofu_pin(dict(serialize_cfg), SPEC_PIN)
except ValueError:
    tofu_during_pending_blocked = True
check(tofu_during_pending_blocked
      and open(serialize_cfgp, "rb").read() == tofu_during_pending_before,
      "active pending transaction blocks attempted TOFU config write")
serialize_b_rc = (serialize_b.cmd_register_key(serialize_args, dict(serialize_cfg))
                  if serialize_ready else 99)
serialize_release.set()
serialize_thread.join(timeout=10)
try:
    serialize_journal = serialize_a._load_register_key_journal(
        serialize_pending, serialize_cfgp)
except Exception:
    serialize_journal = {}
check(serialize_ready and not serialize_thread.is_alive(),
      "CLI operation lock reaches and releases A in-flight deterministically")
check(serialize_a_result == [1] and serialize_b_rc == 1,
      "CLI operation lock makes concurrent B fail closed",
      "A=%r B=%r" % (serialize_a_result, serialize_b_rc))
check(not serialize_b_calls and not serialize_b_keygens,
      "CLI operation lock blocks B network and candidate generation",
      "calls=%r keygens=%r" % (serialize_b_calls, serialize_b_keygens))
check(os.path.lexists(serialize_pending)
      and serialize_journal.get("identity_pubkey")
          == serialize_a_candidate["value"],
      "CLI operation lock preserves accepted A in canonical pending journal",
      "journal=%r candidate=%r" % (
          serialize_journal, serialize_a_candidate["value"]))
check(serialize_journal.get("identity_seed")
      and b64u_encode(serialize_a._publickey(
          b64u_decode(serialize_journal["identity_seed"])))
          == serialize_a_candidate["value"],
      "CLI operation lock keeps every potentially accepted seed recoverable")


# Repeat the attack with real OS processes. A is killed while its request is
# in flight, proving that exclusion lifetime follows the process-owned socket;
# a fresh module then reconciles A's durable, potentially accepted candidate.
proc_ctx = multiprocessing.get_context("fork")
proc_dir = tempfile.mkdtemp(prefix="clack-cli-process-lock-")
proc_cfgp = os.path.join(proc_dir, "legacy.json")
proc_keyp = os.path.join(proc_dir, "identity.key")
proc_pending = proc_cfgp + ".register-key.pending"
proc_peer = "process-lock-peer"
proc_cfg = spec_legacy_config(proc_peer, "process-lock-token")
with open(proc_cfgp, "w", encoding="utf-8") as f:
    json.dump(proc_cfg, f)
os.chmod(proc_cfgp, 0o600)
proc_started = proc_ctx.Event()
proc_hold = proc_ctx.Event()
proc_candidate_q = proc_ctx.Queue()
proc_result_q = proc_ctx.Queue()
proc_b_call_q = proc_ctx.Queue()


def process_lock_a():
    module = fresh_cli_module("process_lock_a")

    def request(*args, **kwargs):
        method, path, body = args[1], args[2], args[3]
        if (method, path) != ("POST", "/v1/register-key"):
            raise AssertionError("unexpected process A request")
        proc_candidate_q.put(body["pubkey"])
        proc_started.set()
        proc_hold.wait(timeout=60)
        raise module.UnknownMutationOutcome("synthetic accepted response loss")

    module.req = request
    rc = module.cmd_register_key(
        direct_cli_args(proc_cfgp, peer=proc_peer, key_path=proc_keyp),
        dict(proc_cfg),
    )
    proc_result_q.put(("a", rc))


def process_lock_b():
    module = fresh_cli_module("process_lock_b")

    def request(*args, **kwargs):
        proc_b_call_q.put((args[1], args[2]))
        return 404, {"error": "not_registered"}

    module.req = request
    rc = module.cmd_register_key(
        direct_cli_args(proc_cfgp, peer=proc_peer, key_path=proc_keyp),
        dict(proc_cfg),
    )
    proc_result_q.put(("b", rc))


proc_a = proc_ctx.Process(target=process_lock_a)
proc_a.start()
proc_ready = proc_started.wait(timeout=10)
proc_candidate = proc_candidate_q.get(timeout=10) if proc_ready else None
check(proc_ready and proc_candidate,
      "real process-lock control reaches A in-flight request")
proc_b = proc_ctx.Process(target=process_lock_b)
proc_b.start()
proc_b.join(timeout=10)
check(not proc_b.is_alive() and proc_b.exitcode == 0,
      "real process B terminates deterministically under contention",
      "alive=%r exit=%r" % (proc_b.is_alive(), proc_b.exitcode))
proc_b_result = proc_result_q.get(timeout=10)
check(proc_b_result == ("b", 1),
      "real process B fails closed while A owns operation lock",
      repr(proc_b_result))
try:
    proc_b_call = proc_b_call_q.get(timeout=0.25)
except queue.Empty:
    proc_b_call = None
check(proc_b_call is None,
      "real process B neither sends nor reconciles while A is in flight",
      repr(proc_b_call))
proc_a.terminate()
proc_a.join(timeout=10)
check(not proc_a.is_alive(),
      "operation-lock stale owner terminates for OS-lifetime release control")
proc_journal = json.loads(open(proc_pending, "rb").read().decode("utf-8"))
check(b64u_encode(serialize_a._publickey(
          b64u_decode(proc_journal["identity_seed"]))) == proc_candidate,
      "killed A candidate seed remains recoverable in durable journal")
proc_recover = fresh_cli_module("process_lock_recover")
proc_recover_calls = []


def process_recover_req(*args, **kwargs):
    method, path = args[1], args[2]
    proc_recover_calls.append((method, path))
    if (method, path) == ("GET", "/v1/register-key/status"):
        return 200, {
            "registered": True,
            "peer": proc_peer,
            "identity_pubkey": proc_candidate,
        }
    raise AssertionError("unexpected process recovery request")


proc_recover.req = process_recover_req
proc_recover_rc = proc_recover.cmd_register_key(
    direct_cli_args(proc_cfgp, peer=proc_peer, key_path=proc_keyp),
    dict(proc_cfg),
)
with open(proc_keyp, "rb") as f:
    proc_published_seed = f.read().strip()
check(proc_recover_rc == 0
      and proc_recover_calls == [("GET", "/v1/register-key/status")]
      and not os.path.lexists(proc_pending)
      and b64u_encode(proc_recover._publickey(
          b64u_decode(proc_published_seed.decode("ascii")))) == proc_candidate,
      "fresh process/module reconciles A after OS releases stale-owner lock",
      "rc=%r calls=%r pending=%r" % (
          proc_recover_rc, proc_recover_calls, os.path.lexists(proc_pending)))


# The event seam and the underlying rename/exchange seam each inject an
# operator replacement at the last publication boundary. The operator bytes
# must win, the key must remain unpublished, and restart must be deterministic.
def run_config_cas_race(label, syscall_level=False):
    race_dir = tempfile.mkdtemp(prefix="clack-cli-config-cas-%s-" % label)
    race_cfgp = os.path.join(race_dir, "legacy.json")
    race_keyp = os.path.join(race_dir, "identity.key")
    race_pending = race_cfgp + ".register-key.pending"
    race_peer = "config-cas-" + label
    race_cfg = spec_legacy_config(race_peer, "config-cas-token")
    with open(race_cfgp, "w", encoding="utf-8") as f:
        json.dump(race_cfg, f)
    os.chmod(race_cfgp, 0o600)
    with open(race_cfgp, "rb") as f:
        base_bytes = f.read()
    operator_cfg = dict(race_cfg)
    operator_cfg["operator_revoked"] = label
    operator_bytes = (json.dumps(operator_cfg, sort_keys=True) + "\n").encode()
    module = fresh_cli_module("config_cas_" + label)
    accepted = {"candidate": None}

    def accept_candidate(*args, **kwargs):
        method, path = args[1], args[2]
        if (method, path) == ("POST", "/v1/register-key"):
            candidate = args[3]["pubkey"]
            accepted["candidate"] = candidate
            return 200, {
                "registered": True,
                "peer": race_peer,
                "rotated": False,
                "identity_pubkey": candidate,
            }
        if (method, path) == ("GET", "/v1/register-key/status"):
            return 200, {
                "registered": True,
                "peer": race_peer,
                "identity_pubkey": accepted["candidate"],
            }
        raise AssertionError("unexpected config CAS request")

    module.req = accept_candidate
    injected = {"value": False}

    def inject_operator():
        if not injected["value"]:
            atomic_operator_write(race_cfgp, operator_bytes)
            injected["value"] = True

    if syscall_level:
        seam_name = ("_LOCAL_RENAME_EXCHANGE"
                     if hasattr(module, "_LOCAL_RENAME_EXCHANGE")
                     else "_LOCAL_REPLACE")
        real_seam = getattr(module, seam_name)

        def racing_seam(src, dst, *args, **kwargs):
            if os.path.abspath(dst) == os.path.abspath(race_cfgp):
                inject_operator()
            return real_seam(src, dst, *args, **kwargs)

        setattr(module, seam_name, racing_seam)
    else:
        def publication_hook(event):
            if event == "config:before_replace":
                inject_operator()

        module._LOCAL_PUBLICATION_HOOK = publication_hook

    first_rc = module.cmd_register_key(
        direct_cli_args(race_cfgp, peer=race_peer, key_path=race_keyp),
        dict(race_cfg),
    )
    with open(race_cfgp, "rb") as f:
        after_first = f.read()
    first_pending = os.path.lexists(race_pending)
    first_key_absent = not os.path.lexists(race_keyp)

    drift_rc = 99
    drift_exact = False
    reconcile_rc = 99
    if first_pending:
        drift_module = fresh_cli_module("config_cas_drift_" + label)
        drift_module.req = accept_candidate
        drift_rc = drift_module.cmd_register_key(
            direct_cli_args(race_cfgp, peer=race_peer, key_path=race_keyp),
            dict(operator_cfg),
        )
        with open(race_cfgp, "rb") as f:
            drift_exact = f.read() == operator_bytes
        atomic_operator_write(race_cfgp, base_bytes)
        restart_module = fresh_cli_module("config_cas_restart_" + label)
        restart_module.req = accept_candidate
        reconcile_rc = restart_module.cmd_register_key(
            direct_cli_args(race_cfgp, peer=race_peer, key_path=race_keyp),
            restart_module.load_config(race_cfgp),
        )
    return {
        "injected": injected["value"],
        "first_rc": first_rc,
        "operator_exact": after_first == operator_bytes,
        "key_absent": first_key_absent,
        "pending": first_pending,
        "drift_rc": drift_rc,
        "drift_exact": drift_exact,
        "reconcile_rc": reconcile_rc,
        "final_key": os.path.lexists(race_keyp),
        "final_pending": os.path.lexists(race_pending),
    }


for cas_label, syscall_level in (("event", False), ("syscall", True)):
    cas = run_config_cas_race(cas_label, syscall_level=syscall_level)
    check(cas["injected"], "config CAS %s race injected" % cas_label)
    check(cas["first_rc"] == 1 and cas["operator_exact"],
          "config CAS %s race preserves byte-exact operator config" % cas_label,
          repr(cas))
    check(cas["key_absent"] and cas["pending"],
          "config CAS %s race retains pending and publishes no key" % cas_label,
          repr(cas))
    check(cas["drift_rc"] == 1 and cas["drift_exact"],
          "config CAS %s drifted restart remains closed" % cas_label,
          repr(cas))
    check(cas["reconcile_rc"] == 0 and cas["final_key"]
          and not cas["final_pending"],
          "config CAS %s reconciles after byte-exact operator restore" % cas_label,
          repr(cas))


# A byte-identical operator replacement at the syscall seam must still be
# detected by inode identity. Because the operator bytes equal the journal
# baseline, restart may explicitly adopt that new inode and reconcile.
same_inode_dir = tempfile.mkdtemp(prefix="clack-cli-config-cas-inode-")
same_inode_cfgp = os.path.join(same_inode_dir, "legacy.json")
same_inode_keyp = os.path.join(same_inode_dir, "identity.key")
same_inode_pending = same_inode_cfgp + ".register-key.pending"
same_inode_peer = "config-cas-inode"
same_inode_cfg = spec_legacy_config(same_inode_peer, "config-cas-inode-token")
with open(same_inode_cfgp, "w", encoding="utf-8") as f:
    json.dump(same_inode_cfg, f)
os.chmod(same_inode_cfgp, 0o600)
with open(same_inode_cfgp, "rb") as f:
    same_inode_bytes = f.read()
same_inode_original = os.stat(same_inode_cfgp).st_ino
same_inode_module = fresh_cli_module("config_cas_inode")
same_inode_candidate = {"value": None}


def same_inode_req(*args, **kwargs):
    method, path = args[1], args[2]
    if (method, path) == ("POST", "/v1/register-key"):
        same_inode_candidate["value"] = args[3]["pubkey"]
        return 200, {
            "registered": True,
            "peer": same_inode_peer,
            "rotated": False,
            "identity_pubkey": same_inode_candidate["value"],
        }
    if (method, path) == ("GET", "/v1/register-key/status"):
        return 200, {
            "registered": True,
            "peer": same_inode_peer,
            "identity_pubkey": same_inode_candidate["value"],
        }
    raise AssertionError("unexpected byte-identical CAS request")


same_inode_module.req = same_inode_req
same_inode_real_exchange = same_inode_module._LOCAL_RENAME_EXCHANGE
same_inode_injected = {"value": False}


def same_inode_exchange(src, dst, *args, **kwargs):
    if (os.path.abspath(dst) == os.path.abspath(same_inode_cfgp)
            and not same_inode_injected["value"]):
        atomic_operator_write(same_inode_cfgp, same_inode_bytes)
        same_inode_injected["value"] = True
    return same_inode_real_exchange(src, dst, *args, **kwargs)


same_inode_module._LOCAL_RENAME_EXCHANGE = same_inode_exchange
same_inode_first_rc = same_inode_module.cmd_register_key(
    direct_cli_args(
        same_inode_cfgp, peer=same_inode_peer, key_path=same_inode_keyp),
    dict(same_inode_cfg),
)
same_inode_replaced = os.stat(same_inode_cfgp).st_ino
check(same_inode_injected["value"] and same_inode_first_rc == 1
      and same_inode_replaced != same_inode_original
      and open(same_inode_cfgp, "rb").read() == same_inode_bytes,
      "config CAS rejects byte-identical lower-level inode replacement")
check(os.path.lexists(same_inode_pending)
      and not os.path.lexists(same_inode_keyp),
      "byte-identical inode race retains pending and publishes no key")
same_inode_restart = fresh_cli_module("config_cas_inode_restart")
same_inode_restart.req = same_inode_req
same_inode_restart_rc = same_inode_restart.cmd_register_key(
    direct_cli_args(
        same_inode_cfgp, peer=same_inode_peer, key_path=same_inode_keyp),
    same_inode_restart.load_config(same_inode_cfgp),
)
check(same_inode_restart_rc == 0
      and os.path.lexists(same_inode_keyp)
      and not os.path.lexists(same_inode_pending),
      "byte-identical operator inode is adopted only on explicit restart")


# Simulate process death after a lower-level exchange raced an operator write,
# but before in-process compensation. The publishing journal and deterministic
# stage name must let restart put the operator inode back, retain the candidate,
# and later reconcile only after an explicit baseline restore.
crash_dir = tempfile.mkdtemp(prefix="clack-cli-config-crash-exchange-")
crash_cfgp = os.path.join(crash_dir, "legacy.json")
crash_keyp = os.path.join(crash_dir, "identity.key")
crash_pending = crash_cfgp + ".register-key.pending"
crash_peer = "config-crash-exchange"
crash_cfg = spec_legacy_config(crash_peer, "config-crash-token")
with open(crash_cfgp, "w", encoding="utf-8") as f:
    json.dump(crash_cfg, f)
os.chmod(crash_cfgp, 0o600)
crash_base_bytes = open(crash_cfgp, "rb").read()
crash_operator_cfg = dict(crash_cfg)
crash_operator_cfg["operator_revoked"] = "crash-window"
crash_operator_bytes = (json.dumps(
    crash_operator_cfg, sort_keys=True) + "\n").encode()
crash_module = fresh_cli_module("config_crash_exchange")
crash_candidate = {"value": None}


def crash_req(*args, **kwargs):
    method, path = args[1], args[2]
    if (method, path) == ("POST", "/v1/register-key"):
        crash_candidate["value"] = args[3]["pubkey"]
        return 200, {
            "registered": True,
            "peer": crash_peer,
            "rotated": False,
            "identity_pubkey": crash_candidate["value"],
        }
    if (method, path) == ("GET", "/v1/register-key/status"):
        return 200, {
            "registered": True,
            "peer": crash_peer,
            "identity_pubkey": crash_candidate["value"],
        }
    raise AssertionError("unexpected crash-window request")


crash_module.req = crash_req
crash_real_exchange = crash_module._LOCAL_RENAME_EXCHANGE
crash_injected = {"value": False}


def crash_exchange(src, dst, *args, **kwargs):
    if (os.path.abspath(dst) == os.path.abspath(crash_cfgp)
            and not crash_injected["value"]):
        atomic_operator_write(crash_cfgp, crash_operator_bytes)
        crash_injected["value"] = True
        crash_real_exchange(src, dst, *args, **kwargs)
        raise SystemExit("synthetic process death after exchange")
    return crash_real_exchange(src, dst, *args, **kwargs)


crash_module._LOCAL_RENAME_EXCHANGE = crash_exchange
try:
    crash_module.cmd_register_key(
        direct_cli_args(crash_cfgp, peer=crash_peer, key_path=crash_keyp),
        dict(crash_cfg),
    )
except SystemExit:
    crash_terminated = True
else:
    crash_terminated = False
crash_journal = json.loads(open(crash_pending, "rb").read().decode("utf-8"))
check(crash_terminated and crash_injected["value"]
      and crash_journal["phase"] == "publishing"
      and not os.path.lexists(crash_keyp),
      "exchange-window process death retains publishing journal and no key")
crash_restart = fresh_cli_module("config_crash_exchange_restart")
crash_restart.req = crash_req
crash_restart_rc = crash_restart.cmd_register_key(
    direct_cli_args(crash_cfgp, peer=crash_peer, key_path=crash_keyp),
    crash_restart.load_config(crash_cfgp),
)
check(crash_restart_rc == 1
      and open(crash_cfgp, "rb").read() == crash_operator_bytes
      and not os.path.lexists(crash_keyp)
      and os.path.lexists(crash_pending),
      "restart compensates interrupted exchange and restores operator config")
atomic_operator_write(crash_cfgp, crash_base_bytes)
crash_final = fresh_cli_module("config_crash_exchange_final")
crash_final.req = crash_req
crash_final_rc = crash_final.cmd_register_key(
    direct_cli_args(crash_cfgp, peer=crash_peer, key_path=crash_keyp),
    crash_final.load_config(crash_cfgp),
)
check(crash_final_rc == 0 and os.path.lexists(crash_keyp)
      and not os.path.lexists(crash_pending),
      "compensated exchange candidate reconciles after explicit restore")


# First-contact confirmation must pin the original live config before journal
# creation. A lost accepted response then remains read-only restart-reconcilable
# without ever copying the seed into the live JSON config.
tofu_dir = tempfile.mkdtemp(prefix="clack-cli-tofu-order-")
tofu_cfgp = os.path.join(tofu_dir, "legacy.json")
tofu_keyp = os.path.join(tofu_dir, "identity.key")
tofu_pending = tofu_cfgp + ".register-key.pending"
tofu_peer = "tofu-order-peer"
tofu_cfg = {"peers": {tofu_peer: "tofu-order-token"}, "base_url": BASE}
with open(tofu_cfgp, "w", encoding="utf-8") as f:
    json.dump(tofu_cfg, f)
os.chmod(tofu_cfgp, 0o600)
tofu_module = fresh_cli_module("tofu_order")
tofu_module._config_path = tofu_cfgp
tofu_module._selected_peer = tofu_peer
tofu_module.fetch_relay_identity = lambda origin, cfg: (SPEC_PIN, IDKEY)
tofu_candidate = {"value": None}
tofu_calls = []


def tofu_lost_acceptance(*args, **kwargs):
    cfg, method, path = args[0], args[1], args[2]
    tofu_module._ensure_origin_verified(tofu_module.base_url(cfg), cfg)
    tofu_calls.append((method, path))
    if (method, path) == ("POST", "/v1/register-key"):
        tofu_candidate["value"] = args[3]["pubkey"]
        raise tofu_module.UnknownMutationOutcome("synthetic accepted TOFU loss")
    raise AssertionError("unexpected first-contact request")


tofu_module.req = tofu_lost_acceptance
old_stdin = tofu_module.sys.stdin
old_input = builtins.input
tofu_module.sys.stdin = type("TTY", (), {"isatty": lambda self: True})()
builtins.input = lambda prompt="": "YES"
try:
    tofu_first_rc = tofu_module.cmd_register_key(
        direct_cli_args(tofu_cfgp, peer=tofu_peer, key_path=tofu_keyp),
        dict(tofu_cfg),
    )
finally:
    tofu_module.sys.stdin = old_stdin
    builtins.input = old_input
with open(tofu_cfgp, encoding="utf-8") as f:
    tofu_after_first = json.load(f)
tofu_pending_after_first = os.path.lexists(tofu_pending)

tofu_restart = fresh_cli_module("tofu_order_restart")
tofu_restart._config_path = tofu_cfgp
tofu_restart._selected_peer = tofu_peer
tofu_restart.fetch_relay_identity = lambda origin, cfg: (SPEC_PIN, IDKEY)
tofu_restart_calls = []


def tofu_status(*args, **kwargs):
    cfg, method, path = args[0], args[1], args[2]
    tofu_restart._ensure_origin_verified(tofu_restart.base_url(cfg), cfg)
    tofu_restart_calls.append((method, path))
    if (method, path) == ("GET", "/v1/register-key/status"):
        return 200, {
            "registered": True,
            "peer": tofu_peer,
            "identity_pubkey": tofu_candidate["value"],
        }
    raise AssertionError("TOFU restart must be read-only")


tofu_restart.req = tofu_status
try:
    tofu_restart_rc = (tofu_restart.cmd_register_key(
        direct_cli_args(tofu_cfgp, peer=tofu_peer, key_path=tofu_keyp),
        tofu_restart.load_config(tofu_cfgp),
    ) if tofu_pending_after_first else 99)
except SystemExit:
    tofu_restart_rc = 1
check(tofu_first_rc == 1 and tofu_calls == [("POST", "/v1/register-key")]
      and tofu_pending_after_first,
      "TOFU pin plus ambiguous acceptance retains one pending candidate",
      "rc=%r calls=%r pending=%r" % (
          tofu_first_rc, tofu_calls, tofu_pending_after_first))
check(tofu_after_first.get("relay_identity_fingerprint") == SPEC_PIN
      and "identity_privkey" not in tofu_after_first
      and "identity_seed" not in tofu_after_first,
      "TOFU pin precedes journal baseline with no inline seed leakage",
      repr(tofu_after_first))
check(tofu_restart_rc == 0
      and tofu_restart_calls == [("GET", "/v1/register-key/status")]
      and os.path.lexists(tofu_keyp)
      and not os.path.lexists(tofu_pending),
      "TOFU lost acceptance restart publishes separate key read-only",
      "rc=%r calls=%r" % (tofu_restart_rc, tofu_restart_calls))


# Existing external hardlinks for config, key, and operation lock must fail
# before any request or local mutation.
def run_simple_hardlink_case(role):
    case_dir = tempfile.mkdtemp(prefix="clack-cli-hardlink-%s-" % role)
    peer = "hardlink-" + role
    cfgp = os.path.join(case_dir, "legacy.json")
    keyp = os.path.join(case_dir, "identity.key")
    lockp = cfgp + ".register-key.lock"
    cfg = spec_legacy_config(peer, "hardlink-token")
    with open(cfgp, "w", encoding="utf-8") as f:
        json.dump(cfg, f)
    os.chmod(cfgp, 0o600)
    target = cfgp if role == "config" else keyp if role == "key" else lockp
    if role != "config":
        with open(target, "wb") as f:
            f.write((role + "-credential").encode())
        os.chmod(target, 0o600)
    alias = os.path.join(case_dir, "outside-sibling-" + role)
    os.link(target, alias)
    before = local_tree_snapshot(case_dir)
    module = fresh_cli_module("external_hardlink_" + role)
    calls = []
    module.req = lambda *a, **k: calls.append((a[1], a[2])) or (503, {})
    rc = module.cmd_register_key(
        direct_cli_args(cfgp, peer=peer, key_path=keyp), dict(cfg))
    return (rc, calls, before == local_tree_snapshot(case_dir),
            os.path.samefile(target, alias), os.stat(target).st_nlink)


for hardlink_role in ("config", "key", "lock"):
    hl_rc, hl_calls, hl_exact, hl_same, hl_nlink = run_simple_hardlink_case(
        hardlink_role)
    check(hl_rc == 1 and not hl_calls,
          "external hardlink %s rejects before every request" % hardlink_role,
          "rc=%r calls=%r" % (hl_rc, hl_calls))
    check(hl_exact and hl_same and hl_nlink == 2,
          "external hardlink %s leaves aliases byte-exact" % hardlink_role)


# Pending and quarantine names depend on a valid transaction. Create one with
# an ambiguous 503, then add the outside alias and demand a zero-request retry.
def make_pending_hardlink_fixture(tag):
    case_dir = tempfile.mkdtemp(prefix="clack-cli-hardlink-%s-" % tag)
    peer = "hardlink-" + tag
    cfgp = os.path.join(case_dir, "legacy.json")
    keyp = os.path.join(case_dir, "identity.key")
    pending = cfgp + ".register-key.pending"
    cfg = spec_legacy_config(peer, "hardlink-token")
    with open(cfgp, "w", encoding="utf-8") as f:
        json.dump(cfg, f)
    os.chmod(cfgp, 0o600)
    module = fresh_cli_module("make_pending_" + tag)
    module.req = lambda *a, **k: (503, {"error": "unavailable"})
    rc = module.cmd_register_key(
        direct_cli_args(cfgp, peer=peer, key_path=keyp), dict(cfg))
    return case_dir, peer, cfgp, keyp, pending, cfg, rc


pending_dir, pending_peer, pending_cfgp, pending_keyp, pending_path, pending_cfg, pending_make_rc = make_pending_hardlink_fixture("pending")
pending_alias = os.path.join(pending_dir, "outside-sibling-pending")
os.link(pending_path, pending_alias)
pending_before = local_tree_snapshot(pending_dir)
pending_module = fresh_cli_module("external_hardlink_pending")
pending_calls = []
pending_module.req = lambda *a, **k: pending_calls.append((a[1], a[2])) or (503, {})
pending_rc = pending_module.cmd_register_key(
    direct_cli_args(pending_cfgp, peer=pending_peer, key_path=pending_keyp),
    dict(pending_cfg),
)
check(pending_make_rc == 1 and pending_rc == 1 and not pending_calls,
      "external hardlink pending rejects before every request",
      "make=%r retry=%r calls=%r" % (
          pending_make_rc, pending_rc, pending_calls))
check(pending_before == local_tree_snapshot(pending_dir)
      and os.path.samefile(pending_path, pending_alias)
      and os.stat(pending_path).st_nlink == 2,
      "external hardlink pending leaves aliases byte-exact")

quar_dir, quar_peer, quar_cfgp, quar_keyp, quar_pending, quar_cfg, quar_make_rc = make_pending_hardlink_fixture("quarantine")
quar_journal = _rc._load_register_key_journal(quar_pending, quar_cfgp)
quar_path = quar_pending + ".rejected-" + quar_journal["transaction_id"]
with open(quar_path, "wb") as f:
    f.write(b"operator quarantine reservation")
os.chmod(quar_path, 0o600)
quar_alias = os.path.join(quar_dir, "outside-sibling-quarantine")
os.link(quar_path, quar_alias)
quar_before = local_tree_snapshot(quar_dir)
quar_module = fresh_cli_module("external_hardlink_quarantine")
quar_calls = []


def quar_status(*args, **kwargs):
    quar_calls.append((args[1], args[2]))
    return 200, {
        "registered": True,
        "peer": quar_peer,
        "identity_pubkey": b64u_encode(b"y" * 32),
    }


quar_module.req = quar_status
quar_rc = quar_module.cmd_register_key(
    direct_cli_args(quar_cfgp, peer=quar_peer, key_path=quar_keyp),
    dict(quar_cfg),
)
check(quar_make_rc == 1 and quar_rc == 1 and not quar_calls,
      "external hardlink quarantine rejects before every request",
      "make=%r retry=%r calls=%r" % (
          quar_make_rc, quar_rc, quar_calls))
check(quar_before == local_tree_snapshot(quar_dir)
      and os.path.samefile(quar_path, quar_alias)
      and os.stat(quar_path).st_nlink == 2,
      "external hardlink quarantine leaves aliases byte-exact")


# Insert a multiply-linked foreign inode after the initial absence check but at
# the journal replacement boundary. It must remain canonical and unmodified;
# no request or key publication is permitted.
alias_dir = tempfile.mkdtemp(prefix="clack-cli-hardlink-race-")
alias_peer = "hardlink-race"
alias_cfgp = os.path.join(alias_dir, "legacy.json")
alias_keyp = os.path.join(alias_dir, "identity.key")
alias_pending = alias_cfgp + ".register-key.pending"
alias_cfg = spec_legacy_config(alias_peer, "hardlink-race-token")
with open(alias_cfgp, "w", encoding="utf-8") as f:
    json.dump(alias_cfg, f)
os.chmod(alias_cfgp, 0o600)
alias_foreign = os.path.join(alias_dir, "outside-sibling-journal")
with open(alias_foreign, "wb") as f:
    f.write(b"foreign journal reservation")
os.chmod(alias_foreign, 0o600)
alias_module = fresh_cli_module("external_hardlink_race")
alias_injected = {"value": False}
alias_calls = []


def alias_hook(event):
    if event == "journal:before_replace" and not alias_injected["value"]:
        os.link(alias_foreign, alias_pending)
        alias_injected["value"] = True


alias_module._LOCAL_PUBLICATION_HOOK = alias_hook
alias_module.req = lambda *a, **k: alias_calls.append((a[1], a[2])) or (503, {})
alias_rc = alias_module.cmd_register_key(
    direct_cli_args(alias_cfgp, peer=alias_peer, key_path=alias_keyp),
    dict(alias_cfg),
)
check(alias_injected["value"] and alias_rc == 1 and not alias_calls,
      "external hardlink alias race rejects before every request",
      "injected=%r rc=%r calls=%r" % (
          alias_injected["value"], alias_rc, alias_calls))
check(open(alias_pending, "rb").read() == b"foreign journal reservation"
      and os.path.samefile(alias_pending, alias_foreign)
      and os.stat(alias_pending).st_nlink == 2
      and not os.path.lexists(alias_keyp),
      "external hardlink alias race preserves foreign inode and no key")


# A lock artifact created and externally aliased after abstract-lock acquisition
# is detected again at the journal transition boundary.
lock_race_dir = tempfile.mkdtemp(prefix="clack-cli-lock-hardlink-race-")
lock_race_peer = "lock-hardlink-race"
lock_race_cfgp = os.path.join(lock_race_dir, "legacy.json")
lock_race_keyp = os.path.join(lock_race_dir, "identity.key")
lock_race_pending = lock_race_cfgp + ".register-key.pending"
lock_race_path = lock_race_cfgp + ".register-key.lock"
lock_race_alias = os.path.join(lock_race_dir, "outside-sibling-lock")
lock_race_cfg = spec_legacy_config(lock_race_peer, "lock-race-token")
with open(lock_race_cfgp, "w", encoding="utf-8") as f:
    json.dump(lock_race_cfg, f)
os.chmod(lock_race_cfgp, 0o600)
lock_race_module = fresh_cli_module("lock_hardlink_race")
lock_race_injected = {"value": False}
lock_race_calls = []


def lock_race_hook(event):
    if event == "journal:before_replace" and not lock_race_injected["value"]:
        with open(lock_race_path, "wb") as f:
            f.write(b"late lock reservation")
        os.chmod(lock_race_path, 0o600)
        os.link(lock_race_path, lock_race_alias)
        lock_race_injected["value"] = True


lock_race_module._LOCAL_PUBLICATION_HOOK = lock_race_hook
lock_race_module.req = lambda *a, **k: lock_race_calls.append((a[1], a[2])) or (503, {})
lock_race_rc = lock_race_module.cmd_register_key(
    direct_cli_args(
        lock_race_cfgp, peer=lock_race_peer, key_path=lock_race_keyp),
    dict(lock_race_cfg),
)
check(lock_race_injected["value"] and lock_race_rc == 1
      and not lock_race_calls and not os.path.lexists(lock_race_pending)
      and not os.path.lexists(lock_race_keyp),
      "late external-hardlink lock alias rejects before journal and request")
check(os.path.samefile(lock_race_path, lock_race_alias)
      and os.stat(lock_race_path).st_nlink == 2
      and open(lock_race_path, "rb").read() == b"late lock reservation",
      "late lock alias remains byte-exact and multiply linked")


# A config hardlink added at the final config transition cannot be exchanged or
# followed by key publication, even after the relay accepted the candidate.
config_link_dir = tempfile.mkdtemp(prefix="clack-cli-config-hardlink-race-")
config_link_peer = "config-hardlink-race"
config_link_cfgp = os.path.join(config_link_dir, "legacy.json")
config_link_keyp = os.path.join(config_link_dir, "identity.key")
config_link_pending = config_link_cfgp + ".register-key.pending"
config_link_alias = os.path.join(config_link_dir, "outside-sibling-config")
config_link_cfg = spec_legacy_config(config_link_peer, "config-link-token")
with open(config_link_cfgp, "w", encoding="utf-8") as f:
    json.dump(config_link_cfg, f)
os.chmod(config_link_cfgp, 0o600)
config_link_bytes = open(config_link_cfgp, "rb").read()
config_link_module = fresh_cli_module("config_hardlink_race")
config_link_calls = []
config_link_injected = {"value": False}


def config_link_req(*args, **kwargs):
    config_link_calls.append((args[1], args[2]))
    candidate = args[3]["pubkey"]
    return 200, {
        "registered": True,
        "peer": config_link_peer,
        "rotated": False,
        "identity_pubkey": candidate,
    }


def config_link_hook(event):
    if event == "config:before_replace" and not config_link_injected["value"]:
        os.link(config_link_cfgp, config_link_alias)
        config_link_injected["value"] = True


config_link_module.req = config_link_req
config_link_module._LOCAL_PUBLICATION_HOOK = config_link_hook
config_link_rc = config_link_module.cmd_register_key(
    direct_cli_args(
        config_link_cfgp, peer=config_link_peer, key_path=config_link_keyp),
    dict(config_link_cfg),
)
check(config_link_injected["value"] and config_link_rc == 1
      and config_link_calls == [("POST", "/v1/register-key")]
      and os.path.lexists(config_link_pending)
      and not os.path.lexists(config_link_keyp),
      "config hardlink alias race retains accepted pending and no key")
check(open(config_link_cfgp, "rb").read() == config_link_bytes
      and os.path.samefile(config_link_cfgp, config_link_alias)
      and os.stat(config_link_cfgp).st_nlink == 2,
      "config hardlink alias race preserves byte-exact operator inode")

stop_relay()
print("PASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
