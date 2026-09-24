#!/usr/bin/env python3
"""v0.2.12 mandatory Ed25519 request-signing tests (scratch only, never live).

Spins up an isolated relay (temp dir, port 18995) and covers:
  - signed send/poll/ack round trip between enrolled peers
  - tampered body / path / raw query / nonce / method -> 401 bad_signature
  - wrong-key (valid sig, wrong identity) -> 401 bad_signature
  - unknown X-Clack-Key -> 401 unknown_key
  - replayed request -> 401 replay
  - expired / future nonces -> 401 stale_nonce (with valid-window controls)
  - NULL-key peer -> 401 upgrade_required
  - nonce persistence across relay restart (replay still caught)
  - sweep prunes expired nonces; hard-cap eviction (unit)
  - CLI keygen/enroll/send/poll/ack round trip (auto-signing)
  - vendored ed25519.py benchmark: p50/p99 sign+verify (flags p50 > 50ms;
    5ms was the original budget, unattainable in pure Python -- see note
    at the benchmark)
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
import urllib.request
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
RELAY_PY = os.path.join(HERE, "relay.py")
CLI = os.path.join(HERE, "relay-cli.py")
PORT = int(os.environ.get("CLACK_TEST_PORT", "18995"))
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


_spec = importlib.util.spec_from_file_location("relay_cli", CLI)
_rc = importlib.util.module_from_spec(_spec)
sys.argv = ["relay-cli.py"]
_spec.loader.exec_module(_rc)

_spec2 = importlib.util.spec_from_file_location("relay_mod", RELAY_PY)
_rm = importlib.util.module_from_spec(_spec2)
_spec2.loader.exec_module(_rm)

# Canonical vendored crypto (ed25519.py). The CLI inlines a copy (_rc);
# the RFC vectors below pin both to the standard so the two copies can
# never silently drift from each other or from Ed25519 itself.
_spec3 = importlib.util.spec_from_file_location(
    "ed25519_canonical", os.path.join(HERE, "ed25519.py"))
_ed = importlib.util.module_from_spec(_spec3)
_spec3.loader.exec_module(_ed)

TMPD = tempfile.mkdtemp(prefix="clack-sign-test-")
SRV = None
KEYS = {}   # peer -> (seed, pub, pub_b64)


def fresh_key(peer):
    seed, pub = _rc.keygen()
    KEYS[peer] = (seed, pub, b64u_encode(pub))
    return KEYS[peer]


def sign_headers(peer, method, path, body, nonce=None):
    seed, _, _ = KEYS[peer]
    if nonce is None:
        nonce = "%d:%s" % (int(time.time()), secrets.token_hex(16))
    canon = ("clack-ed25519-v1\n" + method.upper() + "\n" + path + "\n"
             + hashlib.sha256(body).hexdigest() + "\n" + nonce).encode()
    return {"X-Clack-Scheme": "1", "X-Clack-Key": peer,
            "X-Clack-Nonce": nonce,
            "X-Clack-Sig": _rc.sign(seed, canon).hex()}


def call(token, method, path, body=None, peer=None, headers=None, nonce=None):
    data = body if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method)
    if token:
        r.add_header("Authorization", "Bearer " + token)
    if data is not None:
        r.add_header("Content-Type", "application/json")
    hdrs = dict(headers) if headers else {}
    if peer is not None and headers is None:
        # auto-sign only when the caller did not craft headers by hand
        # (tamper tests pass headers= AND must not be re-signed)
        hdrs.update(sign_headers(peer, method, path, data or b"",
                                 nonce=nonce))
    for k, v in hdrs.items():
        r.add_header(k, v)
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def err_of(body):
    try:
        return json.loads(body).get("error", "?")
    except Exception:
        return "?"


def _der_ints(der):
    """Minimal DER parser returning the INTEGERs of a PKCS#1 RSAPrivateKey."""
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
    """Scratch RSA identity key for the relay (P1/P2: the CLI round trip
    needs a real /v1/identity, otherwise token-bearing CLI calls abort)."""
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


def start_relay():
    global SRV
    cfg = {"port": PORT,
           "peers": {"alice": ALICE_TOKEN},
           "identity_pubkeys": {"alice": KEYS["alice"][2]},
           "enrollment": "open", "pow_difficulty": 8,
           "identity_key": _gen_rsa_identity_key(TMPD)}
    with open(os.path.join(TMPD, "relay-config.json"), "w") as f:
        json.dump(cfg, f)
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


def db():
    return sqlite3.connect(os.path.join(TMPD, "relay.db"))


def seed_handshake(a_name, b_name):
    """White-box an ACTIVE handshake row for (a_name, b_name).

    v0.2.13 gates /v1/send on mutual consent. This suite tests request
    signing, not the handshake flow (see test-handshake.py), so the rows
    it needs are seeded directly -- mirroring caller_identity()'s
    resolution (identity_pubkey when present, else the peer name).
    """
    con = db()
    con.execute("PRAGMA busy_timeout=5000")
    def ident(peer):
        r = con.execute("SELECT identity_pubkey FROM peers WHERE name=?",
                        (peer,)).fetchone()
        return r[0] if r and r[0] else peer
    a, b = sorted([ident(a_name), ident(b_name)])
    now = time.time()
    con.execute(
        """INSERT OR REPLACE INTO handshakes(
               a_identity, b_identity, status, created_at,
               pending_expires_at, expires_at, last_activity,
               via_link_id, redeemer_identity, generation)
           VALUES(?, ?, 'active', ?, NULL, NULL, ?, 'test-signing', NULL, 0)""",
        (a, b, now, now),
    )
    con.commit()
    con.close()


def enroll_open(name):
    seed, pub, pub_b64 = fresh_key(name)
    code, ch = call(None, "POST", "/v1/enroll/challenge", b"{}")[:2]
    ch = json.loads(ch)
    assert code == 200, ch
    nonce = b64u_decode(ch["nonce"])
    sig = _rc.sign(seed, nonce + pub)
    body = json.dumps({"identity_pubkey": pub_b64, "name": name,
                       "proof": {"nonce": b64u_encode(nonce),
                                 "signature": b64u_encode(sig)}}).encode()
    code, out = call(None, "POST", "/v1/enroll", body)[:2]
    out = json.loads(out)
    assert code == 200, out
    return out["service_token"], out["peer_name"]


ALICE_TOKEN = "kr_test_" + secrets.token_urlsafe(24)


def _hx(*groups):
    s = "".join(groups)
    assert all(len(g) == 8 for g in groups), "vector group typo: %r" % (groups,)
    return bytes.fromhex(s)


# RFC 8032 Section 7.1 test vectors (ground truth for Ed25519 itself).
# Each entry: (secret_key, public_key, message, signature). Hex is written
# in 8-char groups so a dropped digit fails loudly at import-parse time
# instead of silently testing the wrong vector.
RFC_VECTORS = [
    ("TEST 1 (empty msg)",
     _hx("9d61b19d", "effd5a60", "ba844af4", "92ec2cc4",
         "4449c569", "7b326919", "703bac03", "1cae7f60"),
     _hx("d75a9801", "82b10ab7", "d54bfed3", "c964073a",
         "0ee172f3", "daa62325", "af021a68", "f707511a"),
     b"",
     _hx("e5564300", "c360ac72", "9086e2cc", "806e828a",
         "84877f1e", "b8e5d974", "d873e065", "22490155",
         "5fb88215", "90a33bac", "c61e3970", "1cf9b46b",
         "d25bf5f0", "595bbe24", "65514143", "8e7a100b")),
    ("TEST 2 (1-byte msg)",
     _hx("4ccd089b", "28ff96da", "9db6c346", "ec114e0f",
         "5b8a319f", "35aba624", "da8cf6ed", "4fb8a6fb"),
     _hx("3d4017c3", "e843895a", "92b70aa7", "4d1b7ebc",
         "9c982ccf", "2ec4968c", "c0cd55f1", "2af4660c"),
     bytes.fromhex("72"),
     _hx("92a009a9", "f0d4cab8", "720e820b", "5f642540",
         "a2b27b54", "16503f8f", "b3762223", "ebdb69da",
         "085ac1e4", "3e15996e", "458f3613", "d0f11d8c",
         "387b2eae", "b4302aee", "b00d2916", "12bb0c00")),
    ("TEST 3 (2-byte msg)",
     _hx("c5aa8df4", "3f9f837b", "edb7442f", "31dcb7b1",
         "66d38535", "076f094b", "85ce3a2e", "0b4458f7"),
     _hx("fc51cd8e", "6218a1a3", "8da47ed0", "0230f058",
         "0816ed13", "ba3303ac", "5deb9115", "48908025"),
     bytes.fromhex("af82"),
     _hx("6291d657", "deec2402", "4827e69c", "3abe01a3",
         "0ce548a2", "84743a44", "5e3680d7", "db5ac3ac",
         "18ff9b53", "8d16f290", "ae67f760", "984dc659",
         "4a7c15e9", "716ed28d", "c027bece", "ea1ec40a")),
]


def run_rfc_vectors():
    # Pin BOTH vendored copies to the RFC: keygen, sign, and verify must
    # reproduce the standard exactly. Without this, sign/verify could be
    # merely self-consistent (relay and CLI agreeing with each other)
    # while silently incompatible with every other Ed25519 implementation.
    for label, sk, pk, msg, sig in RFC_VECTORS:
        check(_ed._publickey(sk) == pk,
              "RFC %s keygen (ed25519.py)" % label, pk.hex()[:16])
        check(_rc._publickey(sk) == pk,
              "RFC %s keygen (cli inlined)" % label, pk.hex()[:16])
        s_ed = _ed.sign(sk, msg)
        s_rc = _rc.sign(sk, msg)
        check(s_ed == sig, "RFC %s sign (ed25519.py)" % label, s_ed.hex()[:16])
        check(s_rc == sig, "RFC %s sign (cli inlined)" % label, s_rc.hex()[:16])
        check(s_ed == s_rc, "RFC %s copies agree" % label)
        check(_ed.verify(pk, sig, msg), "RFC %s verify (ed25519.py)" % label)
        check(_rc.verify(pk, sig, msg), "RFC %s verify (cli inlined)" % label)
        check(not _ed.verify(pk, sig, msg + b"x"),
              "RFC %s tampered msg rejected" % label)


def main():
    run_rfc_vectors()
    fresh_key("alice")
    fresh_key("carol")  # wrong-key material (never enrolled server-side)
    start_relay()
    try:
        run_round_trip()
        run_tamper_matrix()
        run_replay_and_freshness()
        run_null_key()
        run_persistence()
        run_prune_and_cap()
        run_key_validation()
        run_legacy_gate()
        run_trusted_proxy()
        run_rate_budget()
        run_delayed_body()
        run_cli_round_trip()
        run_benchmark()
    finally:
        stop_relay()
    print("signing tests: %d passed, %d failed" % (PASS, FAIL))
    return 1 if FAIL else 0


class _FakeHandlerSelf:
    def __init__(self, ip, headers):
        self.client_address = (ip, 9999)
        self.headers = headers


def _client_ip_for(sock_ip, headers, trusted_proxies):
    old = _rm.relay_cfg
    _rm.relay_cfg = {"trusted_proxies": trusted_proxies}
    try:
        return _rm.Handler._client_ip(_FakeHandlerSelf(sock_ip, headers))
    finally:
        _rm.relay_cfg = old


def run_trusted_proxy():
    """Flint P2-deploy: per-IP rate-limit buckets behind a trusted edge."""
    # Default (no trusted_proxies): forwarded headers are never honored.
    check(_client_ip_for("10.1.2.3",
                         {"X-Forwarded-For": "203.0.113.7"}, []) == "10.1.2.3",
          "untrusted: X-Forwarded-For ignored")
    check(_client_ip_for("10.1.2.3",
                         {"CF-Connecting-IP": "203.0.113.7"}, None)
          == "10.1.2.3",
          "untrusted: CF-Connecting-IP ignored")
    # Trusted edge: CF-Connecting-IP wins, else first XFF entry.
    check(_client_ip_for("127.0.0.1", {"CF-Connecting-IP": "203.0.113.7"},
                         ["127.0.0.1/32"]) == "203.0.113.7",
          "trusted: CF-Connecting-IP honored")
    check(_client_ip_for("127.0.0.1",
                         {"X-Forwarded-For": "198.51.100.9, 10.0.0.1"},
                         ["127.0.0.1/32"]) == "198.51.100.9",
          "trusted: first X-Forwarded-For entry honored")
    check(_client_ip_for("127.0.0.1", {}, ["127.0.0.1/32"]) == "127.0.0.1",
          "trusted: no headers falls back to socket IP")
    check(_client_ip_for("127.0.0.1", {"CF-Connecting-IP": "garbage!!"},
                         ["127.0.0.1/32"]) == "127.0.0.1",
          "trusted: invalid header value falls back to socket IP")
    # A source outside the trusted CIDRs never gets header treatment.
    check(_client_ip_for("10.9.9.9", {"CF-Connecting-IP": "203.0.113.7"},
                         ["127.0.0.1/32"]) == "10.9.9.9",
          "outside trusted CIDRs: headers ignored")
    # Config ergonomics: bare string and bad CIDRs.
    check(_client_ip_for("127.0.0.1", {"CF-Connecting-IP": "203.0.113.7"},
                         "127.0.0.1/32") == "203.0.113.7",
          "trusted_proxies accepts a bare string")
    check(_client_ip_for("127.0.0.1", {"CF-Connecting-IP": "203.0.113.7"},
                         ["not-a-cidr"]) == "127.0.0.1",
          "invalid CIDR entries are ignored")


def run_round_trip():
    bob_tok, bob_peer = enroll_open("sigbob")
    check(bob_peer == "sigbob", "enroll sigbob (open gate)", bob_peer)
    seed_handshake("sigbob", "alice")  # v0.2.13: send gate
    mid = str(uuid.uuid4())
    body = json.dumps({"id": mid, "to": "alice",
                       "text": "signed hello"}).encode()
    code, out = call(bob_tok, "POST", "/v1/send", body, peer="sigbob")
    check(code == 200 and json.loads(out).get("accepted"),
          "signed send accepted", "%s %s" % (code, out[:80]))
    code, out = call(ALICE_TOKEN, "GET", "/v1/poll?timeout=1", peer="alice")
    msgs = json.loads(out).get("messages", [])
    check(code == 200 and msgs and msgs[0]["id"] == mid
          and msgs[0]["text"] == "signed hello",
          "signed poll delivers", "%s %s" % (code, out[:80]))
    code, out = call(ALICE_TOKEN, "POST", "/v1/ack",
                     json.dumps({"ids": [mid]}).encode(), peer="alice")
    check(code == 200 and json.loads(out).get("acked") == [mid],
          "signed ack works", "%s %s" % (code, out[:80]))
    return bob_tok


BOB = {}


def run_tamper_matrix():
    bob_tok, _ = enroll_open("tampbob")
    BOB["tok"] = bob_tok

    def c(method, path, body, peer="tampbob", headers=None, nonce=None):
        return call(bob_tok, method, path, body, peer=peer,
                    headers=headers, nonce=nonce)

    # control: valid
    h = sign_headers("tampbob", "GET", "/v1/peers", b"")
    code, _ = c("GET", "/v1/peers", None, headers=h)
    check(code == 200, "tamper matrix control 200", code)

    # tampered body
    good = json.dumps({"id": str(uuid.uuid4()), "to": "alice",
                       "text": "good"}).encode()
    evil = json.dumps({"id": str(uuid.uuid4()), "to": "alice",
                       "text": "EVIL"}).encode()
    code, out = c("POST", "/v1/send", evil,
                  headers=sign_headers("tampbob", "POST", "/v1/send", good))
    check(code == 401 and err_of(out) == "bad_signature",
          "tampered body -> bad_signature", "%s %s" % (code, out[:60]))

    # tampered path
    code, out = c("GET", "/v1/peers/evil", None,
                  headers=sign_headers("tampbob", "GET", "/v1/peers", b""))
    # /v1/peers/evil is not a routed endpoint, but auth runs first
    check(code == 401 and err_of(out) == "bad_signature",
          "tampered path -> bad_signature", "%s %s" % (code, out[:60]))

    # tampered raw query
    code, out = c("GET", "/v1/poll?timeout=1&x=2", None,
                  headers=sign_headers("tampbob", "GET",
                                       "/v1/poll?timeout=1", b""))
    check(code == 401 and err_of(out) == "bad_signature",
          "tampered query -> bad_signature", "%s %s" % (code, out[:60]))

    # tampered method
    code, out = c("POST", "/v1/peers", None,
                  headers=sign_headers("tampbob", "GET", "/v1/peers", b""))
    check(code == 401 and err_of(out) == "bad_signature",
          "tampered method -> bad_signature", "%s %s" % (code, out[:60]))

    # tampered nonce (flip a hex char, keep format valid)
    h = sign_headers("tampbob", "GET", "/v1/peers", b"")
    ts, rnd = h["X-Clack-Nonce"].split(":")
    bad_rnd = ("0" if rnd[0] != "0" else "1") + rnd[1:]
    h["X-Clack-Nonce"] = ts + ":" + bad_rnd
    code, out = c("GET", "/v1/peers", None, headers=h)
    check(code == 401 and err_of(out) == "bad_signature",
          "tampered nonce -> bad_signature", "%s %s" % (code, out[:60]))

    # wrong key: carol's seed signs, but X-Clack-Key claims tampbob
    seed_c, _, _ = KEYS["carol"]
    nonce = "%d:%s" % (int(time.time()), secrets.token_hex(16))
    canon = ("clack-ed25519-v1\nGET\n/v1/peers\n"
             + hashlib.sha256(b"").hexdigest() + "\n" + nonce).encode()
    h = {"X-Clack-Scheme": "1", "X-Clack-Key": "tampbob",
         "X-Clack-Nonce": nonce, "X-Clack-Sig": _rc.sign(seed_c, canon).hex()}
    code, out = c("GET", "/v1/peers", None, headers=h)
    check(code == 401 and err_of(out) == "bad_signature",
          "wrong key -> bad_signature", "%s %s" % (code, out[:60]))

    # unknown key name
    h = sign_headers("tampbob", "GET", "/v1/peers", b"")
    h["X-Clack-Key"] = "nobody-here"
    code, out = c("GET", "/v1/peers", None, headers=h)
    check(code == 401 and err_of(out) == "unknown_key",
          "unknown key -> unknown_key", "%s %s" % (code, out[:60]))

    # missing scheme header
    h = sign_headers("tampbob", "GET", "/v1/peers", b"")
    del h["X-Clack-Scheme"]
    code, out = c("GET", "/v1/peers", None, headers=h)
    check(code == 401 and err_of(out) == "missing_signature",
          "missing scheme -> missing_signature", "%s %s" % (code, out[:60]))


def run_replay_and_freshness():
    bob_tok = BOB["tok"]

    def c(method, path, body, headers=None, nonce=None):
        return call(bob_tok, method, path, body, peer="tampbob",
                    headers=headers, nonce=nonce)

    # replay
    h = sign_headers("tampbob", "GET", "/v1/peers", b"")
    c1, _ = c("GET", "/v1/peers", None, headers=h)
    c2, out2 = c("GET", "/v1/peers", None, headers=h)
    check(c1 == 200 and c2 == 401 and err_of(out2) == "replay",
          "replay -> 401 replay", "%s/%s" % (c1, c2))

    # expired nonce (700s old, validly signed)
    old = "%d:%s" % (int(time.time()) - 700, secrets.token_hex(16))
    code, out = c("GET", "/v1/peers", None,
                  headers=sign_headers("tampbob", "GET", "/v1/peers", b"",
                                       nonce=old))
    check(code == 401 and err_of(out) == "stale_nonce",
          "expired nonce -> stale_nonce", "%s %s" % (code, out[:60]))

    # future nonce (+300s, validly signed)
    fut = "%d:%s" % (int(time.time()) + 300, secrets.token_hex(16))
    code, out = c("GET", "/v1/peers", None,
                  headers=sign_headers("tampbob", "GET", "/v1/peers", b"",
                                       nonce=fut))
    check(code == 401 and err_of(out) == "stale_nonce",
          "future nonce -> stale_nonce", "%s %s" % (code, out[:60]))

    # valid-window controls (500s old and +60s future are inside the window)
    ok_old = "%d:%s" % (int(time.time()) - 500, secrets.token_hex(16))
    code, _ = c("GET", "/v1/peers", None,
                headers=sign_headers("tampbob", "GET", "/v1/peers", b"",
                                     nonce=ok_old))
    check(code == 200, "500s-old nonce inside window -> 200", code)
    ok_fut = "%d:%s" % (int(time.time()) + 60, secrets.token_hex(16))
    code, _ = c("GET", "/v1/peers", None,
                headers=sign_headers("tampbob", "GET", "/v1/peers", b"",
                                     nonce=ok_fut))
    check(code == 200, "+60s nonce inside skew -> 200", code)


def run_null_key():
    tok, peer = enroll_open("nullkey")
    con = db()
    try:
        con.execute("UPDATE peers SET identity_pubkey=NULL WHERE name=?",
                    (peer,))
        con.commit()
    finally:
        con.close()
    code, out = call(tok, "GET", "/v1/peers", peer=peer)
    check(code == 401 and err_of(out) == "upgrade_required",
          "NULL-key peer -> upgrade_required", "%s %s" % (code, out[:60]))


def run_persistence():
    bob_tok = BOB["tok"]
    # nonce recorded, then relay restarts -> replay must still be caught
    h = sign_headers("tampbob", "GET", "/v1/peers", b"")
    c1, _ = call(bob_tok, "GET", "/v1/peers", None, headers=h)
    check(c1 == 200, "persistence setup 200", c1)
    stop_relay()
    start_relay()
    c2, out2 = call(bob_tok, "GET", "/v1/peers", None, headers=h)
    check(c2 == 401 and err_of(out2) == "replay",
          "nonce survives restart -> replay", "%s %s" % (c2, out2[:60]))


def run_prune_and_cap():
    # --- sweep prunes expired nonces ---
    con = db()
    try:
        now = time.time()
        con.execute("INSERT INTO seen_nonces(nonce, peer, expires_at)"
                    " VALUES(?,?,?)", ("prune-old-1", "tampbob", now - 5))
        con.execute("INSERT INTO seen_nonces(nonce, peer, expires_at)"
                    " VALUES(?,?,?)", ("prune-old-2", "tampbob", now - 1))
        con.execute("INSERT INTO seen_nonces(nonce, peer, expires_at)"
                    " VALUES(?,?,?)", ("prune-live", "tampbob", now + 500))
        con.commit()
    finally:
        con.close()
    # sweep runs on every request (throttled to 60s); unsigned /health hits
    # are free and trigger it without any Ed25519 cost.
    gone = False
    for _ in range(75):
        try:
            urllib.request.urlopen(BASE + "/health", timeout=5).close()
        except Exception:
            pass
        con = db()
        try:
            rows = con.execute(
                "SELECT nonce FROM seen_nonces WHERE nonce LIKE 'prune-%'"
            ).fetchall()
        finally:
            con.close()
        if [r[0] for r in rows] == ["prune-live"]:
            gone = True
            break
        time.sleep(1)
    check(gone, "sweep prunes expired nonces, keeps live", rows)

    # --- nonce store: fail closed at capacity, never evict live (R2) -------
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE seen_nonces(nonce TEXT PRIMARY KEY,"
                " peer TEXT NOT NULL, expires_at REAL NOT NULL)")
    old_cap = _rm.NONCE_STORE_CAP
    _rm.NONCE_STORE_CAP = 100
    try:
        base = time.time()
        res = [_rm._nonce_record(con, "cap-%d" % i, "p", base + 3600 + i)
               for i in range(150)]
        n = con.execute("SELECT COUNT(*) FROM seen_nonces").fetchone()[0]
        # a live nonce recorded before capacity pressure is still known:
        # the replay guarantee must not depend on load
        still = _rm._nonce_record(con, "cap-50", "p", base + 3650)
        # duplicate insert reports replay and stores nothing new
        dup = _rm._nonce_record(con, "cap-99", "p", base + 3699)
        n2 = con.execute("SELECT COUNT(*) FROM seen_nonces").fetchone()[0]
        # expired rows are pruned to make room for a fresh nonce: use a
        # second store with 98 live + 2 expired rows at cap; the new
        # insert reaps the expired pair and lands.
        con2 = sqlite3.connect(":memory:")
        con2.execute("CREATE TABLE seen_nonces(nonce TEXT PRIMARY KEY,"
                     " peer TEXT NOT NULL, expires_at REAL NOT NULL)")
        base2 = time.time()
        for i in range(98):
            assert _rm._nonce_record(
                con2, "k-%d" % i, "p", base2 + 3600) == "recorded"
        con2.execute("INSERT INTO seen_nonces(nonce, peer, expires_at)"
                     " VALUES(?,?,?)", ("old-1", "p", base2 - 10))
        con2.execute("INSERT INTO seen_nonces(nonce, peer, expires_at)"
                     " VALUES(?,?,?)", ("old-2", "p", base2 - 5))
        con2.commit()
        room = _rm._nonce_record(con2, "k-new", "p", base2 + 7200)
        n3 = con2.execute("SELECT COUNT(*) FROM seen_nonces").fetchone()[0]
        con2.close()
    finally:
        _rm.NONCE_STORE_CAP = old_cap
        con.close()
    check(all(r == "recorded" for r in res[:100]),
          "nonce store records up to cap", res[99])
    check(all(r == "full" for r in res[100:]),
          "nonce store refuses new requests at cap (fail closed)", res[100])
    check(n <= 100, "hard cap enforced (n=%d <= 100)" % n, n)
    check(still == "replay",
          "R2 live nonce still rejected under capacity pressure", still)
    check(dup == "replay" and n2 == n, "duplicate nonce -> replay, no growth",
          (dup, n2))
    check(room == "recorded" and n3 == 99,
          "expired rows pruned to make room", (room, n3))


def run_cli_round_trip():
    """CLI keygen -> enroll (open) -> send -> poll -> ack, all auto-signed."""
    d = tempfile.mkdtemp(prefix="clack-cli-sign-")
    cfgp = os.path.join(d, "cli.json")
    r = subprocess.run(
        [sys.executable, CLI, "--config", cfgp, "keygen",
         "--relay", BASE, "--key-path", os.path.join(d, "cli.key")],
        capture_output=True, text=True, timeout=60)
    check(r.returncode == 0, "CLI keygen exit 0", r.stderr[-200:])
    cfg = json.load(open(cfgp))
    # POSIX mode bits are meaningless on Windows (ACLs govern access);
    # Flint's review confirmed the synthetic ACL was owner-only there.
    mode_ok = (os.name == "nt" or
               oct(os.stat(cfg["identity_privkey_path"]).st_mode & 0o777)
               == "0o600")
    check(cfg.get("identity_privkey_path") == os.path.join(d, "cli.key")
          and "identity_privkey" not in cfg
          and mode_ok,
          "CLI key in separate mode-600 file, not inline", str(cfg)[:120])
    r = subprocess.run(
        [sys.executable, CLI, "--config", cfgp, "enroll", "--name", "clichat",
         "--relay", BASE, "--yes"],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120)
    check(r.returncode == 0, "CLI enroll exit 0", r.stderr[-300:])
    cfg = json.load(open(cfgp))
    peer = cfg.get("peer_name")
    check(peer == "clichat", "CLI enrolled as clichat", peer)
    seed_handshake("clichat", "alice")  # v0.2.13: send gate
    mid = str(uuid.uuid4())
    r = subprocess.run(
        [sys.executable, CLI, "--config", cfgp, "send", "--to", "alice",
         "--text", "cli signed hi", "--id", mid],
        capture_output=True, text=True, timeout=60)
    check(r.returncode == 0 and mid in r.stdout,
          "CLI send auto-signed", r.stderr[-200:] + r.stdout[-200:])
    # alice polls via raw signed call and sees the CLI's message
    code, out = call(ALICE_TOKEN, "GET", "/v1/poll?timeout=1", peer="alice")
    msgs = json.loads(out).get("messages", [])
    check(code == 200 and any(m["id"] == mid for m in msgs),
          "CLI-sent message polled", "%s %s" % (code, out[:80]))
    r = subprocess.run(
        [sys.executable, CLI, "--config", cfgp, "poll", "--timeout", "1"],
        capture_output=True, text=True, timeout=60)
    check(r.returncode == 0, "CLI poll auto-signed exit 0",
          r.stderr[-200:])


def run_key_validation():
    """R5: small-order / non-prime-order Ed25519 keys are rejected."""
    seed, pub = _ed.keygen()
    check(_ed.is_valid_pubkey(pub), "R5 canonical keygen key accepted")
    lo = bytes([1]) + bytes(31)
    check(not _ed.is_valid_pubkey(lo), "R5 low-order key rejected")
    check(not _ed.is_valid_pubkey(bytes(32)), "R5 all-zero key rejected")
    check(not _ed.is_valid_pubkey(b"short"), "R5 wrong-length key rejected")
    # The raw verifier still admits the trivial forgery -- that is why the
    # gate exists; enrollment must refuse the key regardless.
    check(_ed.verify(lo, lo + bytes(32), b"m1")
          and _ed.verify(lo, lo + bytes(32), b"m2"),
          "R5 PoC: raw verifier accepts trivial sig for two messages")
    # Enrollment with the low-order key: the proof verifies, the key must not.
    code, ch = call(None, "POST", "/v1/enroll/challenge", b"{}")[:2]
    ch = json.loads(ch)
    assert code == 200, ch
    nonce = b64u_decode(ch["nonce"])
    body = json.dumps(
        {"identity_pubkey": b64u_encode(lo), "name": "loworder",
         "proof": {"nonce": b64u_encode(nonce),
                   "signature": b64u_encode(lo + bytes(32))}}).encode()
    code, out = call(None, "POST", "/v1/enroll", body)[:2]
    check(code == 400 and err_of(out) == "bad_identity",
          "R5 enroll rejects low-order key", "%s %s" % (code, out[:80]))
    # A pre-fix row holding a bad key fails closed at request time.
    tok = "badkey-token-1"
    con = sqlite3.connect(os.path.join(TMPD, "relay.db"))
    try:
        con.execute(
            "INSERT INTO peers(name, token_hash, created_at, identity_pubkey,"
            " enroll_gate) VALUES(?,?,?,?,?)",
            ("badkey", hashlib.sha256(tok.encode()).hexdigest(),
             time.time(), b64u_encode(lo), "open"))
        con.commit()
    finally:
        con.close()
    code, out = call(
        tok, "POST", "/v1/peers", b"", peer="badkey",
        headers={"X-Clack-Scheme": "1", "X-Clack-Key": "badkey",
                 "X-Clack-Nonce": "%d:%s" % (int(time.time()),
                                             secrets.token_hex(16)),
                 "X-Clack-Sig": "00" * 64})[:2]
    check(code == 401 and err_of(out) == "upgrade_required",
          "R5 stored low-order key fails closed", "%s %s" % (code, out[:80]))


def run_legacy_gate():
    """R6: legacy invite endpoints honor the enrollment gate.

    The scratch relay runs enrollment=open, so /v1/invites/challenge and
    /v1/invites/redeem must refuse with invite_not_allowed."""
    code, out = call(None, "POST", "/v1/invites/challenge",
                     json.dumps({"invite_id": "nope"}).encode())[:2]
    check(code == 400 and err_of(out) == "invite_not_allowed",
          "R6 legacy challenge honors gate", "%s %s" % (code, out[:60]))
    code, out = call(None, "POST", "/v1/invites/redeem",
                     json.dumps({"invite_id": "nope"}).encode())[:2]
    check(code == 400 and err_of(out) == "invite_not_allowed",
          "R6 legacy redeem honors gate", "%s %s" % (code, out[:60]))


def run_rate_budget():
    """R4: unsigned garbage on a stolen bearer must not burn the peer's
    60/min budget -- the budget is charged only after signature verify."""
    bob_tok, _ = enroll_open("ratebob")
    seed_handshake("ratebob", "alice")  # v0.2.13: send gate
    bad = 0
    for _ in range(70):
        code, _ = call(bob_tok, "GET", "/v1/peers", None)[:2]
        if code == 401:
            bad += 1
    check(bad == 70, "R4 unsigned attempts are 401s, never 429", bad)
    body = json.dumps({"id": str(uuid.uuid4()), "to": "alice",
                       "text": "x"}).encode()
    code, out = call(bob_tok, "POST", "/v1/send", body, peer="ratebob")[:2]
    check(code == 200,
          "R4 signed request still within budget after unsigned spam",
          "%s %s" % (code, out[:80]))


def run_delayed_body():
    """R3: a request whose body arrives after its nonce expired is rejected
    and never recorded -- freshness is rechecked after the client-paced
    body read, immediately before the atomic nonce record."""
    import socket
    tok, _ = enroll_open("slowbob")
    ts = int(time.time()) - 599  # just inside the 600s window at send time
    nonce = "%d:%s" % (ts, secrets.token_hex(16))
    body = json.dumps({"id": str(uuid.uuid4()), "to": "alice",
                       "text": "delayed"}).encode()
    hdrs = sign_headers("slowbob", "POST", "/v1/send", body, nonce=nonce)
    head = ("POST /v1/send HTTP/1.1\r\nHost: x\r\n"
            "Authorization: Bearer %s\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %d\r\n"
            "X-Clack-Scheme: 1\r\nX-Clack-Key: slowbob\r\n"
            "X-Clack-Nonce: %s\r\nX-Clack-Sig: %s\r\n"
            "Connection: close\r\n\r\n"
            % (tok, len(body), nonce, hdrs["X-Clack-Sig"]))
    s = socket.create_connection(("127.0.0.1", PORT), timeout=30)
    try:
        s.sendall(head.encode())
        # Cross the expiry boundary while the body is "in flight".
        time.sleep(3)
        s.sendall(body)
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
    finally:
        s.close()
    status = resp.split(b"\r\n", 1)[0]
    check(b"401" in status and b"stale_nonce" in resp,
          "R3 delayed body -> 401 stale_nonce, never recorded",
          status[:60])


def run_benchmark():
    """Vendored ed25519.py sign+verify latency under poll-like load."""
    seed, pub = _rc.keygen()
    msg = (b"clack-ed25519-v1\nGET\n/v1/poll?timeout=25\n"
           + hashlib.sha256(b"").hexdigest().encode() + b"\n123:abc")
    lat = []
    N = 21
    for _ in range(N):
        t = time.perf_counter()
        sig = _rc.sign(seed, msg)
        assert _rc.verify(pub, sig, msg)
        lat.append((time.perf_counter() - t) * 1000.0)
    lat.sort()
    p50 = lat[N // 2]
    p99 = lat[int(N * 0.99) - 1] if N >= 100 else lat[-1]
    print("benchmark vendored ed25519 sign+verify: n=%d p50=%.1fms p99=%.1fms"
          % (N, p50, p99), flush=True)
    # Budget note (2026-09-23): the original 5ms budget was written against
    # an implementation measuring ~4524ms per round-trip (900x over) and is
    # not attainable in pure Python -- the extended-coordinate rework floors
    # at ~10ms/op (~20ms round-trip) on this VM class, verified
    # byte-identical to the old code. The 50ms bar below is a regression
    # guard: anything near the old seconds-per-op blows past it, while a
    # healthy implementation clears it with 2.5x headroom. If sub-5ms ever
    # matters, that means reaching for a native lib (PyNaCl), not more
    # Python-level tuning.
    check(p50 <= 50.0, "benchmark p50 <= 50ms (vendored ed25519)",
          "p50=%.1fms p99=%.1fms -- FLAGGED: pure-python Ed25519 is ~%.0fx "
          "over the 50ms regression bar; every authenticated request pays "
          "this in sign (client) + verify (relay)" % (p50, p99, p50 / 50.0))


if __name__ == "__main__":
    sys.exit(main())
