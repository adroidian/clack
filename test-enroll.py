#!/usr/bin/env python3
"""Agent self-enrollment + reserved-names test suite (scratch only, never live).

Ships with the repo; test-relay.sh runs it as its final phase. Covers:
  HTTP API (runs 1-6): invite mint/enroll, PoW gate (+negatives), open gate,
    names, idempotency, invite negatives, rate limit, /join prompt, and
    reserved peer names (wrong key -> 403, pinned key claims, unreserved
    first-come, invalid config entries ignored).
  CLI end-to-end (run 7): relay-cli.py enroll on all three gates plus the
    non-TTY --yes guard.
"""
import base64
import hashlib
import importlib.util
import json
import os
import re
import secrets
import shutil
import sqlite3
import stat
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
PORT = int(os.environ.get("CLACK_TEST_PORT", "18996"))
BASE = "http://127.0.0.1:%d" % PORT
ALICE_TOKEN = "kr_test_" + secrets.token_urlsafe(24)
TMPD = tempfile.mkdtemp(prefix="clack-enroll-test-")
SRV = None
PASS = 0
FAIL = 0

# ed25519 from the CLI's vendored implementation (no external deps).
_spec = importlib.util.spec_from_file_location("relay_cli", CLI)
_rc = importlib.util.module_from_spec(_spec)
sys.argv = ["relay-cli.py"]  # keep argparse at import time quiet
_spec.loader.exec_module(_rc)

# v0.2.12: the scratch relays' config peer "alice" needs a signing keypair,
# wired into each test config via identity_pubkeys. One keypair is reused
# for every scratch instance (the token differs per run; the key is the
# same test identity).
_ALICE_SEED, _ALICE_PUB = _rc.keygen()
ALICE_PUB_B64 = _rc.b64u_encode(_ALICE_PUB)


def _sign_tuple(seed, peer_name, pub_b64):
    """Build the `sign` argument for api(): (seed, peer_name, pub_b64)."""
    return (seed, peer_name, pub_b64)


ALICE_SIGN = (_ALICE_SEED, "alice", ALICE_PUB_B64)

# Expected version is whatever relay.py declares (not hardcoded here).
_m = re.search(r'^VERSION\s*=\s*"([^"]+)"', open(RELAY_PY).read(), re.M)
EXPECTED_VERSION = _m.group(1) if _m else "?"
print("test-enroll: expecting relay version %s" % EXPECTED_VERSION, flush=True)


def check(cond, label, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("ok   %s" % label, flush=True)
    else:
        FAIL += 1
        print("FAIL %s -- %s" % (label, detail), flush=True)


def b64u_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def pow_lead_zero(digest):
    n = 0
    for byte in digest:
        if byte == 0:
            n += 8
        else:
            n += 8 - byte.bit_length()
            break
    return n


def _der_ints(buf):
    """Minimal DER parser: read a SEQUENCE of INTEGERs, return [ints].

    Only what we need to pull (n, e, d) out of a PKCS#1 RSAPrivateKey --
    not a general ASN.1 decoder."""
    pos = 0

    def read_len():
        nonlocal pos
        b = buf[pos]
        pos += 1
        if b < 0x80:
            return b
        n = b & 0x7f
        v = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
        return v

    assert buf[pos] == 0x30, "expected DER SEQUENCE"
    pos += 1
    end = pos + read_len()
    out = []
    while pos < end:
        assert buf[pos] == 0x02, "expected DER INTEGER"
        pos += 1
        ln = read_len()
        out.append(int.from_bytes(buf[pos:pos + ln], "big"))
        pos += ln
    return out


def _gen_test_rsa_key(tmpd):
    """Self-contained scratch RSA identity key for the TOFU tests.

    Generated fresh per run with the openssl CLI (1024-bit is plenty for a
    scratch relay) and returned as {"n","e","d"} hex, the shape the relay
    config expects. No checked-in key material, no /tmp dependencies."""
    pem = os.path.join(tmpd, "test-id.pem")
    der = os.path.join(tmpd, "test-id.der")
    subprocess.run(["openssl", "genrsa", "-out", pem, "1024"],
                   check=True, capture_output=True)
    # -traditional: OpenSSL 3 defaults `openssl rsa` DER output to PKCS#8;
    # we need the raw PKCS#1 RSAPrivateKey for the minimal DER parser.
    subprocess.run(["openssl", "rsa", "-in", pem, "-traditional",
                    "-outform", "DER", "-out", der],
                   check=True, capture_output=True)
    with open(der, "rb") as f:
        _ver, n, e, d = _der_ints(f.read())[:4]
    return {"n": format(n, "x"), "e": format(e, "x"), "d": format(d, "x")}


def start_server(enrollment="invite,pow,open", reserved_names=None):
    global SRV
    cfg = {
        "port": PORT,
        "peers": {"alice": ALICE_TOKEN},
        # v0.2.12: config peer alice must have a signing key or every
        # authenticated call 401s with upgrade_required.
        "identity_pubkeys": {"alice": ALICE_PUB_B64},
        "enrollment": enrollment,
        "pow_difficulty": 8,  # tiny so the harness solves fast
    }
    if reserved_names is not None:
        cfg["reserved_names"] = reserved_names
    with open(os.path.join(TMPD, "relay-config.json"), "w") as f:
        json.dump(cfg, f)
    log = open(os.path.join(TMPD, "srv.log"), "a")
    SRV = subprocess.Popen(
        [sys.executable, RELAY_PY],
        env=dict(os.environ, CLACK_RELAY_BASE=TMPD),
        stdout=log, stderr=subprocess.STDOUT)
    for _ in range(40):
        if SRV.poll() is not None:
            # Died during startup (e.g. strict config refusal): don't wait
            # out the full 10s polling a socket that will never open.
            raise RuntimeError("scratch server exited during startup")
        try:
            with urllib.request.urlopen(BASE + "/health", timeout=2) as r:
                h = json.loads(r.read().decode())
            if h.get("version") == EXPECTED_VERSION:
                return
        except Exception:
            pass
        time.sleep(0.25)
    raise RuntimeError("scratch server did not start")


def stop_server():
    global SRV
    if SRV and SRV.poll() is None:
        SRV.terminate()
        try:
            SRV.wait(timeout=5)
        except Exception:
            SRV.kill()
    SRV = None
    # Wait until the old listener is really gone (kills the restart race
    # that once produced a RemoteDisconnected in the harness).
    for _ in range(40):
        try:
            urllib.request.urlopen(BASE + "/health", timeout=2).close()
        except Exception:
            break
        time.sleep(0.25)


def api(method, path, body=None, token=None, accept=None, sign=None):
    """sign: optional (seed, peer_name, pub_b64) tuple -- adds the v0.2.12
    X-Clack-* Ed25519 request-signing headers via the CLI's sign_headers."""
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    if token:
        r.add_header("Authorization", "Bearer " + token)
    if data is not None:
        r.add_header("Content-Type", "application/json")
    if accept:
        r.add_header("Accept", accept)
    if sign is not None:
        seed, peer_name, pub_b64 = sign
        cfg = {"kind": _rc.IDENTITY_KIND, "peer_name": peer_name,
               "identity_pubkey": pub_b64,
               "identity_privkey": _rc.b64u_encode(seed)}
        for k, v in _rc.sign_headers(cfg, method, path, data).items():
            r.add_header(k, v)
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            raw = resp.read().decode()
            ctype = resp.headers.get("Content-Type", "")
            return resp.status, (json.loads(raw) if "json" in ctype else raw), ctype
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read().decode())
        except Exception:
            payload = {"error": "http_%d" % e.code}
        return e.code, payload, ""
    except Exception as e:
        print("!!! api(%s %s) raised %r; server log tail:" % (method, path, e))
        try:
            with open(os.path.join(TMPD, "srv.log")) as f:
                print("".join(f.readlines()[-30:]))
        except Exception as le:
            print("(could not read srv.log: %r)" % le)
        raise


def db_conn():
    return sqlite3.connect(os.path.join(TMPD, "relay.db"))


def db_exec(sql, params=()):
    con = db_conn()
    try:
        con.execute(sql, params)
        con.commit()
    finally:
        con.close()


def db_get(sql, params=()):
    con = db_conn()
    try:
        return con.execute(sql, params).fetchone()
    finally:
        con.close()


def fresh_key():
    seed, pub = _rc.keygen()
    return seed, pub, b64u_encode(pub)


def get_challenge(invite_id=None):
    code, ch, _ = api("POST", "/v1/enroll/challenge",
                      {"invite_id": invite_id} if invite_id else {})
    assert code == 200, "challenge failed: %r" % (ch,)
    return ch


def solve_pow(chal_raw, difficulty):
    while True:
        cand = secrets.token_bytes(16)
        if pow_lead_zero(hashlib.sha256(chal_raw + cand).digest()) >= difficulty:
            return cand


def enroll_agent(name=None, gate=None, invite_id=None, secret=None, key=None):
    """Happy-path enrollment. Returns (code, out, pub_b64, seed).
    `key` is an optional (seed, pub, pub_b64) tuple; otherwise fresh."""
    if key is None:
        seed, pub, pub_b64 = fresh_key()
    else:
        seed, pub, pub_b64 = key
    ch = get_challenge(invite_id if gate == "invite" else None)
    body = {"identity_pubkey": pub_b64}
    if name:
        body["name"] = name
    if ch["gate"] == "pow":
        chal_raw = b64u_decode(ch["challenge"])
        pn = solve_pow(chal_raw, int(ch["difficulty"]))
        sig = _rc.sign(seed, chal_raw + pn + pub)
        body["pow_nonce"] = b64u_encode(pn)
        proof_nonce = chal_raw  # server hashes presented + pow_nonce itself
    elif gate == "invite":
        nonce = b64u_decode(ch["nonce"])
        sig = _rc.sign(seed, nonce + invite_id.encode("utf-8") + pub)
        body["invite_id"] = invite_id
        body["secret"] = secret
        proof_nonce = nonce
    else:
        nonce = b64u_decode(ch["nonce"])
        sig = _rc.sign(seed, nonce + pub)
        proof_nonce = nonce
    body["proof"] = {"nonce": b64u_encode(proof_nonce),
                     "signature": b64u_encode(sig)}
    code, out, _ = api("POST", "/v1/enroll", body)
    return code, out, pub_b64, seed


def run_http_tests():
    # ============ RUN 1: all gates (invite, pow) ============
    start_server()
    try:
        # --- T1: mint invite as alice
        code, mint, _ = api("POST", "/v1/invites/mint",
                            {"expiry_seconds": 3600, "max_uses": 1},
                            token=ALICE_TOKEN, sign=ALICE_SIGN)
        check(code == 200 and "invite_id" in mint, "T1 mint invite as alice", mint)
        link = mint.get("link", "")
        iid = mint["invite_id"]
        # v0.2.12: provenance is identity-based (config peer alice carries
        # an Ed25519 identity now), so by= carries alice's identity pubkey,
        # not the mutable peer name. Human-readable inviter_name is exposed
        # on the enroll response instead (checked in T2 below).
        check("i=%s" % iid in link and "by=%s" % ALICE_PUB_B64 in link,
              "T1 link carries invite id + inviter identity", link[:80])

        # --- T2: invite-gate enroll
        code, out, pub_b64, seed = enroll_agent(
            name="inviteagent", gate="invite", invite_id=iid, secret="WRONG")
        # (sanity: wrong secret must fail before the real attempt)
        check(code == 400 and out.get("error") == "bad_secret",
              "T2 wrong secret rejected first", out)
        code, out, pub_b64, seed = enroll_agent(
            name="inviteagent", gate="invite", invite_id=iid,
            secret=mint["link"].split("k=")[1].split("&")[0])
        check(code == 200 and out.get("peer_name") == "inviteagent",
              "T2 invite-gate enroll -> 200, chosen name", out)
        check(out.get("contract_version") == EXPECTED_VERSION,
              "T2 contract_version %s" % EXPECTED_VERSION, out)
        tok = out.get("service_token")
        code, peers, _ = api("GET", "/v1/peers", token=tok,
                             sign=_sign_tuple(seed, "inviteagent", pub_b64))
        check(code == 200 and "inviteagent" in peers.get("peers", []),
              "T2 token authenticates (/v1/peers)", peers)
        row = db_get("SELECT invited_by FROM peers WHERE name=?",
                     ("inviteagent",))
        # v0.2.12: invited_by stores the inviter's stable Ed25519 identity,
        # not the mutable peer name (names can be reassigned; see R6/R7).
        check(row and row[0] == ALICE_PUB_B64,
              "T2 invited_by provenance = alice identity", row)
        check(out.get("inviter_name") == "alice",
              "T2 inviter_name = alice", out.get("inviter_name"))
        uses = db_get("SELECT uses FROM invites WHERE invite_id=?", (iid,))
        check(uses and uses[0] == 1, "T2 invite use consumed", uses)

        # --- T3: PoW gate
        code, out, pub_b64, seed = enroll_agent(name="powagent", gate="pow")
        check(code == 200 and out.get("enrollment") == "pow",
              "T3 pow-gate enroll -> 200", out)
        row = db_get("SELECT invited_by FROM peers WHERE name=?", ("powagent",))
        check(row and row[0] == "pow", "T3 invited_by provenance = pow", row)

        # wrong pow_nonce -> bad_pow
        seed2, pub2, pub_b64_2 = fresh_key()
        ch = get_challenge()
        chal_raw = b64u_decode(ch["challenge"])
        bad_pn = b"\x00" * 16  # overwhelmingly unlikely to meet difficulty 8
        assert pow_lead_zero(hashlib.sha256(chal_raw + bad_pn).digest()) < 8
        sig = _rc.sign(seed2, chal_raw + bad_pn + pub2)
        code, out, _ = api("POST", "/v1/enroll", {
            "identity_pubkey": pub_b64_2,
            "pow_nonce": b64u_encode(bad_pn),
            "proof": {"nonce": b64u_encode(chal_raw),
                      "signature": b64u_encode(sig)}})
        check(code == 400 and out.get("error") == "bad_pow",
              "T3 wrong pow_nonce -> bad_pow", out)

        # tampered signature -> bad_proof
        seed3, pub3, pub_b64_3 = fresh_key()
        ch = get_challenge()
        chal_raw = b64u_decode(ch["challenge"])
        pn = solve_pow(chal_raw, int(ch["difficulty"]))
        sig = _rc.sign(seed3, chal_raw + pn + pub3)
        bad_sig = bytearray(sig)
        bad_sig[0] ^= 1
        code, out, _ = api("POST", "/v1/enroll", {
            "identity_pubkey": pub_b64_3,
            "pow_nonce": b64u_encode(pn),
            "proof": {"nonce": b64u_encode(chal_raw),
                      "signature": b64u_encode(bytes(bad_sig))}})
        check(code == 400 and out.get("error") == "bad_proof",
              "T3 tampered signature -> bad_proof", out)
    finally:
        stop_server()

    # ============ RUN 2: genuine open gate (open-only config) ============
    start_server(enrollment="open")
    try:
        # --- T4: open enrollment succeeds, inviter null
        code, out, pub_b64, seed = enroll_agent(name="openagent", gate="open")
        check(code == 200 and out.get("enrollment") == "open",
              "T4 open-gate enroll -> 200, inviter null", out)
        row = db_get("SELECT invited_by FROM peers WHERE name=?",
                     ("openagent",))
        check(row and row[0] == "open" and out.get("inviter_name") is None,
              "T4 invited_by provenance = open", (row, out.get("inviter_name")))

        # --- T5: names
        code, out, _, _ = enroll_agent(name="dupname", gate="open")
        check(code == 200 and out.get("peer_name") == "dupname",
              "T5 requested name assigned", out)
        code, out2, _, _ = enroll_agent(name="dupname", gate="open")
        pn2 = out2.get("peer_name", "")
        check(code == 200 and pn2.startswith("dupname-") and len(pn2) == 12,
              "T5 duplicate -> dupname-xxxx", pn2)
        code, out3, _, _ = enroll_agent(name="!!bad name!!", gate="open")
        pn3 = out3.get("peer_name", "")
        check(code == 200 and pn3.startswith("guest-") and len(pn3) == 14,
              "T5 invalid name -> guest-xxxxxxxx", pn3)
        code, out4, _, _ = enroll_agent(gate="open")
        pn4 = out4.get("peer_name", "")
        check(code == 200 and pn4.startswith("guest-") and len(pn4) == 14,
              "T5 omitted name -> guest-xxxxxxxx", pn4)
        code, out5, _, _ = enroll_agent(name="guest-hacker", gate="open")
        pn5 = out5.get("peer_name", "")
        check(code == 200 and pn5.startswith("guest-") and pn5 != "guest-hacker",
              "T5 guest- prefix reserved -> guest-xxxxxxxx", pn5)

        # --- T6: idempotency (same pubkey re-enrolls to the same peer)
        code, out6, pub_b64_6, seed6 = enroll_agent(name="idempotent", gate="open")
        name6 = out6.get("peer_name")
        tok6 = out6.get("service_token")
        ch = get_challenge()
        nonce = b64u_decode(ch["nonce"])
        sig = _rc.sign(seed6, nonce + b64u_decode(pub_b64_6))
        code, out7, _ = api("POST", "/v1/enroll", {
            "identity_pubkey": pub_b64_6, "name": "idempotent",
            "proof": {"nonce": b64u_encode(nonce),
                      "signature": b64u_encode(sig)}})
        check(code == 200 and out7.get("peer_name") == name6,
              "T6 re-enroll same pubkey -> same peer name", out7)
        tok7 = out7.get("service_token")
        check(tok7 and tok7 != tok6, "T6 fresh token issued", "")
        code, peers, _ = api("GET", "/v1/peers", token=tok7,
                             sign=_sign_tuple(seed6, name6, pub_b64_6))
        check(code == 200, "T6 new token works", code)
        code, out_old, _ = api("GET", "/v1/peers", token=tok6,
                               sign=_sign_tuple(seed6, name6, pub_b64_6))
        check(code == 401, "T6 old token dead -> 401", code)
    finally:
        stop_server()

    # ============ RUN 3: invite negatives + rate-limit isolation ============
    start_server()
    try:
        # --- T8: bad secret
        code, mint, _ = api("POST", "/v1/invites/mint",
                            {"expiry_seconds": 3600, "max_uses": 1},
                            token=ALICE_TOKEN, sign=ALICE_SIGN)
        iid2 = mint["invite_id"]
        code, out, _, _ = enroll_agent(name="neg1", gate="invite",
                                       invite_id=iid2, secret="wrong-secret")
        check(code == 400 and out.get("error") == "bad_secret",
              "T8 bad secret -> bad_secret", out)

        # --- T8: expired invite -> 410 at challenge time
        code, mint, _ = api("POST", "/v1/invites/mint",
                            {"expiry_seconds": 3600, "max_uses": 1},
                            token=ALICE_TOKEN, sign=ALICE_SIGN)
        iid3 = mint["invite_id"]
        db_exec("UPDATE invites SET exp=? WHERE invite_id=?",
                (time.time() - 10, iid3))
        code, out, _ = api("POST", "/v1/enroll/challenge", {"invite_id": iid3})
        check(code == 410 and out.get("error") == "invite_unusable",
              "T8 expired invite -> 410 invite_unusable", (code, out))
    finally:
        stop_server()

    # ============ RUN 4: rate limit on a pristine server ============
    start_server()
    try:
        # --- T7: 11 rapid enrolls; budget is 10/min per IP
        results = []
        for i in range(11):
            code, out, _, _ = enroll_agent(name="rl%d" % i, gate="open")
            results.append((code, out.get("error") if code != 200 else "ok"))
        n200 = sum(1 for c, _ in results if c == 200)
        n429 = [e for c, e in results if c == 429]
        check(n200 == 10 and len(n429) == 1 and n429[0] == "rate_limited",
              "T7 burst 11 -> 10x200 then 429 rate_limited", results)
    finally:
        stop_server()

    # ============ RUN 5: /join plain-text prompt ============
    start_server()
    try:
        # --- T9
        code, body, ctype = api("GET", "/join", accept="text/plain")
        check(code == 200 and "text/plain" in ctype,
              "T9 /join text/plain -> 200 text/plain", (code, ctype))
        check("Join Clack" in body and "The Agent Network" in body,
              "T9 prompt header present", body[:60])
        check(BASE in body, "T9 prompt contains relay base URL", "")
        check("invite" in body and "pow" in body and "open" in body,
              "T9 prompt lists enabled gates", "")
        check("alice" not in body and "kr_test_" not in body,
              "T9 no peer names/secrets leaked", "")
        code, html, ctype = api("GET", "/join")
        check(code == 200 and "text/html" in ctype and "<html" in html.lower(),
              "T9 HTML branch untouched", ctype)
        code, js, ctype = api("GET", "/join", accept="application/json")
        check(code == 200 and js.get("protocol_version") == EXPECTED_VERSION,
              "T9 JSON branch untouched (v%s)" % EXPECTED_VERSION,
              js.get("protocol_version"))
    finally:
        stop_server()

    # ============ RUN 6: reserved peer names ============
    pinned_seed, pinned_pub, pinned_b64 = fresh_key()
    other_seed, other_pub, other_b64 = fresh_key()
    start_server(enrollment="open,pow",
                 reserved_names={"pinned-agent": pinned_b64})
    try:
        # --- R1: wrong key on a reserved name -> 403, no peer created
        code, out, squatter_b64, _ = enroll_agent(name="pinned-agent",
                                                  gate="open")
        check(code == 403 and out.get("error") == "reserved_name",
              "R1 wrong key on reserved name -> 403 reserved_name",
              (code, out))
        row = db_get("SELECT 1 FROM peers WHERE identity_pubkey=?",
                     (squatter_b64,))
        check(row is None, "R1 rejected enroll creates no peer row", row)
        row = db_get("SELECT 1 FROM peers WHERE name=?", ("pinned-agent",))
        check(row is None, "R1 reserved name stays unclaimed", row)

        # --- R2: the pinned key claims the reserved name
        code, out, _, _ = enroll_agent(name="pinned-agent", gate="open",
                                       key=(pinned_seed, pinned_pub,
                                            pinned_b64))
        check(code == 200 and out.get("peer_name") == "pinned-agent",
              "R2 pinned key claims reserved name -> 200 exact name", out)
        tok = out.get("service_token")
        code, peers, _ = api("GET", "/v1/peers", token=tok,
                             sign=_sign_tuple(pinned_seed, "pinned-agent",
                                              pinned_b64))
        check(code == 200 and "pinned-agent" in peers.get("peers", []),
              "R2 pinned token authenticates", peers)

        # --- R2b: pinned key re-enrolls -> same name (find-or-create by
        # identity is untouched by reservations)
        code, out2, _, _ = enroll_agent(name="pinned-agent", gate="open",
                                        key=(pinned_seed, pinned_pub,
                                             pinned_b64))
        check(code == 200 and out2.get("peer_name") == "pinned-agent",
              "R2b pinned re-enroll -> same name", out2)

        # --- R3: unreserved names keep first-come behavior
        code, out, _, _ = enroll_agent(name="free-agent", gate="open")
        check(code == 200 and out.get("peer_name") == "free-agent",
              "R3 unreserved name -> first-come 200", out)

        # --- R4: reservations hold on the pow gate too
        code, out, _, _ = enroll_agent(name="pinned-agent", gate="pow")
        check(code == 403 and out.get("error") == "reserved_name",
              "R4 pow gate wrong key -> 403 reserved_name", (code, out))

    finally:
        stop_server()

    # ============ RUN 6b: strict config -- malformed reserved_names refuse
    # startup loudly instead of being silently ignored.
    bad_cfgs = [
        (["not", "a", "dict"], "non-dict section"),
        ({"bad name!": pinned_b64}, "invalid name charset"),
        ({"guest-evil": pinned_b64}, "guest- prefix"),
        ({"badkey": "not-a-key"}, "malformed key"),
        ({"shortkey": b64u_encode(b"short")}, "wrong key length"),
    ]
    log_path = os.path.join(TMPD, "srv.log")
    for bad, label in bad_cfgs:
        mark = os.path.getsize(log_path) if os.path.exists(log_path) else 0
        try:
            start_server(enrollment="open", reserved_names=bad)
        except RuntimeError:
            check(True, "R5 strict refuses startup: %s" % label)
            with open(log_path) as f:
                f.seek(mark)
                tail = f.read()
            check("reserved_names" in tail,
                  "R5 refusal names the problem: %s" % label, tail[-200:])
        else:
            check(False, "R5 strict refuses startup: %s" % label,
                  "server started, expected refusal")
            stop_server()

    # ============ RUN 6c: grandfathering -- a name reserved AFTER an
    # identity enrolled stays with the enrolled identity; only NEW
    # enrollments are gated.
    leg_seed, leg_pub, leg_b64 = fresh_key()
    start_server(enrollment="open")  # no reservations yet
    try:
        code, out, _, _ = enroll_agent(name="legacy", gate="open",
                                       key=(leg_seed, leg_pub, leg_b64))
        assert code == 200 and out.get("peer_name") == "legacy", out
    finally:
        stop_server()
    start_server(enrollment="open", reserved_names={"legacy": other_b64})
    try:
        code, out, _, _ = enroll_agent(name="legacy", gate="open",
                                       key=(leg_seed, leg_pub, leg_b64))
        check(code == 200 and out.get("peer_name") == "legacy",
              "R6 grandfather: existing enrollment keeps its name", out)
        code, out, _, _ = enroll_agent(name="legacy", gate="open")
        check(code == 403 and out.get("error") == "reserved_name",
              "R6 grandfather: new key still rejected", (code, out))
    finally:
        stop_server()

    # ============ RUN 6d: no retroactive eviction -- if a squatter holds a
    # name when it becomes reserved, the squatter keeps it and the pinned
    # key gets the normal suffixed fallback. Telemetry surfaces it; the
    # operator decides. (Fresh pinned key: the RUN 6 pinned identity is
    # already enrolled as "pinned-agent" in this scratch DB, and re-enroll
    # would just return that name -- correctly, per R6.)
    v_seed, v_pub, v_b64 = fresh_key()
    start_server(enrollment="open")  # no reservations yet
    try:
        code, out, _, _ = enroll_agent(name="victim", gate="open")
        assert code == 200 and out.get("peer_name") == "victim", out
    finally:
        stop_server()
    start_server(enrollment="open", reserved_names={"victim": v_b64})
    try:
        code, out, _, _ = enroll_agent(name="victim", gate="open",
                                       key=(v_seed, v_pub, v_b64))
        pn = out.get("peer_name", "")
        check(code == 200 and pn.startswith("victim-") and pn != "victim",
              "R7 squatter keeps name; pinned key gets suffixed fallback", pn)
    finally:
        stop_server()


def run_cli_tests():
    """Spec item 10: CLI `enroll` end-to-end on scratch, all three gates."""
    cli_tmpd = tempfile.mkdtemp(prefix="clack-cli-enroll-")
    servers = []

    def start_relay(port, enrollment, token):
        d = os.path.join(cli_tmpd, "r%d" % port)
        os.makedirs(d)
        cfg = {"port": port, "peers": {"alice": token},
               # v0.2.12: alice needs a signing key for authed calls.
               "identity_pubkeys": {"alice": ALICE_PUB_B64},
               # v0.2.13 F4: the CLI fails closed when the relay has no
               # verifiable identity, so scratch relays must provision one
               # (as run_tofu_tests already does).
               "identity_key": _gen_test_rsa_key(d),
               "enrollment": enrollment, "pow_difficulty": 8}
        with open(os.path.join(d, "relay-config.json"), "w") as f:
            json.dump(cfg, f)
        log = open(os.path.join(d, "srv.log"), "a")
        p = subprocess.Popen([sys.executable, RELAY_PY],
                             env=dict(os.environ, CLACK_RELAY_BASE=d),
                             stdout=log, stderr=subprocess.STDOUT)
        base = "http://127.0.0.1:%d" % port
        for _ in range(40):
            try:
                with urllib.request.urlopen(base + "/health", timeout=2) as r:
                    if json.loads(r.read().decode()).get("version") == EXPECTED_VERSION:
                        return p, base
            except Exception:
                pass
            time.sleep(0.25)
        raise RuntimeError("relay %d did not start" % port)

    def authed(base, cli_cfg_path, path):
        """GET path with the CLI identity config's bearer + v0.2.12 Ed25519
        request signature (the CLI's own sign_headers over the key file)."""
        c = json.load(open(cli_cfg_path))
        hdrs = _rc.sign_headers(c, "GET", path, None)
        assert hdrs, "CLI config cannot sign: %s" % cli_cfg_path
        r = urllib.request.Request(base + path)
        r.add_header("Authorization", "Bearer " + c["service_token"])
        for k, v in hdrs.items():
            r.add_header(k, v)
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode())

    try:
        # ---- invite gate ----
        p, base = start_relay(18997, "invite,pow,open",
                              "kr_test_" + secrets.token_urlsafe(24))
        servers.append(p)
        token = json.load(open(os.path.join(cli_tmpd, "r18997",
                                             "relay-config.json")))["peers"]["alice"]
        rq = urllib.request.Request(
            base + "/v1/invites/mint",
            data=json.dumps({"expiry_seconds": 600, "max_uses": 1}).encode(),
            method="POST")
        rq.add_header("Authorization", "Bearer " + token)
        rq.add_header("Content-Type", "application/json")
        # v0.2.12: mint is authenticated -> must be signed as alice.
        for k, v in _rc.sign_headers(
                {"kind": _rc.IDENTITY_KIND, "peer_name": "alice",
                 "identity_pubkey": ALICE_PUB_B64,
                 "identity_privkey": _rc.b64u_encode(_ALICE_SEED)},
                "POST", "/v1/invites/mint", rq.data).items():
            rq.add_header(k, v)
        with urllib.request.urlopen(rq, timeout=10) as resp:
            mint = json.loads(resp.read().decode())
        secret = mint["link"].split("k=")[1].split("&")[0]
        cfg1 = os.path.join(cli_tmpd, "cli-invite.json")
        r = subprocess.run(
            [sys.executable, CLI, "--config", cfg1, "enroll", "--name", "cliinvite",
             "--invite-id", mint["invite_id"], "--secret", secret,
             "--relay", base, "--yes"],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120)
        check(r.returncode == 0, "CLI invite-gate enroll exit 0", r.stderr[-500:])
        c1 = json.load(open(cfg1))
        check(c1.get("peer_name") == "cliinvite" and c1.get("service_token"),
              "CLI invite config saved with token", c1.get("peer_name"))
        check(oct(os.stat(cfg1).st_mode & 0o777) == "0o600",
              "CLI invite config mode 600", oct(os.stat(cfg1).st_mode))
        code, peers = authed(base, cfg1, "/v1/peers")
        check(code == 200 and "cliinvite" in peers["peers"],
              "CLI invite token authenticates", peers)

        # ---- pow gate ----
        p, base = start_relay(18998, "pow", "kr_test_" + secrets.token_urlsafe(24))
        servers.append(p)
        cfg2 = os.path.join(cli_tmpd, "cli-pow.json")
        r = subprocess.run(
            [sys.executable, CLI, "--config", cfg2, "enroll", "--name", "clipow",
             "--relay", base, "--yes"],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120)
        check(r.returncode == 0, "CLI pow-gate enroll exit 0", r.stderr[-500:])
        c2 = json.load(open(cfg2))
        code, peers = authed(base, cfg2, "/v1/peers")
        check(code == 200 and "clipow" in peers["peers"],
              "CLI pow token authenticates", peers)

        # ---- open gate ----
        p, base = start_relay(18999, "open", "kr_test_" + secrets.token_urlsafe(24))
        servers.append(p)
        cfg3 = os.path.join(cli_tmpd, "cli-open.json")
        r = subprocess.run(
            [sys.executable, CLI, "--config", cfg3, "enroll", "--name", "cliopen",
             "--relay", base, "--yes"],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120)
        check(r.returncode == 0, "CLI open-gate enroll exit 0", r.stderr[-500:])
        c3 = json.load(open(cfg3))
        code, peers = authed(base, cfg3, "/v1/peers")
        check(code == 200 and "cliopen" in peers["peers"],
              "CLI open token authenticates", peers)

        # ---- non-TTY without --yes fails cleanly ----
        cfg4 = os.path.join(cli_tmpd, "cli-noyes.json")
        r = subprocess.run(
            [sys.executable, CLI, "--config", cfg4, "enroll", "--name", "nope",
             "--relay", base],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)
        check(r.returncode != 0 and "Traceback" not in r.stderr
              and "--yes" in r.stderr,
              "CLI non-TTY without --yes: clean error", r.stderr[-300:])
    finally:
        for p in servers:
            try:
                p.terminate()
                p.wait(timeout=5)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        if FAIL:
            print("KEEPING scratch dir: %s" % cli_tmpd)
        else:
            shutil.rmtree(cli_tmpd, ignore_errors=True)


def run_tofu_tests():
    """Spec: stable-key TOFU. Fingerprint is over the relay's public key
    (stable), never over the per-nonce signature; signature verifies."""
    tofu_tmpd = tempfile.mkdtemp(prefix="clack-tofu-")
    srv = None
    try:
        idkey = _gen_test_rsa_key(tofu_tmpd)
        d = os.path.join(tofu_tmpd, "r1")
        os.makedirs(d)
        cfg = {"port": 18994, "peers": {"alice": ALICE_TOKEN},
               "enrollment": "open", "pow_difficulty": 8,
               "identity_key": idkey}
        with open(os.path.join(d, "relay-config.json"), "w") as f:
            json.dump(cfg, f)
        log = open(os.path.join(d, "srv.log"), "a")
        srv = subprocess.Popen(
            [sys.executable, RELAY_PY],
            env=dict(os.environ, CLACK_RELAY_BASE=d),
            stdout=log, stderr=subprocess.STDOUT)
        base = "http://127.0.0.1:18994"
        for _ in range(40):
            try:
                with urllib.request.urlopen(base + "/health", timeout=2) as r:
                    if json.loads(r.read().decode()).get("version") == EXPECTED_VERSION:
                        break
            except Exception:
                pass
            time.sleep(0.25)

        def identity(nonce):
            with urllib.request.urlopen(
                    base + "/v1/identity?nonce=" + nonce, timeout=10) as r:
                return json.loads(r.read().decode())

        # T1: public_key present
        i1 = identity(secrets.token_hex(16))
        pub = i1.get("public_key")
        check(isinstance(pub, dict) and "n" in pub and "e" in pub,
              "TOFU public_key present in /v1/identity", str(pub)[:60])

        # T2: fingerprint stable across different nonces
        i2 = identity(secrets.token_hex(16))
        fp1 = _rc.relay_identity_fingerprint(i1["public_key"])
        fp2 = _rc.relay_identity_fingerprint(i2["public_key"])
        check(fp1 == fp2 and fp1.startswith("sha256:") and len(fp1) == 23,
              "TOFU fingerprint stable across nonces", "%s vs %s" % (fp1, fp2))
        # ... and NOT equal to hashing either per-nonce signature
        sigfp1 = "sha256:" + hashlib.sha256(
            base64.b64decode(i1["signature"])).hexdigest()[:16]
        check(sigfp1 != fp1,
              "TOFU fingerprint is not the signature hash", sigfp1)

        # T3: signature verifies against the presented key; tampered fails
        ok = _rc.relay_identity_verify(
            i1["public_key"], i1["nonce"], i1["signature"])
        check(ok, "TOFU nonce signature verifies (pure-stdlib RSA)")
        bad_sig = base64.b64encode(
            bytearray(base64.b64decode(i1["signature"]))).decode()
        # flip a byte in the middle of the signature
        raw = bytearray(base64.b64decode(i1["signature"]))
        raw[len(raw) // 2] ^= 0x01
        bad = base64.b64encode(bytes(raw)).decode()
        check(not _rc.relay_identity_verify(
            i1["public_key"], i1["nonce"], bad),
              "TOFU tampered signature rejected")

        # T4: CLI enroll pins the fingerprint; wrong pin aborts
        cfg_path = os.path.join(tofu_tmpd, "tofu-cli.json")
        r = subprocess.run(
            [sys.executable, CLI, "--config", cfg_path, "enroll",
             "--name", "tofupeer", "--relay", base, "--yes"],
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=120)
        check(r.returncode == 0, "TOFU CLI enroll exit 0", r.stderr[-500:])
        c = json.load(open(cfg_path))
        check(c.get("relay_identity_fingerprint") == fp1,
              "TOFU pin saved in identity config", c.get("relay_identity_fingerprint"))
        # wrong pin -> check_relay_identity must abort (SystemExit)
        wrong = dict(c, relay_identity_fingerprint="sha256:deadbeefdeadbeef")
        try:
            _rc.check_relay_identity(base, wrong)
            check(False, "TOFU wrong pin aborts", "no SystemExit raised")
        except SystemExit:
            check(True, "TOFU wrong pin aborts")
        # right pin -> returns the fingerprint
        got = _rc.check_relay_identity(base, c)
        check(got == fp1, "TOFU matching pin returns fingerprint", got)
    finally:
        if srv:
            try:
                srv.terminate()
                srv.wait(timeout=5)
            except Exception:
                try:
                    srv.kill()
                except Exception:
                    pass
        if FAIL:
            print("KEEPING scratch dir: %s" % tofu_tmpd)
        else:
            shutil.rmtree(tofu_tmpd, ignore_errors=True)


def run_telemetry_tests():
    """Spec: per-peer enrollment telemetry recorded at enroll/poll/send."""
    # The HTTP runs leave the scratch server stopped; start a fresh one
    # with only the open gate so the enrollment gate is deterministic.
    start_server(enrollment="open")
    try:
        _run_telemetry_tests_inner()
    finally:
        stop_server()


def _run_telemetry_tests_inner():
    db_path = os.path.join(TMPD, "relay.db")

    def peer_row(name):
        con = sqlite3.connect(db_path)
        try:
            return con.execute(
                "SELECT enroll_gate, enroll_ip, created_at, last_poll_at, last_send_at"
                " FROM peers WHERE name=?", (name,)).fetchone()
        finally:
            con.close()

    # T1: config peer has enroll_gate='config'
    row = peer_row("alice")
    check(row is not None and row[0] == "config",
          "telemetry config peer gate='config'", row)

    # T2: open-gate enroll records gate + ip, no activity yet
    code, out, pub_b64, seed = enroll_agent(name="telepeer", gate="open")
    check(code == 200, "telemetry enroll ok", out)
    tok = out.get("service_token")
    # v0.2.13: /v1/send requires mutual consent. This suite tests
    # enrollment telemetry, not handshakes (see test-handshake.py), so
    # seed the ACTIVE row directly, mirroring caller_identity().
    con = sqlite3.connect(db_path)
    con.execute("PRAGMA busy_timeout=5000")
    r = con.execute("SELECT identity_pubkey FROM peers WHERE name='alice'").fetchone()
    alice_id = r[0] if r and r[0] else "alice"
    a, b = sorted([alice_id, pub_b64])
    now = time.time()
    con.execute(
        """INSERT OR REPLACE INTO handshakes(
               a_identity, b_identity, status, created_at,
               pending_expires_at, expires_at, last_activity,
               via_link_id, redeemer_identity, generation)
           VALUES(?, ?, 'active', ?, NULL, NULL, ?, 'test-enroll', NULL, 0)""",
        (a, b, now, now))
    con.commit()
    con.close()
    row = peer_row("telepeer")
    check(row is not None and row[0] == "open",
          "telemetry enroll_gate='open'", row)
    check(row is not None and row[1] in ("127.0.0.1", "::1"),
          "telemetry enroll_ip recorded", row[1] if row else None)
    check(row is not None and row[2] and row[3] is None and row[4] is None,
          "telemetry no activity yet at enroll", row)

    # T3: poll records last_poll_at
    code, msgs, _ = api("GET", "/v1/poll?timeout=1", token=tok,
                         sign=_sign_tuple(seed, "telepeer", pub_b64))
    check(code == 200, "telemetry poll ok", code)
    row = peer_row("telepeer")
    check(row is not None and row[3],
          "telemetry last_poll_at recorded", row[3] if row else None)

    # T4: send records last_send_at
    mid = str(uuid.uuid4())
    code, sout, _ = api("POST", "/v1/send",
                        {"id": mid, "to": "alice", "text": "telemetry ping"},
                        token=tok,
                        sign=_sign_tuple(seed, "telepeer", pub_b64))
    check(code == 200 and sout.get("accepted"),
          "telemetry send ok", sout)
    row = peer_row("telepeer")
    check(row is not None and row[4],
          "telemetry last_send_at recorded", row[4] if row else None)


def main():
    run_http_tests()
    run_cli_tests()
    run_tofu_tests()
    run_telemetry_tests()
    print("----\npass=%d fail=%d" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    finally:
        stop_server()
        if FAIL:
            print("KEEPING scratch dir for forensics: %s" % TMPD)
        else:
            shutil.rmtree(TMPD, ignore_errors=True)
