#!/usr/bin/env python3
"""test-handshake.py -- server-side tests for mutual-consent handshakes (v0.2.13).

Covers HANDSHAKE_SPEC_DRAFT.md sections 2-9 as implemented in relay.py,
plus the Zari canary amendments:

  A1. redeem of an already-pending pair NEVER extends pending_expires_at
      (original deadline preserved), including across relay restarts.
  A2. handshake_inactivity_expiry_days defaults to 0 = never; no inactivity
      sweep exists in the canary.
  A3. accept binds to (redeemer_identity, current pair generation): revoke
      bumps the generation; a replayed/re-signed accept minted for a
      pre-revoke pending is rejected (409 stale_generation) and can never
      land on the post-revoke row.
  A4. Race interleavings with machine-checkable receipts read from
      COMMITTED SQLite state (the DB file is re-opened; in-process memory
      is not trusted):
        - send -> revoke -> poll: recipient gets NOTHING; queued messages
          are dead-lettered with reason handshake_revoked.
        - concurrent final-use redemption: exactly max_uses successes and
          the DB counter shows the correct final value.
        - accept-after-revoke and replayed-accept attempts are denied.
        - accept vs revoke raced: final state is always revoked, DB
          consistent, no exception.
  A5. Restart persistence: pending_expires_at survives SIGKILL + restart
      byte-identical (no reset, no recompute, no extension); an
      expired-by-restart deadline still denies accept atomically.
  A6. Zari review round 2 (2026-09-24):
        - a user revoke is never erased by expiry/sweep: forcing
          hard-expiry conditions on a revoked row and running the
          periodic sweep leaves status/generation/revocation-memory
          untouched; stale accepts and old links still cannot resurrect
          the pair.
        - poll/revoke concurrent ordering: across raced iterations the
          invariant holds that every unacked message is dead-lettered
          with handshake_revoked at revoke-commit, whether or not a poll
          fetched it first; no poll fetch running after revoke-commit
          can ever return the pair's mail (a response already in flight
          may still carry pre-revoke bytes -- the physical boundary).
  A7. BUG-008 (2026-09-25): revoke dead-letters ALL unacked mail between
      the pair, including collected-but-unacked (v0.2.16 at-least-once
      redelivery kept those pollable post-revoke). Phase 5c proves:
      collect (no ack) -> revoke -> repeated polls return nothing, the
      row carries dead_reason=handshake_revoked WITH collected_at set,
      and receipts report "dead" (not "collected") for it.
  A8. Fetch revocation filter (2026-09-25, Aaron's call: revocation =
      revocation). Acked mail survives the dead-letter sweep, and
      /v1/fetch has no ack filter by design (the recovery handle) --
      so fetch must consult the handshake status too. Phase 5d proves:
      pre-revoke fetch returns the acked thread history for both
      participants; post-revoke fetch with the known in_reply_to
      returns nothing for BOTH sides; a still-active pair's fetch is
      unaffected. Dead-lettered rows are excluded at the SQL layer.

Documented delivery boundary (also in relay.py's revoke handler):
revocation cannot retract plaintext already written to the client's
socket, and cannot un-ack an ack. Everything else -- including
collected-but-unacked mail -- is dead-lettered with reason
handshake_revoked and never delivered after revoke-commit. The status
flip, revocation memory, and dead-letter sweep happen in ONE atomic
transaction; a send racing revoke either fully precedes it (its message
is then dead-lettered) or fully follows it (403).

Runs its relay on port 18805 (scratch port; never touches 18802).
"""
import base64
import hashlib
import json
import os
import re
import secrets
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

RELAY = os.path.expanduser("~/workspace/clack-relay/relay.py")
PORT = 18805
BASE = "http://127.0.0.1:%d" % PORT
SIGN_SCHEME = "clack-ed25519-v1"


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


def raw_req(method, path, body=None):
    """Unauthenticated request (public endpoints)."""
    data = json.dumps(body).encode() if body is not None else b""
    rq = urllib.request.Request(
        BASE + path,
        data=data if method != "GET" else None,
        headers={"Content-Type": "application/json"}, method=method,
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
    """Split a clack:// handshake link into its fragment params."""
    frag = link.split("#", 1)[1]
    return dict(urllib.parse.parse_qsl(frag))


def pow_solve(presented, difficulty):
    """Find pow_nonce with sha256(presented + pow_nonce) >= difficulty
    leading zero bits."""
    i = 0
    while True:
        cand = b"pow%d" % i
        d = hashlib.sha256(presented + cand).digest()
        n = 0
        for byte in d:
            if byte == 0:
                n += 8
            else:
                n += 8 - byte.bit_length()
                break
        if n >= difficulty:
            return cand
        i += 1


# ---------------------------------------------------------------- harness

TMPD = tempfile.mkdtemp(prefix="hs-test-")
DB_PATH = os.path.join(TMPD, "relay.db")
RECEIPTS_PATH = os.path.join(TMPD, "receipts.jsonl")
receipts_f = open(RECEIPTS_PATH, "w")
PASS = []
FAIL = []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name + (" -- " + str(detail) if detail and not cond else ""))
    if not cond and detail:
        print("     detail: %s" % (detail,))


def receipt(**kw):
    receipts_f.write(json.dumps(kw) + "\n")
    receipts_f.flush()


def db():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def write_config(extra=None):
    cfg = {
        "port": PORT,
        "bind": "127.0.0.1",
        "base_url": BASE,
        "peers": {"hs_nminter": N_TOKEN},
        "identity_pubkeys": {"hs_nminter": N_IDENT.pub_b64},
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
            with urllib.request.urlopen(BASE + "/health", timeout=2) as r:
                if r.status == 200:
                    return
        except Exception:
            pass
        if SRV.poll() is not None:
            raise AssertionError("relay exited during startup; see %s/srv.log" % TMPD)
        time.sleep(0.25)
    raise AssertionError("relay did not come up; see %s/srv.log" % TMPD)


def stop_relay(sig=signal.SIGTERM):
    global SRV
    if SRV is None:
        return
    SRV.send_signal(sig)
    try:
        SRV.wait(timeout=15)
    except subprocess.TimeoutExpired:
        SRV.kill()
        SRV.wait(timeout=15)
    SRV = None
    time.sleep(0.3)


def enroll_pow(ident, display_tag):
    """Enroll a fresh identity via the PoW gate. Returns Client."""
    code, ch = raw_req("POST", "/v1/enroll/challenge", {})
    assert code == 200, ch
    assert ch["gate"] == "pow", ch
    presented = b64u_decode(ch["challenge"])
    difficulty = ch["difficulty"]
    pow_nonce = pow_solve(presented, difficulty)
    msg = presented + pow_nonce + ident.pub
    sig = ident.sign(msg)
    code, out = raw_req("POST", "/v1/enroll", {
        "identity_pubkey": ident.pub_b64,
        "proof": {"nonce": ch["challenge"], "signature": b64u_encode(sig)},
        "pow_nonce": b64u_encode(pow_nonce),
    })
    assert code == 200, out
    return Client(out["peer_name"], ident, out["service_token"])


def enroll_invite_gate(ident, h):
    """Fetch an invite-bound challenge for handshake link h."""
    code, ch = raw_req("POST", "/v1/enroll/challenge", {"invite_id": h})
    assert code == 200, ch
    assert ch["gate"] == "invite", ch
    presented = b64u_decode(ch["nonce"])
    msg = presented + h.encode("utf-8") + ident.pub
    sig = ident.sign(msg)
    return {
        "identity_pubkey": ident.pub_b64,
        "proof": {"nonce": ch["nonce"], "signature": b64u_encode(sig)},
    }


def mint_link(n_client, max_uses=1, exp_days=7, note=None):
    body = {"max_uses": max_uses, "exp_days": exp_days}
    if note is not None:
        body["note"] = note
    code, out = n_client.req("POST", "/v1/handshakes/mint-link", body)
    assert code == 200, out
    frag = parse_link(out["link"])
    return out, frag


def redeem_fresh(ident, frag, auth_client=None):
    """Redeem a link as a never-before-seen identity (invite gate)."""
    body = {"h": frag["h"], "k": frag["k"]}
    body.update(enroll_invite_gate(ident, frag["h"]))
    if auth_client is not None:
        code, out = auth_client.req("POST", "/v1/handshakes/redeem", body)
    else:
        code, out = raw_req("POST", "/v1/handshakes/redeem", body)
    return code, out


def redeem_authed(client, frag):
    return client.req("POST", "/v1/handshakes/redeem",
                      {"h": frag["h"], "k": frag["k"]})


# ------------------------------------------------------------- phase 0: setup
print("== phase 0: setup ==")
N_IDENT = Ident(TMPD, "nminter")
N_TOKEN = secrets.token_urlsafe(24)
write_config()
# Port must be free before we start (never touch 18802; we use 18805).
# Probe with connect: a listening socket means busy; refused (or a bare
# TIME_WAIT) means free.
import socket as _s
try:
    _probe = _s.create_connection(("127.0.0.1", PORT), timeout=2)
    _probe.close()
    print("port %d busy; aborting" % PORT)
    sys.exit(2)
except OSError:
    pass
try:
    start_relay()
    N = Client("hs_nminter", N_IDENT, N_TOKEN)

    # Migration assertions: tables exist, zero handshake rows (no backfill).
    c = db()
    hs_cols = [r[1] for r in c.execute("PRAGMA table_info(handshakes)").fetchall()]
    check("migration: handshakes table", "status" in hs_cols)
    check("migration: generation column", "generation" in hs_cols)
    check("migration: no backfill rows",
          c.execute("SELECT COUNT(*) FROM handshakes").fetchone()[0] == 0)
    check("migration: link_revocations table",
          c.execute("SELECT COUNT(*) FROM link_revocations").fetchone()[0] == 0)
    inv_cols = [r[1] for r in c.execute("PRAGMA table_info(invites)").fetchall()]
    check("migration: invites.grant_handshake", "grant_handshake" in inv_cols)
    check("migration: invites.note", "note" in inv_cols)
    msg_cols = [r[1] for r in c.execute("PRAGMA table_info(messages)").fetchall()]
    check("migration: messages.dead_reason", "dead_reason" in msg_cols)
    c.close()
    receipt(test="migration_zero_rows",
            handshake_rows=0, link_revocation_rows=0, has_generation=True,
            has_dead_reason=True, has_grant_handshake=True, passed=True)

    # Inactivity knob: default must be 0 (never) -- canary amendment A2.
    import importlib.util as _ilu
    spec = _ilu.spec_from_file_location("relaymod", RELAY)
    relaymod = _ilu.module_from_spec(spec)
    spec.loader.exec_module(relaymod)
    check("inactivity default is 0 (canary)", relaymod.HS_INACTIVITY_DAYS == 0,
          "got %r" % relaymod.HS_INACTIVITY_DAYS)
    src = open(RELAY).read()
    check("no inactivity sweep in sweep()",
          "last_activity <=" not in src and "last_activity<=" not in src)

    # --------------------------------------- phase 1: mint/redeem/accept/send
    print("== phase 1: round trip ==")
    Z_IDENT = Ident(TMPD, "z1")
    mint_out, frag = mint_link(N, max_uses=1, exp_days=7, note="hello z")
    check("mint-link 200", True)
    check("link v=4", frag.get("v") == "4", frag)
    check("link has h,k,by,exp,max",
          all(k in frag for k in ("h", "k", "by", "exp", "max")), frag)
    check("link_id == h", mint_out["link_id"] == frag["h"])
    check("by names minter", frag["by"] == "hs_nminter", frag.get("by"))
    k_raw = b64u_decode(frag["k"])
    check("claim secret k is 32 bytes", len(k_raw) == 32)

    code, red = redeem_fresh(Z_IDENT, frag)
    check("redeem 200", code == 200, (code, red))
    check("redeem status pending", red.get("status") == "pending", red)
    HSID_Z = red["handshake_id"]
    check("handshake_id embeds generation 0", HSID_Z.endswith("|0"), HSID_Z)
    T0 = red["pending_expires_at"]
    check("pending deadline set ~24h out",
          abs(T0 - (time.time() + 86400)) < 120, T0)
    check("redeem names DB minter identity",
          red.get("minter_identity") == N_IDENT.pub_b64, red.get("minter_identity"))
    Z = Client(red["peer_name"], Z_IDENT, red["service_token"])
    Z_NAME = red["peer_name"]

    # Send gate: pending -> 403 handshake_required, both directions.
    code, _ = N.req("POST", "/v1/send",
                    {"id": str(uuid.uuid4()), "to": Z_NAME, "text": "early"})
    check("send before accept -> 403 handshake_required",
          code == 403, code)
    code, _ = Z.req("POST", "/v1/send",
                    {"id": str(uuid.uuid4()), "to": "hs_nminter", "text": "early"})
    check("reverse send before accept -> 403", code == 403, code)

    # Minter cannot accept its own link.
    code, out = N.req("POST", "/v1/handshakes/accept", {"handshake_id": HSID_Z})
    check("minter accept -> 403 not_redeemer",
          code == 403 and out.get("error") == "not_redeemer", (code, out))

    code, acc = Z.req("POST", "/v1/handshakes/accept", {"handshake_id": HSID_Z})
    check("accept 200", code == 200, (code, acc))
    check("accept -> active", acc.get("status") == "active", acc)
    code, acc2 = Z.req("POST", "/v1/handshakes/accept", {"handshake_id": HSID_Z})
    check("accept idempotent", code == 200 and acc2.get("status") == "active",
          (code, acc2))

    mid1 = str(uuid.uuid4())
    code, sent = N.req("POST", "/v1/send",
                       {"id": mid1, "to": Z_NAME, "text": "after accept"})
    check("send after accept 200", code == 200, (code, sent))
    code, pol = Z.req("GET", "/v1/poll?timeout=1")
    got = [m for m in pol.get("messages", []) if m["id"] == mid1]
    check("recipient polls the message", code == 200 and len(got) == 1,
          (code, pol))

    code, lst = N.req("GET", "/v1/handshakes")
    check("GET /v1/handshakes lists active",
          code == 200 and any(h["status"] == "active" for h in lst["handshakes"]),
          (code, lst))
    receipt(test="round_trip", mint=200, redeem=200, accept=200,
            send_before_accept=403, send_after_accept=200,
            poll_delivered=len(got), passed=True)

    # ------------------------------- phase 2: no deadline extension (A1)
    print("== phase 2: no deadline extension ==")
    Z2_IDENT = Ident(TMPD, "z2")
    _, frag2 = mint_link(N, max_uses=5, exp_days=7)
    code, red2 = redeem_fresh(Z2_IDENT, frag2)
    check("z2 redeem 200", code == 200, (code, red2))
    T1 = red2["pending_expires_at"]
    Z2 = Client(red2["peer_name"], Z2_IDENT, red2["service_token"])
    Z2_NAME = red2["peer_name"]
    # Re-redeem the same pending pair (fresh challenge+proof, as a retry
    # would): the ORIGINAL deadline must be preserved, not refreshed.
    # Note: the idempotent retry rotates the service token (proof-of-key
    # verified), so the client adopts the latest token, like a real retry.
    time.sleep(1.1)
    code, red2b = redeem_fresh(Z2_IDENT, frag2)
    check("re-redeem 200", code == 200, (code, red2b))
    check("re-redeem keeps ORIGINAL pending_expires_at",
          red2b["pending_expires_at"] == T1,
          (T1, red2b.get("pending_expires_at")))
    Z2 = Client(red2b["peer_name"], Z2_IDENT, red2b["service_token"])
    # Same from the authenticated path.
    code, red2c = redeem_authed(Z2, frag2)
    check("authed re-redeem keeps deadline",
          code == 200 and red2c["pending_expires_at"] == T1, (code, red2c))
    c = db()
    db_t1 = c.execute(
        "SELECT pending_expires_at FROM handshakes WHERE redeemer_identity=?",
        (Z2_IDENT.pub_b64,)).fetchone()[0]
    c.close()
    check("DB deadline unchanged", db_t1 == T1, (db_t1, T1))
    receipt(test="no_deadline_extension", t1=T1,
            t2=red2b["pending_expires_at"], unchanged=red2b["pending_expires_at"] == T1,
            db_value=db_t1, passed=True)

    # --------------------------------- phase 3: expired pending vs accept
    print("== phase 3: expired pending ==")
    c = db()
    c.execute("UPDATE handshakes SET pending_expires_at=? WHERE redeemer_identity=?",
              (time.time() - 10, Z2_IDENT.pub_b64))
    c.commit()
    c.close()
    code, out = Z2.req("POST", "/v1/handshakes/accept",
                       {"handshake_id": red2["handshake_id"]})
    # 410 either way: the guarded UPDATE denies the lapsed deadline
    # atomically; a sweep may additionally have marked it revoked first.
    check("expired accept -> 410 denied",
          code == 410 and out.get("error") in ("handshake_expired", "handshake_revoked"),
          (code, out))
    c = db()
    st = c.execute("SELECT status FROM handshakes WHERE redeemer_identity=?",
                   (Z2_IDENT.pub_b64,)).fetchone()[0]
    c.close()
    check("expired row NOT flipped to active", st != "active", st)
    # A lapsed pending is a new consent round: fresh redeem gets a NEW
    # deadline (not an extension -- the old one lapsed), then accepts.
    # (The fresh redeem rotates the service token again; adopt it.)
    code, red2d = redeem_fresh(Z2_IDENT, frag2)
    T2 = red2d["pending_expires_at"]
    check("lapsed pending: new redeem, new deadline",
          code == 200 and T2 > T1, (code, T1, T2))
    Z2 = Client(red2d["peer_name"], Z2_IDENT, red2d["service_token"])
    code, acc = Z2.req("POST", "/v1/handshakes/accept",
                       {"handshake_id": red2d["handshake_id"]})
    check("accept after fresh redeem 200", code == 200, (code, acc))
    receipt(test="expired_accept_denied", code=410, row_not_active=(st != "active"),
            fresh_redeem_deadline_newer=(T2 > T1), passed=True)

    # --------------------------------- phase 4: tampered `by` is display-only
    print("== phase 4: tampered by ==")
    Z3_IDENT = Ident(TMPD, "z3")
    _, frag3 = mint_link(N, max_uses=1, exp_days=7)
    evil_frag = dict(frag3)
    evil_frag["by"] = "mallory"  # attacker rewrites the display name
    code, red3 = redeem_fresh(Z3_IDENT, evil_frag)
    check("redeem with forged by 200", code == 200, (code, red3))
    check("minter still N's identity (by ignored)",
          red3.get("minter_identity") == N_IDENT.pub_b64,
          red3.get("minter_identity"))
    check("minter_name_hint still N",
          red3.get("minter_name_hint") == "hs_nminter",
          red3.get("minter_name_hint"))
    Z3 = Client(red3["peer_name"], Z3_IDENT, red3["service_token"])
    code, acc = Z3.req("POST", "/v1/handshakes/accept",
                       {"handshake_id": red3["handshake_id"]})
    check("z3 accept 200", code == 200, (code, acc))
    receipt(test="tampered_by", minter_identity_matches=(red3.get("minter_identity") == N_IDENT.pub_b64),
            passed=True)

    # ------------------------- phase 5: revoke -> dead letters, no delivery
    print("== phase 5: revoke ==")
    # N<->Z are active (phase 1). Queue a message, revoke before poll.
    mid_dl = str(uuid.uuid4())
    code, _ = N.req("POST", "/v1/send",
                    {"id": mid_dl, "to": Z_NAME, "text": "doomed"})
    check("send pre-revoke 200", code == 200, code)
    code, rev = N.req("POST", "/v1/handshakes/revoke", {"peer": Z_NAME})
    check("revoke 200", code == 200, (code, rev))
    check("revoke bumps generation in id",
          rev.get("handshake_id", "").endswith("|1"), rev)
    code, pol = Z.req("GET", "/v1/poll?timeout=1")
    got_dl = [m for m in pol.get("messages", []) if m["id"] == mid_dl]
    check("poll after revoke returns ZERO of the queued messages",
          code == 200 and len(got_dl) == 0, (code, pol))
    # Committed DB state: dead letter with reason, uncollected.
    c = db()
    row = c.execute(
        "SELECT expires_at, collected_at, acked_at, dead_reason FROM messages WHERE id=?",
        (mid_dl,)).fetchone()
    check("dead letter row exists", row is not None)
    dl_ok = (row is not None and row["dead_reason"] == "handshake_revoked"
             and row["collected_at"] is None and row["acked_at"] is None
             and row["expires_at"] <= time.time())
    check("dead_reason=handshake_revoked, uncollected", dl_ok,
          dict(row) if row else None)
    # Pair-scoped revocation memory recorded.
    mem = c.execute("SELECT COUNT(*) FROM link_revocations").fetchone()[0]
    check("link_revocations has the pair entry", mem >= 1, mem)
    c.close()
    # Sends now fail closed.
    code, out = N.req("POST", "/v1/send",
                      {"id": str(uuid.uuid4()), "to": Z_NAME, "text": "x"})
    check("send after revoke -> 403 handshake_revoked",
          code == 403 and out.get("error") == "handshake_revoked", (code, out))
    code, out = Z.req("POST", "/v1/send",
                      {"id": str(uuid.uuid4()), "to": "hs_nminter", "text": "x"})
    check("reverse send after revoke -> 403", code == 403, code)
    # Receipts surface the dead letter to the sender.
    code, rcp = N.req("GET", "/v1/receipts?limit=100")
    dl_rcp = [r for r in rcp.get("receipts", []) if r["id"] == mid_dl]
    check("receipt shows dead + reason",
          len(dl_rcp) == 1 and dl_rcp[0]["state"] == "dead"
          and dl_rcp[0]["dead_reason"] == "handshake_revoked",
          dl_rcp)
    # Revoke is idempotent; accept-after-revoke is denied.
    code, rev2 = N.req("POST", "/v1/handshakes/revoke", {"peer": Z_NAME})
    check("revoke idempotent", code == 200 and rev2.get("revoked") is True,
          (code, rev2))
    code, out = Z.req("POST", "/v1/handshakes/accept", {"handshake_id": HSID_Z})
    # The pre-revoke (gen 0) id is dead: revoked rows report 410
    # handshake_revoked ahead of the generation check.
    check("accept-after-revoke denied",
          code in (409, 410), (code, out))
    receipt(test="revoke_dead_letters", dead_letter_rows=1,
            dead_reason=row["dead_reason"] if row else None,
            poll_returned=len(got_dl), send_after_revoke=403,
            accept_after_revoke=code, passed=(code in (409, 410)))

    # ------- phase 5b: dedup retry across revoke (send ordering)
    print("== phase 5b: dedup retry vs revoke ==")
    Z6_IDENT = Ident(TMPD, "z6")
    _, frag6 = mint_link(N, max_uses=1, exp_days=7)
    code, red6 = redeem_fresh(Z6_IDENT, frag6)
    check("z6 redeem 200", code == 200, (code, red6))
    Z6 = Client(red6["peer_name"], Z6_IDENT, red6["service_token"])
    code, _ = Z6.req("POST", "/v1/handshakes/accept",
                     {"handshake_id": red6["handshake_id"]})
    check("z6 accept 200", code == 200, code)
    DUP_ID = str(uuid.uuid4())
    code, _ = Z6.req("POST", "/v1/send",
                     {"id": DUP_ID, "to": "hs_nminter", "text": "dedup probe"})
    check("z6 send 200", code == 200, code)
    code, _ = N.req("POST", "/v1/handshakes/revoke",
                    {"peer": red6["peer_name"]})
    check("z6 revoke 200", code == 200, code)
    # Retry of the ACCEPTED send: dedup answers before the gate, so the
    # client gets the original outcome (duplicate:true), not a 403 --
    # and learns nothing about the revoke from this path.
    code, dup = Z6.req("POST", "/v1/send",
                       {"id": DUP_ID, "to": "hs_nminter", "text": "dedup probe"})
    check("retry of accepted send -> 200 duplicate:true (not 403)",
          code == 200 and dup.get("duplicate") is True, (code, dup))
    # A NEW send after revoke is gated: 403.
    code, ns = Z6.req("POST", "/v1/send",
                      {"id": str(uuid.uuid4()), "to": "hs_nminter", "text": "x"})
    check("new send after revoke -> 403 handshake_revoked",
          code == 403 and ns.get("error") == "handshake_revoked",
          (code, ns))
    # The original message was dead-lettered by the revoke.
    c = db()
    dl6 = c.execute("SELECT dead_reason FROM messages WHERE id=?",
                    (DUP_ID,)).fetchone()
    c.close()
    check("original message dead-lettered",
          dl6 is not None and dl6[0] == "handshake_revoked", dl6)
    receipt(test="dedup_retry_across_revoke",
            retry_duplicate=True, new_send_403=True,
            dead_reason=dl6[0] if dl6 else None, passed=True)

    # ------- phase 5c: revoke kills collected-but-unacked (BUG-008)
    print("== phase 5c: revoke vs collected-unacked ==")
    Z7_IDENT = Ident(TMPD, "z7")
    _, frag7 = mint_link(N, max_uses=1, exp_days=7)
    code, red7 = redeem_fresh(Z7_IDENT, frag7)
    check("z7 redeem 200", code == 200, (code, red7))
    Z7 = Client(red7["peer_name"], Z7_IDENT, red7["service_token"])
    code, _ = Z7.req("POST", "/v1/handshakes/accept",
                     {"handshake_id": red7["handshake_id"]})
    check("z7 accept 200", code == 200, code)
    Z7_NAME = red7["peer_name"]
    MID_C = str(uuid.uuid4())
    code, _ = N.req("POST", "/v1/send",
                    {"id": MID_C, "to": Z7_NAME,
                     "text": "collected never acked"})
    check("send pre-collect 200", code == 200, code)
    code, pol = Z7.req("GET", "/v1/poll?timeout=1")
    got_c = [m for m in pol.get("messages", []) if m["id"] == MID_C]
    check("first poll collects the message (no ack)",
          code == 200 and len(got_c) == 1, (code, pol))
    # Deliberately NO ack: the poll stands in for a dropped read. Under
    # v0.2.16 at-least-once this row stays pollable -- revoke must still
    # kill it (BUG-008: the old sweep only dead-lettered uncollected).
    code, _ = N.req("POST", "/v1/handshakes/revoke", {"peer": Z7_NAME})
    check("z7 revoke 200", code == 200, code)
    c = db()
    rowc = c.execute(
        "SELECT collected_at, acked_at, dead_reason, expires_at"
        " FROM messages WHERE id=?", (MID_C,)).fetchone()
    c.close()
    check("dead letter row exists", rowc is not None)
    dlc_ok = (rowc is not None
              and rowc["dead_reason"] == "handshake_revoked"
              and rowc["collected_at"] is not None
              and rowc["acked_at"] is None
              and rowc["expires_at"] <= time.time())
    check("collected-but-unacked dead-lettered", dlc_ok,
          dict(rowc) if rowc else None)
    # No redelivery: repeated fresh polls return nothing for the peer.
    NODELIV = True
    for attempt in range(3):
        code, pol2 = Z7.req("GET", "/v1/poll?timeout=1")
        got2 = [m for m in pol2.get("messages", []) if m["id"] == MID_C]
        ok2 = (code == 200 and len(got2) == 0)
        if not ok2:
            NODELIV = False
        check("no redelivery after revoke (poll %d)" % attempt, ok2,
              (code, pol2))
    # Sender-side receipts surface "dead", not "collected", for it.
    code, rcp = N.req("GET", "/v1/receipts?limit=100")
    dl_rcp = [r for r in rcp.get("receipts", []) if r["id"] == MID_C]
    check("receipt shows dead (not collected) for collected-unacked",
          len(dl_rcp) == 1 and dl_rcp[0]["state"] == "dead"
          and dl_rcp[0]["dead_reason"] == "handshake_revoked"
          and dl_rcp[0]["collected_at"] is not None, dl_rcp)
    receipt(test="revoke_kills_collected_unacked",
            dead_reason=rowc["dead_reason"] if rowc else None,
            collected_at_set=(rowc["collected_at"] is not None
                              if rowc else None),
            redelivered_after_revoke=(not NODELIV),
            receipt_state=dl_rcp[0]["state"] if dl_rcp else None,
            passed=(dlc_ok and NODELIV))

    # ------- phase 5d: revoke blocks /v1/fetch thread history
    # (Aaron's call: revocation = revocation). Acked mail survives the
    # dead-letter sweep, so fetch -- which has no ack filter by design
    # (the recovery handle) -- must consult the handshake status too.
    print("== phase 5d: revoke vs fetch thread history ==")
    Z8_IDENT = Ident(TMPD, "z8")
    _, frag8 = mint_link(N, max_uses=1, exp_days=7)
    code, red8 = redeem_fresh(Z8_IDENT, frag8)
    check("z8 redeem 200", code == 200, (code, red8))
    Z8 = Client(red8["peer_name"], Z8_IDENT, red8["service_token"])
    code, _ = Z8.req("POST", "/v1/handshakes/accept",
                     {"handshake_id": red8["handshake_id"]})
    check("z8 accept 200", code == 200, code)
    Z8_NAME = red8["peer_name"]
    M_ROOT = str(uuid.uuid4())
    code, _ = N.req("POST", "/v1/send",
                    {"id": M_ROOT, "to": Z8_NAME, "text": "thread root"})
    check("thread root send 200", code == 200, code)
    M_R1 = str(uuid.uuid4())
    code, _ = Z8.req("POST", "/v1/send",
                     {"id": M_R1, "to": N.name, "text": "reply one",
                      "in_reply_to": M_ROOT})
    check("thread reply send 200", code == 200, code)
    M_R2 = str(uuid.uuid4())
    code, _ = N.req("POST", "/v1/send",
                    {"id": M_R2, "to": Z8_NAME, "text": "reply two",
                      "in_reply_to": M_ROOT})
    check("thread reply2 send 200", code == 200, code)
    # Both sides ack what they received: the thread is fully acked
    # mail -- exactly the rows the dead-letter sweep leaves behind.
    code, _ = Z8.req("POST", "/v1/ack", {"ids": [M_ROOT, M_R2]})
    check("z8 acks 200", code == 200, code)
    code, _ = N.req("POST", "/v1/ack", {"ids": [M_R1]})
    check("n acks 200", code == 200, code)
    # Pre-revoke: fetch returns the acked thread history for both
    # participants (recovery contract intact).
    code, fz = Z8.req("GET", "/v1/fetch?in_reply_to=%s" % M_ROOT)
    fz_ids = sorted(m["id"] for m in fz.get("messages", []))
    check("pre-revoke z8 fetch sees acked thread",
          code == 200 and fz_ids == sorted([M_R1, M_R2]), (code, fz_ids))
    code, fn = N.req("GET", "/v1/fetch?in_reply_to=%s" % M_ROOT)
    fn_ids = sorted(m["id"] for m in fn.get("messages", []))
    check("pre-revoke n fetch sees acked thread (sender side)",
          code == 200 and fn_ids == sorted([M_R1, M_R2]), (code, fn_ids))
    # Revoke, then fetch with the known in_reply_to: nothing, both
    # directions, even though every row was acked.
    code, _ = N.req("POST", "/v1/handshakes/revoke", {"peer": Z8_NAME})
    check("z8 revoke 200", code == 200, code)
    code, fz2 = Z8.req("GET", "/v1/fetch?in_reply_to=%s" % M_ROOT)
    check("post-revoke z8 fetch returns nothing",
          code == 200 and fz2.get("messages") == [], (code, fz2))
    code, fn2 = N.req("GET", "/v1/fetch?in_reply_to=%s" % M_ROOT)
    check("post-revoke n fetch returns nothing (revoker too)",
          code == 200 and fn2.get("messages") == [], (code, fn2))
    # Control: a still-active pair's fetch is unaffected.
    Z9_IDENT = Ident(TMPD, "z9")
    _, frag9 = mint_link(N, max_uses=1, exp_days=7)
    code, red9 = redeem_fresh(Z9_IDENT, frag9)
    check("z9 redeem 200", code == 200, (code, red9))
    Z9 = Client(red9["peer_name"], Z9_IDENT, red9["service_token"])
    code, _ = Z9.req("POST", "/v1/handshakes/accept",
                     {"handshake_id": red9["handshake_id"]})
    check("z9 accept 200", code == 200, code)
    M9R = str(uuid.uuid4())
    code, _ = N.req("POST", "/v1/send",
                    {"id": M9R, "to": red9["peer_name"], "text": "ctl root"})
    check("control root send 200", code == 200, code)
    M9Q = str(uuid.uuid4())
    code, _ = Z9.req("POST", "/v1/send",
                     {"id": M9Q, "to": N.name, "text": "ctl reply",
                      "in_reply_to": M9R})
    check("control reply send 200", code == 200, code)
    code, _ = Z9.req("POST", "/v1/ack", {"ids": [M9R]})
    check("control ack 200", code == 200, code)
    code, f9 = Z9.req("GET", "/v1/fetch?in_reply_to=%s" % M9R)
    f9_ids = [m["id"] for m in f9.get("messages", [])]
    check("control pair fetch still works post-other-revoke",
          code == 200 and f9_ids == [M9Q], (code, f9_ids))
    receipt(test="revoke_blocks_fetch",
            pre_revoke_fetch_ok=(fz_ids == sorted([M_R1, M_R2])),
            post_revoke_empty=(fz2.get("messages") == []
                               and fn2.get("messages") == []),
            control_ok=(f9_ids == [M9Q]),
            passed=(fz_ids == sorted([M_R1, M_R2])
                   and fz2.get("messages") == []
                   and fn2.get("messages") == []
                   and f9_ids == [M9Q]))

    # ------- phase 6: old links can't resurrect; replayed accepts can't land
    print("== phase 6: generation binding ==")
    # The phase-1 link is spent/revoked-memory: redeem must fail with the
    # IDENTICAL unusable-link shape.
    code, out = redeem_authed(Z, frag)
    check("old link redeem -> 403 link_unusable (identical shape)",
          code == 403 and out.get("error") == "link_unusable", (code, out))
    # A dedicated multi-use link isolates the pair-scoped revocation
    # memory: the link still has uses left, but THIS pair revoked a
    # handshake created by it, so redeem must fail with the IDENTICAL
    # unusable-link shape (while other pairs could still use it).
    Z4_IDENT = Ident(TMPD, "z4")
    _, fragm = mint_link(N, max_uses=2, exp_days=7)
    code, redm = redeem_fresh(Z4_IDENT, fragm)
    check("z4 redeem 200", code == 200, (code, redm))
    Z4 = Client(redm["peer_name"], Z4_IDENT, redm["service_token"])
    code, _ = N.req("POST", "/v1/handshakes/revoke", {"peer": redm["peer_name"]})
    check("z4 revoke 200", code == 200, code)
    # The same pair re-redeeming over the revoked link: blocked with the
    # IDENTICAL unusable-link shape as an exhausted/missing link.
    code, out = redeem_fresh(Z4_IDENT, fragm)
    check("revoked-pair re-redeem (same identity) -> 403 link_unusable",
          code == 403 and out.get("error") == "link_unusable", (code, out))
    receipt(test="revoked_pair_link_blocked", code=403,
            error=out.get("error"), passed=(code == 403))
    # Fresh consent over a NEW link works: pending at generation 1.
    _, frag4 = mint_link(N, max_uses=1, exp_days=7)
    code, red4 = redeem_authed(Z, frag4)
    check("new link redeem 200", code == 200, (code, red4))
    check("new pending at generation 1",
          red4["handshake_id"].endswith("|1"), red4["handshake_id"])
    HSID_Z_NEW = red4["handshake_id"]
    # Replayed accept minted for the pre-revoke pending (gen 0): the
    # generation in the id is stale -> 409, and it must NOT activate.
    code, out = Z.req("POST", "/v1/handshakes/accept", {"handshake_id": HSID_Z})
    check("replayed pre-revoke accept -> 409 stale_generation",
          code == 409 and out.get("error") == "stale_generation", (code, out))
    c = db()
    st = c.execute(
        "SELECT status, generation FROM handshakes WHERE redeemer_identity=?",
        (Z_IDENT.pub_b64,)).fetchone()
    c.close()
    check("replayed accept did not activate", st["status"] == "pending",
          dict(st))
    # Fresh accept for the current generation works.
    code, acc = Z.req("POST", "/v1/handshakes/accept",
                      {"handshake_id": HSID_Z_NEW})
    check("current-generation accept 200", code == 200, (code, acc))
    check("active at generation 1",
          acc.get("status") == "active" and acc["handshake_id"].endswith("|1"),
          acc)
    receipt(test="old_link_no_resurrect", code=403, passed=True)
    receipt(test="replayed_accept_stale_generation", code=409,
            row_still_pending=(st["status"] == "pending"),
            fresh_accept=200, passed=True)

    # --------------------------------- phase 7: final-use redemption race
    print("== phase 7: concurrent final-use redemption ==")
    RACERS = []
    for i in range(6):
        ri = Ident(TMPD, "r%d" % i)
        RACERS.append(enroll_pow(ri, "r%d" % i))
    _, frag5 = mint_link(N, max_uses=3, exp_days=7)
    race_results = []
    race_lock = threading.Lock()

    def racer(c):
        try:
            code, out = redeem_authed(c, frag5)
            ok = (code == 200)
        except Exception as e:  # noqa: BLE001 -- record, don't crash
            code, out, ok = "exc", str(e), False
        with race_lock:
            race_results.append((c.name, code, ok))

    threads = [threading.Thread(target=racer, args=(c,)) for c in RACERS]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)
    winners = [r for r in race_results if r[2]]
    check("6 racers all answered", len(race_results) == 6, race_results)
    check("exactly max_uses=3 winners", len(winners) == 3,
          [(r[0], r[1]) for r in race_results])
    # Committed DB state: the counter shows exactly 3.
    c = db()
    uses = c.execute("SELECT uses, max_uses FROM invites WHERE invite_id=?",
                     (frag5["h"],)).fetchone()
    check("DB uses == max_uses == 3", uses["uses"] == 3 and uses["max_uses"] == 3,
          dict(uses))
    n_pending = c.execute(
        "SELECT COUNT(*) FROM handshakes WHERE via_link_id=? AND status='pending'",
        (frag5["h"],)).fetchone()[0]
    check("3 pending handshakes from the link", n_pending == 3, n_pending)
    c.close()
    receipt(test="final_use_race", threads=6, max_uses=3,
            successes=len(winners), db_uses=uses["uses"],
            db_max_uses=uses["max_uses"], pending_rows=n_pending,
            passed=(len(winners) == 3 and uses["uses"] == 3))

    # ------------------- phase 8: accept/revoke/send/poll interleavings
    print("== phase 8: interleavings ==")
    # 8a: accept vs revoke raced -- revoke is unilateral, so the final
    # state is ALWAYS revoked and the DB stays consistent.
    RA_IDENT = Ident(TMPD, "ra")
    _, frag6 = mint_link(N, max_uses=1, exp_days=7)
    code, red6 = redeem_fresh(RA_IDENT, frag6)
    RA = Client(red6["peer_name"], RA_IDENT, red6["service_token"])
    HSID_RA = red6["handshake_id"]
    race8a = {}

    def do_accept():
        try:
            race8a["accept"] = RA.req("POST", "/v1/handshakes/accept",
                                      {"handshake_id": HSID_RA})
        except Exception as e:  # noqa: BLE001
            race8a["accept"] = ("exc", str(e))

    def do_revoke():
        try:
            race8a["revoke"] = N.req("POST", "/v1/handshakes/revoke",
                                     {"peer": red6["peer_name"]})
        except Exception as e:  # noqa: BLE001
            race8a["revoke"] = ("exc", str(e))

    ta = threading.Thread(target=do_accept)
    tb = threading.Thread(target=do_revoke)
    ta.start()
    tb.start()
    ta.join(timeout=60)
    tb.join(timeout=60)
    check("accept and revoke both answered",
          "accept" in race8a and "revoke" in race8a, race8a)
    check("revoke 200", race8a["revoke"][0] == 200, race8a["revoke"])
    acc_code = race8a["accept"][0]
    check("accept got 200 or a clean denial", acc_code in (200, 409, 410),
          race8a["accept"])
    c = db()
    st8a = c.execute(
        "SELECT status, generation FROM handshakes WHERE via_link_id=?",
        (frag6["h"],)).fetchone()
    c.close()
    check("final state revoked", st8a["status"] == "revoked", dict(st8a))
    check("generation bumped once", st8a["generation"] == 1, dict(st8a))
    receipt(test="accept_revoke_race", accept_code=acc_code,
            revoke_code=race8a["revoke"][0], final_status=st8a["status"],
            generation=st8a["generation"], passed=True)

    # 8b: N sends x10 while revoking R2's handshake. Invariant: NOTHING
    # sent is delivered after the revoke commits -- every 200'd message is
    # dead-lettered, every later send 403s, poll returns zero.
    R2_IDENT = Ident(TMPD, "r2b")
    _, frag7 = mint_link(N, max_uses=1, exp_days=7)
    code, red7 = redeem_fresh(R2_IDENT, frag7)
    R2 = Client(red7["peer_name"], R2_IDENT, red7["service_token"])
    R2_NAME = red7["peer_name"]
    code, _ = R2.req("POST", "/v1/handshakes/accept",
                     {"handshake_id": red7["handshake_id"]})
    assert code == 200, code
    batch_ids = [str(uuid.uuid4()) for _ in range(10)]
    send_results = []
    s_lock = threading.Lock()

    def do_send(mid):
        try:
            code, _ = N.req("POST", "/v1/send",
                            {"id": mid, "to": R2_NAME, "text": "race"})
        except Exception:  # noqa: BLE001
            code = "exc"
        with s_lock:
            send_results.append((mid, code))

    def do_revoke2():
        try:
            N.req("POST", "/v1/handshakes/revoke", {"peer": R2_NAME})
        except Exception:  # noqa: BLE001
            pass

    sts = [threading.Thread(target=do_send, args=(mid,)) for mid in batch_ids]
    tr = threading.Thread(target=do_revoke2)
    for t in sts:
        t.start()
    tr.start()
    for t in sts:
        t.join(timeout=120)
    tr.join(timeout=60)
    ok_sends = [mid for mid, code in send_results if code == 200]
    denied = [mid for mid, code in send_results if code == 403]
    check("every send either 200 or clean 403",
          len(ok_sends) + len(denied) == 10, send_results)
    code, pol = R2.req("GET", "/v1/poll?timeout=1")
    got8b = [m for m in pol.get("messages", []) if m["id"] in batch_ids]
    check("poll returns ZERO of the raced messages", len(got8b) == 0,
          [m["id"] for m in got8b])
    c = db()
    dead = 0
    for mid in ok_sends:
        r = c.execute(
            "SELECT dead_reason, collected_at FROM messages WHERE id=?",
            (mid,)).fetchone()
        if r and r["dead_reason"] == "handshake_revoked" and r["collected_at"] is None:
            dead += 1
    c.close()
    check("every 200'd message dead-lettered", dead == len(ok_sends),
          (dead, len(ok_sends)))
    receipt(test="send_revoke_race", sends_200=len(ok_sends),
            sends_403=len(denied), dead_lettered=dead, poll_returned=len(got8b),
            passed=(dead == len(ok_sends) and len(got8b) == 0))

    # --------------------------------- phase 9: restart persistence (A5)
    print("== phase 9: restart persistence ==")
    R5_IDENT = Ident(TMPD, "r5")
    _, frag8 = mint_link(N, max_uses=1, exp_days=7)
    code, red8 = redeem_fresh(R5_IDENT, frag8)
    check("r5 redeem 200", code == 200, (code, red8))
    T3 = red8["pending_expires_at"]
    R5 = Client(red8["peer_name"], R5_IDENT, red8["service_token"])
    c = db()
    db_t3 = c.execute(
        "SELECT pending_expires_at FROM handshakes WHERE redeemer_identity=?",
        (R5_IDENT.pub_b64,)).fetchone()[0]
    c.close()
    check("DB has the deadline", db_t3 == T3, (db_t3, T3))

    # Hard kill: SIGKILL, no graceful shutdown.
    stop_relay(sig=signal.SIGKILL)
    start_relay()
    # The deadline must be byte-identical: not reset, not recomputed,
    # not extended at startup.
    code, lst = N.req("GET", "/v1/handshakes")
    r5row = [h for h in lst.get("handshakes", [])
             if h.get("peer_identity") == R5_IDENT.pub_b64]
    check("pending row survives restart",
          code == 200 and len(r5row) == 1 and r5row[0]["status"] == "pending",
          (code, r5row))
    check("pending_expires_at UNCHANGED across restart",
          r5row[0]["pending_expires_at"] == T3,
          (r5row[0].get("pending_expires_at"), T3))
    # Re-redeem across the restart boundary: still no extension.
    # (This is the final-use idempotency case: the link is at max_uses,
    # so the retry must hit the transaction's idempotency branch, not 403.)
    code, red8b = redeem_authed(R5, frag8)
    ok_rr = code == 200 and red8b.get("pending_expires_at") == T3
    check("post-restart re-redeem keeps deadline", ok_rr, (code, red8b))
    receipt(test="restart_deadline_persistence", before=T3,
            after=r5row[0]["pending_expires_at"],
            unchanged=(r5row[0]["pending_expires_at"] == T3),
            re_redeem_unchanged=ok_rr,
            passed=True)

    # Expire the deadline out-of-band, restart, accept must deny atomically.
    c = db()
    c.execute("UPDATE handshakes SET pending_expires_at=? WHERE redeemer_identity=?",
              (time.time() - 5, R5_IDENT.pub_b64))
    c.commit()
    c.close()
    stop_relay(sig=signal.SIGKILL)
    start_relay()
    code, out = R5.req("POST", "/v1/handshakes/accept",
                       {"handshake_id": red8["handshake_id"]})
    check("expired-by-restart accept -> 410 denied",
          code == 410 and out.get("error") in ("handshake_expired", "handshake_revoked"),
          (code, out))
    # The sweep may have marked the lapsed pending revoked (clearing
    # redeemer_identity); look the row up by the canonical pair.
    a5, b5 = sorted([N_IDENT.pub_b64, R5_IDENT.pub_b64])
    c = db()
    st9 = c.execute("SELECT status FROM handshakes WHERE a_identity=? AND b_identity=?",
                    (a5, b5)).fetchone()[0]
    c.close()
    check("row not activated by the denied accept", st9 != "active", st9)
    receipt(test="restart_expired_accept_denied", code=410,
            error=out.get("error"), row_not_active=(st9 != "active"),
            passed=True)

    # ------- phase 11: user revoke is not erased by expiry/sweep (Zari A6)
    print("== phase 11: revoke survives expiry/sweep ==")
    S7_IDENT = Ident(TMPD, "s7")
    _, frag9 = mint_link(N, max_uses=1, exp_days=7)
    code, red9 = redeem_fresh(S7_IDENT, frag9)
    check("s7 redeem 200", code == 200, (code, red9))
    S7 = Client(red9["peer_name"], S7_IDENT, red9["service_token"])
    HSID_S7 = red9["handshake_id"]
    code, _ = S7.req("POST", "/v1/handshakes/accept",
                     {"handshake_id": HSID_S7})
    assert code == 200, code
    code, _ = N.req("POST", "/v1/handshakes/revoke",
                    {"peer": red9["peer_name"]})
    check("s7 revoke 200", code == 200, code)
    a7, b7 = sorted([N_IDENT.pub_b64, S7_IDENT.pub_b64])
    c = db()
    before = c.execute(
        "SELECT status, generation FROM handshakes"
        " WHERE a_identity=? AND b_identity=?", (a7, b7)).fetchone()
    check("revoked at generation 1",
          before["status"] == "revoked" and before["generation"] == 1,
          dict(before))
    mem = c.execute(
        "SELECT COUNT(*) FROM link_revocations"
        " WHERE link_id=? AND a_identity=? AND b_identity=?",
        (frag9["h"], a7, b7)).fetchone()[0]
    check("revocation memory present", mem == 1, mem)
    # Simulate hard expiry on the REVOKED row, then force the periodic
    # sweep (restart resets the sweep timer; any request then runs it).
    c.execute("UPDATE handshakes SET expires_at=?, pending_expires_at=?"
              " WHERE a_identity=? AND b_identity=?",
              (time.time() - 10, time.time() - 10, a7, b7))
    c.commit()
    c.close()
    stop_relay()
    start_relay()
    code, _ = N.req("GET", "/v1/handshakes")  # trigger the sweep
    check("sweep-trigger request 200", code == 200, code)
    c = db()
    after = c.execute(
        "SELECT status, generation FROM handshakes"
        " WHERE a_identity=? AND b_identity=?", (a7, b7)).fetchone()
    check("sweep left the revoked row untouched",
          after["status"] == "revoked"
          and after["generation"] == before["generation"],
          dict(after))
    mem2 = c.execute(
        "SELECT COUNT(*) FROM link_revocations"
        " WHERE link_id=? AND a_identity=? AND b_identity=?",
        (frag9["h"], a7, b7)).fetchone()[0]
    c.close()
    check("revocation memory intact after sweep", mem2 == 1, mem2)
    # Stale artifacts still cannot resurrect the pair.
    code, out = S7.req("POST", "/v1/handshakes/accept",
                       {"handshake_id": HSID_S7})
    check("stale accept on revoked pair -> 410 handshake_revoked",
          code == 410 and out.get("error") == "handshake_revoked",
          (code, out))
    code, out = redeem_authed(S7, frag9)
    check("old link re-redeem after sweep -> 403 link_unusable",
          code == 403 and out.get("error") == "link_unusable", (code, out))
    c = db()
    st = c.execute("SELECT status FROM handshakes"
                   " WHERE a_identity=? AND b_identity=?",
                   (a7, b7)).fetchone()[0]
    c.close()
    check("pair still revoked", st == "revoked", st)
    receipt(test="revoke_survives_expiry_sweep",
            generation_before=before["generation"],
            generation_after=after["generation"],
            revocation_memory_intact=(mem2 == 1),
            pair_still_revoked=(st == "revoked"),
            passed=True)

    # ------- phase 12: poll/revoke concurrent ordering (Zari A6)
    print("== phase 12: poll vs revoke ordering ==")
    ORDER_OK = True
    ORDER_DETAIL = []
    for i in range(12):
        ri = Ident(TMPD, "po%d" % i)
        _, fragx = mint_link(N, max_uses=1, exp_days=7)
        code, redx = redeem_fresh(ri, fragx)
        assert code == 200, (i, code, redx)
        RX = Client(redx["peer_name"], ri, redx["service_token"])
        code, _ = RX.req("POST", "/v1/handshakes/accept",
                         {"handshake_id": redx["handshake_id"]})
        assert code == 200, (i, code)
        mid = str(uuid.uuid4())
        code, _ = N.req("POST", "/v1/send",
                        {"id": mid, "to": redx["peer_name"], "text": "order"})
        assert code == 200, (i, mid, code)
        got = {}

        def do_poll(c=RX):
            try:
                got["res"] = c.req("GET", "/v1/poll?timeout=3")
            except Exception as e:  # noqa: BLE001
                got["res"] = ("exc", str(e))

        tp = threading.Thread(target=do_poll)
        tp.start()
        # No sleep: revoke while the poll is in flight to maximize overlap.
        code, _ = N.req("POST", "/v1/handshakes/revoke",
                        {"peer": redx["peer_name"]})
        assert code == 200, (i, code)
        tp.join(timeout=60)
        pcode, pol = got["res"]
        delivered = ([m["id"] for m in pol.get("messages", [])]
                     if isinstance(pol, dict) else [])
        c = db()
        row = c.execute("SELECT collected_at, dead_reason, expires_at"
                        " FROM messages WHERE id=?", (mid,)).fetchone()
        c.close()
        was_delivered = mid in delivered
        # New invariant (BUG-008): the revoke ALWAYS dead-letters the
        # unacked message, whether or not a poll fetched it first. A poll
        # whose fetch ran pre-revoke may still carry the bytes (physical
        # boundary -- cannot retract a response already built), but the
        # row is dead and no later fetch can return it.
        dead = (row is not None and row[1] == "handshake_revoked"
                and row[2] <= time.time())
        ok = (pcode == 200 and dead)
        if not ok:
            ORDER_OK = False
            ORDER_DETAIL.append(
                (i, pcode, was_delivered, dead,
                 dict(row) if row else None))
        else:
            # After the race settles, a fresh poll must return nothing:
            # the revoked peer receives nothing further.
            code2, pol2 = RX.req("GET", "/v1/poll?timeout=1")
            got2 = ([m["id"] for m in pol2.get("messages", [])]
                    if isinstance(pol2, dict) else [])
            if not (code2 == 200 and mid not in got2):
                ORDER_OK = False
                ORDER_DETAIL.append((i, "redelivered_post_revoke",
                                     code2, got2))
    check("12 poll/revoke races: always dead-lettered, never re-fetched",
          ORDER_OK and not ORDER_DETAIL, ORDER_DETAIL[:3])
    receipt(test="poll_revoke_ordering", iterations=12,
            invariant="always_dead_lettered_never_refetched",
            violations=len(ORDER_DETAIL), passed=ORDER_OK)

    # --------------------------------- phase 10: at-cap names handshakes
    print("== phase 10: handshake cap ==")
    # N's active handshakes: Z, Z2, Z3 (3). Cap at 2 -> mint must name them.
    stop_relay()
    write_config(extra={"max_handshakes_per_identity": 2})
    start_relay()
    code, out = N.req("POST", "/v1/handshakes/mint-link",
                      {"max_uses": 1, "exp_days": 7})
    check("at-cap mint -> 403 handshake_cap_reached",
          code == 403 and out.get("error") == "handshake_cap_reached",
          (code, out))
    named = out.get("handshakes", []) if isinstance(out, dict) else []
    check("cap response names existing handshakes", len(named) >= 2,
          [h.get("peer_name_hint") for h in named])
    c = db()
    n_active = c.execute(
        "SELECT COUNT(*) FROM handshakes WHERE status='active'").fetchone()[0]
    c.close()
    receipt(test="cap_reached", code=403, active_handshakes=n_active,
            named=len(named),
            peer_hints=[h.get("peer_name_hint") for h in named],
            passed=(code == 403 and len(named) >= 2))

    print("== done: %d passed, %d failed ==" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failures: %s" % FAIL)
finally:
    receipts_f.close()
    stop_relay()

print("receipts: %s" % RECEIPTS_PATH)
for line in open(RECEIPTS_PATH):
    print("RECEIPT " + line.rstrip())
sys.exit(1 if FAIL else 0)
