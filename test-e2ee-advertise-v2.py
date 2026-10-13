#!/usr/bin/env python3
"""test-e2ee-advertise-v2.py -- focused tests for the corrected in-place E2EE
capability-update candidate, v2 (POST /v1/handshakes/advertise).

Corrects v1 (BLOCKed by reviewer):
- v1 resolved the minter solely from invites.inviter_identity and refused
  pairs with no invite row. v2 is provenance-aware: invite-backed pairs map
  inviter->minter slot / redeemer->redeemer slot; operator-attested pairs
  (no invite row) map a_identity->minter slot / b_identity->redeemer slot
  (sorted order, deterministic, no invite manufactured).
- v1 allowed only the minter to advertise. v2 lets EITHER owner advertise
  their OWN slot (reviewer: "for BOTH owners"); cross-slot advertisement
  is impossible (relay maps caller->slot).
- v1's enc_v guard used value equality (`not in (0, 1)`), which float 1.0
  passes but breaks the integer bitwise AND. v2 requires type(v) is int.
  Mint and accept paths hardened identically.

Phases:
  1. Setup: invite-backed pair (mint 0 / accept 1 -> 0/1/0); operator pair
     via direct DB insert (no invite row) in 0/1/0 shape.
  2. Provenance mapping: inviter->minter slot; redeemer->redeemer slot;
     operator a->minter slot; operator b->redeemer slot; third party->404.
  3. Validation: True/1.0/"1"/2/-1/[1]/{} -> 400; absent -> 200 no-change.
     Mint(1.0)->400; accept(True)->400 (hardened paths).
  4. Upgrade/downgrade: advertise 1 -> cap 1; advertise 0 -> cap 0;
     idempotent re-advertise; generation/identities/created_at preserved;
     pending mail preserved.
  5. Safety: stale generation -> 409; revoked -> 404; pending -> 404.
  6. Duplex: real e2ee encrypt/decrypt + encrypted /v1/send on capable pair.

Runs its relay on port 18808 (scratch; never touches 18802/18806/18807).
Boot target is the CANDIDATE relay.py (working tree on the
candidate/e2ee-advertise-v2 branch).
"""
import base64
import hashlib
import json
import os
import secrets
import socket as _s
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

RELAY = os.path.expanduser("~/workspace/clack-relay/relay.py")
PORT = 18808
BASE = "http://127.0.0.1:%d" % PORT
SIGN_SCHEME = "clack-ed25519-v1"

sys.path.insert(0, os.path.expanduser("~/workspace/clack-relay"))
import e2ee


def b64u_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64u_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class Ident:
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
    def __init__(self, name, ident, token):
        self.name = name
        self.ident = ident
        self.token = token

    def req(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else b""
        nonce = "%d:%s" % (int(time.time()), secrets.token_hex(16))
        canon = ("%s\n%s\n%s\n%s\n%s" % (
            SIGN_SCHEME, method.upper(), path,
            hashlib.sha256(data).hexdigest(), nonce)).encode()
        sig = self.ident.sign(canon)
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + self.token,
            "X-Clack-Scheme": "1",
            "X-Clack-Key": self.name,
            "X-Clack-Nonce": nonce,
            "X-Clack-Sig": sig.hex(),
        }
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


TMPD = tempfile.mkdtemp(prefix="adv-v2-test-")
DB_PATH = os.path.join(TMPD, "relay.db")
PASS = []
FAIL = []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name)
    if not cond and detail:
        print("     detail: %s" % (detail,))


def db():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


A_TOKEN = "tok_" + secrets.token_hex(16)
B_TOKEN = "tok_" + secrets.token_hex(16)
C_TOKEN = "tok_" + secrets.token_hex(16)
D_TOKEN = "tok_" + secrets.token_hex(16)

A_IDENT = Ident(TMPD, "alice")
B_IDENT = Ident(TMPD, "bob")
C_IDENT = Ident(TMPD, "eve")
D_IDENT = Ident(TMPD, "dave")


def write_config():
    cfg = {
        "port": PORT,
        "bind": "127.0.0.1",
        "base_url": BASE,
        "peers": {
            "alice": A_TOKEN, "bob": B_TOKEN,
            "eve": C_TOKEN, "dave": D_TOKEN,
        },
        "identity_pubkeys": {
            "alice": A_IDENT.pub_b64, "bob": B_IDENT.pub_b64,
            "eve": C_IDENT.pub_b64, "dave": D_IDENT.pub_b64,
        },
        "enrollment": "invite,pow",
        "pow_difficulty": 8,
    }
    with open(os.path.join(TMPD, "relay-config.json"), "w") as f:
        json.dump(cfg, f)
    os.chmod(os.path.join(TMPD, "relay-config.json"), 0o600)


SRV = None


def start_relay():
    global SRV
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


def hs_row(a_b64, b_b64):
    a, b = (a_b64, b_b64) if a_b64 <= b_b64 else (b_b64, a_b64)
    c = db()
    row = c.execute(
        "SELECT status, generation, created_at, a_identity, b_identity,"
        " minter_enc_v, redeemer_enc_v, enc_capable, via_link_id"
        " FROM handshakes WHERE a_identity=? AND b_identity=?",
        (a, b)).fetchone()
    c.close()
    return row


def main():
    write_config()
    start_relay()
    try:
        alice = Client("alice", A_IDENT, A_TOKEN)
        bob = Client("bob", B_IDENT, B_TOKEN)
        eve = Client("eve", C_IDENT, C_TOKEN)
        dave = Client("dave", D_IDENT, D_TOKEN)

        # ---- Phase 1a: invite-backed pair, mint(0)/accept(1) -> 0/1/0 ----
        code, mint = alice.req("POST", "/v1/handshakes/mint-link",
                              {"max_uses": 1, "enc_v": 0})
        check("invite mint enc_v=0 accepted", code == 200, str(mint)[:120])
        link = mint["link"]
        frag = dict(urllib.parse.parse_qsl(link.split("#", 1)[1]))
        code, red = bob.req("POST", "/v1/handshakes/redeem",
                            {"h": frag["h"], "k": frag["k"]})
        check("invite redeem ok", code == 200 and "handshake_id" in red,
              str(red)[:120])
        code, acc = bob.req("POST", "/v1/handshakes/accept",
                            {"handshake_id": red["handshake_id"], "enc_v": 1})
        check("invite accept enc_v=1 -> active", code == 200 and
              acc.get("status") == "active", str(acc)[:120])
        hs_id_inv = acc["handshake_id"]
        r = hs_row(A_IDENT.pub_b64, B_IDENT.pub_b64)
        check("invite pair 0/1/0", r and r["minter_enc_v"] == 0 and
              r["redeemer_enc_v"] == 1 and r["enc_capable"] == 0,
              dict(r) if r else None)

        # ---- Phase 1b: operator-attested pair, no invite row, 0/1/0 ----
        # dave+alice operator pair; insert directly (simulates operator
        # attestation); a/b sorted per _hs_pair.
        a_op, b_op = sorted([A_IDENT.pub_b64, D_IDENT.pub_b64])
        c = db()
        c.execute(
            "INSERT INTO handshakes(a_identity,b_identity,status,created_at,"
            " last_activity,via_link_id,generation,minter_enc_v,"
            " redeemer_enc_v,enc_capable)"
            " VALUES(?,?,?,?,?,?,?,?,?,?)",
            (a_op, b_op, "active", time.time(), time.time(),
             "operator:peer_handshakes", 0, 0, 1, 0))
        c.commit()
        c.close()
        r = hs_row(a_op, b_op)
        check("operator pair 0/1/0, no invite",
              r and r["minter_enc_v"] == 0 and r["redeemer_enc_v"] == 1
              and r["enc_capable"] == 0
              and r["via_link_id"] == "operator:peer_handshakes",
              dict(r) if r else None)
        hs_id_op = "%s|%s|0" % (a_op, b_op)
        # Determine which test peer is a vs b.
        a_is_alice = (a_op == A_IDENT.pub_b64)
        a_cli = alice if a_is_alice else dave
        b_cli = dave if a_is_alice else alice

        # ---- Phase 2: provenance-aware slot mapping ----
        # Invite pair: inviter (alice) -> minter slot.
        code, out = alice.req("POST", "/v1/handshakes/advertise",
                              {"handshake_id": hs_id_inv, "enc_v": 1})
        r = hs_row(A_IDENT.pub_b64, B_IDENT.pub_b64)
        check("invite: inviter advertises -> minter slot, cap=1",
              code == 200 and r["minter_enc_v"] == 1
              and r["enc_capable"] == 1, (code, dict(r) if r else None))
        # Invite pair: redeemer (bob) advertises own slot (idempotent).
        code, out = bob.req("POST", "/v1/handshakes/advertise",
                            {"handshake_id": hs_id_inv, "enc_v": 1})
        r = hs_row(A_IDENT.pub_b64, B_IDENT.pub_b64)
        check("invite: redeemer advertises own slot",
              code == 200 and r["redeemer_enc_v"] == 1
              and r["minter_enc_v"] == 1, (code, dict(r) if r else None))
        # Invite pair: redeemer downgrades own slot only.
        code, out = bob.req("POST", "/v1/handshakes/advertise",
                            {"handshake_id": hs_id_inv, "enc_v": 0})
        r = hs_row(A_IDENT.pub_b64, B_IDENT.pub_b64)
        check("invite: redeemer downgrade touches own slot only",
              code == 200 and r["redeemer_enc_v"] == 0
              and r["minter_enc_v"] == 1 and r["enc_capable"] == 0,
              (code, dict(r) if r else None))
        code, out = bob.req("POST", "/v1/handshakes/advertise",
                            {"handshake_id": hs_id_inv, "enc_v": 1})
        check("invite: redeemer re-upgrade -> cap=1", code == 200 and
              hs_row(A_IDENT.pub_b64, B_IDENT.pub_b64)["enc_capable"] == 1)

        # Operator pair: a_identity -> minter slot.
        code, out = a_cli.req("POST", "/v1/handshakes/advertise",
                              {"handshake_id": hs_id_op, "enc_v": 1})
        r = hs_row(a_op, b_op)
        check("operator: a_identity advertises -> minter slot, cap=1",
              code == 200 and r["minter_enc_v"] == 1
              and r["enc_capable"] == 1, (code, dict(r) if r else None))
        # Operator pair: b_identity -> redeemer slot (own slot only).
        code, out = b_cli.req("POST", "/v1/handshakes/advertise",
                              {"handshake_id": hs_id_op, "enc_v": 0})
        r = hs_row(a_op, b_op)
        check("operator: b_identity downgrade touches own slot only",
              code == 200 and r["redeemer_enc_v"] == 0
              and r["minter_enc_v"] == 1 and r["enc_capable"] == 0,
              (code, dict(r) if r else None))
        code, out = b_cli.req("POST", "/v1/handshakes/advertise",
                              {"handshake_id": hs_id_op, "enc_v": 1})
        check("operator: b_identity re-upgrade -> cap=1", code == 200 and
              hs_row(a_op, b_op)["enc_capable"] == 1)

        # Third party cannot advertise.
        code, out = eve.req("POST", "/v1/handshakes/advertise",
                            {"handshake_id": hs_id_op, "enc_v": 1})
        check("third party -> 404", code == 404, (code, out))
        code, out = eve.req("POST", "/v1/handshakes/advertise",
                            {"handshake_id": hs_id_inv, "enc_v": 1})
        check("third party on invite pair -> 404", code == 404)

        # ---- Phase 3: strict validation ----
        for bad in (True, False, 1.0, 0.0, "1", "0", 2, -1, [1], {"v": 1}):
            code, out = a_cli.req("POST", "/v1/handshakes/advertise",
                                  {"handshake_id": hs_id_op, "enc_v": bad})
            check("advertise bad enc_v %r -> 400" % (bad,), code == 400,
                  (code, out))
        # Absent enc_v: no-change read.
        before = hs_row(a_op, b_op)
        code, out = a_cli.req("POST", "/v1/handshakes/advertise",
                              {"handshake_id": hs_id_op})
        after = hs_row(a_op, b_op)
        check("advertise absent enc_v -> 200 no-change",
              code == 200 and dict(before) == dict(after), code)
        # Mint path hardened: float rejected.
        code, out = alice.req("POST", "/v1/handshakes/mint-link",
                              {"max_uses": 1, "enc_v": 1.0})
        check("mint enc_v=1.0 -> 400", code == 400, (code, out))
        code, out = alice.req("POST", "/v1/handshakes/mint-link",
                              {"max_uses": 1, "enc_v": True})
        check("mint enc_v=True -> 400", code == 400, (code, out))
        # Accept path hardened: float/bool rejected.
        # Accept path hardened: float/bool rejected. Use a fresh eve pair so
        # we don't disturb the alice/bob test pair (one row per identity
        # pair; redeem would reset it).
        code, mintE = alice.req("POST", "/v1/handshakes/mint-link",
                                {"max_uses": 1})
        fragE = dict(urllib.parse.parse_qsl(mintE["link"].split("#", 1)[1]))
        code, redE = eve.req("POST", "/v1/handshakes/redeem",
                             {"h": fragE["h"], "k": fragE["k"]})
        check("eve redeem ok (pending)", code == 200, (code, redE))
        code, out = eve.req("POST", "/v1/handshakes/accept",
                            {"handshake_id": redE["handshake_id"],
                             "enc_v": 1.0})
        check("accept enc_v=1.0 -> 400", code == 400, (code, out))
        rpend = hs_row(A_IDENT.pub_b64, C_IDENT.pub_b64)
        check("pair still pending after bad accept",
              rpend and rpend["status"] == "pending",
              dict(rpend) if rpend else None)
        pend_hid = redE["handshake_id"]

        # ---- Phase 4: preservation ----
        r = hs_row(a_op, b_op)
        check("operator pair identities/generation preserved",
              r["a_identity"] == a_op and r["b_identity"] == b_op
              and r["generation"] == 0 and r["status"] == "active",
              dict(r) if r else None)
        # Pending mail preserved across upgrade: use a fresh bob/eve pair
        # (distinct identities; one row per pair). Send plaintext BEFORE
        # capable, upgrade both slots, poll after.
        code, mint3 = bob.req("POST", "/v1/handshakes/mint-link",
                              {"max_uses": 1, "enc_v": 0})
        frag3 = dict(urllib.parse.parse_qsl(mint3["link"].split("#", 1)[1]))
        code, red3 = eve.req("POST", "/v1/handshakes/redeem",
                             {"h": frag3["h"], "k": frag3["k"]})
        code, acc3 = eve.req("POST", "/v1/handshakes/accept",
                             {"handshake_id": red3["handshake_id"],
                              "enc_v": 0})
        hs3 = acc3["handshake_id"]
        code, sent = bob.req("POST", "/v1/send",
                             {"id": uuid.uuid4().hex,
                              "to": "eve", "topic": "t",
                              "text": "pending-plaintext"})
        check("plaintext send pre-upgrade ok", code == 200, (code, sent))
        code, out = bob.req("POST", "/v1/handshakes/advertise",
                            {"handshake_id": hs3, "enc_v": 1})
        code, out = eve.req("POST", "/v1/handshakes/advertise",
                            {"handshake_id": hs3, "enc_v": 1})
        r3 = hs_row(B_IDENT.pub_b64, C_IDENT.pub_b64)
        check("fresh pair upgraded to cap=1",
              r3["enc_capable"] == 1, dict(r3) if r3 else None)
        code, poll = eve.req("GET", "/v1/poll?timeout=2")
        texts = [m.get("text") for m in poll.get("messages", [])]
        check("pending plaintext still deliverable post-upgrade",
              "pending-plaintext" in texts, texts)

        # ---- Phase 5: safety ----
        stale = hs_id_op[:-1] + "9"
        code, out = a_cli.req("POST", "/v1/handshakes/advertise",
                              {"handshake_id": stale, "enc_v": 1})
        check("stale generation -> 409", code == 409, (code, out))
        code, out = a_cli.req("POST", "/v1/handshakes/advertise",
                              {"handshake_id": "bogus", "enc_v": 1})
        check("malformed handshake_id -> 400", code == 400, (code, out))
        # Revoked pair: advertise refused, stays revoked.
        # Revoke takes {"peer": name}; revoke the operator pair from a_cli's
        # side, targeting the other party.
        revoke_target = b_cli.name
        code, rev = a_cli.req("POST", "/v1/handshakes/revoke",
                              {"peer": revoke_target})
        check("revoke ok", code == 200, (code, rev))
        code, out = a_cli.req("POST", "/v1/handshakes/advertise",
                              {"handshake_id": hs_id_op, "enc_v": 1})
        r = hs_row(a_op, b_op)
        check("revoked pair advertise -> 404, stays revoked",
              code == 404 and r["status"] == "revoked",
              (code, dict(r) if r else None))
        # Pending pair: advertise refused.
        code, out = eve.req("POST", "/v1/handshakes/advertise",
                            {"handshake_id": pend_hid, "enc_v": 1})
        check("pending pair advertise -> 404", code == 404, (code, out))

        # ---- Phase 6: real duplex on capable pair ----
        # hs3 (bob/eve) is capable. Encrypt bob->eve via e2ee module.
        e_x = e2ee.ed25519_pub_to_x25519_pub(b64u_decode(C_IDENT.pub_b64))
        env = e2ee.encrypt_envelope("bob", "eve", e_x,
                                    b"duplex-probe-v2")
        code, sent = bob.req("POST", "/v1/send",
                             {"id": uuid.uuid4().hex,
                              "to": "eve", "topic": "t", "enc": env})
        check("encrypted send on capable pair stored",
              code == 200, (code, sent))
        code, poll = eve.req("GET", "/v1/poll?timeout=2")
        got = None
        for m in poll.get("messages", []):
            if m.get("enc_v") == 1:
                try:
                    pt = e2ee.decrypt_envelope(
                        C_IDENT.seed, json.loads(m["text"]),
                        m.get("from", ""), "eve")
                    got = pt.decode()
                except Exception as ex:
                    got = "DECRYPT_FAIL:%s" % ex
        check("peer polls and decrypts", got == "duplex-probe-v2", got)
    finally:
        stop_relay()

    print("\n==== %d PASS, %d FAIL ====" % (len(PASS), len(FAIL)))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
