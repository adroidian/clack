#!/usr/bin/env python3
"""test-fix-a-redeem-repair.py -- v4 link-redeem upgrade with EXPLICIT
CANONICAL row-class selection (Fix A rev3, Zari REQUEST_CHANGES 1635ebf7
on rev2 94d202c; supersedes the a5e0882d repair).

When a v4 capable link (minter_enc_v=1) is redeemed against an already-active
pair with enc_capable=0, the new issuer's advertisement lands ONLY in the
issuer's ORIGINAL ceremony slot, derived from retained original provenance
(invites.inviter_identity via handshakes.via_link_id) -- never from sorted
identity order. Sorted mapping is used ONLY for explicitly operator-attested
pairs. The class is READ from handshakes.provenance -- never inferred from
via_link_id; an invitation row alone cannot override the row's explicit
class. Unknown / missing / conflicting class, or contradictory ceremony
evidence on an operator-attested row, fails closed: no upgrade, the ordinary
idempotent no-op stands, no mutation.

Drives the ACTUAL redeem HTTP path on a scratch relay (port 18807, scratch
DB) and reads committed SQLite state. Covers:

  validity:     both sorted orientations x both issuers -> cap 1 only when
                BOTH original-slot advertisements are 1 (ceremony class,
                set by the real mint/redeem/accept flow)
  regression:   the 3 a5e0882d violations (wrong slot / NULL-redeemer /
                missing provenance) now hold the correct stored state
  rev3:         the 2 1635ebf7 violations -- unknown class + matching
                retained invite (0/0 stays 0/0), and operator-attested +
                contradictory ceremony evidence (0/1 stays 0/1)
  fail-closed:  missing invite row, conflicting inviter (third party),
                conflicting class value, NULL class, ceremony row with
                NULL via_link_id -> no mutation, redeem still 200
                idempotent no-op
  attested:     explicit operator-attested class (via_link_id NULL) uses
                sorted mapping, both orientations, reaching cap1
  idempotency:  re-redeeming the same capable link is a pure no-op
                (row byte-identical, link uses unconsumed)
  no-downgrade: stored 1s are never written back to 0
  preserved:    generation / identities / status untouched by the upgrade
  invalid:      garbage link id -> non-200, no mutation
  reaccept:     c9b14c02 -- the idempotent re-accept upgrade writes
                redeemer_enc_v ONLY for the established redeemer (canonical
                class: ceremony -> non-inviter party; operator-attested ->
                sorted-hi). Non-redeemer re-accepts answer 200 with NO
                mutation (T17/T18/T20/T22/T23); established-redeemer
                re-accepts still upgrade to 1/1/cap1 (T19/T21).

Runs its relay on port 18807 (scratch port; never touches 18802).
"""
import base64, hashlib, json, os, secrets, signal, socket, sqlite3
import subprocess, sys, tempfile, time, urllib.error, urllib.parse, urllib.request
import uuid

PORT = 18807
BASE = "http://127.0.0.1:%d" % PORT
SIGN_SCHEME = "clack-ed25519-v1"
RELAY = os.path.join(os.path.dirname(os.path.abspath(
    __file__ if "__file__" in dir() else "test-fix-a-redeem-repair.py")),
    "relay.py")

def b64u_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def b64u_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

class Ident:
    def __init__(self, tmpd, tag):
        self._tmpd = tmpd
        self._pem = os.path.join(tmpd, "id_%s.pem" % tag)
        subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519",
                        "-out", self._pem], check=True, capture_output=True)
        pubder = subprocess.run(["openssl", "pkey", "-in", self._pem,
                                 "-pubout", "-outform", "DER"], check=True,
                                capture_output=True).stdout
        self.pub = pubder[-32:]
        self.pub_b64 = b64u_encode(self.pub)

    def sign(self, msg):
        tag = uuid.uuid4().hex
        mf = os.path.join(self._tmpd, "m%s.bin" % tag)
        sf = mf + ".sig"
        with open(mf, "wb") as f:
            f.write(msg)
        subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", self._pem,
                        "-rawin", "-in", mf, "-out", sf],
                       check=True, capture_output=True)
        with open(sf, "rb") as f:
            sig = f.read()
        os.unlink(mf); os.unlink(sf)
        return sig

class Client:
    def __init__(self, name, ident, token):
        self.name, self.ident, self.token = name, ident, token
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
                "X-Clack-Scheme": "1", "X-Clack-Key": self.name,
                "X-Clack-Nonce": nonce, "X-Clack-Sig": sig.hex()})
        rq = urllib.request.Request(BASE + path,
            data=data if method != "GET" else None,
            headers=headers, method=method)
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
    data = json.dumps(body).encode() if body is not None else b""
    rq = urllib.request.Request(BASE + path,
        data=data if method != "GET" else None,
        headers={"Content-Type": "application/json"}, method=method)
    try:
        with urllib.request.urlopen(rq, timeout=30) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        raw = e.read().decode() or "{}"
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, {"_raw": raw}

TMPD = tempfile.mkdtemp(prefix="fixa-repair-")
DB_PATH = os.path.join(TMPD, "relay.db")
PASS, FAIL = [], []

def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("PASS " if cond else "FAIL ") + name +
          ("" if cond or not detail else " -- " + str(detail)))

def db():
    return sqlite3.connect(DB_PATH)

def write_config():
    cfg = {"port": PORT, "bind": "127.0.0.1", "base_url": BASE,
           "peers": {"op": OP_TOKEN},
           "identity_pubkeys": {"op": OP_IDENT.pub_b64},
           "enrollment": "invite,pow", "pow_difficulty": 8}
    p = os.path.join(TMPD, "relay-config.json")
    json.dump(cfg, open(p, "w"))
    os.chmod(p, 0o600)

SRV = None
def start_relay():
    global SRV
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
            raise AssertionError("relay exited; see %s/srv.log" % TMPD)
        time.sleep(0.25)
    raise AssertionError("relay did not come up")

def stop_relay():
    global SRV
    if SRV is None:
        return
    SRV.send_signal(signal.SIGTERM)
    try:
        SRV.wait(timeout=15)
    except subprocess.TimeoutExpired:
        SRV.kill(); SRV.wait(timeout=15)
    SRV = None
    time.sleep(0.3)

def pow_solve(presented, difficulty):
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

def enroll_pow(ident):
    code, ch = raw_req("POST", "/v1/enroll/challenge", {})
    assert code == 200, ch
    presented = b64u_decode(ch["challenge"])
    pow_nonce = pow_solve(presented, ch["difficulty"])
    msg = presented + pow_nonce + ident.pub
    sig = ident.sign(msg)
    code, out = raw_req("POST", "/v1/enroll", {
        "identity_pubkey": ident.pub_b64,
        "proof": {"nonce": ch["challenge"], "signature": b64u_encode(sig)},
        "pow_nonce": b64u_encode(pow_nonce)})
    assert code == 200, out
    return Client(out["peer_name"], ident, out["service_token"])

def parse_frag(link):
    return dict(urllib.parse.parse_qsl(link.split("#", 1)[1]))

def mint(client, enc_v=None, max_uses=5):
    body = {"max_uses": max_uses, "exp_days": 7}
    if enc_v is not None:
        body["enc_v"] = enc_v
    code, out = client.req("POST", "/v1/handshakes/mint-link", body)
    assert code == 200, out
    return parse_frag(out["link"])

def enroll_invite_gate(ident, h):
    code, ch = raw_req("POST", "/v1/enroll/challenge", {"invite_id": h})
    assert code == 200 and ch["gate"] == "invite", ch
    presented = b64u_decode(ch["nonce"])
    sig = ident.sign(presented + h.encode() + ident.pub)
    return {"identity_pubkey": ident.pub_b64,
            "proof": {"nonce": ch["nonce"], "signature": b64u_encode(sig)}}

def redeem_fresh(ident, frag):
    body = {"h": frag["h"], "k": frag["k"]}
    body.update(enroll_invite_gate(ident, frag["h"]))
    code, out = raw_req("POST", "/v1/handshakes/redeem", body)
    if code == 200:
        return code, out, Client(out["peer_name"], ident, out["service_token"])
    return code, out, None

def redeem_authed(client, frag):
    return client.req("POST", "/v1/handshakes/redeem",
                      {"h": frag["h"], "k": frag["k"]})

def accept(client, hsid, enc_v=None):
    body = {"handshake_id": hsid}
    if enc_v is not None:
        body["enc_v"] = enc_v
    code, out = client.req("POST", "/v1/handshakes/accept", body)
    assert code == 200, (code, out)
    return out

def reaccept(client, hsid, enc_v):
    """Idempotent re-accept on an already-active pair. Returns (code, out)
    without asserting -- both the fail-closed no-op and the legitimate
    upgrade answer 200."""
    body = {"handshake_id": hsid, "enc_v": enc_v}
    return client.req("POST", "/v1/handshakes/accept", body)

def full_row(a_id, b_id):
    a, b = (a_id, b_id) if a_id <= b_id else (b_id, a_id)
    c = db()
    r = c.execute("SELECT status, via_link_id, generation, redeemer_identity,"
                  " enc_capable, minter_enc_v, redeemer_enc_v, a_identity,"
                  " b_identity FROM handshakes"
                  " WHERE a_identity=? AND b_identity=?", (a, b)).fetchone()
    c.close()
    return r

def link_uses(h):
    c = db()
    u = c.execute("SELECT uses FROM invites WHERE invite_id=?", (h,)).fetchone()
    c.close()
    return u[0] if u else None

def insert_row(a, b, via, minter_v, redeemer_v, cap, provenance):
    """Synthetic active pair row (generation 0) for class-coverage cases
    the natural ceremony flow cannot produce."""
    c = db()
    now = time.time()
    c.execute("INSERT INTO handshakes(a_identity, b_identity, status,"
              " created_at, pending_expires_at, expires_at, last_activity,"
              " via_link_id, redeemer_identity, generation, minter_enc_v,"
              " redeemer_enc_v, enc_capable, provenance)"
              " VALUES(?,?,'active',?,?,NULL,?,?,NULL,0,?,?,?,?)",
              (a, b, now, now + 86400, now, via,
               minter_v, redeemer_v, cap, provenance))
    c.commit(); c.close()

def prov_of(a_id, b_id):
    """(provenance, via_link_id) for the pair row -- the canonical class."""
    a, b = (a_id, b_id) if a_id <= b_id else (b_id, a_id)
    c = db()
    r = c.execute("SELECT provenance, via_link_id FROM handshakes"
                  " WHERE a_identity=? AND b_identity=?", (a, b)).fetchone()
    c.close()
    return r

def mkpair(tag):
    """Legacy helper: two freshly enrolled peers (kept for reference).
    The suite below uses the shared POOL instead to stay under the
    enroll rate limit."""
    i1, i2 = Ident(TMPD, tag + "1"), Ident(TMPD, tag + "2")
    lo, hi = (i1, i2) if i1.pub_b64 <= i2.pub_b64 else (i2, i1)
    return enroll_pow(lo), enroll_pow(hi), lo.pub_b64, hi.pub_b64

POOL = []  # [(ident, client)]

def enroll_pool(n):
    for k in range(n):
        ident = Ident(TMPD, "pool%d" % k)
        POOL.append((ident, enroll_pow(ident)))

def pool_pair(i, j):
    """Clients + sorted identities for pool peers i, j (i != j). Returns
    (c_lo, c_hi, lo_b64, hi_b64, i_lo, i_hi) with pool indices."""
    (ii, ci), (ij, cj) = POOL[i], POOL[j]
    if ii.pub_b64 <= ij.pub_b64:
        return ci, cj, ii.pub_b64, ij.pub_b64, i, j
    return cj, ci, ij.pub_b64, ii.pub_b64, j, i

def redeem_fresh_pool(idx, frag):
    """redeem_fresh for pool peer idx; stores the rotated-token client
    back into the pool so later scenarios reuse a valid token."""
    ident, _old = POOL[idx]
    code, out, client = redeem_fresh(ident, frag)
    if code == 200:
        POOL[idx] = (ident, client)
    return code, out, client

def main():
    enroll_pool(10)  # 10 peers -> 45 distinct pairs; stays under enroll limits
    # ============ T1: inviter=b, issuer=a (orig redeemer) ============
    # a5e0882d V1: stored 0/1 must stay 0/1/cap0 (a's ad stays in the
    # redeemer slot; b's minter slot untouched).
    CA, CB, a, b, IA, IB = pool_pair(0,1)
    f1 = mint(CB, enc_v=0)
    code, red, CA = redeem_fresh_pool(IA, f1)
    assert code == 200, red
    accept(CA, red["handshake_id"], enc_v=1)
    r = full_row(a, b)
    check("T1 setup active NULL-redeemer 0/1/cap0",
          r[0] == "active" and r[3] is None and r[4] == 0
          and r[5] == 0 and r[6] == 1, r)
    check("T1 ceremony flow stamps provenance='ceremony'",
          prov_of(a, b)[0] == "ceremony", prov_of(a, b))
    f2 = mint(CA, enc_v=1)
    code, out = redeem_authed(CB, f2)
    r = full_row(a, b)
    check("T1 redeem 200 idempotent", code == 200 and r[0] == "active",
          (code, out))
    check("T1 issuer=orig-redeemer keeps 0/1/cap0",
          r[5] == 0 and r[6] == 1 and r[4] == 0, r[4:7])
    check("T1 generation/identities preserved",
          r[2] == 0 and r[7] == a and r[8] == b, r)

    # ============ T2: inviter=b, issuer=a, stored 1/0 -> valid 1/1/cap1
    CA, CB, a, b, IA, IB = pool_pair(0,2)
    f1 = mint(CB, enc_v=1)
    code, red, CA = redeem_fresh_pool(IA, f1)
    assert code == 200, red
    accept(CA, red["handshake_id"], enc_v=0)
    r = full_row(a, b)
    check("T2 setup active 1/0/cap0", r[4] == 0 and r[5] == 1 and r[6] == 0, r)
    f2 = mint(CA, enc_v=1)
    code, out = redeem_authed(CB, f2)
    r = full_row(a, b)
    check("T2 valid upgrade issuer=orig-redeemer -> 1/1/cap1",
          r[5] == 1 and r[6] == 1 and r[4] == 1, r[4:7])

    # ============ T3: inviter=a, issuer=b (orig redeemer), NULL redeemer
    # a5e0882d V2: b's ad lands in b's own original (redeemer) slot -> 0/1,
    # never the minter slot.
    CA, CB, a, b, IA, IB = pool_pair(0,3)
    f1 = mint(CA, enc_v=0)
    code, red, CB = redeem_fresh_pool(IB, f1)
    assert code == 200, red
    accept(CB, red["handshake_id"], enc_v=0)
    r = full_row(a, b)
    check("T3 setup active NULL-redeemer 0/0",
          r[0] == "active" and r[3] is None and r[4] == 0
          and r[5] == 0 and r[6] == 0, r)
    f2 = mint(CB, enc_v=1)
    code, out = redeem_authed(CA, f2)
    r = full_row(a, b)
    check("T3 issuer=orig-redeemer(b) ad in own slot -> 0/1/cap0",
          r[5] == 0 and r[6] == 1 and r[4] == 0, r[4:7])

    # ============ T4: inviter=a, issuer=a (orig minter), stored 0/1
    # -> valid 1/1/cap1
    CA, CB, a, b, IA, IB = pool_pair(0,4)
    f1 = mint(CA, enc_v=0)
    code, red, CB = redeem_fresh_pool(IB, f1)
    assert code == 200, red
    accept(CB, red["handshake_id"], enc_v=1)
    r = full_row(a, b)
    check("T4 setup active 0/1/cap0", r[4] == 0 and r[5] == 0 and r[6] == 1, r)
    f2 = mint(CA, enc_v=1)
    code, out = redeem_authed(CB, f2)
    r = full_row(a, b)
    check("T4 valid upgrade issuer=orig-minter -> 1/1/cap1",
          r[5] == 1 and r[6] == 1 and r[4] == 1, r[4:7])

    # ============ T5: idempotency -- re-redeem same capable link ============
    CA, CB, a, b, IA, IB = pool_pair(0,5)
    f1 = mint(CA, enc_v=0)
    code, red, CB = redeem_fresh_pool(IB, f1)
    assert code == 200, red
    accept(CB, red["handshake_id"], enc_v=1)     # stored 0/1
    f2 = mint(CA, enc_v=1)
    code, _ = redeem_authed(CB, f2)
    assert code == 200
    r1 = full_row(a, b)
    u1 = link_uses(f2["h"])
    code, out = redeem_authed(CB, f2)            # second redeem, same link
    r2 = full_row(a, b)
    u2 = link_uses(f2["h"])
    check("T5 re-redeem 200", code == 200, (code, out))
    check("T5 row byte-identical after re-redeem", r1 == r2, (r1, r2))
    check("T5 link uses unconsumed by idempotent re-redeem", u1 == u2,
          (u1, u2))

    # ============ T6: no-downgrade -- stored 1s never written back to 0 ====
    CA, CB, a, b, IA, IB = pool_pair(1,2)
    f1 = mint(CA, enc_v=1)
    code, red, CB = redeem_fresh_pool(IB, f1)
    assert code == 200, red
    accept(CB, red["handshake_id"], enc_v=1)     # stored 1/1/cap1
    r = full_row(a, b)
    check("T6 setup 1/1/cap1", r[4] == 1 and r[5] == 1 and r[6] == 1, r)
    f2 = mint(CB, enc_v=1)
    code, out = redeem_authed(CA, f2)            # cap already 1: branch idle
    r = full_row(a, b)
    check("T6 capable pair untouched (no-downgrade)",
          r[4] == 1 and r[5] == 1 and r[6] == 1, r[4:7])

    # ============ T7: missing provenance -> fail closed (a5e0882d V3) =====
    CA, CB, a, b, IA, IB = pool_pair(1,3)
    f1 = mint(CA, enc_v=0)
    code, red, CB = redeem_fresh_pool(IB, f1)
    assert code == 200, red
    accept(CB, red["handshake_id"], enc_v=0)
    r = full_row(a, b)
    via = r[1]
    c = db(); c.execute("DELETE FROM invites WHERE invite_id=?", (via,))
    c.commit(); c.close()
    f2 = mint(CA, enc_v=1)
    code, out = redeem_authed(CB, f2)
    r = full_row(a, b)
    check("T7 redeem 200 despite missing provenance", code == 200, (code, out))
    check("T7 missing provenance fails closed, keeps 0/0",
          r[5] == 0 and r[6] == 0 and r[4] == 0, r[4:7])

    # ============ T8: conflicting provenance -> fail closed ================
    CA, CB, a, b, IA, IB = pool_pair(1,4)
    CX = POOL[5][1]                                # third party (not in pair)
    f1 = mint(CA, enc_v=0)
    code, red, CB = redeem_fresh_pool(IB, f1)
    assert code == 200, red
    accept(CB, red["handshake_id"], enc_v=0)
    r = full_row(a, b)
    via = r[1]
    c = db()
    c.execute("UPDATE invites SET inviter_identity=? WHERE invite_id=?",
              (CX.ident.pub_b64, via))
    c.commit(); c.close()
    f2 = mint(CB, enc_v=1)
    code, out = redeem_authed(CA, f2)
    r = full_row(a, b)
    check("T8 redeem 200 despite conflicting provenance", code == 200,
          (code, out))
    check("T8 conflicting provenance fails closed, keeps 0/0",
          r[5] == 0 and r[6] == 0 and r[4] == 0, r[4:7])

    # ============ T9: operator-attested (explicit class) =================
    # Explicitly operator-attested pairs (canonical provenance class,
    # via_link_id NULL, no ceremony evidence) use sorted mapping ONLY here.
    CA, CB, a, b, IA, IB = pool_pair(1,5)
    c = db()
    now = time.time()
    c.execute("INSERT INTO handshakes(a_identity, b_identity, status,"
              " created_at, pending_expires_at, expires_at, last_activity,"
              " via_link_id, redeemer_identity, generation, minter_enc_v,"
              " redeemer_enc_v, enc_capable, provenance)"
              " VALUES(?,?,'active',?,?,NULL,?,NULL,NULL,0,0,0,0,"
              " 'operator-attested')",
              (a, b, now, now + 86400, now))
    c.commit(); c.close()
    r = full_row(a, b)
    check("T9 attested row present, explicit class, via_link_id NULL",
          r is not None and r[1] is None and r[0] == "active"
          and prov_of(a, b)[0] == "operator-attested", prov_of(a, b))
    f2 = mint(CA, enc_v=1)                       # issuer=a (sorted-minter)
    code, out = redeem_authed(CB, f2)
    r = full_row(a, b)
    check("T9 attested issuer=a -> minter slot 1, keeps 1/0/cap0",
          code == 200 and r[5] == 1 and r[6] == 0 and r[4] == 0, r[4:7])
    f3 = mint(CB, enc_v=1)                       # issuer=b (sorted-redeemer)
    code, out = redeem_authed(CA, f3)
    r = full_row(a, b)
    check("T9 attested issuer=b -> redeemer slot 1, reaches 1/1/cap1",
          code == 200 and r[5] == 1 and r[6] == 1 and r[4] == 1, r[4:7])

    # ============ T10: non-v4 link redeem stays a pure no-op ==============
    CA, CB, a, b, IA, IB = pool_pair(2,3)
    f1 = mint(CA, enc_v=0)
    code, red, CB = redeem_fresh_pool(IB, f1)
    assert code == 200, red
    accept(CB, red["handshake_id"], enc_v=1)     # stored 0/1
    f2 = mint(CA, enc_v=0)                       # non-capable link
    code, out = redeem_authed(CB, f2)
    r = full_row(a, b)
    check("T10 non-v4 redeem 200 no-op, keeps 0/1/cap0",
          code == 200 and r[5] == 0 and r[6] == 1 and r[4] == 0, r[4:7])

    # ============ T11: 1635ebf7(a) unknown class + retained invite ========
    # Unknown provenance class with a MATCHING retained invite must fail
    # closed: the invite row alone cannot override the explicit class.
    CA, CB, a, b, IA, IB = pool_pair(2,4)
    f1 = mint(CB, enc_v=0)                       # minter=b (sorted hi)
    code, red, CA = redeem_fresh_pool(IA, f1)
    assert code == 200, red
    accept(CA, red["handshake_id"], enc_v=0)     # active 0/0
    r = full_row(a, b)
    via = r[1]
    c = db()
    inv = c.execute("SELECT inviter_identity FROM invites WHERE invite_id=?",
                    (via,)).fetchone()
    assert inv is not None and inv[0] == b, inv  # invite retained, inviter=b
    c.execute("UPDATE handshakes SET provenance='unreviewed'"
              " WHERE a_identity=? AND b_identity=?", (a, b))
    c.commit(); c.close()
    f2 = mint(CB, enc_v=1)                       # issuer=b = orig minter
    code, out = redeem_authed(CA, f2)
    r = full_row(a, b)
    check("T11 redeem 200 despite unknown class", code == 200, (code, out))
    check("T11 unknown class fails closed, keeps 0/0",
          r[5] == 0 and r[6] == 0 and r[4] == 0, r[4:7])

    # ============ T12: 1635ebf7(b) attested + contradictory ceremony ======
    # Explicit operator-attested row carrying contradictory ceremony
    # evidence (via_link_id -> invite with inviter=sorted b) must fail
    # closed: operator slots are never reinterpreted as ceremony roles.
    CA, CB, a, b, IA, IB = pool_pair(2,5)
    f_inv = mint(CB, enc_v=0)                    # invite row, inviter=b
    c = db()
    now = time.time()
    c.execute("INSERT INTO handshakes(a_identity, b_identity, status,"
              " created_at, pending_expires_at, expires_at, last_activity,"
              " via_link_id, redeemer_identity, generation, minter_enc_v,"
              " redeemer_enc_v, enc_capable, provenance)"
              " VALUES(?,?,'active',?,?,NULL,?,?,NULL,0,0,1,0,"
              " 'operator-attested')",
              (a, b, now, now + 86400, now, f_inv["h"]))
    c.commit(); c.close()
    r = full_row(a, b)
    assert r[4] == 0 and r[5] == 0 and r[6] == 1, r   # stored 0/1
    f2 = mint(CB, enc_v=1)                       # issuer=b = sorted hi
    code, out = redeem_authed(CA, f2)
    r = full_row(a, b)
    check("T12 redeem 200 despite contradictory evidence",
          code == 200, (code, out))
    check("T12 attested+ceremony-evidence fails closed, keeps 0/1",
          r[5] == 0 and r[6] == 1 and r[4] == 0, r[4:7])

    # ============ T13: conflicting class value + retained invite =========
    CA, CB, a, b, IA, IB = pool_pair(3,4)
    f1 = mint(CA, enc_v=0)
    code, red, CB = redeem_fresh_pool(IB, f1)
    assert code == 200, red
    accept(CB, red["handshake_id"], enc_v=0)     # active 0/0
    c = db()
    c.execute("UPDATE handshakes SET provenance='migrated'"
              " WHERE a_identity=? AND b_identity=?", (a, b))
    c.commit(); c.close()
    f2 = mint(CA, enc_v=1)
    code, out = redeem_authed(CB, f2)
    r = full_row(a, b)
    check("T13 redeem 200 despite conflicting class", code == 200,
          (code, out))
    check("T13 conflicting class fails closed, keeps 0/0",
          r[5] == 0 and r[6] == 0 and r[4] == 0, r[4:7])

    # ============ T14: ceremony class but via_link_id NULL ===============
    # Class says ceremony but no link evidence is retained: fail closed.
    CA, CB, a, b, IA, IB = pool_pair(3,5)
    f1 = mint(CA, enc_v=1)
    code, red, CB = redeem_fresh_pool(IB, f1)
    assert code == 200, red
    accept(CB, red["handshake_id"], enc_v=0)     # active 1/0/cap0
    c = db()
    c.execute("UPDATE handshakes SET via_link_id=NULL"
              " WHERE a_identity=? AND b_identity=?", (a, b))
    c.commit(); c.close()
    assert prov_of(a, b) == ("ceremony", None), prov_of(a, b)
    f2 = mint(CB, enc_v=1)                       # issuer=b = orig redeemer
    code, out = redeem_authed(CA, f2)
    r = full_row(a, b)
    check("T14 redeem 200 despite NULL via on ceremony row",
          code == 200, (code, out))
    check("T14 ceremony-without-link fails closed, keeps 1/0/cap0",
          r[5] == 1 and r[6] == 0 and r[4] == 0, r[4:7])

    # ============ T15: NULL (missing) class + retained invite ============
    CA, CB, a, b, IA, IB = pool_pair(4,5)
    f1 = mint(CB, enc_v=0)
    code, red, CA = redeem_fresh_pool(IA, f1)
    assert code == 200, red
    accept(CA, red["handshake_id"], enc_v=0)     # active 0/0
    r = full_row(a, b)
    via = r[1]
    c = db()
    inv = c.execute("SELECT inviter_identity FROM invites WHERE invite_id=?",
                    (via,)).fetchone()
    assert inv is not None, "invite retained"
    c.execute("UPDATE handshakes SET provenance=NULL"
              " WHERE a_identity=? AND b_identity=?", (a, b))
    c.commit(); c.close()
    f2 = mint(CA, enc_v=1)                       # issuer=a = orig redeemer
    code, out = redeem_authed(CB, f2)
    r = full_row(a, b)
    check("T15 redeem 200 despite NULL class", code == 200, (code, out))
    check("T15 NULL class fails closed, keeps 0/0",
          r[5] == 0 and r[6] == 0 and r[4] == 0, r[4:7])

    # ============ T16: invalid link id -> error, no mutation =============
    CA, CB, a, b, IA, IB = pool_pair(0,1)        # T1 pair, active 0/1/cap0
    before = full_row(a, b)
    code, out = redeem_authed(CA, {"h": "deadbeef-" + "00" * 8,
                                   "k": "bogus"})
    after = full_row(a, b)
    check("T16 invalid link rejected (non-200)", code != 200, (code, out))
    check("T16 invalid link leaves row untouched", before == after,
          (before, after))

    # ============ T17: re-accept by the MINTER fails closed ==============
    # c9b14c02: the idempotent re-accept handler wrote redeemer_enc_v for
    # EITHER authenticated party. Ceremony, inviter=sorted-lo(a): the
    # established redeemer is b, so a's re-accept must not mutate. Uses a
    # synthetic active row with the REAL invite as via_link_id (avoids the
    # unauthenticated redeem/IP rate limiter; the ownership logic under
    # test -- invite lookup -> inviter -> established redeemer -- is fully
    # exercised against the real invite row).
    CA, CB, a, b, IA, IB = pool_pair(0,6)
    f1 = mint(CA, enc_v=1)                       # inviter=a (sorted lo)
    insert_row(a, b, f1["h"], 1, 0, 0, "ceremony")  # active 1/0/cap0
    hid = "%s|%s|0" % (a, b)
    assert prov_of(a, b) == ("ceremony", f1["h"]), prov_of(a, b)
    before = full_row(a, b)
    code, out = reaccept(CA, hid, 1)             # minter re-accepts
    r = full_row(a, b)
    check("T17 re-accept by minter answers 200 idempotent",
          code == 200, (code, out))
    check("T17 non-redeemer re-accept fails closed, keeps 1/0/cap0",
          before == r and r[5] == 1 and r[6] == 0 and r[4] == 0, r[4:7])

    # ============ T18: same, mirrored orientation (inviter=hi) ==========
    CA, CB, a, b, IA, IB = pool_pair(1,6)
    f1 = mint(CB, enc_v=1)                       # inviter=b (sorted hi)
    insert_row(a, b, f1["h"], 1, 0, 0, "ceremony")  # active 1/0/cap0
    hid = "%s|%s|0" % (a, b)
    assert prov_of(a, b) == ("ceremony", f1["h"]), prov_of(a, b)
    before = full_row(a, b)
    code, out = reaccept(CB, hid, 1)             # minter re-accepts
    r = full_row(a, b)
    check("T18 re-accept by minter answers 200 idempotent",
          code == 200, (code, out))
    check("T18 non-redeemer re-accept fails closed, keeps 1/0/cap0",
          before == r and r[5] == 1 and r[6] == 0 and r[4] == 0, r[4:7])

    # ============ T19: established redeemer re-accept still upgrades ====
    # The legitimate path: the established redeemer's own advertisement
    # recomputes the capability -- 1/0/cap0 -> 1/1/cap1.
    CA, CB, a, b, IA, IB = pool_pair(2,6)
    f1 = mint(CA, enc_v=1)                       # inviter=a -> redeemer=b
    insert_row(a, b, f1["h"], 1, 0, 0, "ceremony")  # active 1/0/cap0
    hid = "%s|%s|0" % (a, b)
    code, out = reaccept(CB, hid, 1)             # established redeemer b
    r = full_row(a, b)
    check("T19 established-redeemer re-accept upgrades to 1/1/cap1",
          code == 200 and r[5] == 1 and r[6] == 1 and r[4] == 1, r[4:7])

    # ============ T20: operator-attested, sorted-lo re-accept ===========
    # Attested class + NULL via: sorted mapping (mirrors advertise) puts
    # b in the redeemer slot, so a's re-accept must not mutate.
    CA, CB, a, b, IA, IB = pool_pair(3,6)
    insert_row(a, b, None, 1, 0, 0, "operator-attested")
    hid = "%s|%s|0" % (a, b)
    before = full_row(a, b)
    code, out = reaccept(CA, hid, 1)             # sorted-lo: minter slot
    r = full_row(a, b)
    check("T20 attested re-accept by sorted-lo answers 200 idempotent",
          code == 200, (code, out))
    check("T20 attested non-redeemer re-accept fails closed, keeps 1/0/cap0",
          before == r and r[5] == 1 and r[6] == 0 and r[4] == 0, r[4:7])

    # ============ T21: attested established redeemer still upgrades =====
    CA, CB, a, b, IA, IB = pool_pair(4,6)
    insert_row(a, b, None, 1, 0, 0, "operator-attested")
    hid = "%s|%s|0" % (a, b)
    code, out = reaccept(CB, hid, 1)             # sorted-hi: redeemer slot
    r = full_row(a, b)
    check("T21 attested established-redeemer re-accept upgrades to 1/1/cap1",
          code == 200 and r[5] == 1 and r[6] == 1 and r[4] == 1, r[4:7])

    # ============ T22: unknown class + retained invite, fail closed =====
    CA, CB, a, b, IA, IB = pool_pair(5,6)
    f_inv = mint(CA, enc_v=0)                    # retained invite row
    insert_row(a, b, f_inv["h"], 1, 0, 0, "unreviewed")
    hid = "%s|%s|0" % (a, b)
    before = full_row(a, b)
    code, out = reaccept(CA, hid, 1)
    r = full_row(a, b)
    check("T22 unknown-class re-accept answers 200 idempotent",
          code == 200, (code, out))
    check("T22 unknown class re-accept fails closed, keeps 1/0/cap0",
          before == r and r[5] == 1 and r[6] == 0 and r[4] == 0, r[4:7])

    # ============ T23: ceremony class but via_link_id NULL =============
    # No link evidence -> the established redeemer cannot be identified,
    # so EVEN the would-be redeemer fails closed.
    CA, CB, a, b, IA, IB = pool_pair(0,7)
    insert_row(a, b, None, 1, 0, 0, "ceremony")
    hid = "%s|%s|0" % (a, b)
    before = full_row(a, b)
    code, out = reaccept(CB, hid, 1)
    r = full_row(a, b)
    check("T23 ceremony-without-link re-accept answers 200 idempotent",
          code == 200, (code, out))
    check("T23 ceremony-without-link re-accept fails closed, keeps 1/0/cap0",
          before == r and r[5] == 1 and r[6] == 0 and r[4] == 0, r[4:7])

    print("== %d passed, %d failed ==" % (len(PASS), len(FAIL)))
    return 0 if not FAIL else 1

try:
    _p = socket.create_connection(("127.0.0.1", PORT), timeout=2)
    _p.close(); print("port %d busy; abort" % PORT); sys.exit(2)
except OSError:
    pass

OP_IDENT = Ident(TMPD, "op")
OP_TOKEN = secrets.token_hex(32)
write_config()
try:
    start_relay()
    OP = Client("op", OP_IDENT, OP_TOKEN)
    rc = main()
finally:
    stop_relay()
sys.exit(rc)
