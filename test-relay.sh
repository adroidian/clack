#!/usr/bin/env bash
# test-relay.sh — self-contained test suite for the Kindred A2A relay.
# Spins up an isolated relay instance (temp dir + temp peers + port 18803),
# runs behavioral assertions with curl, tests restart durability, then
# tears everything down. Nothing touches the production relay.
# Assertions: auth, mandatory Ed25519 request signing (v0.2.12 negative
# matrix: unsigned/tampered/replay/stale-nonce/unknown-key/upgrade_required),
# validation, dedup/409, poll isolation, at-least-once redelivery with
# redelivered/delivery_count flags (issue #4), ack, fetch
# visibility, TTL expiry, 500-recipient cap, identity challenge (fresh-nonce
# PKCS#1 v1.5 SHA-256 + tamper/bad-nonce rejects), 60/min rate limit,
# kill -9 restart durability, peer revocation (removed peer 401s after
# restart; survivors unaffected).
# Final phase runs test-enroll.py (agent self-enrollment, reserved peer
# names, CLI enroll end-to-end) and folds its counts into PASS/FAIL.
set -euo pipefail

PORT=${CLACK_TEST_PORT:-18803}
export PORT
TMPD="$(mktemp -d /tmp/clack-relay-test.XXXXXX)"
export TMPD
BODY="$TMPD/body.json"
PASS=0
FAIL=0

cleanup() {
  if [ -n "${SRV:-}" ] && kill -0 "$SRV" 2>/dev/null; then kill "$SRV" 2>/dev/null || true; fi
  rm -rf "$TMPD"
}
trap cleanup EXIT

ok()   { PASS=$((PASS+1)); echo "ok   $1"; }
bad()  { FAIL=$((FAIL+1)); echo "FAIL $1 -- $2"; }

# --- isolated instance -------------------------------------------------------
TA=$(python3 -c "import secrets;print('kr_test_'+secrets.token_urlsafe(24))")
TB=$(python3 -c "import secrets;print('kr_test_'+secrets.token_urlsafe(24))")
TC=$(python3 -c "import secrets;print('kr_test_'+secrets.token_urlsafe(24))")
TD=$(python3 -c "import secrets;print('kr_test_'+secrets.token_urlsafe(24))")
TZ=$(python3 -c "import secrets;print('kr_test_'+secrets.token_urlsafe(24))")
for i in $(seq 0 8); do eval "TF$i=\$(python3 -c \"import secrets;print('kr_test_'+secrets.token_urlsafe(24))\")"; done

# --- mandatory Ed25519 request signing (v0.2.12) ------------------------------
# Every test peer gets a signing keypair in keys.json. The relay's config
# gets the public halves via identity_pubkeys (wired into the config-gen
# block below). zed is DELIBERATELY keyless server-side: its client key
# exists so it can send well-formed signatures, but the relay stores no
# pubkey for it -> every zed request must 401 upgrade_required.
# NOTE: pure-python Ed25519 sign is ~2.7s on this VM; keygen for 14 peers
# takes ~40s once per suite run. Heavy loops below parallelize.
python3 - "$TMPD/keys.json" <<'EOF'
import json, sys, os
sys.path.insert(0, os.path.expanduser("~/workspace/clack-relay"))
import ed25519, base64
def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
keys = {}
for name in ["alice","bob","carol","dave","zed"] + ["f%d"%i for i in range(9)]:
    seed, pub = ed25519.keygen()
    keys[name] = {"seed": b64u(seed), "pub": b64u(pub)}
json.dump(keys, open(sys.argv[1], "w"))
print("signing keys for %d peers" % len(keys))
EOF

# sign.py PEER METHOD PATH BODYFILE [NONCE] -> prints the 4 X-Clack headers.
# One python per call (~50ms startup + ~2.7s sign on this VM).
cat >"$TMPD/sign.py" <<'EOF'
import os, hashlib, time, secrets, json, base64, sys
sys.path.insert(0, os.path.expanduser("~/workspace/clack-relay"))
import ed25519
def b64u_decode(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
td = os.environ["TMPD"]
keys = json.load(open(os.path.join(td, "keys.json")))
peer, method, path, bodyf = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
entry = keys.get(peer)
if not entry:
    sys.exit(3)  # keyless peer: caller sends the request unsigned
nonce = (sys.argv[5] if len(sys.argv) > 5 and sys.argv[5]
         else "%d:%s" % (int(time.time()), secrets.token_hex(16)))
seed = b64u_decode(entry["seed"])
body = open(bodyf, "rb").read()
canon = ("clack-ed25519-v1\n" + method.upper() + "\n" + path + "\n"
         + hashlib.sha256(body).hexdigest() + "\n" + nonce).encode()
print("X-Clack-Scheme: 1")
print("X-Clack-Key: " + peer)
print("X-Clack-Nonce: " + nonce)
print("X-Clack-Sig: " + ed25519.sign(seed, canon).hex())
EOF

# token -> peer name, so req() can sign as the right identity.
declare -A PEER_OF
PEER_OF[$TA]=alice; PEER_OF[$TB]=bob; PEER_OF[$TC]=carol; PEER_OF[$TD]=dave; PEER_OF[$TZ]=zed
for i in $(seq 0 8); do eval "PEER_OF[\$TF$i]=f$i"; done
# tokens.json: peer -> bearer, for the python-crafted negative matrix below.
python3 - "$TMPD/tokens.json" "$TA" "$TB" "$TC" "$TD" "$TZ" <<'EOF'
import json, sys
json.dump({"alice": sys.argv[2], "bob": sys.argv[3], "carol": sys.argv[4],
           "dave": sys.argv[5], "zed": sys.argv[6]}, open(sys.argv[1], "w"))
EOF
python3 - "$TMPD/relay-config.json" "$TA" "$TB" "$TC" "$TD" "$TF0" "$TF1" "$TF2" "$TF3" "$TF4" "$TF5" "$TF6" "$TF7" "$TF8" "$TMPD/keys.json" <<'EOF'
import json, sys, os, random, math
peers = {"alice": sys.argv[2], "bob": sys.argv[3], "carol": sys.argv[4], "dave": sys.argv[5]}
for i in range(9):
    peers["f%d" % i] = sys.argv[6 + i]
skeys = json.load(open(sys.argv[15]))
# v0.2.12: server-side signing keys for every peer EXCEPT zed (keyless ->
# upgrade_required). Client keys for zed still live in keys.json.
pubkeys = {name: skeys[name]["pub"] for name in peers if name in skeys and name != "zed"}
# test-only 1024-bit RSA identity key (pure python; production uses 2048-bit)
def is_prime(n, k=12):
    if n < 2: return False
    for p in (2,3,5,7,11,13,17,19,23,29,31,37):
        if n % p == 0: return n == p
    d, s = n-1, 0
    while d % 2 == 0: d//=2; s+=1
    for _ in range(k):
        a = random.randrange(2, n-1); x = pow(a, d, n)
        if x in (1, n-1): continue
        for _ in range(s-1):
            x = pow(x,2,n)
            if x == n-1: break
        else: return False
    return True
def gen_prime(bits):
    while True:
        p = random.getrandbits(bits) | (1 << (bits-1)) | 1
        if is_prime(p): return p
while True:
    p, q = gen_prime(512), gen_prime(512)
    if p != q and (p*q).bit_length() == 1024 and math.gcd(65537,(p-1)*(q-1)) == 1:
        n = p*q; d = pow(65537, -1, (p-1)*(q-1)); break
cfg = {"port": int(os.environ.get("PORT", "18803")), "peers": peers,
       "identity_pubkeys": pubkeys,
       "identity_key": {"n": format(n,"x"), "e": "10001", "d": format(d,"x")}}
json.dump(cfg, open(sys.argv[1], "w"))
EOF
IN_N="$(python3 -c "import json;print(json.load(open('$TMPD/relay-config.json'))['identity_key']['n'])")"
IN_E="10001"
# extra peer zed, used only for the revocation test below
python3 - "$TMPD/relay-config.json" "$TZ" <<'EOF'
import json, sys
p = sys.argv[1]; cfg = json.load(open(p))
cfg["peers"]["zed"] = sys.argv[2]
json.dump(cfg, open(p, "w"))
EOF
chmod 600 "$TMPD/relay-config.json"

if ss -tln 2>/dev/null | grep -q ":$PORT "; then echo "port $PORT busy"; exit 1; fi
CLACK_RELAY_BASE="$TMPD" nohup python3 "$HOME/workspace/clack-relay/relay.py" >"$TMPD/srv.log" 2>&1 &
SRV=$!
for i in $(seq 1 40); do
  curl -sf -m 2 "http://127.0.0.1:$PORT/health" >/dev/null 2>&1 && break
  sleep 0.25
done
curl -sf -m 2 "http://127.0.0.1:$PORT/health" >/dev/null || { echo "server did not start"; cat "$TMPD/srv.log"; exit 1; }

# --- helpers -----------------------------------------------------------------
# req METHOD PATH TOKEN DATA [OUT] -> prints HTTP code, body in $OUT (default $BODY)
# v0.2.12: every authed request is Ed25519-signed (X-Clack-Scheme/Key/Nonce/Sig).
# The peer name comes from PEER_OF[token]. Tokens with no entry (badtoken)
# go out unsigned, like a legacy client. zed signs with its client key but
# the relay stores no pubkey for it -> 401 upgrade_required.
req() {
  local m="$1" p="$2" t="$3" d="${4:-}" out="${5:-$BODY}"
  local args=(-s -m 30 -o "$out" -w "%{http_code}" -X "$m" "http://127.0.0.1:$PORT$p")
  [ "$t" != "NOAUTH" ] && args+=(-H "Authorization: Bearer $t")
  [ -n "$d" ] && args+=(-H "Content-Type: application/json" -d "$d")
  local peer="${PEER_OF[$t]:-}"
  if [ -n "$peer" ]; then
    # Unique per calling shell: concurrent background jobs must not share
    # one body file ($$ is the main shell's PID in every subshell).
    local bf
    bf="$(mktemp "$TMPD/.reqbody.XXXXXX")"
    if [ -n "$d" ]; then printf '%s' "$d" >"$bf"; else : >"$bf"; fi
    while IFS= read -r hline; do
      [ -n "$hline" ] && args+=(-H "$hline")
    done < <(python3 "$TMPD/sign.py" "$peer" "$m" "$p" "$bf" 2>/dev/null || true)
    rm -f "$bf"
  fi
  curl "${args[@]}"
}
jget() { python3 -c "
import json
try:
    print(json.load(open('$BODY'))$1)
except (KeyError, IndexError, TypeError):
    print('')
"; }
newid() { python3 -c "import uuid;print(uuid.uuid4())"; }

# --- tests -------------------------------------------------------------------
# v0.2.13: mutual-consent handshakes gate /v1/send. This suite tests the
# relay protocol (auth, signing, validation, dedup, poll, ...), not the
# handshake flow (that's test-handshake.py), so it white-boxes ACTIVE
# handshake rows for the pairs this suite sends between: alice<->bob and
# alice->carol (the queue-cap probe expects 429, which the gate would
# otherwise shadow with 403). Real handshake setup would exercise the
# same gate; these rows isolate this suite's actual subject.
python3 - "$TMPD/relay.db" <<'EOF'
import sqlite3, sys, time
c = sqlite3.connect(sys.argv[1])
c.execute("PRAGMA busy_timeout=5000")
def ident(peer):
    r = c.execute("SELECT identity_pubkey FROM peers WHERE name=?", (peer,)).fetchone()
    return r[0] if r and r[0] else peer
now = time.time()
for x, y in (("alice", "bob"), ("alice", "carol")):
    a, b = sorted([ident(x), ident(y)])
    c.execute(
        """INSERT OR REPLACE INTO handshakes(
               a_identity, b_identity, status, created_at,
               pending_expires_at, expires_at, last_activity,
               via_link_id, redeemer_identity, generation)
           VALUES(?, ?, 'active', ?, NULL, NULL, ?, 'test-relay-sh', NULL, 0)""",
        (a, b, now, now),
    )
c.commit()
c.close()
print("handshake rows seeded")
EOF
[ $? -eq 0 ] && ok "handshake rows seeded" || bad "handshake seed" "python failed"
# zed holds a valid bearer but the relay stores no Ed25519 key for it ->
# 401 upgrade_required (v0.2.12 NULL-key path). This doubles as the setup
# for the revocation test below: after zed is removed from the config the
# same token must 401 with "unauthorized" instead.
CODE="$(req GET /v1/peers "$TZ")"
[ "$CODE" = "401" ] && [ "$(jget "['error']")" = "upgrade_required" ] \
  && ok "keyless peer -> 401 upgrade_required" \
  || bad "keyless peer upgrade_required" "$CODE $(cat "$BODY")"
[ "$(curl -s -m 5 -o "$BODY" -w "%{http_code}" "http://127.0.0.1:$PORT/health")" = "200" ] \
  && [ "$(jget "['ok']")" = "True" ] && ok "health no-auth 200" \
  || bad "health" "$(cat "$BODY")"

[ "$(req GET /v1/peers NOAUTH)" = "401" ] && ok "peers no-auth 401" || bad "peers no-auth" "$(cat "$BODY")"
[ "$(req GET /v1/peers badtoken)" = "401" ] && ok "peers bad-token 401" || bad "peers bad-token" "$(cat "$BODY")"
[ "$(req GET /v1/peers "$TA")" = "200" ] && [ "$(jget "['peers']")" = "['alice', 'bob', 'carol', 'dave', 'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'zed']" ] \
  && ok "peers list" || bad "peers list" "$(cat "$BODY")"

# --- mandatory signing negative matrix (v0.2.12) ------------------------------
# Crafted requests via python (full header/body control). Each case prints
# "ok|name|" or "FAIL|name|detail"; the shell loop folds them into PASS/FAIL.
while IFS='|' read -r st nm dt; do
  [ "$st" = "ok" ] && ok "$nm" || bad "$nm" "$dt"
done < <(python3 - <<'PYEOF'
import json, os, sys, time, secrets, hashlib, base64, urllib.request, urllib.error
sys.path.insert(0, os.path.expanduser("~/workspace/clack-relay"))
import ed25519
BASE = "http://127.0.0.1:%s" % os.environ.get("PORT", "18803")
keys = json.load(open(os.path.join(os.environ["TMPD"], "keys.json")))
tokens = json.load(open(os.path.join(os.environ["TMPD"], "tokens.json")))
T = tokens["alice"]

def b64u_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def sign_headers(peer, method, path, body, nonce=None):
    seed = b64u_decode(keys[peer]["seed"])
    if nonce is None:
        nonce = "%d:%s" % (int(time.time()), secrets.token_hex(16))
    canon = ("clack-ed25519-v1\n" + method.upper() + "\n" + path + "\n"
             + hashlib.sha256(body).hexdigest() + "\n" + nonce).encode()
    return {"X-Clack-Scheme": "1", "X-Clack-Key": peer,
            "X-Clack-Nonce": nonce,
            "X-Clack-Sig": ed25519.sign(seed, canon).hex()}

def call(token, method, path, body=None, headers=None):
    r = urllib.request.Request(BASE + path, data=body, method=method)
    if token:
        r.add_header("Authorization", "Bearer " + token)
    for k, v in (headers or {}).items():
        r.add_header(k, v)
    if body is not None:
        r.add_header("Content-Type", "application/json")
    try:
        resp = urllib.request.urlopen(r, timeout=30)
        return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

def err(b):
    try: return json.loads(b).get("error", "?")
    except Exception: return "?"

def check(name, cond, detail=""):
    print(("ok|%s|" % name) if cond else ("FAIL|%s|%s" % (name, detail)))

c, b = call(T, "GET", "/v1/peers")
check("unsigned authed -> 401 missing_signature",
      c == 401 and err(b) == "missing_signature", "%s %s" % (c, b[:60]))

h = sign_headers("alice", "GET", "/v1/peers", b""); h["X-Clack-Scheme"] = "2"
c, b = call(T, "GET", "/v1/peers", headers=h)
check("wrong scheme -> 401 missing_signature",
      c == 401 and err(b) == "missing_signature", "%s %s" % (c, b[:60]))

h = sign_headers("bob", "GET", "/v1/peers", b"")  # bob's sig, alice's token
c, b = call(T, "GET", "/v1/peers", headers=h)
check("key/token mismatch -> 401 unknown_key",
      c == 401 and err(b) == "unknown_key", "%s %s" % (c, b[:60]))

good = b'{"id":"x","to":"bob","text":"good"}'
h = sign_headers("alice", "POST", "/v1/send", good)
c, b = call(T, "POST", "/v1/send", b'{"id":"x","to":"bob","text":"EVIL"}', h)
check("tampered body -> 401 bad_signature",
      c == 401 and err(b) == "bad_signature", "%s %s" % (c, b[:60]))

h = sign_headers("alice", "GET", "/v1/peers", b"")
c, b = call(T, "GET", "/v1/peers?x=1", headers=h)
check("tampered query -> 401 bad_signature",
      c == 401 and err(b) == "bad_signature", "%s %s" % (c, b[:60]))

h = sign_headers("alice", "GET", "/v1/peers", b"")
c, b = call(T, "POST", "/v1/peers", headers=h)
check("tampered method -> 401 bad_signature",
      c == 401 and err(b) == "bad_signature", "%s %s" % (c, b[:60]))

h = sign_headers("alice", "GET", "/v1/peers", b""); h["X-Clack-Sig"] = "00" * 64
c, b = call(T, "GET", "/v1/peers", headers=h)
check("corrupt signature -> 401 bad_signature",
      c == 401 and err(b) == "bad_signature", "%s %s" % (c, b[:60]))

h = sign_headers("alice", "GET", "/v1/peers", b"")
c1, _ = call(T, "GET", "/v1/peers", headers=h)
c2, b2 = call(T, "GET", "/v1/peers", headers=h)
check("replay -> 401 replay",
      c1 == 200 and c2 == 401 and err(b2) == "replay",
      "%s/%s %s" % (c1, c2, b2[:60]))

old = "%d:%s" % (int(time.time()) - 900, secrets.token_hex(16))
h = sign_headers("alice", "GET", "/v1/peers", b"", nonce=old)
c, b = call(T, "GET", "/v1/peers", headers=h)
check("stale nonce -> 401 stale_nonce",
      c == 401 and err(b) == "stale_nonce", "%s %s" % (c, b[:60]))

fut = "%d:%s" % (int(time.time()) + 600, secrets.token_hex(16))
h = sign_headers("alice", "GET", "/v1/peers", b"", nonce=fut)
c, b = call(T, "GET", "/v1/peers", headers=h)
check("future nonce -> 401 stale_nonce",
      c == 401 and err(b) == "stale_nonce", "%s %s" % (c, b[:60]))

h = sign_headers("alice", "GET", "/v1/peers", b"")
c, b = call(T, "GET", "/v1/peers", headers=h)
check("valid signature -> 200 (control)", c == 200, "%s %s" % (c, b[:60]))
PYEOF
)

ID1="$(newid)"
CODE="$(req POST /v1/send "$TA" "{\"id\":\"$ID1\",\"to\":\"bob\",\"topic\":\"test.hello\",\"text\":\"hi bob\"}")"
[ "$CODE" = "200" ] && [ "$(jget "['accepted']")" = "True" ] && ok "send valid" || bad "send valid" "$CODE $(cat "$BODY")"

CODE="$(req POST /v1/send "$TA" "{\"id\":\"$ID1\",\"to\":\"bob\",\"text\":\"again\"}")"
[ "$CODE" = "200" ] && [ "$(jget "['duplicate']")" = "True" ] && ok "send idempotent duplicate" || bad "duplicate" "$CODE $(cat "$BODY")"

CODE="$(req POST /v1/send "$TB" "{\"id\":\"$ID1\",\"to\":\"alice\",\"text\":\"steal\"}")"
[ "$CODE" = "409" ] && ok "cross-peer id collision 409" || bad "id collision" "$CODE $(cat "$BODY")"

for case in \
  '{"id":"not-a-uuid","to":"bob","text":"x"}|id_must_be_uuid' \
  '{"id":"'"$(newid)"'","to":"nobody","text":"x"}|unknown_peer' \
  '{"id":"'"$(newid)"'","to":"alice","text":"x"}|cannot_send_to_self' \
  '{"id":"'"$(newid)"'","to":"bob","topic":"bad topic!","text":"x"}|bad_topic' \
  '{"id":"'"$(newid)"'","to":"bob","text":""}|bad_text' \
  '{"id":"'"$(newid)"'","to":"bob","text":"x","ttl_secs":99999999}|bad_ttl' ; do
  d="${case%%|*}"; want="${case##*|}"
  CODE="$(req POST /v1/send "$TA" "$d")"
  [ "$CODE" = "400" ] && [ "$(jget "['error']")" = "$want" ] && ok "validate $want" || bad "validate $want" "$CODE $(cat "$BODY")"
done

CODE="$(req GET "/v1/poll?timeout=1" "$TB")"
[ "$CODE" = "200" ] && [ "$(jget "['messages'][0]['id']")" = "$ID1" ] \
  && [ "$(jget "['messages'][0]['from']")" = "alice" ] \
  && [ "$(jget "['messages'][0]['text']")" = "hi bob" ] && ok "poll delivers" || bad "poll" "$CODE $(cat "$BODY")"
[ "$(jget "['messages'][0]['redelivered']")" = "False" ] \
  && [ "$(jget "['messages'][0]['delivery_count']")" = "1" ] \
  && ok "first delivery not flagged redelivered" || bad "first-delivery flags" "$(cat "$BODY")"

CODE="$(req GET "/v1/poll?timeout=1" "$TA")"
[ "$CODE" = "200" ] && [ "$(jget "['messages']")" = "[]" ] && ok "poll isolation (alice sees none)" || bad "poll isolation" "$(cat "$BODY")"

CODE="$(req GET "/v1/poll?timeout=1" "$TB")"
[ "$(jget "['messages'][0]['id']")" = "$ID1" ] && ok "at-least-once re-poll before ack" || bad "re-poll" "$(cat "$BODY")"
[ "$(jget "['messages'][0]['redelivered']")" = "True" ] \
  && [ "$(jget "['messages'][0]['delivery_count']")" = "2" ] \
  && ok "re-poll flagged redelivered with count" || bad "redelivery flags" "$(cat "$BODY")"

# --- issue #4: mid-read poll drop must not lose mail --------------------------
# Simulates the 2026-09-24 field incident: carol's poll response is "lost"
# (fetched server-side, bytes never processed client-side, no ack). The
# next poll must redeliver the same message, flagged.
MID="$(newid)"
CODE="$(req POST /v1/send "$TA" "{\"id\":\"$MID\",\"to\":\"carol\",\"text\":\"drop test\"}")"
[ "$CODE" = "200" ] && ok "issue4 send" || bad "issue4 send" "$CODE $(cat "$BODY")"
CODE="$(req GET "/v1/poll?timeout=1" "$TC")"
[ "$(jget "['messages'][0]['id']")" = "$MID" ] \
  && [ "$(jget "['messages'][0]['redelivered']")" = "False" ] && ok "issue4 first fetch" || bad "issue4 fetch" "$(cat "$BODY")"
# client "crashes" here: no ack, response discarded.
CODE="$(req GET "/v1/poll?timeout=1" "$TC")"
[ "$(jget "['messages'][0]['id']")" = "$MID" ] \
  && [ "$(jget "['messages'][0]['redelivered']")" = "True" ] \
  && [ "$(jget "['messages'][0]['delivery_count']")" = "2" ] \
  && ok "issue4 redelivery after dropped read" || bad "issue4 redeliver" "$(cat "$BODY")"
CODE="$(req POST /v1/ack "$TC" "{\"ids\":[\"$MID\"]}")"
[ "$(jget "['acked']")" = "['$MID']" ] && ok "issue4 ack" || bad "issue4 ack" "$(cat "$BODY")"
CODE="$(req GET "/v1/poll?timeout=1" "$TC")"
[ "$(jget "['messages']")" = "[]" ] && ok "issue4 ack retires message" || bad "issue4 retire" "$(cat "$BODY")"

RID="$(newid)"
CODE="$(req POST /v1/send "$TB" "{\"id\":\"$RID\",\"to\":\"alice\",\"text\":\"got it\",\"in_reply_to\":\"$ID1\"}")"
[ "$CODE" = "200" ] && ok "reply with in_reply_to" || bad "reply" "$CODE $(cat "$BODY")"

CODE="$(req POST /v1/ack "$TB" "{\"ids\":[\"$ID1\"]}")"
[ "$CODE" = "200" ] && [ "$(jget "['acked']")" = "['$ID1']" ] && ok "ack" || bad "ack" "$CODE $(cat "$BODY")"
CODE="$(req GET "/v1/poll?timeout=1" "$TB")"
[ "$(jget "['messages']")" = "[]" ] && ok "acked message gone from poll" || bad "acked poll" "$(cat "$BODY")"
CODE="$(req GET "/v1/receipts?limit=10" "$TA")"
RSTATE="$(python3 -c "
import json
try:
    rs = json.load(open('$BODY'))['receipts']
    r = [x for x in rs if x['id'] == '$ID1'][0]
    print(r['state'], r['fetch_count'])
except Exception:
    print('ERR')
")"
[ "$CODE" = "200" ] && [ "$RSTATE" = "acked 2" ] && ok "receipts show state + fetch_count" || bad "receipts" "$CODE $RSTATE"

CODE="$(req POST /v1/ack "$TA" "{\"ids\":[\"$RID\"]}")"  # alice acks bob->alice msg: fine
[ "$(jget "['acked']")" = "['$RID']" ] && ok "ack own message" || bad "ack own" "$(cat "$BODY")"
CODE="$(req POST /v1/ack "$TC" "{\"ids\":[\"$RID\"]}")"  # carol acks others' msg: no-op
[ "$(jget "['acked']")" = "[]" ] && ok "cross-peer ack no-op" || bad "cross-peer ack" "$(cat "$BODY")"

CODE="$(req GET "/v1/fetch?in_reply_to=$ID1" "$TA")"
[ "$CODE" = "200" ] && [ "$(jget "['messages'][0]['id']")" = "$RID" ] && ok "fetch thread (participant)" || bad "fetch" "$CODE $(cat "$BODY")"
CODE="$(req GET "/v1/fetch?in_reply_to=$ID1" "$TC")"
[ "$(jget "['messages']")" = "[]" ] && ok "fetch visibility (non-participant sees none)" || bad "fetch visibility" "$(cat "$BODY")"

EID="$(newid)"
req POST /v1/send "$TA" "{\"id\":\"$EID\",\"to\":\"bob\",\"text\":\"short-lived\",\"ttl_secs\":2}" >/dev/null
sleep 3
CODE="$(req GET "/v1/poll?timeout=1" "$TB")"
[ "$(jget "['messages']")" = "[]" ] && ok "ttl expiry" || bad "ttl expiry" "$(cat "$BODY")"

# queue cap: 500 pending for carol -> next send 429s queue_full.
# Pre-fill via SQL: 500 live signed sends would take ~50min under the
# GIL-serialized pure-python verifier (~2.4s each). The cap check counts
# unacked, unexpired rows per recipient; inserting them directly exercises
# the exact enforcement path, and one live signed send proves the 501st
# is rejected (plus a live control send to a non-full peer succeeds).
N="$(python3 - "$TMPD/relay.db" <<'PYEOF'
import sqlite3, sys, time
db = sqlite3.connect(sys.argv[1])
now = time.time()
db.executemany(
    "INSERT INTO messages(id, sender, recipient, topic, text, in_reply_to,"
    " created_at, expires_at, acked_at) VALUES(?,?,?,?,?,?,?,?,NULL)",
    [("cap-%d" % i, "alice", "carol", None, "fill", None,
      now, now + 3600) for i in range(500)])
db.commit()
print(db.execute("SELECT COUNT(*) FROM messages WHERE recipient='carol'"
                 " AND acked_at IS NULL").fetchone()[0])
PYEOF
)"
[ "$N" = "500" ] && ok "queue pre-fill 500" || bad "queue pre-fill" "n=$N"
CODE="$(req POST /v1/send "$TA" "{\"id\":\"$(newid)\",\"to\":\"carol\",\"text\":\"overflow\"}")"
[ "$CODE" = "429" ] && [ "$(jget "['error']")" = "queue_full" ] \
  && ok "queue cap 500 -> 429 queue_full" \
  || bad "queue cap" "overflow=$CODE $(cat "$BODY")"
# control: a non-full recipient still accepts
CODE="$(req POST /v1/send "$TA" "{\"id\":\"$(newid)\",\"to\":\"bob\",\"text\":\"not full\"}")"
[ "$CODE" = "200" ] && ok "queue cap control (bob not full)" || bad "queue cap control" "$CODE"
# hygiene: drain bob's queue -- the restart-durability test below was written
# against an empty queue and asserts messages[0]; a leftover here would
# (correctly) survive the restart and break that assertion.
CODE="$(req GET "/v1/poll?timeout=1" "$TB")"
BID="$(jget "['messages'][0]['id']")"
if [ "$CODE" = "200" ] && [ -n "$BID" ]; then
  req POST /v1/ack "$TB" "{\"ids\":[\"$BID\"]}" >/dev/null
fi

# identity challenge: fresh nonce, PKCS#1 v1.5 SHA-256, pure-python verify
verify_sig() { # nonce_hex sig_b64 -> prints True/False
  python3 - "$1" "$2" "$IN_N" "$IN_E" <<'EOF'
import sys, hashlib, base64
nonce_hex, sig_b64, n_hex, e_hex = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
try:
    nonce = bytes.fromhex(nonce_hex); sig = base64.b64decode(sig_b64)
    n, e = int(n_hex,16), int(e_hex,16); k = (n.bit_length()+7)//8
    em = pow(int.from_bytes(sig,"big"), e, n).to_bytes(k,"big")
    t = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(nonce).digest()
    print(em == b"\x00\x01" + b"\xff"*(k-len(t)-3) + b"\x00" + t)
except Exception:
    print(False)
EOF
}
NONCE="$(python3 -c "import secrets;print(secrets.token_hex(32))")"
CODE="$(req GET "/v1/identity?nonce=$NONCE" NOAUTH)"
[ "$CODE" = "200" ] && [ "$(jget "['nonce']")" = "$NONCE" ] \
  && [ "$(jget "['algorithm']")" = "rsassa-pkcs1-v1_5-sha256" ] \
  && [ "$(verify_sig "$NONCE" "$(jget "['signature']")")" = "True" ] \
  && ok "identity challenge verifies" || bad "identity challenge" "$CODE $(cat "$BODY")"
# tampered nonce must NOT verify against the returned signature
SIG="$(jget "['signature']")"
TAMPERED="${NONCE:0:62}ff"
[ "$(verify_sig "$TAMPERED" "$SIG")" = "False" ] && ok "identity tamper rejected" || bad "identity tamper" "verified?!"
for badq in "" "nonce=zzzz" "nonce=abcd" "nonce=$(python3 -c "print('ab'*130)")"; do
  CODE="$(req GET "/v1/identity?$badq" NOAUTH)"
  { [ "$CODE" = "400" ] && ok "identity rejects bad nonce ($badq)"; } || bad "identity bad nonce" "$badq -> $CODE"
done

# rate limit: the 60/min sliding window can't be triggered live -- 61
# GIL-serialized verifies (~2.4s each) can't fit in one 60s window -- so
# the window logic is unit-tested against the imported relay module (fast,
# no crypto), and a live smoke proves signed requests aren't falsely 429'd.
while IFS='|' read -r st nm dt; do
  [ "$st" = "ok" ] && ok "$nm" || bad "$nm" "$dt"
done < <(python3 - <<'PYEOF'
import importlib.util, time
spec = importlib.util.spec_from_file_location(
    "relay", "/home/hatch/workspace/clack-relay/relay.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
tok = "unittest-token-sha2"
r = [m.rate_ok(tok) for _ in range(60)] + [m.rate_ok(tok)]
r2 = m.rate_ok("other-token")
m.rate_hits[tok] = [time.time() - 61.0] * 60
r3 = m.rate_ok(tok)
if all(r[:60]) and not r[60] and r2 and r3:
    print("ok|rate limit 60/min sliding window|")
else:
    print("FAIL|rate limit 60/min sliding window|%s" % (r,))
PYEOF
)
CODE="$(req GET /v1/peers "$TD")"
[ "$CODE" = "200" ] && ok "rate limit live smoke (no false 429)" || bad "rate limit live" "$CODE"

# restart durability: message survives kill -9 + restart
DID="$(newid)"
CODE="$(req POST /v1/send "$TA" "{\"id\":\"$DID\",\"to\":\"bob\",\"text\":\"survive-restart\"}")"
[ "$CODE" = "200" ] || { bad "restart durability (setup send)" "$CODE $(cat "$BODY")"; }
kill -9 "$SRV"; sleep 1
CLACK_RELAY_BASE="$TMPD" nohup python3 "$HOME/workspace/clack-relay/relay.py" >"$TMPD/srv2.log" 2>&1 &
SRV=$!
for i in $(seq 1 40); do curl -sf -m 2 "http://127.0.0.1:$PORT/health" >/dev/null 2>&1 && break; sleep 0.25; done
CODE="$(req GET "/v1/poll?timeout=1" "$TB")"
[ "$CODE" = "200" ] && [ "$(jget "['messages'][0]['id']")" = "$DID" ] \
  && [ "$(jget "['messages'][0]['text']")" = "survive-restart" ] \
  && ok "restart durability (kill -9)" || bad "restart durability" "$CODE $(cat "$BODY")"

# revocation: remove zed from config, restart, old bearer must 401 (v0.1 bug:
# init_db only upserted, so removed peers kept authenticating)
python3 - "$TMPD/relay-config.json" <<'EOF'
import json, sys
p = sys.argv[1]; cfg = json.load(open(p))
del cfg["peers"]["zed"]; json.dump(cfg, open(p, "w"))
EOF
kill "$SRV" 2>/dev/null; sleep 1
CLACK_RELAY_BASE="$TMPD" nohup python3 "$HOME/workspace/clack-relay/relay.py" >"$TMPD/srv3.log" 2>&1 &
SRV=$!
for i in $(seq 1 40); do curl -sf -m 2 "http://127.0.0.1:$PORT/health" >/dev/null 2>&1 && break; sleep 0.25; done
CODE="$(req GET /v1/peers "$TZ")"
[ "$CODE" = "401" ] && [ "$(jget "['error']")" = "unauthorized" ] \
  && ok "revoked peer bearer 401 unauthorized" \
  || bad "revoked peer still authenticates" "$CODE $(cat "$BODY")"
[ "$(req GET /v1/peers "$TA")" = "200" ] && ok "surviving peer still authenticates" \
  || bad "surviving peer" "$(cat "$BODY")"

# --- peer_hashes regression (test-peer-hashes.py) ---------------------------
# Hash-only config peers (protected provisioning) must survive the
# init_db config rebuild: no revocation, no message/webhook loss, no
# name retirement. Spins no relay; exercises init_db directly on
# scratch DBs. Never touches production.
echo "---- peer-hashes phase (test-peer-hashes.py) ----"
PH_RC=0
PH_OUT="$(python3 "$HOME/workspace/clack-relay/test-peer-hashes.py" 2>&1)" || PH_RC=$?
echo "$PH_OUT"
PH_PASS="$(printf '%s\n' "$PH_OUT" | sed -n 's/^pass=\([0-9][0-9]*\) fail=.*/\1/p')"
PH_FAIL="$(printf '%s\n' "$PH_OUT" | sed -n 's/^pass=.* fail=\([0-9][0-9]*\)/\1/p')"
PASS=$((PASS + ${PH_PASS:-0}))
FAIL=$((FAIL + ${PH_FAIL:-0}))
[ "$PH_RC" = "0" ] || bad "test-peer-hashes.py exit code" "$PH_RC"

# --- real supervisor-style restart (test-real-restart.py) -------------------
# Spawns ACTUAL relay processes, SIGTERMs them like a supervisor would,
# restarts them, and verifies hash-only peer/message/webhook retention,
# revocation, dual-source fail-closed, and disposable restore. Scratch
# ports 18980-18983 and scratch dirs only; never touches production.
echo "---- real-restart phase (test-real-restart.py) ----"
RR_RC=0
RR_OUT="$(python3 "$HOME/workspace/clack-relay/test-real-restart.py" 2>&1)" || RR_RC=$?
echo "$RR_OUT"
RR_PASS="$(printf '%s\n' "$RR_OUT" | sed -n 's/^pass=\([0-9][0-9]*\) fail=.*/\1/p')"
RR_FAIL="$(printf '%s\n' "$RR_OUT" | sed -n 's/^pass=.* fail=\([0-9][0-9]*\)/\1/p')"
PASS=$((PASS + ${RR_PASS:-0}))
FAIL=$((FAIL + ${RR_FAIL:-0}))
[ "$RR_RC" = "0" ] || bad "test-real-restart.py exit code" "$RR_RC"

# --- agent self-enrollment + reserved names (test-enroll.py) ------------------
# Final phase: spins its own scratch instances (ports 18996-18999); never
# touches this script's instance or the production relay.
echo "---- enrollment phase (test-enroll.py) ----"
ENROLL_RC=0
# test-enroll.py spins its own scratch instances on its default ports
# (18994-18999); drop our port override so it doesn't collide with this
# script's relay on $PORT.
ENROLL_OUT="$(env -u CLACK_TEST_PORT python3 "$HOME/workspace/clack-relay/test-enroll.py" 2>&1)" || ENROLL_RC=$?
echo "$ENROLL_OUT"
ENROLL_PASS="$(printf '%s\n' "$ENROLL_OUT" | sed -n 's/^pass=\([0-9][0-9]*\) fail=.*/\1/p')"
ENROLL_FAIL="$(printf '%s\n' "$ENROLL_OUT" | sed -n 's/^pass=.* fail=\([0-9][0-9]*\)/\1/p')"
PASS=$((PASS + ${ENROLL_PASS:-0}))
FAIL=$((FAIL + ${ENROLL_FAIL:-0}))
[ "$ENROLL_RC" = "0" ] || bad "test-enroll.py exit code" "$ENROLL_RC"

echo "----"
echo "pass=$PASS fail=$FAIL"
[ "$FAIL" = "0" ]
