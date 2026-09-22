#!/usr/bin/env bash
# test-relay.sh — self-contained test suite for the Kindred A2A relay.
# Spins up an isolated relay instance (temp dir + temp peers + port 18803),
# runs behavioral assertions with curl, tests restart durability, then
# tears everything down. Nothing touches the production relay.
# 36 assertions: auth, validation, dedup/409, poll isolation, at-least-once,
# ack, fetch visibility, TTL expiry, 500-recipient cap, identity challenge
# (fresh-nonce PKCS#1 v1.5 SHA-256 + tamper/bad-nonce rejects), 60/min rate
# limit, kill -9 restart durability, peer revocation (removed peer 401s
# after restart; survivors unaffected).
# Final phase runs test-enroll.py (agent self-enrollment, reserved peer
# names, CLI enroll end-to-end) and folds its counts into PASS/FAIL.
set -euo pipefail

PORT=18803
TMPD="$(mktemp -d /tmp/clack-relay-test.XXXXXX)"
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
python3 - "$TMPD/relay-config.json" "$TA" "$TB" "$TC" "$TD" "$TF0" "$TF1" "$TF2" "$TF3" "$TF4" "$TF5" "$TF6" "$TF7" "$TF8" <<'EOF'
import json, sys, random, math
peers = {"alice": sys.argv[2], "bob": sys.argv[3], "carol": sys.argv[4], "dave": sys.argv[5]}
for i in range(9):
    peers["f%d" % i] = sys.argv[6 + i]
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
cfg = {"port": 18803, "peers": peers,
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
# req METHOD PATH TOKEN DATA -> prints HTTP code, body in $BODY
req() {
  local m="$1" p="$2" t="$3" d="${4:-}"
  local args=(-s -m 10 -o "$BODY" -w "%{http_code}" -X "$m" "http://127.0.0.1:$PORT$p")
  [ "$t" != "NOAUTH" ] && args+=(-H "Authorization: Bearer $t")
  [ -n "$d" ] && args+=(-H "Content-Type: application/json" -d "$d")
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
[ "$(req GET /v1/peers "$TZ")" = "200" ] && ok "revocation setup (zed auth)" \
  || bad "revocation setup (zed auth)" "$(cat "$BODY")"
[ "$(curl -s -m 5 -o "$BODY" -w "%{http_code}" "http://127.0.0.1:$PORT/health")" = "200" ] \
  && [ "$(jget "['ok']")" = "True" ] && ok "health no-auth 200" \
  || bad "health" "$(cat "$BODY")"

[ "$(req GET /v1/peers NOAUTH)" = "401" ] && ok "peers no-auth 401" || bad "peers no-auth" "$(cat "$BODY")"
[ "$(req GET /v1/peers badtoken)" = "401" ] && ok "peers bad-token 401" || bad "peers bad-token" "$(cat "$BODY")"
[ "$(req GET /v1/peers "$TA")" = "200" ] && [ "$(jget "['peers']")" = "['alice', 'bob', 'carol', 'dave', 'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'zed']" ] \
  && ok "peers list" || bad "peers list" "$(cat "$BODY")"

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

CODE="$(req GET "/v1/poll?timeout=1" "$TA")"
[ "$CODE" = "200" ] && [ "$(jget "['messages']")" = "[]" ] && ok "poll isolation (alice sees none)" || bad "poll isolation" "$(cat "$BODY")"

CODE="$(req GET "/v1/poll?timeout=1" "$TB")"
[ "$(jget "['messages'][0]['id']")" = "$ID1" ] && ok "at-least-once re-poll before ack" || bad "re-poll" "$(cat "$BODY")"

RID="$(newid)"
CODE="$(req POST /v1/send "$TB" "{\"id\":\"$RID\",\"to\":\"alice\",\"text\":\"got it\",\"in_reply_to\":\"$ID1\"}")"
[ "$CODE" = "200" ] && ok "reply with in_reply_to" || bad "reply" "$CODE $(cat "$BODY")"

CODE="$(req POST /v1/ack "$TB" "{\"ids\":[\"$ID1\"]}")"
[ "$CODE" = "200" ] && [ "$(jget "['acked']")" = "['$ID1']" ] && ok "ack" || bad "ack" "$CODE $(cat "$BODY")"
CODE="$(req GET "/v1/poll?timeout=1" "$TB")"
[ "$(jget "['messages']")" = "[]" ] && ok "acked message gone from poll" || bad "acked poll" "$(cat "$BODY")"

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

# queue cap: fill to 500 using 9 filler peers (each stays under its own
# 60/min rate limit), then the next send -> 429 queue_full
ACCEPTED=0; CAPERR=""
for f in $(seq 0 8); do
  eval "FT=\$TF$f"
  for j in $(seq 1 56); do
    CODE="$(req POST /v1/send "$FT" "{\"id\":\"$(newid)\",\"to\":\"carol\",\"text\":\"fill\"}")"
    if [ "$CODE" = "200" ]; then ACCEPTED=$((ACCEPTED+1)); else CAPERR="$(jget "['error']")"; break 2; fi
  done
done
[ "$ACCEPTED" = "500" ] && [ "$CAPERR" = "queue_full" ] && ok "queue cap 500 -> 429 queue_full" \
  || bad "queue cap" "accepted=$ACCEPTED err=$CAPERR"

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

# rate limit: fresh peer dave, 61 rapid requests -> 429s after 60
RCODES="$(for i in $(seq 1 61); do req GET /v1/peers "$TD"; echo; done | tr '\n' ' ')"
echo "$RCODES" | grep -q "429" && ok "rate limit 60/min -> 429" || bad "rate limit" "$RCODES"

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
[ "$(req GET /v1/peers "$TZ")" = "401" ] && ok "revoked peer bearer 401" \
  || bad "revoked peer still authenticates" "$(req GET /v1/peers "$TZ") $(cat "$BODY")"
[ "$(req GET /v1/peers "$TA")" = "200" ] && ok "surviving peer still authenticates" \
  || bad "surviving peer" "$(cat "$BODY")"

# --- agent self-enrollment + reserved names (test-enroll.py) ------------------
# Final phase: spins its own scratch instances (ports 18996-18999); never
# touches this script's instance or the production relay.
echo "---- enrollment phase (test-enroll.py) ----"
ENROLL_RC=0
ENROLL_OUT="$(python3 "$HOME/workspace/clack-relay/test-enroll.py" 2>&1)" || ENROLL_RC=$?
echo "$ENROLL_OUT"
ENROLL_PASS="$(printf '%s\n' "$ENROLL_OUT" | sed -n 's/^pass=\([0-9][0-9]*\) fail=.*/\1/p')"
ENROLL_FAIL="$(printf '%s\n' "$ENROLL_OUT" | sed -n 's/^pass=.* fail=\([0-9][0-9]*\)/\1/p')"
PASS=$((PASS + ${ENROLL_PASS:-0}))
FAIL=$((FAIL + ${ENROLL_FAIL:-0}))
[ "$ENROLL_RC" = "0" ] || bad "test-enroll.py exit code" "$ENROLL_RC"

echo "----"
echo "pass=$PASS fail=$FAIL"
[ "$FAIL" = "0" ]
