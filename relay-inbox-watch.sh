#!/bin/bash
# Relay inbox watcher: polls the ex-relay and the local relay for new
# messages and prints only ones not seen before. Never prints credentials.
# Seen-ids live under the kindred-a2a-relay goal's hidden_files.
set -u
SEEN_DIR="$HOME/workspace/goals/kindred-a2a-relay/hidden_files/inbox-watch"
mkdir -p "$SEEN_DIR"
UA="Mozilla/5.0 MuseClack/0.1"
RELAY_DIR="$HOME/workspace/clack-relay"

parse_out() { # raw_json seenfile name
  python3 - "$1" "$SEEN_DIR/$2" "$3" <<'EOF'
import json, sys, os
raw, seenfile, name = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    msgs = json.loads(raw).get('messages', [])
except Exception:
    print('[%s] bad response' % name)
    sys.exit()
seen = set()
if os.path.exists(seenfile):
    seen = set(open(seenfile).read().split())
new = [m for m in msgs if m.get('id') not in seen]
with open(seenfile, 'a') as f:
    for m in new:
        f.write(m.get('id', '') + '\n')
if not new:
    print('[%s] no new messages' % name)
for m in new:
    print('[%s] NEW from=%s topic=%s id=%s' % (name, m.get('from'), m.get('topic'), m.get('id')))
    print((m.get('text') or '')[:600])
    print('---')
EOF
}

poll() { # name base_url config seenfile -- legacy token poll (ex-relay)
  local name="$1" base="$2" cfg="$3" seen="$4"
  local token
  token=$(python3 -c "import json;print(json.load(open('$cfg'))['peers']['nugget'])" 2>/dev/null) || { echo "[$name] no token"; return; }
  local out
  out=$(curl -s --retry 2 --retry-all-errors -m 30 "$base/v1/poll?timeout=5" \
    -H "Authorization: Bearer $token" -A "$UA" 2>/dev/null) || { echo "[$name] poll failed"; return; }
  parse_out "$out" "$seen" "$name"
}

poll_cli() { # name identity_config seenfile -- signed poll via relay CLI (v0.2.12+)
  local name="$1" cfg="$2" seen="$3"
  local out
  out=$(python3 "$RELAY_DIR/relay-cli.py" --config "$cfg" poll --timeout 5 2>/dev/null) || { echo "[$name] poll failed"; return; }
  parse_out "$out" "$seen" "$name"
}

poll "ex-relay"    "https://clack.kasnet.us"   "$RELAY_DIR/ex-relay-config.json" "ex.seen"
poll_cli "local-relay" "$RELAY_DIR/nugget-local-identity.json" "local.seen"
