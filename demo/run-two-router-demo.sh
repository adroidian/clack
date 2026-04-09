#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMPDIR="$(mktemp -d)"
PORT_A=17331
PORT_B=17332
trap 'kill ${PID_A:-} ${PID_B:-} 2>/dev/null || true; rm -rf "$TMPDIR"' EXIT

fuser -k ${PORT_A}/tcp ${PORT_B}/tcp >/dev/null 2>&1 || true
sleep 1

cp "$ROOT/demo/router-a.config.json" "$TMPDIR/router-a.config.json"
cp "$ROOT/demo/router-b.config.json" "$TMPDIR/router-b.config.json"

(
  cd "$ROOT"
  CLACK_CONFIG_PATH="$TMPDIR/router-a.config.json" node router.js > "$TMPDIR/router-a.log" 2>&1
) &
PID_A=$!

(
  cd "$ROOT"
  CLACK_CONFIG_PATH="$TMPDIR/router-b.config.json" node router.js > "$TMPDIR/router-b.log" 2>&1
) &
PID_B=$!

sleep 1

echo "== router health =="
curl -s http://127.0.0.1:17331/health
printf '\n'
curl -s http://127.0.0.1:17332/health
printf '\n\n'

echo "== send agent-a -> agent-b through router-a =="
curl -s -X POST http://127.0.0.1:17331/route \
  -H 'Content-Type: application/json' \
  -H 'X-Clack-Token: demo-shared-token' \
  -d '{"to":"agent-b","from":"agent-a","topic":"demo","message":"hello from demo"}'
printf '\n\n'

echo "== poll router-b for queued messages =="
curl -s http://127.0.0.1:17332/poll/agent-b
printf '\n\n'

echo "== logs =="
printf '\n-- router-a.log --\n'
cat "$TMPDIR/router-a.log"
printf '\n-- router-b.log --\n'
cat "$TMPDIR/router-b.log"
