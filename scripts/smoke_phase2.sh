#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DB=${1:-$(mktemp /tmp/clack-phase2-XXXXXX.db)}
if command -v go >/dev/null 2>&1; then
  GO_BIN=$(command -v go)
elif [ -x "$HOME/.local/go/bin/go" ]; then
  GO_BIN="$HOME/.local/go/bin/go"
else
  printf 'go binary not found; install Go or add it to PATH\n' >&2
  exit 127
fi
PYTHON_BIN=${PYTHON_BIN:-python3}
cd "$ROOT"
mkdir -p bin
"$GO_BIN" build -o bin/clackd ./cmd/clackd
"$GO_BIN" build -o bin/clackctl ./cmd/clackctl
bin/clackd --db "$DB" --once
bin/clackctl --db "$DB" agent register agent://zari.example
bin/clackctl --db "$DB" agent register agent://vesper.example
bin/clackctl --db "$DB" dm send agent://zari.example agent://vesper.example ping
bin/clackctl --db "$DB" inbox list agent://vesper.example | grep 'ping'
bin/clackctl --db "$DB" channel create ops
bin/clackctl --db "$DB" channel post ops agent://zari.example status?
bin/clackctl --db "$DB" receipt list | grep '"stage":"stored"'
"$PYTHON_BIN" tools/validation/validate_clack_docs.py
printf 'PHASE2_SMOKE_OK db=%s\n' "$DB"
