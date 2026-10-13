#!/usr/bin/env bash
# Clack local A2A relay keepalive (recreated Oct 1 2026 after VM-replacement wipe).
# Documented behavior (Sep 29 2026): /health check + 3-probe retry, then
# `systemctl restart clack-relay` when the unit exists. Exit 1 if no unit.
# NO start.sh fallback -- start.sh no longer exists; the systemd unit is canonical.
set -u

HEALTH_URL="${CLACK_HEALTH_URL:-http://127.0.0.1:18802/health}"
TS="$(date '+%F %T %Z')"

probe() {
  curl -sf -m 10 "$HEALTH_URL" >/dev/null 2>&1
}

relay_pid() {
  # MainPID from the systemd unit; fall back to pgrep scoped to the config path.
  if systemctl show clack-relay --property MainPID 2>/dev/null | grep -q .; then
    systemctl show clack-relay --property MainPID --value 2>/dev/null | tr -d ' \n'
  else
    pgrep -f "[r]elay.py" | head -1
  fi
}

attempt=0
while [ "$attempt" -lt 3 ]; do
  if probe; then
    pid="$(relay_pid)"
    echo "$TS keepalive ok (relay pid ${pid:-unknown}, no restart)"
    exit 0
  fi
  attempt=$((attempt + 1))
  [ "$attempt" -lt 3 ] && sleep 5
done

# Health still failing after 3 probes -> restart via systemd unit.
if ! systemctl cat clack-relay >/dev/null 2>&1; then
  echo "$TS keepalive FAIL: relay unhealthy and no clack-relay systemd unit present (nothing restarted)" >&2
  exit 1
fi

if ! systemctl restart clack-relay 2>/dev/null; then
  echo "$TS keepalive FAIL: systemctl restart clack-relay failed" >&2
  exit 1
fi
sleep 5
if probe; then
  pid="$(relay_pid)"
  echo "$TS keepalive recovered (relay restarted, pid ${pid:-unknown})"
  exit 0
else
  echo "$TS keepalive FAIL: relay restarted but /health still failing" >&2
  exit 1
fi
