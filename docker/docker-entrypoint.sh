#!/bin/sh
# Clack relay container entrypoint.
#
# Runs as root just long enough to own the data dir and mint the first-run
# config, then drops to the unprivileged `clack` user before the relay
# starts. The relay itself never runs as root.
set -eu

DATA="${CLACK_RELAY_BASE:-/data}"
APP_DIR="${APP_DIR:-/app}"
mkdir -p "$DATA"

if [ ! -f "$DATA/relay-config.json" ]; then
    echo "clack-relay: no config at $DATA/relay-config.json — generating first-run config" >&2
    python3 "$APP_DIR/init-config.py" "$DATA/relay-config.json"
fi
chmod 600 "$DATA/relay-config.json"
chown -R clack:clack "$DATA"

# Drop privileges. setpriv ships in util-linux (present in python:slim);
# fall back to su if it ever isn't.
if command -v setpriv >/dev/null 2>&1; then
    exec setpriv --reuid=clack --regid=clack --clear-groups python3 "$APP_DIR/relay.py"
else
    exec su -s /bin/sh clack -c "exec python3 $APP_DIR/relay.py"
fi
