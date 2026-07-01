#!/usr/bin/env bash
# install.sh — First-time setup of Clack Gateway on omni.
# Run as a user with sudo. Service runs as the 'clack' system user.
set -euo pipefail

INSTALL_DIR="/opt/clack-gateway"
SERVICE_NAME="clack-gateway"
# chitin/clack-core — our fork of win4r/openclaw-a2a-gateway.
# Contains Chitin shims (/routes, /deliveries/recent) + harness-agnostic transport layer.
# Primary: Gitea (internal). Mirror: github.com/adroidian/clack-core (public).
UPSTREAM="https://github.com/adroidian/clack.git"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> Clack Gateway install"

# --- Create system user ---
if ! id -u clack &>/dev/null; then
  echo "--> Creating system user 'clack'..."
  sudo useradd --system --no-create-home --shell /bin/false clack
fi

# --- Directory layout (Vesper-approved) ---
echo "--> Creating directory layout at $INSTALL_DIR..."
sudo mkdir -p "$INSTALL_DIR"/{app,config,data,logs}
sudo chown -R clack:clack "$INSTALL_DIR"
sudo chmod 750 "$INSTALL_DIR"/{config,data,logs}

# --- Clone clack-core ---
if [ -d "$INSTALL_DIR/app/.git" ]; then
  echo "--> app/ already exists, skipping clone (use update.sh to upgrade)"
else
  echo "--> Cloning clack-core..."
  sudo -u clack git clone "$UPSTREAM" "$INSTALL_DIR/app"
fi

echo "--> Installing Node dependencies..."
sudo -u clack bash -c "cd $INSTALL_DIR/app && npm ci --production --silent"

# --- Config ---
if [ ! -f "$INSTALL_DIR/config/gateway.yml" ]; then
  echo "--> Installing example config..."
  sudo cp "$REPO_DIR/config/gateway.example.yml" "$INSTALL_DIR/config/gateway.yml"
  sudo cp "$REPO_DIR/config/env.example" "$INSTALL_DIR/config/env"
  sudo chown clack:clack "$INSTALL_DIR/config/gateway.yml" "$INSTALL_DIR/config/env"
  sudo chmod 640 "$INSTALL_DIR/config/gateway.yml"
  sudo chmod 600 "$INSTALL_DIR/config/env"
  echo ""
  echo "  !! Edit $INSTALL_DIR/config/gateway.yml before starting."
  echo "  !! Inject CLACK_BOOTSTRAP_SECRET from a secret manager into $INSTALL_DIR/config/env."
  echo ""
else
  echo "--> Config already exists, skipping."
fi

# --- systemd ---
echo "--> Installing systemd unit..."
sudo cp "$REPO_DIR/systemd/clack-gateway.service" /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE_NAME"

echo ""
echo "==> Install complete."
echo "    1. Fill in $INSTALL_DIR/config/gateway.yml (copy allowed_agents from kin-net registry)"
echo "    2. Inject secrets: CLACK_BOOTSTRAP_SECRET from a secret manager"
echo "    3. Optionally seed: cp <kin-net-export> $INSTALL_DIR/config/bootstrap-registry.json"
echo "    4. Start: sudo systemctl start $SERVICE_NAME"
echo "    5. Check: sudo systemctl status $SERVICE_NAME"
echo "    6. Tail logs: sudo journalctl -u $SERVICE_NAME -f"
