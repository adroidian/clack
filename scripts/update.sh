#!/usr/bin/env bash
# update.sh — Pull latest openclaw-a2a-gateway and restart service.
# Preserves config/ and data/. Creates app.prev backup for rollback.
set -euo pipefail

INSTALL_DIR="/opt/clack-gateway"
SERVICE_NAME="clack-gateway"

echo "==> Clack Gateway update"

# --- Backup ---
echo "--> Backing up app/ to app.prev..."
[ -d "$INSTALL_DIR/app.prev" ] && sudo rm -rf "$INSTALL_DIR/app.prev"
sudo cp -r "$INSTALL_DIR/app" "$INSTALL_DIR/app.prev"

# --- Pull ---
echo "--> Pulling latest..."
sudo -u clack bash -c "cd $INSTALL_DIR/app && git pull --ff-only"
sudo -u clack bash -c "cd $INSTALL_DIR/app && npm ci --production --silent"

# --- Restart ---
echo "--> Restarting service..."
sudo systemctl restart "$SERVICE_NAME"

# Brief wait then status
sleep 2
sudo systemctl status "$SERVICE_NAME" --no-pager -l

echo ""
echo "==> Update complete. Rollback available: scripts/rollback.sh"
