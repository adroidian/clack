#!/usr/bin/env bash
# rollback.sh — Revert to the previous app/ version.
# config/ and data/ are never touched.
set -euo pipefail

INSTALL_DIR="/opt/clack-gateway"
SERVICE_NAME="clack-gateway"

echo "==> Clack Gateway rollback"

if [ ! -d "$INSTALL_DIR/app.prev" ]; then
  echo "ERROR: No previous version found at $INSTALL_DIR/app.prev"
  echo "       Nothing to roll back to."
  exit 1
fi

echo "--> Stopping service..."
sudo systemctl stop "$SERVICE_NAME"

echo "--> Swapping app/ <-> app.prev..."
[ -d "$INSTALL_DIR/app.bad" ] && sudo rm -rf "$INSTALL_DIR/app.bad"
sudo mv "$INSTALL_DIR/app" "$INSTALL_DIR/app.bad"
sudo mv "$INSTALL_DIR/app.prev" "$INSTALL_DIR/app"

echo "--> Starting service..."
sudo systemctl start "$SERVICE_NAME"

sleep 2
sudo systemctl status "$SERVICE_NAME" --no-pager -l

echo ""
echo "==> Rollback complete."
echo "    Broken version preserved at $INSTALL_DIR/app.bad"
echo "    Remove it when satisfied: sudo rm -rf $INSTALL_DIR/app.bad"
