# Rollback Procedures

## Standard rollback (after a bad update)

`update.sh` always creates `app.prev` before pulling. If the new version misbehaves:

```bash
cd /path/to/chitin/clack
bash scripts/rollback.sh
```

This stops the service, swaps `app/` and `app.prev/`, and restarts. The broken
version is preserved at `app.bad` for inspection.

`config/` and `data/` are **never touched** by rollback.

## Manual rollback (if scripts fail)

```bash
sudo systemctl stop clack-gateway
sudo mv /opt/clack-gateway/app /opt/clack-gateway/app.bad
sudo mv /opt/clack-gateway/app.prev /opt/clack-gateway/app
sudo systemctl start clack-gateway
sudo systemctl status clack-gateway
```

## Config rollback

The gateway config is not versioned by update/rollback scripts — Vesper manages it.
To revert a config change:

1. `sudo systemctl stop clack-gateway`
2. Restore from your config backup or Gitea history
3. `sudo cp <backup> /opt/clack-gateway/config/gateway.yml`
4. `sudo systemctl start clack-gateway`

## Registry data rollback

The registry lives in `/opt/clack-gateway/data/`. Agents re-register automatically
on their next heartbeat, so losing registry state is recoverable without manual intervention.
In the worst case: stop gateway, delete `data/registry.json`, restart — all agents
self-heal within one TTL cycle (default 120s).

## Checking service health after any operation

```bash
# Service status
sudo systemctl status clack-gateway

# Live logs
sudo journalctl -u clack-gateway -f

# Health endpoint (gateway must be running)
curl -s http://localhost:15200/health | jq .

# Current registry state
curl -s http://localhost:15200/registry | jq .
```

## Version pinning

To pin to a specific upstream commit instead of HEAD:

```bash
sudo -u clack bash -c "cd /opt/clack-gateway/app && git checkout <commit-sha>"
sudo -u clack bash -c "cd /opt/clack-gateway/app && npm ci --production"
sudo systemctl restart clack-gateway
```
