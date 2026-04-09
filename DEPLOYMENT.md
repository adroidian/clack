# Clack Deployment Notes

This document is intentionally generic. Replace all example values with your own.

## Router deployment

1. Copy `config.example.json` to `config.json`
2. Fill in:
   - `clackToken`
   - local control endpoint URLs/credentials
   - route table
3. Run:
   ```bash
   node router.js
   ```

Recommended:
- run behind systemd, pm2, or Docker
- expose over TLS via reverse proxy or tunnel
- restrict inbound access to trusted senders

## Python server deployment

Required env vars:
- `CLACK_PORT`
- `CLACK_TOKEN`
- `CLACK_INBOX_ROOT`

Optional env vars:
- `CLACK_PENDING_QUEUE_PATH`
- `CLACK_AGENT_GATEWAYS_JSON`

Run:
```bash
python3 clack_server.py
```

## Safe rollout advice

- Never replace tokens in place without verifying all peers update together
- Keep one known-good router revision available for rollback
- Validate `/health` before sending test traffic
- Send one test message agent-to-agent after deploy

## What this repo does NOT include

- product-specific control-plane configs
- cloud tunnel configs
- personal DNS names
- service account credentials
- real agent topology