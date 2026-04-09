# Clack

Clack is a lightweight message bus for autonomous agents and automation workers.

It handles the boring but necessary parts of inter-agent communication:
- routing messages to the right target
- forwarding across local or remote boundaries
- poll fallback when push delivery is unavailable
- inbox file drops for durable handoff
- retry and dedupe around wake/delivery attempts

## Why Clack exists

Most agent systems can already *send a message* somewhere. The hard part is everything around that:
- which runtime owns the target agent?
- can that target receive push directly or only poll?
- what happens when the wake call fails?
- how do you preserve a message long enough to retry?

Clack is the thin coordination layer around those problems.

## Design

Clack has two layers:

### 1. Core
The core is responsible for:
- accepting messages
- normalizing payloads
- route lookup
- queueing fallback
- retries
- inbox persistence
- dedupe / rate limiting

### 2. Adapters
Adapters are responsible for speaking a concrete delivery protocol.

Current built-in adapter types:
- `ws-rpc` — local WebSocket RPC control plane
- `remote-http` — forward to another Clack router over HTTP
- `http-wake` — wake/deliver through an HTTP endpoint
- `queue-http` — enqueue work for a polling consumer

That means the bus is no longer tied to one private control protocol at the core level.

## Repository contents

- `router.js` — HTTP router with adapter-based delivery
- `clack_server.py` — inbox + wake server with adapter-based delivery
- `config.example.json` — example router config
- `DEPLOYMENT.md` — deployment notes
- `HOW_IT_WORKS.md` — implementation details and boundaries
- `SANITIZE_CHECKLIST.md` — pre-publication review checklist

## Quick start

### Router
```bash
cp config.example.json config.json
node router.js
```

### Server
```bash
export CLACK_PORT=15100
export CLACK_TOKEN=replace-me
export CLACK_INBOX_ROOT=/srv/clack/inbox
export CLACK_ROUTES_JSON='{}'
export CLACK_ADAPTERS_JSON='{}'
python3 clack_server.py
```

## Router config model

The router is configured with three main sections:

- `auth` — shared auth used for inbound route requests
- `adapters` — named delivery integrations
- `routes` — target agent → adapter + target mapping

Example:

```json
{
  "routerName": "router-host-name",
  "port": 7331,
  "auth": {
    "sharedToken": "replace-with-shared-secret"
  },
  "adapters": {
    "local-control": {
      "type": "ws-rpc",
      "url": "ws://127.0.0.1:18789",
      "token": "replace-with-local-control-token",
      "connect": {
        "challengeEvent": "connect.challenge",
        "method": "connect",
        "scopes": ["operator.write"]
      },
      "deliver": {
        "method": "chat.send",
        "targetField": "sessionKey",
        "messageField": "message",
        "idempotencyField": "idempotencyKey"
      }
    },
    "remote-router": {
      "type": "remote-http",
      "baseUrl": "https://remote-router.example.com",
      "path": "/route",
      "authHeader": "X-Clack-Token"
    }
  },
  "routes": {
    "agent-a": {
      "adapter": "local-control",
      "target": "agent:agent-a:main"
    },
    "remote-agent": {
      "adapter": "remote-router",
      "target": "agent:remote-agent:main"
    }
  }
}
```

## Security notes

Clack assumes:
- a shared secret for router-to-router and sender-to-router auth
- local delivery credentials are managed out of band
- network boundaries and TLS are handled by the operator

Do **not** commit:
- real tokens
- real control-plane credentials
- real domains
- real routes
- real infrastructure topology

## Current status

This repo is a **private staging export** being cleaned for a future public mirror.
The code and docs are intentionally genericized, but still under review before GitHub sync.

## License

MIT — see `LICENSE`.
