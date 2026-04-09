# Clack

Clack is a lightweight agent-to-agent messaging layer for autonomous agents or automation workers.

It provides:
- HTTP routing between agents
- local control-plane WebSocket delivery
- remote router-to-router forwarding
- poll fallback for agents that cannot receive push directly
- a small Python server for inbox + wake orchestration

## Status

This repository is a **sanitized staging export** prepared for eventual public release.
It is intentionally generic:
- no real domains
- no real tokens
- no personal paths
- no internal hostnames
- no production agent names required

## Components

### `router.js`
Node router that:
- accepts `POST /route`
- forwards locally over a WebSocket control endpoint
- forwards remotely over HTTP to another Clack router
- exposes `GET /health`
- supports `GET /poll/:agent` and `POST /queue/:agent`

### `clack_server.py`
Python server that:
- accepts JSON-RPC `tasks/send`
- writes messages into per-agent inbox directories
- wakes target agents through configurable HTTP endpoints or a queue fallback
- retries failed wake attempts

## Repo Layout

- `router.js` — Node router
- `clack_server.py` — Python inbox/wake server
- `config.example.json` — sample router config
- `README.md` — overview
- `DEPLOYMENT.md` — safe deployment guidance
- `SANITIZE_CHECKLIST.md` — what to review before publishing to GitHub

## Quick Start

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
python3 clack_server.py
```

## Security Model

Clack assumes:
- a shared secret for router-to-router and sender-to-router auth
- local delivery credentials are managed out of band
- network boundaries and TLS are handled by the operator

Do **not** commit real secrets, real routes, or production control-plane credentials.

## Current abstraction boundary

This export is sanitized, but it still ships with a concrete adapter model:
- the router expects a challenge/response WebSocket control endpoint for local delivery
- the Python server expects HTTP wake endpoints or queue endpoints

That is better than being branded, but it is not yet a fully pluggable transport layer. If we want a stronger public release, the next cleanup step is to split protocol adapters from core routing.

## Next Step

Use this private staging repo to finish scrub/review. Once the checklist is clean, sync to GitHub.