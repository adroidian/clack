# HOW_IT_WORKS

This repository is a sanitized staging export of Clack.

## What is structural
- `router.js` is the HTTP/WebSocket router
- `clack_server.py` is the inbox + wake server
- `config.example.json` shows required router config shape

## What is advisory
- the README and deployment notes are examples
- agent names in examples are placeholders
- local file paths in docs are illustrative only

## Router flow
1. Receive `POST /route`
2. Validate `X-Clack-Token`
3. Look up target in route table
4. If target maps to a named local gateway, call `chat.send` over WebSocket
5. If target maps to a remote URL, POST to `${gateway}/route`
6. If local gateway delivery fails, queue for `GET /poll/:agent`

## Python server flow
1. Receive JSON-RPC `tasks/send`
2. Normalize message payload
3. Dedupe and rate-limit
4. Write JSON file into `CLACK_INBOX_ROOT/<agent>/`
5. Attempt wake delivery using config from `CLACK_AGENT_GATEWAYS_JSON`
6. On repeated failure, store retry metadata in `CLACK_PENDING_QUEUE_PATH`
7. Background watcher retries failed wakes and wakes agents for newly dropped inbox files

## Files written
- inbox message files under `CLACK_INBOX_ROOT/<agent>/`
- pending retry queue file at `CLACK_PENDING_QUEUE_PATH`

## Known gaps
- no auth rotation machinery
- no built-in encryption at rest
- no packaged systemd/Docker manifests yet
- no turnkey public deployment example yet
- public release still requires human review of naming and examples
