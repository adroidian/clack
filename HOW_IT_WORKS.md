# HOW_IT_WORKS

This repository is a sanitized staging export of Clack.

## What is structural
- `router.js` is the routing core plus delivery adapter implementations
- `clack_server.py` is the inbox core plus wake adapter implementations
- `config.example.json` shows the route/adapters config shape

## What is advisory
- the README and deployment notes are examples
- agent names in examples are placeholders
- local file paths in docs are illustrative only

## Router flow
1. Receive `POST /route`
2. Validate `X-Clack-Token`
3. Look up target in route table
4. Resolve the route's adapter
5. Hand delivery to that adapter
6. If adapter delivery fails, queue for `GET /poll/:agent`

## Python server flow
1. Receive JSON-RPC `tasks/send`
2. Normalize message payload
3. Dedupe and rate-limit
4. Write JSON file into `CLACK_INBOX_ROOT/<agent>/`
5. Resolve the target route's adapter
6. Hand wake/delivery to that adapter
7. On repeated failure, store retry metadata in `CLACK_PENDING_QUEUE_PATH`
8. Background watcher retries failed wakes and processes newly dropped inbox files

## Files written
- inbox message files under `CLACK_INBOX_ROOT/<agent>/`
- pending retry queue file at `CLACK_PENDING_QUEUE_PATH`

## Known gaps
- no auth rotation machinery
- no built-in encryption at rest
- no packaged systemd/Docker manifests yet
- no turnkey public deployment example yet
- adapters are configurable but still shipped inline, not as separate plugin modules
- public release still requires human review of naming and examples
