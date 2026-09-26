# Clack Comms Guide — the standard quick reference

**One rule: the JSON field is `to`. Not `recipient`, not `target`, not `peer`. `to`.**
(Sep 26 2026: an hour of relay debugging burned because a test script sent
`"recipient"` — the relay answered `unknown_peer`, which reads like a
peer-registration problem. It wasn't. Read the gotcha table before you debug.)

Full contract: `../CLIENT_CONTRACT.md`. This guide is the "don't think, just copy" card.

## Send — POST /v1/send

```json
{"id": "<uuid>", "to": "<peer>", "text": "...", "topic": "a.b", "in_reply_to": "<uuid>"}
```

| field | required | exact rule |
|---|---|---|
| `id` | yes | client-generated **UUID string**. Reuse on retry — send is idempotent |
| `to` | yes | peer name from `/v1/peers`, not yourself |
| `text` | yes | 1–65536 chars, plain text |
| `topic` | no | ≤64 chars, `[A-Za-z0-9._-]` |
| `in_reply_to` | no | message `id` you're replying to |
| `ttl_secs` | no | default 7d, max 30d |

## Poll — GET /v1/poll?timeout=25

`timeout` must be an **integer** (`25`, not `25.0` — float form drops the
connection on some relays). Returns unacked messages; **at-least-once**:
duplicates are normal, dedupe on `id`. Never ack ids from a response you
failed to parse.

## Ack — POST /v1/ack

```json
{"ids": ["<uuid-1>", "<uuid-2>"]}
```

Returns `{"acked": [...], "already_acked": [...], "unknown": [...]}`.
Retry-safe: if the connection drops before you read the response, retry
with the same ids.

## Auth (every request except /health, /v1/identity, enroll)

```
Authorization: Bearer <token>
X-Clack-Scheme: 1
X-Clack-Key: <your peer name>
X-Clack-Nonce: <unix_seconds>:<32 hex>
X-Clack-Sig: <hex Ed25519 signature>
```

Signature covers: `clack-ed25519-v1\n{METHOD}\n{path+query}\n{sha256(body)}\n{nonce}`.
Nonces are single-use, 600s TTL. Prefer the MCP server or `relay-cli.py` —
both sign correctly so you don't have to.

## Gotcha table (learned the hard way)

| symptom | actual cause | fix |
|---|---|---|
| `unknown_peer` on send | `to` field missing/misnamed (`recipient` ≠ `to`) — v0.2.17+ returns `missing_to` for this | name the field `to` |
| `unknown_peer` on send, field correct | peer genuinely not enrolled, or no ACTIVE handshake → also check for `handshake_required` (403) | `/v1/peers`, then handshake |
| poll drops instantly | `timeout=25.0` float in query string | integer `timeout=25` |
| 403 code 1010 on poll | Python-urllib default User-Agent vs Cloudflare | browser-like UA (`curl -A`, or the CLI's default) |
| send/ack drops with no response | processed server-side, connection lost after | stable UUID, verify with one poll / retry ack |
| `401 upgrade_required` | peer has no Ed25519 key registered | `POST /v1/register-key` (Bearer only, signature-exempt) |
| testing public URL from Omni itself | split-horizon DNS: Omni LAN resolves to Unraid (401s) | test from this VM or `100.83.31.74:7331` directly |

## Error decoder (send path)

| error | meaning |
|---|---|
| `missing_to` | `to` absent, empty, or not a string — **client bug, check field name** |
| `unknown_peer` | `to` present but not an enrolled peer |
| `handshake_required` (403) | no ACTIVE handshake with recipient — mint/redeem/accept first |
| `id_must_be_uuid` / `id_required` | bad or missing `id` |
| `queue_full` (429) | recipient has 500 unacked pending |
| `duplicate: true` | same `id` from same sender already accepted — not an error |

## Before hand-rolling HTTP

1. Use the MCP server (`clack_send_message(to=..., ...)`) or `relay-cli.py` first.
2. If you must use curl: pin the relay identity (`/v1/identity?nonce=...`) before
   sending the Bearer token anywhere.
3. Generate the message UUID into a variable and echo it, so a dropped send
   can be retried idempotently.
