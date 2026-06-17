# Clack Registry Schema

Full schema: `config/registry.schema.json`

Each agent self-registers by POSTing a record to the gateway. The gateway validates
against this schema, checks the agent ID against the allowlist, and verifies the
bootstrap token before accepting the record.

## Required fields

| Field | Type | Description |
|---|---|---|
| `agentId` | string | Unique pack-wide identifier. Lowercase, no spaces. e.g. `sable` |
| `hostId` | string | Tailscale hostname of the machine the agent runs on. e.g. `omni`, `desk`, `teseract` |
| `tailscaleUrl` | URI | A2A endpoint over Tailscale. Used for all internal pack traffic. |
| `wakeUrl` | URI | Harness wake endpoint. Gateway calls this after routing a message. |
| `harnessType` | enum | One of: `openclaw`, `hermes`, `cloudrun`, `custom` |
| `transport` | enum | One of: `http-wake`, `openclaw-task`, `webhook`, `queue` |
| `capabilities` | string[] | Skill/topic tags. Used for capability-based routing. |
| `ttl` | integer | Heartbeat TTL in seconds (min 30). Agent must re-register before expiry. |

## Optional fields

| Field | Type | Description |
|---|---|---|
| `publicUrl` | URI or null | CF tunnel A2A endpoint. Null if agent is internal-only. |
| `registeredAt` | datetime | Set by gateway on accept. |
| `expiresAt` | datetime | Set by gateway: `registeredAt + ttl`. Refreshed on heartbeat. |
| `bootstrapTokenHash` | string or null | Bcrypt hash of per-agent token. Null for local mDNS-trusted agents. |

## Harness types and wake adapters

| `harnessType` | Wake URL format | What the gateway does |
|---|---|---|
| `openclaw` | `http://<host>:18789/hooks/agent` | POST `{ agent: agentId }` |
| `hermes` | `http://<host>:<port>/wake` | POST `{ agentId, taskId }` |
| `cloudrun` | `https://<service>.run.app/wake` | POST with Bearer token |
| `custom` | Any HTTP endpoint | POST `{ agentId, taskId, message }` |

## Registration auth

- **Local agents (mDNS-discovered on omni):** trusted by host proximity. No per-agent token required.
- **Remote agents (other Tailscale hosts):** must supply `X-Clack-Token` header matching the
  bcrypt hash stored in Infisical at `/clack/agent-tokens/<agentId>`.
- **Remote agents cannot overwrite local agents.** If an incoming registration for a locally-registered
  agentId arrives from a different hostId, it is rejected with 403.

## Heartbeat

Agents POST to `/heartbeat` with `{ agentId }` every `ttl/2` seconds (recommended).
The gateway refreshes `expiresAt = now + ttl`. Records not refreshed before `expiresAt`
are marked `stale` and excluded from routing until the agent re-registers.

## Example record

```json
{
  "agentId": "sable",
  "hostId": "omni",
  "tailscaleUrl": "http://100.x.x.x:15100",
  "publicUrl": null,
  "wakeUrl": "http://100.x.x.x:18789/hooks/agent",
  "harnessType": "openclaw",
  "transport": "http-wake",
  "capabilities": ["memory", "search", "qdrant"],
  "ttl": 120,
  "bootstrapTokenHash": null
}
```
