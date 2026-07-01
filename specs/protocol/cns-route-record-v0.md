# CNS Route Record v0

Status: draft
Updated: 2026-06-23

## Purpose

Define how CNS stores, resolves, and expires routes to agents.

Route records are separate from agent identity documents. An agent can have multiple route records (e.g. one for direct HTTP, one for filedrop fallback, one for Hermes wake). Clack Core selects the best available route based on kind, priority, status, and proof freshness.

CNS Route Record answers:
- How can agent X currently be reached?
- When was that route last proved?
- What proof exists that it works?
- Is this route still fresh or stale?

## Route record shape

```json
{
  "routeRecordVersion": "1.0-draft",
  "routeId": "route-zari-clack-http-20260623",
  "agentId": "agent://zari.example",
  "kind": "clack-http",
  "status": "active",
  "priority": 10,
  "endpoint": "http://example.invalid:15100/a2a",
  "createdAt": "2026-06-23T07:00:00Z",
  "expiresAt": "2026-06-23T08:30:00Z",
  "updatedAt": "2026-06-23T07:00:00Z",
  "proofAt": "2026-06-23T07:00:00Z",
  "proofKind": "delivery",
  "proofId": "rcpt-018ff2d2-3f31-7f1a-9a4d-6d78f7d4c001-routed",
  "ttlSeconds": 5400,
  "metadata": {}
}
```

## Required fields

| Field | Type | Rule |
|---|---|---|
| `routeRecordVersion` | string | `1.0-draft` for this draft. |
| `routeId` | string | Unique route record ID. |
| `agentId` | string | Stable agent URI: `agent://name.owner`. |
| `kind` | string | Route kind. See Route kinds below. |
| `status` | string | One of: `active`, `stale`, `unreachable`. |
| `priority` | integer | Lower = preferred. See priority tiers below. |
| `createdAt` | string | ISO-8601 UTC. |
| `expiresAt` | string | ISO-8601 UTC. Expired routes must not be used without re-proof. |

## Optional fields

| Field | Type | Rule |
|---|---|---|
| `endpoint` | string | URL or filesystem path for this route. Omit if not applicable (e.g. some relay kinds). |
| `proofAt` | string | ISO-8601 UTC — when was this route last proved? |
| `proofKind` | string | One of: `heartbeat`, `delivery`, `wake-output`, `health-check`, `none`. |
| `proofId` | string | Receipt ID or log reference that proved this route. |
| `ttlSeconds` | integer | Positive; used to compute expiry on creation/re-proof. |
| `updatedAt` | string | ISO-8601 UTC — last update. |
| `metadata` | object | Non-secret auxiliary data (e.g. `hermesProfileMap`, `inboxPath`). |

## Route kinds

| Kind | Transport | Notes |
|---|---|---|
| `local-http` | HTTP POST to localhost or LAN IP | Preferred for same-host or same-LAN delivery. |
| `clack-http` | HTTP POST via Clack server | Cross-host push over tailnet or LAN. |
| `filedrop` | Filesystem write to inbox path | No-network fallback; store-only by nature. |
| `store-only` | Inbox/dead-drop | Explicit store-only; no wake. |
| `hermes-wake` | HTTP POST to Hermes `/wake` endpoint | Wake Hermes profile for bounded continuation. |
| `openclaw-hook` | OpenClaw gateway hook | Wake via gateway hooks. |
| `relay` | Self-hosted relay path | Cross-LAN relay without Tailscale/Cloudflare. |
| `lakebed-dead-drop` | Lakebed broker/dead-drop | Async cockpit path; treat as store-only. |
| `tailscale-http` | HTTP via Tailscale IP | Current fallback; becoming non-primary. |
| `p2p-libp2p` | libp2p QUIC+Noise | Future P2P; not yet in production. |
| `p2p-iroh` | Iroh QUIC | Future P2P Rust alternative. |
| `unknown` | Unknown transport | Needs inspection. |

## Priority tiers

Lower priority number = more preferred when multiple routes are available.

| Priority | Tier | Examples |
|---|---|---|
| 10 | Direct LAN/local HTTP | `local-http`, `clack-http` direct |
| 20 | Wake capable | `hermes-wake`, `openclaw-hook` |
| 30 | Relay | `relay`, `tailscale-http` |
| 50 | Dead-drop/store-only | `filedrop`, `lakebed-dead-drop`, `store-only` |
| 99 | Unknown | `unknown` |

## Status transitions

```text
active  ──(TTL expires)──► stale
active  ──(delivery fails)──► unreachable
stale   ──(re-proved)──► active
stale   ──(delivery fails)──► unreachable
unreachable  ──(re-proved)──► active
```

A stale route may still be attempted with a warning receipt. An unreachable route must not be used without manual re-proof or re-registration.

## Proof kinds

| Proof kind | Meaning | Resulting stage |
|---|---|---|
| `heartbeat` | Gateway heartbeat confirmed route alive. | route considered fresh but not send-proved. |
| `delivery` | Actual message delivered and accepted. | direct-send capability proven. |
| `wake-output` | Agent wake job completed. | wake capability proven. |
| `health-check` | Health/ready endpoint responded. | direct-health proved; not delivery proof. |
| `none` | No proof yet; route exists by registration only. | route must not be used for wake/delivery claims. |

## Clack v1 compatibility

Current Clack v1 Python server routes are configured via env vars (`ROUTES_JSON`, `ADAPTERS_JSON`). These should be migrated to CNS route records. The adapter names map as:

| Clack v1 adapter | CNS route kind |
|---|---|
| `store-only` | `filedrop` or `store-only` |
| `queue-http` | `clack-http` |
| `http-wake` | `local-http` or `clack-http` |
| `hermes-wake` | `hermes-wake` |

## Validation rules

A valid CNS route record must:

1. Include all required fields.
2. Use `agent://` URI for `agentId`.
3. Use a known `kind`.
4. Use a known `status`.
5. `priority` must be a positive integer.
6. `expiresAt` must be after `createdAt`.
7. If `proofKind` is `delivery` or `wake-output`, `proofId` should be present.
8. Route records with `kind` `filedrop` or `store-only` must not be used to claim wake capability.
9. No raw IP addresses or tokens in top-level fields; use `metadata` or `endpoint`.
