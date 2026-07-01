# CNS Heartbeat and Expiry Semantics v0

Status: draft
Updated: 2026-06-23

## Purpose

Define how agents register, maintain liveness, and how CNS expires stale records.

Heartbeat is not a trust proof. It is a liveness proof: the agent and its route are still
reachable. Delivery proof (`delivered` receipt) and wake proof (`woke` receipt) carry
stronger capability claims and should be used in place of heartbeat wherever possible.

## Registration

On first contact, an agent registers:

1. A CNS agent identity document (see `cns-agent-identity-v0.md`).
2. One or more CNS route records (see `cns-route-record-v0.md`).

Registration sets `registeredAt` on the identity doc and `createdAt` on each route record.
Route records include a `ttlSeconds` field that determines the expiry window.

## Heartbeat flow

```text
agent -> CNS gateway: POST /heartbeat
  body: { agentId, routeId, proofKind: "heartbeat", proofAt: <now-iso8601> }

CNS gateway -> route record: update proofAt, proofKind, recompute expiresAt = now + ttlSeconds
CNS gateway -> agent: 200 OK { updated: true, expiresAt: <new-expiry> }
```

A heartbeat extends the route record's `expiresAt` by `ttlSeconds` from the heartbeat
timestamp. It does not change `createdAt`.

If the agent sends a heartbeat for an unknown `routeId`, the gateway responds with
`404 route-not-found`. The agent must re-register.

## TTL values

| Route kind | Recommended TTL | Notes |
|---|---|---|
| `clack-http` | 300s | Legacy KNS heartbeat interval; inherit for continuity. |
| `local-http` | 300s | Same-host routes may use shorter TTL if desired. |
| `hermes-wake` | 3600s | Wake routes are less time-sensitive; long TTL acceptable. |
| `filedrop` | 86400s | File paths rarely change; extend aggressively. |
| `store-only` | 86400s | Same as filedrop. |
| `relay` | 900s | Relay session liveness; re-probe every 15 min. |
| `tailscale-http` | 300s | Treat same as clack-http during transition. |

Agents may request a shorter or longer TTL at registration. The gateway may cap the maximum.
Minimum enforced TTL is 60s. A heartbeat payload with `ttlSeconds: 0` or an omitted
TTL means "use the existing route TTL, or the route-kind default if the route does not
have one." It does not mean immediate expiry.

## Stale and expiry

When `expiresAt` passes without a heartbeat or delivery proof:

- Route record status transitions: `active` → `stale`.
- Clack Core may still attempt delivery to a stale route but must emit a warning receipt.
- Stale routes must not be reported as `direct-send` capability without re-proof.

When a stale route fails delivery:

- Route record status transitions: `stale` → `unreachable`.
- Unreachable routes must not be used until re-proved.

Agent identity docs have a separate `expiresAt` (typically months). Identity expiry means
the whole agent registration needs renewal. Route record expiry is operational liveness;
identity expiry is administrative.

## Re-proof via delivery

When Clack Core successfully delivers a message through a route:

- Update route record `proofAt = now`.
- Update `proofKind = "delivery"`.
- Set status to `active` if previously stale.
- Extend `expiresAt` by `ttlSeconds`.

Delivery proof is stronger than heartbeat. Prefer it where available.

## Wake proof

A successful `woke` receipt (agent ran, produced output):

- Update route record `proofAt = now`.
- Update `proofKind = "wake-output"`.
- Set status to `active`.
- Extend `expiresAt` by `ttlSeconds`.

Wake proof proves both route reachability and agent execution.

## KNS compatibility

KNS used a 300s heartbeat TTL via `kns_clack_heartbeat.py`. On migration to CNS:

- The existing heartbeat scripts continue to work against the CNS gateway heartbeat endpoint
  if the endpoint is backward-compatible.
- The 300s TTL is preserved for `clack-http` routes (see table above).
- KNS stored `registered_at` as Unix float; CNS uses ISO-8601. Migration scripts must convert.

## Expiry vs revocation

Expiry is passive: time passes, TTL elapses, record goes stale.
Revocation is active: an owner or admin explicitly deletes a grant or route record.

For heartbeat purposes, focus on expiry. Revocation is an administrative operation
outside the heartbeat loop.

## Validation rules

A valid heartbeat payload must:

1. Include `agentId` as `agent://` URI.
2. Include `routeId` as a non-empty string.
3. Include `proofAt` as ISO-8601 UTC timestamp.
4. `proofKind` must be one of: `heartbeat`, `delivery`, `wake-output`, `health-check`.
5. No secret fields.

Fixture coverage lives in `specs/fixtures/valid-heartbeat.json` and
`specs/fixtures/invalid-heartbeat.json`, validated by
`tools/validation/validate_clack_docs.py`.
