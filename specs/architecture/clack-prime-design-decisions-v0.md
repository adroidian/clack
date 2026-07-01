# Clack Prime Design Decisions v0

Status: Phase 1 decision record
Updated: 2026-06-29

## Purpose

Resolve the open Clack Prime design questions blocking first controlled agent rollout planning.

This document records current v0 decisions. It does not deploy anything, publish a mirror, alter routes, or approve live testing.

## Decision summary

| Question | Decision |
|---|---|
| Identity expiry/renewal | Identities expire administratively; default one year for local/dev, shorter if policy requires. Renewal updates `updatedAt` and `expiresAt`; renewal must not change `agentId` ownership semantics, and `agentId` must not be reassigned to a different agent. |
| Route record vs gateway registry ownership | CNS route records are authoritative. Gateway registry/cache is derived operational state only. |
| Trust class defaults | Missing/unknown trust defaults to deny. Same-owner private agents may be `core-private`; cross-owner edges require explicit grants. |
| `hermesProfile` edge cases | Required for `harnessType: hermes`; absent only allowed for non-Hermes or `unknown` harness identities. |
| Heartbeat TTL by route kind | Use route-kind defaults from `cns-heartbeat-v0.md`; route-specific `ttlSeconds` may override, minimum 60s. |
| Relay node placement | Relay is a future transport adapter, not identity/policy authority. First relay should be a single self-hosted node after local/stub gates, not in Phase 2/local MVP. |
| Capability grant storage | Store grants in CNS/SQLite `capability_grants`; route proof never extends grant expiry. |

## 1. Identity expiry and renewal

### Decision

Identity documents have administrative expiry separate from route liveness.

Default policy:

- local/dev identity default: one year;
- production/live identity duration: rollout-packet decision;
- renewal updates `updatedAt` and `expiresAt`;
- renewal must not change `agentId` ownership semantics;
- expired identity means the agent must re-register or be explicitly renewed before new grants/routes are trusted.

### Rationale

Route expiry answers "can this route be used now?" Identity expiry answers "is this registered agent still administratively valid?" Blending them would make a heartbeat accidentally extend trust, which is exactly how ghosts get keys. No, thank you.

### Implementation impact

- Keep `agents.expires_at` separate from `route_records.expires_at`.
- Do not let `ApplyHeartbeat` modify agent identity expiry.
- Add future renewal API as explicit administrative operation.

## 2. Route records vs gateway registry ownership

### Decision

CNS route records are authoritative. Gateway registry state is a cache/projection for serving route lookup and operational health.

### Rationale

The gateway needs fast lookup and local operational state, but route truth belongs in CNS so agents can reason from durable records and receipts.

### Implementation impact

- `route_records` table remains source for route kind/status/priority/proof/expiry.
- Gateway registry import/export must be treated as migration/compatibility only.
- Env-driven route definitions are legacy compatibility, not the future authority.

## 3. Trust class defaults

### Decision

Deny by default.

Trust classes:

| Trust class | Default behavior |
|---|---|
| `core-private` | Eligible for same-owner grants; still capability-checked. |
| `peer-aaron` | Compatibility label for known peer-private lane; requires explicit grants. |
| `cross-human` | Explicit grants required for each edge/capability. |
| `unknown` or missing | Deny except discovery/registration workflows explicitly allowed by policy. |

### Rationale

Trust class is a policy hint, not a capability grant. Grants remain the authorization primitive.

### Implementation impact

- `CheckCapability` remains grant-based.
- Future policy layer may use trust class to suggest defaults, but not to bypass grants.
- Public docs should eventually generalize `peer-aaron` before mirror if anonymization requires it.

## 4. `hermesProfile` requirement edge cases

### Decision

`hermesProfile` is required when `harnessType` is `hermes`.

Allowed cases:

| Harness type | `hermesProfile` required? | Notes |
|---|---:|---|
| `hermes` | yes | Needed to wake/run the correct Hermes profile. |
| `claude-code` | no | Future fields may name CLI workspace/session. |
| `openclaw` | no | Gateway hook identity is route/metadata concern. |
| `unknown` | no | Registration is incomplete; deny sensitive capabilities. |

### Rationale

A Hermes wake without a profile is a wrong-number call with tools. That is not a route; that is a haunted phone.

### Implementation impact

Current validation is correct: Hermes identities require `hermesProfile`; non-Hermes identities may omit it.

## 5. Heartbeat TTL per route kind

### Decision

Use the route-kind defaults defined in `cns-heartbeat-v0.md`:

| Route kind | Default TTL |
|---|---:|
| `clack-http` | 300s |
| `local-http` | 300s |
| `tailscale-http` | 300s |
| `hermes-wake` | 3600s |
| `relay` | 900s |
| `filedrop` | 86400s |
| `store-only` | 86400s |
| other/unknown | 300s until policy says otherwise |

Minimum accepted TTL is 60s. `ttlSeconds: 0` in heartbeat payload means "use existing route/default TTL," not "expire immediately."

### Rationale

Short TTLs are useful for direct routes; long TTLs are fine for store-only/filedrop paths that rarely change and do not prove wake/delivery.

### Implementation impact

Current `ApplyHeartbeat` behavior from PR #6 is the desired v0 behavior, and `cns-heartbeat-v0.md` now documents the `ttlSeconds: 0` fallback semantics.

## 6. Relay node placement

### Decision

Relay is a future transport adapter. It does not own identity, grants, or policy.

First relay placement, when approved later:

1. single self-hosted relay node;
2. no inbound ports on agent hosts;
3. outbound agent sessions only;
4. CNS route kind `relay` points at the relay route, not at private agent internals;
5. relay receipts prove relay acceptance/pickup, not target wake unless a `woke` receipt exists.

### Rationale

The relay solves cross-LAN transport. It must not become a second registry, policy engine, or secret swamp.

### Implementation impact

- Keep `clack-relay-v0.md` design-only.
- Do not implement or deploy relay before rollout gate approval.
- Relay route records and grants remain CNS-managed.

## 7. Capability grant storage location

### Decision

Capability grants live in CNS/SQLite `capability_grants` for v0.

Grant facts:

- grant expiry is independent from route expiry;
- route heartbeat/delivery/wake proof never extends grant expiry;
- `tools` and `admin` require `ownerApprovedBy`;
- grants should be referenced by policy receipts when available;
- future external policy engines may project into CNS, but CNS remains the local enforcement cache.

### Rationale

Routes prove reachability. Grants prove permission. Different problem, different timer, different failure mode. Mixing them is how "it responded once" becomes "it can run admin tools forever." Absolutely not.

### Implementation impact

Current `capability_grants` table remains the local v0 storage location. Future work should add grant IDs into policy-checked receipts.

## Updated rollout posture

After these decisions, the correct status is:

```text
local-ready; live rollout pending packet approval
```

Next recommended artifact:

```text
first-agent-rollout-packet-v0.md
```

It should target one low-risk local/stub path first, not a mesh-wide rollout.
