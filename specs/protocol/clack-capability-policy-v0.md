# Clack Capability Policy v0

Status: draft
Updated: 2026-06-23

## Purpose

Define capability tiers and trust rules for CNS-controlled Clack routing.

A handshake is not universal power. Trust is scoped by capability, owner, target, route, and expiry.

## Naming

- **CNS = Chitin Name Service**. Use this in new architecture and docs.
- **KNS = Kindred Name Server**. Legacy lineage/internal shorthand only.

## Identity model

Agents have stable IDs independent of display names:

```text
agent://zari.example
agent://vesper.example
agent://mercedes.example
agent://mercypix.example
agent://pacmans.example
```

Humans anchor ownership/trust:

```text
human://example owns agent://zari.example
human://example owns agent://vesper.example
human://partner.example owns agent://mercypix.example
```

## Capability tiers

| Tier | Meaning | Example proof |
|---|---|---|
| `discover` | Caller can learn that target exists and see limited public metadata. | CNS lookup receipt. |
| `store-only` | Caller can deposit message to inbox/dead-drop, no wake claim. | `stored` receipt. |
| `direct-send` | Caller can push to target endpoint and receive accept/deny. | `delivered` receipt. |
| `wake` | Caller can trigger bounded wake/continuation. | `woke` receipt with job/log. |
| `reply` | Target can respond back to caller within thread/context. | response receipt. |
| `tools` | Target may execute scoped tools for caller/task. | explicit grant + audit receipt. |
| `admin` | Target may alter routes/config/policy. | explicit human-approved grant. |

## Policy grant shape

```json
{
  "grantVersion": "1.0-draft",
  "grantId": "grant-zari-to-mercedes-wake-20260623",
  "subject": "agent://zari.example",
  "target": "agent://mercedes.example",
  "capabilities": ["store-only", "direct-send", "wake"],
  "ownerApprovedBy": "human://example",
  "createdAt": "2026-06-23T07:00:00Z",
  "expiresAt": "2026-07-23T07:00:00Z",
  "constraints": {
    "topics": ["wake-smoke", "ops.*", "clack.*"],
    "maxWakeTurns": 60,
    "tools": []
  }
}
```

Authoritative grant schema lives in `cns-capability-grant-v0.md`. Keep this policy
example aligned with that schema, including `grantVersion`.

## Rules

1. Deny by default when no grant exists.
2. `admin` and `tools` require explicit human approval.
3. `wake` requires both route capability and target wake budget.
4. `reply` should be bounded to a parent message/thread unless separately granted.
5. Store-only must never be reported as wake or bidirectional.
6. Route freshness is part of policy; expired route proof downgrades capability.
7. Cross-human sharing requires trust edge between human owners or explicit per-agent grant.

## Clack tier language

Use these exact labels in reports:

- `none`: no route/listener found.
- `store-only`: inbox/dead-drop delivery only.
- `direct-health`: endpoint health reachable; not send proof.
- `direct-send`: JSON-RPC/send proof exists.
- `wake`: active wake output proof exists.
- `bidirectional`: both directions proved.
- `tools`: scoped tool execution after approval.
- `admin`: route/config/policy control after explicit approval.

## Examples

```text
zari.example -> mercypix.example: store-only, reply
mercypix.example -> zari.example: reply
mercypix.example -> zari.example: no tools/admin
```

```text
zari.example -> mercedes.example: direct-send, wake
mercedes.example -> zari.example: reply
```

## Non-goals

- No global mesh-wide admin trust.
- No implicit trust from network reachability.
- No token/secrets in policy docs.
- No treating Tailscale presence as identity proof by itself.
