# CNS Capability Grant v0

Status: draft
Updated: 2026-06-23

## Purpose

Define the capability grant document that encodes what one agent is permitted to do with another
in the CNS/Clack system.

Grants are the authorization layer. They do not describe routing — route records do that.
A grant says: caller X may perform capability Y against target Z, under constraints C, until expiry E.

CNS Capability Grant answers:
- Can this caller perform this capability against this target?
- Who approved the grant?
- Is the grant still valid?
- Are there topic/budget/tool constraints?

## Grant document shape

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
  },
  "metadata": {}
}
```

## Required fields

| Field | Type | Rule |
|---|---|---|
| `grantVersion` | string | `1.0-draft` for this draft. |
| `grantId` | string | Unique grant ID. Format: `grant-{subject-name}-to-{target-name}-{cap}-{date}`. |
| `subject` | string | Agent URI of the caller being granted capability. |
| `target` | string | Agent URI of the target being accessed. |
| `capabilities` | array | One or more capability tier labels. See capability tiers below. |
| `createdAt` | string | ISO-8601 UTC — when this grant was issued. |
| `expiresAt` | string | ISO-8601 UTC — when this grant expires. |

## Optional fields

| Field | Type | Rule |
|---|---|---|
| `ownerApprovedBy` | string | Human URI (`human://name`) of the approving owner. Required for `tools` and `admin` capabilities. |
| `constraints` | object | Scope restrictions. See constraint model below. |
| `metadata` | object | Non-secret auxiliary data. |

## Capability tiers

| Tier | Meaning | Escalation required |
|---|---|---|
| `discover` | Caller can query target identity/metadata. | No. |
| `store-only` | Caller can deposit to inbox/dead-drop. No wake. | No. |
| `direct-send` | Caller can push to target endpoint. | No. |
| `wake` | Caller can trigger bounded agent wake/continuation. | Yes; wake budget enforced. |
| `reply` | Target may respond back within thread. | No (implicit on most grants). |
| `tools` | Target may execute scoped tools for caller. | Yes; `ownerApprovedBy` required. |
| `admin` | Target may alter routes/config/policy. | Yes; `ownerApprovedBy` required. |

For `tools` or `admin` capabilities, `ownerApprovedBy` must be present.

## Constraint model

Constraints narrow the scope of a grant without changing its capability tier.

| Field | Type | Meaning |
|---|---|---|
| `topics` | array of strings | Glob patterns for allowed topic fields. Messages outside matching topics are denied. Empty = all topics allowed. |
| `maxWakeTurns` | integer | Maximum Hermes continuation turns per wake invocation. |
| `tools` | array of strings | Explicit list of tool IDs permitted under `tools` capability. Empty list = no tools despite capability label. |
| `replyThreadOnly` | boolean | If true, `reply` is scoped to a parent thread; standalone messages blocked. |
| `maxMessagesPerHour` | integer | Rate cap per grant. |

## Trust edge model

### Same-owner agents

Agents owned by the same human default to `core-private` trust. Grants between them are
issued by the shared owner. No cross-owner approval required.

```text
human://example grants: agent://zari.example -> agent://mercedes.example: direct-send, wake
```

### Cross-human agents

Agents owned by different humans require the source owner to explicitly grant the edge.
The target owner does not automatically inherit trust.

```text
human://example grants: agent://zari.example -> agent://mercypix.example: store-only, reply
# mercypix.example -> zari.example is NOT automatically granted by the above
human://partner.example must issue: agent://mercypix.example -> agent://zari.example: reply
```

No universal trust handshake. Every cross-human edge is scoped independently.

## Deny by default

When no grant exists for a (subject, target, capability) triple, the answer is deny.

The Clack message plane checks grants before routing. A missing or expired grant produces
a `failed` receipt with `reason: no-capability-grant`.

## Grant lifecycle

```text
issued -> active -> expired
active -> (subject requests capability) -> checked against constraints
active -> (admin revoke) -> deleted
```

Expired grants must be renewed explicitly. Route proof expiry and grant expiry are
independent: a fresh route record does not extend a grant.

## Cross-reference with route records

A grant does not guarantee a working route. Both must hold for delivery:

1. A valid, non-expired grant for the capability.
2. An active route record for the target with matching kind and proof freshness.

If a route record expires but the grant is valid, a new route probe is needed —
not a new grant.

## Validation rules

A valid CNS capability grant must:

1. Include all required fields.
2. Use `agent://` URI for both `subject` and `target`.
3. All items in `capabilities` must be known capability tier labels.
4. `expiresAt` must be after `createdAt`.
5. If `capabilities` includes `tools` or `admin`, `ownerApprovedBy` must be present.
6. `ownerApprovedBy`, if present, must be a `human://` URI.
7. No raw tokens, secrets, or key material in any field.
8. `capabilities` must not be empty.
