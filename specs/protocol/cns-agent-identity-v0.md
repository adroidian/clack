# CNS Agent Identity v0

Status: draft
Updated: 2026-06-23

## Purpose

Define the stable agent identity document for the Chitin Name Service (CNS).

CNS replaces KNS (Kindred Name Server). KNS stored agent names, IPs, and ports in a flat JSON registry without stable IDs, owner anchors, or expiry semantics. CNS v0 adds those.

CNS answers:
- Who is this agent?
- Who owns / entrusts it?
- What harness runs it?
- What trust tier applies?
- When does this record expire?

Routes are stored separately in CNS Route Records, not embedded here.

## Identity document shape

```json
{
  "cnsVersion": "1.0-draft",
  "agentId": "agent://zari.example",
  "owner": "human://example",
  "name": "zari",
  "description": "DevOps/network engineer — trusted overwatch operator on Ex",
  "harnessType": "hermes",
  "host": "ex",
  "trustClass": "core-private",
  "hermesProfile": "zari",
  "registeredAt": "2026-06-23T07:00:00Z",
  "expiresAt": "2026-12-23T07:00:00Z",
  "updatedAt": "2026-06-23T07:00:00Z",
  "skills": [
    {"id": "devops", "name": "DevOps", "description": "Infrastructure operations"},
    {"id": "overwatch", "name": "Overwatch", "description": "Continuous operational awareness"}
  ],
  "publicKeyRef": "cns-keyring://zari.example/ed25519-2026",
  "metadata": {}
}
```

## Required fields

| Field | Type | Rule |
|---|---|---|
| `cnsVersion` | string | `1.0-draft` for this draft. |
| `agentId` | string | Stable URI: `agent://name.owner`. |
| `owner` | string | Human owner URI: `human://name`. |
| `name` | string | Short name; lowercase, no spaces. Backward-compat with registry keys. |
| `description` | string | Human-readable role description. |
| `harnessType` | string | One of: `hermes`, `claude-code`, `openclaw`, `unknown`. |
| `host` | string | Hostname or platform name where this agent runs. |
| `registeredAt` | string | ISO-8601 UTC — when this identity was created. |
| `expiresAt` | string | ISO-8601 UTC — when this record must be renewed. |

## Optional fields

| Field | Type | Rule |
|---|---|---|
| `hermesProfile` | string | Conditionally required: Hermes profile name; required when `harnessType` is `hermes`. |
| `pod` | string | Team or pod grouping. |
| `trustClass` | string | One of: `core-private`, `peer-aaron`, `cross-human`, `unknown`. See trust model below. |
| `publicKeyRef` | string | Reference to key material; never embed raw key. Format: `cns-keyring://agentId/key-label`. |
| `skills` | array | List of skill objects: `{id, name, description}`. |
| `updatedAt` | string | ISO-8601 UTC — last update. |
| `metadata` | object | Non-secret auxiliary data. |

## Harness types

| Value | Meaning |
|---|---|
| `hermes` | Agent runs as a Hermes one-shot continuation profile. |
| `claude-code` | Agent runs as a Claude Code CLI session (e.g. Claude in Cowork). |
| `openclaw` | Agent runs inside an OpenClaw gateway harness. |
| `unknown` | Harness is not confirmed. |

## Trust classes

| Class | Meaning |
|---|---|
| `core-private` | Same human owner, high-trust. Example: zari.example, vesper.example. |
| `peer-aaron` | Peer human owner, limited grant required. Example: nora.aaron, mercedes.example. |
| `cross-human` | Different owner. Explicit trust edge required. Example: mercypix.example. |
| `unknown` | Trust not established. Deny by default. |

## Owner anchoring

Humans anchor trust. Every agent must have exactly one owner.

```text
human://example owns agent://zari.example
human://example owns agent://vesper.example
human://example owns agent://mercedes.example
human://partner.example owns agent://mercypix.example
```

Cross-human capability grants require the source human to explicitly grant the edge. No automatic trust between agents of different owners.

## Agent ID naming rules

```text
agent://<name>.<owner>
```

- `name`: lowercase alphanumeric, hyphens allowed. No spaces.
- `owner`: lowercase short name of the human owner.
- Stable: once assigned, an `agentId` must not be reassigned to a different agent.
- Display names (e.g. "Mercedes", "Mercy") are never stable IDs. Resolve via CNS.

## KNS migration note

| KNS field | CNS v0 equivalent | Notes |
|---|---|---|
| `name` | `name` + `agentId` | KNS name becomes both short name and part of stable URI. |
| `host` | `host` | Same. |
| `tailscaleIp` | Route record, kind `tailscale-http` | Not in identity doc; moves to route records. |
| `url` | Route record, kind `clack-http` or `local-http` | Moves to route records. |
| `inboxPath` | Route record, kind `filedrop` | Moves to route records. |
| `capabilities.streaming` | Not in v0 | A2A compat flag; re-evaluate in Phase 2. |
| `capabilities.pushNotifications` | Route record or capability grant | Depends on use. |
| `authentication.token` | `publicKeyRef` | Tokens must stay out of identity docs. |
| `gatewayPort` | Route record metadata | Moves to route records. |
| `registered_at` (unix float) | `registeredAt` (ISO-8601) | Format normalized. |
| `version` | `cnsVersion` + `harnessType` | Split into distinct fields. |
| `deliveryMode` | Route records classify capability | Explicit in route records. |
| `hermesProfile` | `hermesProfile` | Retained as optional. |
| `trustClass` | `trustClass` | Now a first-class field. |

## Validation rules

A valid CNS agent identity document must:

1. Include all required fields.
2. Use `agent://` URI for `agentId`.
3. Use `human://` URI for `owner`.
4. Use a known `harnessType`.
5. `expiresAt` must be after `registeredAt`.
6. Include no raw tokens, secrets, or key material in any field.
7. `hermesProfile` must be present when `harnessType` is `hermes`.
8. `name` must match the name component of `agentId`.
