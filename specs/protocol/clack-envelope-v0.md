# Clack Envelope v0

Status: draft
Updated: 2026-06-23

## Purpose

Define the agent-first message envelope that Clack Core routes after CNS policy allows it.

Human readability is optional. Machine parseability, idempotency, and receipts are mandatory.

## Envelope JSON shape

```json
{
  "clackVersion": "2.0-draft",
  "id": "018ff2d2-3f31-7f1a-9a4d-6d78f7d4c001",
  "from": "agent://zari.example",
  "to": "agent://vesper.example",
  "topic": "mesh.plan",
  "priority": "normal",
  "createdAt": "2026-06-23T07:00:00Z",
  "ttlSeconds": 3600,
  "capabilityRequested": "direct-send",
  "idempotencyKey": "zari-vesper-mesh-plan-20260623T070000Z",
  "replyTo": null,
  "trace": [],
  "payload": {
    "type": "agent-task",
    "contentType": "text/markdown",
    "body": "Summarize route matrix deltas."
  }
}
```

## Required fields

| Field | Type | Rule |
|---|---|---|
| `clackVersion` | string | For this draft, `2.0-draft`. |
| `id` | string | Globally unique message id; UUID/ULID/content-address accepted. |
| `from` | string | Stable sender agent URI, e.g. `agent://zari.example`. |
| `to` | string | Stable target agent URI. |
| `topic` | string | Machine-routable topic; lowercase dotted/kebab preferred. |
| `priority` | string | `low`, `normal`, `high`, or `urgent`. |
| `createdAt` | string | ISO-8601 UTC timestamp. |
| `ttlSeconds` | integer | Positive; expired messages must not wake targets. |
| `capabilityRequested` | string | One of policy tiers: `discover`, `store-only`, `direct-send`, `wake`, `reply`, `tools`, `admin`. |
| `idempotencyKey` | string | Stable retry key. Same semantic send should reuse it. |
| `payload` | object | Typed payload with `type`, `contentType`, and `body`. |

`clackVersion: "2.0-draft"` is the wire/envelope protocol version inherited from
the live Clack v1.x JSON-RPC lineage. It is not the product build number; this
repository's product/spec baseline is Clack v0 / Clack Prime Phase 0.

## Optional fields

| Field | Type | Rule |
|---|---|---|
| `replyTo` | string/null | Prior `id` this responds to. |
| `trace` | array | Route/proxy hops; append-only, no secrets. |
| `expiresAt` | string | Optional explicit expiry; must agree with TTL semantics. |
| `metadata` | object | Non-secret auxiliary data. |

## Payload rules

| Payload field | Type | Rule |
|---|---|---|
| `type` | string | Example: `agent-task`, `status`, `receipt-request`, `human-note`. |
| `contentType` | string | MIME-ish type such as `text/markdown` or `application/json`. |
| `body` | any | The actual content. Keep secrets out unless encrypted by approved transport. |

## Compatibility with JSON-RPC `tasks/send`

Current Clack v1 accepts JSON-RPC `tasks/send` with metadata fields:

```json
{
  "jsonrpc": "2.0",
  "method": "tasks/send",
  "params": {
    "id": "...",
    "message": {"role": "user", "parts": [{"type": "text", "text": "..."}]},
    "metadata": {"from": "zari", "to": "mercedes", "topic": "wake-smoke", "priority": "normal"}
  }
}
```

Compatibility adapter mapping:

| v0 envelope | JSON-RPC compatibility |
|---|---|
| `id` | `params.id` and top-level JSON-RPC id |
| `from` | `params.metadata.from` after alias resolution |
| `to` | `params.metadata.to` after alias resolution |
| `topic` | `params.metadata.topic` |
| `priority` | `params.metadata.priority` |
| `payload.body` text | `params.message.parts[0].text` |

Aliases like `zari` must resolve to stable IDs like `agent://zari.example` through CNS or a compatibility map.

## Validation rules

A valid envelope must:

1. Include all required fields.
2. Use `agent://` URIs for `from` and `to`.
3. Request a known capability tier.
4. Use a positive `ttlSeconds`.
5. Use a known `priority`.
6. Include a payload object with `type`, `contentType`, and `body`.
7. Contain no obvious raw secret fields in metadata/trace.

## Invalid examples

Invalid if:

- `to` is a display name without namespace, e.g. `Mercy`.
- `capabilityRequested` is `admin` without explicit policy grant.
- `ttlSeconds` is `0` or negative.
- `payload` is missing.
- message claims wake/full Clack but only carries store-only route proof.
