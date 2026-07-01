# Clack Receipt v0

Status: draft
Updated: 2026-06-23

## Purpose

Every Clack operation should produce machine-readable proof. Receipts are how agents distinguish store-only, direct-send, wake, response, and failure.

## Receipt JSON shape

```json
{
  "receiptVersion": "1.0-draft",
  "receiptId": "rcpt-018ff2d2-3f31-7f1a-9a4d-6d78f7d4c001-routed",
  "messageId": "018ff2d2-3f31-7f1a-9a4d-6d78f7d4c001",
  "from": "agent://zari.example",
  "to": "agent://vesper.example",
  "stage": "routed",
  "route": {
    "kind": "clack-http",
    "target": "http://example.invalid/a2a",
    "via": "cns-route-record"
  },
  "ok": true,
  "reason": null,
  "at": "2026-06-23T07:01:00Z",
  "proof": {
    "httpStatus": 202,
    "routeTier": "direct-send",
    "inboxPath": null,
    "wakeLog": null,
    "responseId": null
  }
}
```

## Receipt stages

| Stage | Meaning | Minimum proof |
|---|---|---|
| `accepted` | Source Clack accepted syntactically valid request. | message id, source timestamp. |
| `policy-checked` | CNS/policy allowed or denied capability. | capability tier, grant id or denial reason. |
| `routed` | A route was selected. | route kind and route record id/source. |
| `stored` | Message was persisted to inbox/dead-drop. | inbox/dead-drop path or object id. |
| `delivered` | Target endpoint accepted direct send. | HTTP status / broker ack / peer ack. |
| `woke` | Target agent wake process ran. | wake job id/log/output pointer. |
| `responded` | Target produced response. | response id/path/message id. |
| `failed` | A stage failed. | actionable `reason`. |

## Required fields

| Field | Type | Rule |
|---|---|---|
| `receiptVersion` | string | `1.0-draft` for this draft. |
| `receiptId` | string | Unique receipt id. |
| `messageId` | string | Envelope id this receipt proves. |
| `from` | string | Original sender stable agent URI. |
| `to` | string | Original target stable agent URI. |
| `stage` | string | One of defined stages. |
| `ok` | boolean | True only if this stage succeeded. |
| `reason` | string/null | Null on success, actionable reason on failure. |
| `at` | string | ISO-8601 UTC timestamp. |
| `proof` | object | Stage-specific evidence. |

## Route kinds

- `local-http`
- `clack-http`
- `filedrop`
- `store-only`
- `hermes-wake`
- `openclaw-hook`
- `relay`
- `lakebed-dead-drop`
- `p2p-libp2p`
- `p2p-iroh`
- `unknown`

## Failure reasons

Failure reasons must be precise enough for an agent to act:

| Reason | Meaning |
|---|---|
| `unknown-target` | CNS cannot resolve target. |
| `capability-denied` | Policy denies requested capability. |
| `route-stale` | Route exists but proof expired. |
| `route-unreachable` | Network route failed. |
| `store-only-no-wake` | Stored successfully but no wake route/proof. |
| `wake-timeout` | Wake job did not complete in budget. |
| `target-auth-failed` | Target rejected credentials/token. |
| `payload-invalid` | Envelope/payload failed validation. |
| `duplicate-idempotency-key` | Duplicate semantic send detected. |

## Tier proof rules

- Store-only is proven by `stored`, not by `woke`.
- Direct-send requires `delivered` from target endpoint.
- Wake requires `woke` with a wake log/output/job id.
- Bidirectional requires receipts in both directions.
- Tools/admin requires explicit policy receipt, not just route reachability.

## Validation rules

A valid receipt must:

1. Reference a message id.
2. Use known stage.
3. Use `agent://` IDs for `from` and `to`.
4. If `ok` is false, include non-empty `reason`.
5. If `stage` is `failed`, `ok` must be false.
6. If `stage` is `woke`, proof must include `wakeLog` or `wakeJobId`.
7. If `stage` is `stored`, proof must include an inbox/dead-drop/object reference.
