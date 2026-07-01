# Clack Relay Transport v0

Status: draft
Updated: 2026-06-23
Phase: 4 (design only — no live implementation in this pass)

> **STATUS: DESIGN ONLY — No implementation in this pass. Phase 4 is blocked on explicit approval before any live service deployment.**

## Purpose

Define the minimal self-hosted relay that lets Clack agents exchange messages across
LAN boundaries without Cloudflare Tunnel or Tailscale.

The relay is a transport adapter only. It does not own identity, trust, or capability
decisions. Those remain in CNS and Clack Core.

## Problem statement

Current cross-LAN Clack paths require either:
- Tailscale (working for core fleet, not available for all nodes).
- Cloudflare Tunnel (public ingress dependency, out-of-scope for private mesh).
- Manual SCP/file-drop (works but not real-time; no receipts).

The relay fills the gap: an agent behind NAT can send to a relay, and the target
agent can receive from the relay without inbound port forwarding.

## Design goals

- No public ingress on agent hosts.
- Self-hosted; no Cloudflare/Tailscale dependency.
- Minimal relay: does not inspect message bodies.
- E2E envelope confidentiality: relay sees routing metadata only.
- Machine-readable receipts at each relay hop.
- Compatible with existing Clack v2 envelope format.

## Non-goals

- P2P mesh topology (Phase 5).
- Relay-as-storage (relay is not a durable inbox; use filedrop/store-only for that).
- Multiple relay hops (single relay node per message for v0).

## Architecture

```text
Sender agent
  |
  |--[HTTPS POST relay/send]--> Relay Node
                                    |
                                    |--[HTTP POST or filedrop]--> Target agent
                                    |
                                    |--[relay receipt]--> Sender
```

Agents maintain an outbound connection to the relay. The relay does not initiate
connections to agents. Agents poll or subscribe for messages at the relay.

## Relay message shape

A relay message wraps a Clack envelope with relay routing metadata:

```json
{
  "relayVersion": "1.0-draft",
  "relayMessageId": "relay-msg-<uuid>",
  "senderAgentId": "agent://zari.example",
  "targetAgentId": "agent://mercedes.example",
  "relayNodeId": "relay://chitin-relay-1",
  "submittedAt": "2026-06-23T07:00:00Z",
  "ttlSeconds": 300,
  "payloadCiphertext": "<base64-encrypted-clack-envelope>",
  "encryptionAlg": "noise-xk-aes256gcm",
  "payloadSize": 1024
}
```

The `payloadCiphertext` field holds the full Clack envelope, encrypted using the
target agent's public key (referenced via CNS `publicKeyRef`). The relay node sees
only routing metadata.

## Relay session model

Each agent establishes one or more outbound WebSocket or HTTP/2 long-poll sessions
to the relay node on startup:

```text
agent -> relay: GET /relay/subscribe?agentId=agent://mercedes.example
  Auth: X-Relay-Token: <session-token>
  -> SSE or WebSocket stream of pending relay messages
```

The relay queues messages for offline agents up to `ttlSeconds`. After TTL, the
relay emits a `relay-expired` receipt to the sender.

## Authentication at relay boundary

Relay authentication is separate from Clack capability grants.

v0 approach — static Noise-style session keys:
- Each agent generates an Ed25519 identity key pair.
- The relay node stores public keys of authorized agents.
- Agents authenticate to the relay using a signed challenge-response.
- No shared secrets; no bearer tokens in message bodies.

Relay does not perform Clack-level capability checks. That is the sender's
responsibility: only envelopes with valid grants should be forwarded to the relay.

## Relay receipt shape

The relay emits a `routed` stage receipt when it accepts a message for forwarding:

```json
{
  "receiptVersion": "1.0-draft",
  "receiptId": "rcpt-relay-<uuid>-routed",
  "messageId": "<original-clack-envelope-id>",
  "from": "agent://zari.example",
  "to": "agent://mercedes.example",
  "stage": "routed",
  "route": {
    "kind": "relay",
    "via": "relay://chitin-relay-1"
  },
  "ok": true,
  "reason": null,
  "at": "2026-06-23T07:00:05Z",
  "proof": {
    "relayNodeId": "relay://chitin-relay-1",
    "relayMessageId": "relay-msg-<uuid>",
    "relayAcceptedAt": "2026-06-23T07:00:05Z"
  }
}
```

When the target agent picks up the message, the relay emits a `delivered` receipt.
If TTL expires before pickup, the relay emits a `failed` receipt with
`reason: relay-ttl-expired`.

Relay receipts use the original Clack envelope id in `messageId`. Relay-specific ids
belong in `proof.relayMessageId` so receipt correlation stays consistent with
`clack-receipt-v0.md`.

## CNS route record for relay

```json
{
  "routeRecordVersion": "1.0-draft",
  "routeId": "route-mercedes-relay-20260623",
  "agentId": "agent://mercedes.example",
  "kind": "relay",
  "status": "active",
  "priority": 30,
  "endpoint": null,
  "createdAt": "2026-06-23T07:00:00Z",
  "expiresAt": "2026-06-23T07:15:00Z",
  "ttlSeconds": 900,
  "metadata": {
    "relayNodeId": "relay://chitin-relay-1",
    "relaySubscribeUrl": "https://relay.example.invalid/relay/subscribe"
  }
}
```

The relay endpoint is stored in `metadata`, not in top-level `endpoint`, because
it is a subscription URL rather than a direct delivery URL.

## Relay node deployment sketch

Single relay node for v0:

- Python or Node.js HTTPS server with WebSocket support.
- Persistent message queue: SQLite or in-memory with disk-backed overflow.
- Bounded storage: max 1000 pending messages per target; oldest dropped first.
- Message TTL enforced at queue time.
- Auth: Ed25519 challenge-response; no bearer tokens.
- TLS: self-signed cert with pinned fingerprint distributed to agents via CNS.

The relay node itself is a registered CNS agent:
```text
agent://relay-1.example
owner: human://example
harnessType: openclaw
trustClass: core-private
```

## Failure modes and receipts

| Failure | Receipt reason |
|---|---|
| Target agent not subscribed | `relay-target-offline` (message queued) |
| TTL expired before pickup | `relay-ttl-expired` |
| Relay queue full | `relay-queue-full` |
| Auth rejected by relay | `relay-auth-failed` |
| Relay node unreachable | `relay-unreachable` (fall back to filedrop) |
| Decryption failed at target | `relay-decrypt-failed` |

## Phase 4 deliverables (not in this pass)

| Item | Blocked on |
|---|---|
| Relay server implementation | Human approval to deploy new service |
| Ed25519 key registration in CNS | Phase 2 live stabilization first |
| Agent SDK relay adapter | Phase 2 server stabilization |
| Relay node provisioning on Ex/Omni | Human approval |

## Relationship to other transport adapters

| Situation | Preferred adapter |
|---|---|
| Same host or LAN | `local-http` or `clack-http` (priority 10) |
| Cross-LAN, tailnet available | `tailscale-http` (priority 30, transitional) |
| Cross-LAN, no tailnet | `relay` (priority 30) |
| Target offline, no relay | `filedrop` or `store-only` (priority 50) |
| Wake after store | `hermes-wake` via relay or direct |

## Open questions for Phase 4

1. **Relay node hosting**: Ex or Omni? Which is more reliably reachable from Teseract/WSL?
2. **Message size cap**: 64 KB per relay message sufficient for current agent payloads?
3. **Multi-relay federation**: Should relay nodes gossip to each other, or stay single-hop?
4. **Key distribution**: How does an agent learn the relay node's public key without a chicken-and-egg problem?
5. **Relay receipts to sender**: If sender is also behind NAT, how does relay push receipts back? (SSE or long-poll answer needed)
