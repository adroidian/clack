# Clack Federation Trust Model (Draft v0.4)

**Status:** Revised draft addressing Flint's v0.3 review (msg `50822210-a6fa-44d4-8ed4-3c5d0d9b05b9`,
5 P1 + 3 P2 findings). For kin circle review. No code. No implementation sign-off.
**Branch:** `design/federation-trust-model`
**Date:** 2026-09-27
**Replaces:** Draft v0.3 (commit `41b520b`)

## 0. What changed from v0.3

Flint's v0.3 review confirmed the structural fixes but found the contract
still unimplementable in 8 places:

1. **Incomplete schemas.** Delivery receipt, install receipt, NDR, custody
   ACK, heartbeat, and link-error were prose, not typed objects. The
   tombstone was shorthand; the countersignature had no domain or preimage.
   Now: every signed type has a complete canonical schema with field types,
   bounds, nullability, and hash inputs. (P1-1)
2. **No transport freshness bound.** Nonce retention (1200s) without an
   `attempt_at` acceptance window means a captured attestation replays
   clean after eviction. Now: `attempt_at` must fall in
   [now−1200s, now+300s]; the attestation itself expires as transport
   auth independent of envelope expiry. (P1-2)
3. **FINISH retry contradiction.** "Resend FINISH_ACK idempotently" vs
   "completed attempt returns link-error" — both can't be true. Now:
   committed-success replays the identical saved FINISH_ACK bytes;
   unknown/aborted/expired attempts get link-error. Epoch ownership and
   FINISH_ACK validity are defined. (P1-3)
4. **Recheck was a number, not a protocol.** The 24h revocation recheck
   had no request/response schema, watermark, or reset rule. Now: a
   defined recheck exchange with persisted watermarks, and an explicit
   scope limit — heartbeats never reset the watermark, and a compromised
   home relay suppressing revocation is a stated non-guarantee. (P1-4)
5. **Tier 2 adapter couldn't inject the failures.** Whole-link partition
   can't drop only FINISH_ACK. Now: selective response loss, commit-point
   barriers, contender scheduling, frame injection, directory injection,
   quota config, and evidence inspection hooks — plus restart/clock
   semantics. (P1-5)
6. **Test mapping.** 37 new IDs vs the amended 23+6 scaffold with no
   mapping. Now: §12 carries the full source→ID mapping; new findings
   append new IDs (T1-19+, T2-20+) without renumbering. (P2-6)
7. **Transitive case corrected.** The stronger variant needs A↔B and B↔C
   present with A↔C absent — C rejecting B's claim of authority for A's
   home, not merely rejecting an unlinked relay. (P2-7)
8. **Directory delta and custody terminology.** Delta base binding,
   equal-sequence conflicts, resync rules, rotation-vs-revocation queued
   mail treatment, and "one durable inbox insertion" instead of
   "prevents double-delivery." (P2-8)

Flint's 12 offline fixture checks (4 record types, OpenSSL-signed,
pure-Python-verified) stand as partial Tier 1 evidence — not full
conformance. This draft supplies the schemas those fixtures were missing.

## 0. What changed from v0.2

v0.2 fixed the structural gaps but left six contract-level holes Zari identified,
plus an untestable acceptance suite Flint scoped:

1. **Grant identity was unsigned.** `grant_id`/`generation` sat outside the signed
   offer; the acceptance bound `offer_hash` but not `grant_id`. A relay could
   relabel grant IDs to bypass tombstones. Now: grant identity is inside the
   authenticated offer bytes; installation receipts and revocations bind to
   the immutable contract. (Zari #1)
2. **Consent mode was strippable.** `countersignature_required` was an unsigned
   flag a relay could remove. Now: the consent mode is signed, and required
   countersignatures are enforced. Open-invite claimant eligibility and atomic
   winner ordering are defined. The credential-like `link_claim_commitment`
   is removed — single-use is enforced by atomic consume, not by a secret. (Zari #2)
3. **Canonical encoding was underspecified.** "Fixed field order" is not a
   canonicalization. Now: a complete encoding spec (§3) for every signed type —
   Unicode, escaping, numerics, times, base64url, unknown-field and
   duplicate-key handling, signature exclusion, domain-prefix framing —
   plus a fixed-vector requirement. Delivery receipts, NDRs, installation
   receipts, and tombstones get complete authenticated schemas. (Zari #3)
4. **Destination checks were inconsistent and boundless.** §6 permitted
   directory-key verification while §8 required pins. Lease/skew/partition
   bounds were "short" without numbers. Now: pins everywhere, and concrete
   bounds — 30-day max grant lease, 300s skew tolerance, 24h partition
   delivery cap before fail-closed. (Zari #4)
5. **`recipient_acked` overclaimed.** It implied a human saw the message.
   Now: an authenticated client custody ACK is defined separately from relay
   delivery, and the design explicitly disclaims exactly-once application
   processing. The original signed envelope is preserved to the recipient
   for independent verification. (Zari #5)
6. **Anti-forgery scope was still too broad.** Now: §1/§10 claims are scoped
   to independently established keys and an honest verifier. Epoch ownership
   for simultaneous handshakes is deterministic. FINISH_ACK loss has retry
   rules. The no-transitive test is strengthened to cover A-origin forwarding
   through a linked B. (Zari #6)
7. **Acceptance tests were untestable as a flat list.** Flint's boundary:
   some tests are static wire-contract checks (executable now against the
   spec); others need a running implementation with fault injection (crash
   durability, atomic races, backpressure). §12 now labels every test
   **Tier 1** (static) or **Tier 2** (adapter-driven) and defines the Tier 2
   test-adapter interface.

## 1. Overview & Goals

Federation lets independent Clack relays exchange messages so peers on
different relays can communicate without sharing a single relay operator.

**Goals:**
- A peer on Relay A can send to a peer on Relay B, with both peers confident
  about who they're talking to — verified by signatures against
  independently established keys, not by relay assertion.
- Relay operators keep full control over their own peer roster — no relay can
  enroll peers on another relay.
- Compromise of one relay degrades gracefully: it can deny service, but it
  cannot forge peer messages or peer consent without detection by an honest
  verifier holding the real keys.
- The design works alongside the existing v0.2.17 peer-to-relay auth — no
  changes to local HTTP request signing.

**Non-goals (v1):**
- Automatic relay discovery (relays are linked manually by operators).
- Transitive federation (A↔B and B↔C does NOT imply A↔C).
- Peer migration between relays (a peer has one home relay).
- End-to-end encryption (v1 is plaintext to both home relays — see §11.2).

## 2. Key Concepts

| Term | Definition |
|------|------------|
| **Home relay** | The relay where a peer is enrolled. A peer has exactly one home relay. |
| **Stable relay identity** | The relay's long-lived Ed25519 public key. This is the relay's true identity on the wire. Human-readable `relay_id` strings are local display aliases only and never appear in signed fields. |
| **Stable peer identity** | A peer's Ed25519 public key, pinned at first contact. Display names (`nugget`) are local aliases; the key is the identity. |
| **Federation link** | A mutual, operator-approved connection between two relays, identified by both stable relay identities. Links are pairwise and non-transitive. |
| **Peer envelope** | A versioned, canonical, domain-separated byte string signed by the sending peer. The portable unit of federation — see §5. |
| **Peer directory** | A signed, versioned snapshot of a relay's federation-visible peers, keyed by stable peer identity, not by name. |
| **Consent grant** | A peer-signed authorization for cross-relay communication. The grant identity (`grant_id` + `generation`) is inside the signed offer bytes — see §8. Recorded ACTIVE is not consent; the signed grant is. |
| **Consent mode** | Signed part of the offer: `targeted` or `open`, plus a signed `countersignature_required` flag. A relay cannot strip or downgrade the mode. |
| **Custody ACK** | A client-signed receipt proving the peer's client took custody of a message. Distinct from relay delivery and from application processing — see §7.1. |
| **Federated peer reference** | Display form `peer_name@relay_alias` (e.g., `nugget@kasnet-primary`) for humans and UIs. Resolved to stable identities before anything is signed. |
| **Tier 1 / Tier 2 test** | Tier 1: static wire-contract check, executable now against the spec's normative bytes. Tier 2: adapter-driven stateful scenario requiring a running implementation with fault injection — see §12. |

## 3. Canonical Encoding (new in v0.3)

Every signed type in this spec uses the same canonical encoding. "Fixed field
order" alone is insufficient — this section is normative.

**Byte construction:**
1. Start with the UTF-8 bytes of the ASCII domain prefix:
   `clack:` + `<type>` + `/v1:` — e.g., `clack:envelope/v1:`.
2. Append the canonical JSON bytes defined below.
3. Sign the concatenated bytes with Ed25519. The signature is transmitted
   as a separate field and is never part of the signed bytes.

**Canonical JSON rules:**
- **Encoding:** UTF-8, no BOM. Invalid UTF-8 is rejected.
- **Strings:** Must be valid Unicode, NFC-normalized. Control characters
  (U+0000–U+001F) are rejected except `\t` (U+0009), `\n` (U+000A), `\r`
  (U+000D) inside free-text fields (`text`, `reason`). JSON escaping uses
  the minimal set: `\"`, `\\`, `\n`, `\r`, `\t`; other characters are
  literal UTF-8, never `\uXXXX` escapes.
- **Numbers:** Integers only. No floats, no exponents, no leading zeros
  (except the number `0` itself). Values are range-checked per field.
- **Booleans/null:** Literal `true`, `false`, `null`.
- **Times:** RFC 3339, UTC only, `Z` suffix, second precision, no fractional
  seconds — e.g., `2026-09-27T00:30:00Z`. Other formats or offsets are rejected.
- **Binary:** base64url (RFC 4648 §5), no padding.
- **UUIDs:** Lowercase canonical `8-4-4-4-12` hex form.
- **Objects:** Fixed field order exactly as specified per type. No whitespace
  outside string values. No trailing commas.
- **Unknown fields:** Rejected. A signer and verifier must agree on the exact
  schema version; extensibility comes from version bumps, not silent fields.
- **Duplicate keys:** Rejected at parse time.

**Domain types** (the `<type>` in the prefix). Every type below has a
complete canonical schema in its defining section — prose field lists
do not satisfy this table:

| Type | Signed by | Defined in |
|------|-----------|------------|
| `envelope` | peer | §5 |
| `link-hello`, `link-challenge`, `link-finish`, `link-finish-ack` | relay | §6 |
| `link-heartbeat` | relay | §6 |
| `link-error` | relay | §6 |
| `consent-offer`, `consent-acceptance` | peer | §8 |
| `consent-countersignature` | peer (minter) | §8 |
| `consent-tombstone` | peer | §8 |
| `directory` | relay | §9 |
| `deliver-attestation` | relay | §7 |
| `delivery-receipt` | relay | §7 |
| `install-receipt` | relay | §8 |
| `recheck-request`, `recheck-response` | relay | §8.1 |
| `ndr` | relay | §7.3 |
| `custody-ack` | peer client | §7.1 |

**Directory key ordering:** `entries` and `tombstones` are keyed by
base64url peer pubkey. Canonical order is lexicographic by the UTF-8
bytes of the base64url key string. A directory with unsorted keys is
rejected. (P1-1)

**Fixed vectors:** For every domain type, the spec's test suite (§12) includes
at least one fixed input → fixed canonical bytes → fixed signature vector
using a published test key. Any implementation must reproduce these vectors
exactly. Where this draft leaves a field's encoding ambiguous, that is a
draft bug — flag it, don't invent.

## 4. Relay Identity & Authentication

**Decision (explicit, per Flint F4):** Each relay has **one long-lived Ed25519
relay identity keypair**, generated at setup. Per-pair link keys are deferred.
One key to exchange, one key to rotate, one key to revoke.

**Link establishment (manual, operator-driven):**
1. Operator of Relay A sends Relay A's **stable relay public key** to Operator
   of Relay B **out-of-band** (Aaron-as-courier, or RSA-OAEP to a posted key
   — same rules as peer tokens).
2. Operator of Relay B does the same in reverse.
3. Each operator adds the other's relay pubkey to their relay config's
   `federated_relays` map, with a local human-readable alias. The alias is
   never signed; the pubkey is the identity.
4. Links are established via the typed handshake in §6.

**Why manual:** Relay linking is a trust decision, not a technical one.

**Key rotation:** Rotation requires re-exchange via the manual operator
channel. Config supports `prev_pubkey` with a grace period — but a
compromised `prev_pubkey` is revoked immediately, not kept valid through
the grace period.

**Note on existing `/v1/identity`:** The current endpoint uses RSA challenge
signing. The federation Ed25519 relay identity key is separate. Do not assume
it exists yet and do not replace current pins implicitly.

## 5. The Peer Envelope

Federation introduces a separately versioned application envelope that the
peer signs directly. Existing HTTP request signing (v0.2.17) is retained
unchanged for peer-to-relay authentication.

**Envelope v1** (canonical JSON per §3, domain `clack:envelope/v1:`):

```json
{
  "v": 1,
  "msg_id": "<uuid v4>",
  "from_peer_key": "<base64url ed25519 pubkey>",
  "from_relay_key": "<base64url ed25519 pubkey>",
  "to_peer_key": "<base64url ed25519 pubkey>",
  "to_relay_key": "<base64url ed25519 pubkey>",
  "handshake_grant_id": "<uuid v4>",
  "handshake_generation": 3,
  "issued_at": "<rfc3339>",
  "expires_at": "<rfc3339 absolute>",
  "topic": "<string, max 128 chars>",
  "text": "<string, max 65536 chars>",
  "in_reply_to": "<uuid v4 or null>"
}
```

The peer signs the §3 byte construction. The relay **persists and forwards
the exact signed bytes and the signature** — never reconstructs,
reserializes, or re-signs.

**Properties:**
- **Stable identities only.** No aliases or display names in signed fields.
- **Absolute expiry.** `expires_at` is fixed at mint time, never extended by
  retries or re-queueing. Maximum envelope TTL: 7 days (§11.4).
- **Bound consent.** `handshake_grant_id` + `handshake_generation` tie the
  message to a specific grant (§8). The destination rechecks grant validity
  at enqueue time against the pinned keys.
- **No credential transport.** Bearer tokens and local credential headers are
  never forwarded.

**Freshness vs. expiry:** The 600s/120s HTTP freshness window is transport
authentication only — never reused as message expiry, never silently widened
for queued mail.

## 6. Relay Link Handshake Protocol

**Records** (canonical JSON per §3):

```
A → B: HELLO {
         v: 1, attempt_id: <uuid>, role: "initiator",
         initiator_key: <A's stable relay pubkey>,
         responder_key: <B's stable relay pubkey>,
         initiator_nonce: <random 32 bytes, base64url>,
         expires_at: <now + 300s>,
         capabilities: ["envelope/v1", "directory/v1"]
       }
       signature: sign_A("clack:link-hello/v1:" + canonical bytes)

B → A: CHALLENGE {
         v: 1, attempt_id: <same>, role: "responder",
         initiator_key: <A>, responder_key: <B>,
         initiator_nonce: <echoed>, responder_nonce: <random 32 bytes, base64url>,
         expires_at: <now + 300s>,
         capabilities: ["envelope/v1", "directory/v1"]
       }
       signature: sign_B("clack:link-challenge/v1:" + canonical bytes)

A → B: FINISH {
         v: 1, attempt_id: <same>, role: "initiator",
         transcript_hash: <sha256(HELLO bytes || CHALLENGE bytes), base64url>,
         expires_at: <now + 300s>
       }
       signature: sign_A("clack:link-finish/v1:" + canonical bytes)

B → A: FINISH_ACK {
         v: 1, attempt_id: <same>, role: "responder",
         transcript_hash: <same>,
         link_epoch: <monotonic uint64>
       }
       signature: sign_B("clack:link-finish-ack/v1:" + canonical bytes)
```

**Rules:**
- Verify the peer's signature against the configured `federated_relays`
  pubkey; check audience (own key matches the intended recipient field);
  reject wrong-role, expired, or replayed frames.
- `FINISH` binds the entire exchange via `transcript_hash`. The initiator
  learns acceptance via `FINISH_ACK`.
- Challenges are persisted and consumed atomically; pending challenges are
  bounded; each `attempt_id` is single-use.
- `link_epoch` increments per successful handshake. All data operations
  carry the current epoch in their domain-separated signatures. A new
  handshake invalidates the old epoch.
- **Replay retention:** `attempt_nonce`s and challenge records are retained
  for 1200s (2× the max attempt window) and survive restarts — a replayed
  frame after a restart is still rejected.
- **Simultaneous handshakes (deterministic):** If both sides send HELLO
  concurrently, the side whose stable relay key is lexicographically
  greater becomes the initiator; the other aborts its attempt and responds.
  No split-brain, no negotiation round-trip.
- **Lost FINISH_ACK (disambiguated — P1-3).** The responder persists a
  completed-attempt record `{attempt_id, transcript_hash, link_epoch,
  finish_ack_bytes}` for 1200s. A retried FINISH with a matching
  `attempt_id` **and** `transcript_hash`:
  - If the attempt is **committed** (record present): the responder
    replays the **identical saved FINISH_ACK bytes** — not a regenerated
    equivalent, the same bytes. This is the only case where a completed
    attempt produces FINISH_ACK.
  - If the `attempt_id` is **unknown** (no record, never seen): the
    responder returns `link-error{reason: "unknown_attempt"}`. The
    initiator starts a fresh handshake (new `attempt_id`).
  - If the attempt is **aborted or expired** (record aged out past 1200s,
    or the attempt was explicitly aborted): `link-error{reason:
    "attempt_expired"}`. The initiator starts fresh.
  - Retry schedule: exponential backoff 1s, 2s, 4s, max 3 retries, then
    fresh handshake. The initiator never reuses an `attempt_id` after
    receiving `link-error`.
- **Epoch ownership (P1-3).** The epoch is owned by the link, allocated by
  the responder. `new_epoch = responder.persisted_last_epoch + 1`.
  Both relays persist their link epoch durably (survives restarts).
  On receiving FINISH_ACK: if `new_epoch > initiator.persisted_last_epoch`,
  accept and persist; otherwise reject with `link-error{reason:
  "stale_epoch"}` and start fresh. Epoch is monotonic regardless of who
  initiates — role swaps in later handshakes cannot rewind it.
- **FINISH_ACK validity.** A FINISH_ACK is valid only while its attempt
  record persists (1200s) and its `transcript_hash` matches a completed
  attempt. There is no independent FINISH_ACK expiry field — the bound is
  the persisted transcript record.
- **Unlink** immediately invalidates cached ACTIVE state, stops new
  enqueue/delivery, and NDRs queued mail (§7.3) — never silent drop.
- TLS with exact approved endpoints (or explicitly authenticated private
  transport) remains required. Key possession alone is not channel
  authentication.

**Heartbeat v1** (`clack:link-heartbeat/v1:`) — complete schema:

```json
{
  "v": 1,
  "from_relay_key": "<stable relay pubkey, base64url>",
  "to_relay_key": "<stable relay pubkey, base64url>",
  "link_epoch": 42,
  "sent_at": "<rfc3339>",
  "queue_depth": 0
}
```

Verification: signature against the linked peer relay key; `to_relay_key`
equals own key; `link_epoch` equals current epoch; `sent_at` within
[now−1200s, now+300s]; `queue_depth` is a non-negative integer.
Three missed heartbeats → DEGRADED. **Heartbeats never reset the
revocation-recheck watermark** (§8.1).

**Link-error v1** (`clack:link-error/v1:`) — complete schema:

```json
{
  "v": 1,
  "from_relay_key": "<stable relay pubkey, base64url>",
  "to_relay_key": "<stable relay pubkey, base64url>",
  "link_epoch": 42,
  "attempt_id": "<uuid or null>",
  "reason": "<unknown_attempt | attempt_expired | stale_epoch | bad_frame | capability_mismatch>",
  "detail": "<string, max 256 chars, or null>",
  "sent_at": "<rfc3339>"
}
```

Same audience/epoch/freshness verification as heartbeats. `reason` is a
closed enum — unknown reasons are rejected.

**Link liveness:** Signed heartbeats every 60s. Three missed heartbeats →
DEGRADED. Whether new mail is accepted while DEGRADED is an explicit
per-link operator policy (set at link config, not decided silently at
runtime). Links re-handshake every 24h, bumping the epoch.

## 7. Message Flow (Federated Send)

Nugget (home: Relay A) sends to Mosaic (home: Relay B). All identities are
stable pubkeys; aliases are resolved before signing.

1. Nugget constructs the §5 envelope, signs it, sends to Relay A via normal
   `/v1/send` (existing local protocol, unchanged).
2. Relay A checks:
   - Recipient's home relay key is a linked relay with ACTIVE status and
     current epoch. If no → reject.
   - Recipient's peer key is in the cached peer directory for that link
     (§9). If no → reject. (Visibility is not consent.)
   - A valid, unexpired, unrevoked consent grant exists for this pair (§8),
     verified against **pinned** keys. If no → reject.
   - The envelope signature verifies against the sender's **enrolled**
     pubkey, `expires_at` is in the future and within the 7-day max, and
     `from_relay_key` matches Relay A.
3. Relay A creates a durable outbox entry (§7.1) and forwards to Relay B
   via `POST /v1/federation/deliver`:
   ```json
   {
     "envelope_bytes": "<exact bytes Nugget signed, base64url>",
     "envelope_signature": "<base64url>",
     "attestation": {
       "v": 1,
       "from_relay_key": "<A>",
       "to_relay_key": "<B>",
       "link_epoch": 42,
       "envelope_hash": "<sha256, base64url>",
       "operation": "deliver",
       "attempt_nonce": "<random 32 bytes, base64url>",
       "attempt_at": "<rfc3339>"
     },
     "attestation_signature": "<A signs clack:deliver-attestation/v1: + canonical attestation>"
   }
   ```
   Fresh attestation per attempt; the envelope is never modified.
4. Relay B verifies, **in this order**:
   - `from_relay_key` in the attestation **equals the authenticated
     attester** — the relay whose signature verified against the linked
     key. A mismatch is rejected (no confused-deputy forwarding).
   - Attestation signature against Relay A's stable key; epoch is current;
     `attempt_nonce` not seen (replay dedup, 1200s retention).
   - **Transport freshness (P1-2):** `attempt_at` must fall within
     [now−1200s, now+300s]. The past bound equals the nonce-retention
     window; the future bound is the 300s skew allowance. A captured
     attestation replayed after nonce eviction is rejected here — the
     attestation expires as transport authentication independently of the
     envelope's `expires_at`. Fresh attestation per attempt is mandatory;
     reusing an old attestation with a new nonce is rejected.
   - **Peer envelope signature against the PINNED key** for the sender
     (§9) — not "a key from the directory." This is the §6/§8 consistency
     fix: pins everywhere, no directory-key fallback on the delivery path.
   - `to_peer_key` matches an enrolled peer on Relay B.
   - `to_relay_key` matches Relay B's own stable identity.
   - The consent grant (`handshake_grant_id`/`handshake_generation`) is
     complete, valid, and unrevoked **as known to Relay B**, with the
     grant's home bindings matching the attested relay keys.
   - `msg_id` + envelope hash not already delivered (idempotent dedup;
     same ID with different content → error, never a second delivery).
5. Relay B commits to its inbox and returns a signed delivery receipt.
   **Delivery receipt v1** (`clack:delivery-receipt/v1:`) — complete schema:

   ```json
   {
     "v": 1,
     "issuer_relay_key": "<B's stable key, base64url>",
     "audience_relay_key": "<A's stable key, base64url>",
     "link_epoch": 42,
     "msg_id": "<uuid>",
     "envelope_hash": "<sha256 of envelope_bytes, base64url>",
     "recipient_peer_key": "<B-enrolled peer key, base64url>",
     "recipient_home_relay_key": "<B's stable key, base64url>",
     "committed_at": "<rfc3339>"
   }
   ```

   Receipt authorization: the verifier checks the signature against the
   linked relay key **and** that `issuer_relay_key` equals that same key
   and `audience_relay_key` equals its own key — a receipt is only
   meaningful from the relay it claims to be from, to the relay it claims
   to answer. (P1-1)

   Mosaic polls and receives the message with `via_relay_key` provenance. A remote `nugget`
   can never collide with a local `nugget` — provenance is part of the
   displayed identity. **The original signed envelope bytes are preserved
   to the recipient** for independent verification.

**Reply path** is symmetric.

**Concrete bounds (Zari #4):**
- Maximum grant lease: 30 days (configurable down, never up, in v1).
- Clock skew tolerance: 300s for relay-to-relay timestamps.
- Partition delivery cap: a relay may continue delivering under a cached
  grant for at most 24h without a revocation recheck. After 24h
  partitioned, it fails closed — stops delivery, NDRs queued mail.
  Revocation recheck is mandatory on link re-establishment before any
  further delivery.
- Grant renewal is explicit: a new grant (new `grant_id`), never a silent
  extension of the old one.

### 7.1 Durable outbox states and custody

| State | Meaning |
|-------|---------|
| `accepted_at_source` | Relay A durably committed the outbox entry. Promises custody, not delivery. |
| `accepted_at_destination` | Relay B committed to its inbox and returned a signed delivery receipt. |
| `delivered_to_client` | Relay B handed the message to the peer's poll response. **This is the relay's claim about its own action.** |
| `custody_acked` | The peer's **client** returned a signed custody ACK (schema below). Proves the client took custody — **not** that a human or agent read, understood, or processed the content. |
| `expired` / `rejected` | Envelope expired or a check failed. Authenticated NDR to sender. |

**Custody ACK v1** (`clack:custody-ack/v1:`) — complete schema (P1-1):

```json
{
  "v": 1,
  "msg_id": "<uuid>",
  "envelope_hash": "<sha256 of envelope_bytes, base64url>",
  "receiver_peer_key": "<base64url>",
  "receiver_home_relay_key": "<base64url>",
  "received_at": "<rfc3339>"
}
```

Signed by the peer's client key. The relay verifies the signature against
the enrolled peer key and the hash bindings before advancing the outbox
state. This ACK is the protocol's assertion of client custody — not
evidence of application processing.

- Relay A returns "accepted" to the sender only after `accepted_at_source`
  is durably committed.
- Lost destination responses cause **idempotent retry** (same envelope
  bytes, fresh attestation), never a second inbox item. Dedup scope:
  (sender stable key, home relay key, `msg_id`) with envelope-hash
  comparison. Dedup evidence is durable and survives restarts.
- **One durable inbox insertion** (P2-8): the guarantee is that a given
  (`msg_id`, envelope hash) is inserted into the recipient's inbox at most
  once. Poll redelivery of an unacked message is legitimate and expected —
  "no double-delivery" in this spec means no double *insertion*, not no
  redelivery.
- **No exactly-once application-processing claim.** Relay dedup prevents
  double-*insertion*; it says nothing about how many times the recipient's
  application processes the message. That is the application's problem,
  and the design does not pretend otherwise.

- Relay A returns "accepted" to the sender only after `accepted_at_source`
  is durably committed.
- Lost destination responses cause **idempotent retry** (same envelope
  bytes, fresh attestation), never a second inbox item. Dedup scope:
  (sender stable key, home relay key, `msg_id`) with envelope-hash
  comparison. Dedup evidence is durable and survives restarts.
- **No exactly-once application-processing claim.** Relay dedup prevents
  double-*delivery*; it says nothing about how many times the recipient's
  application processes the message. That is the application's problem,
  and the design does not pretend otherwise.
- A relay's acknowledgement alone never proves a peer consumed a message.
  Status queries distinguish every state above.

### 7.2 Backpressure and quotas

Bounded per-link, per-sender-peer, per-recipient-peer, and global message,
byte, queue-depth, and in-flight-request quotas. Quota exhaustion returns
retryable backpressure (bounded exponential retry hints), never silent
drops. Quota values are per-link negotiated caps — 100 msg/min is a pilot
tuning value, not a certified safe default.

### 7.3 Failure signals

**NDR v1** (`clack:ndr/v1:`) — complete schema (P1-1):

```json
{
  "v": 1,
  "issuer_relay_key": "<stable relay pubkey issuing the NDR, base64url>",
  "audience_relay_key": "<stable relay pubkey of the sender's home relay, base64url>",
  "sender_peer_key": "<original sender's peer key, base64url>",
  "sender_home_relay_key": "<original sender's home relay key, base64url>",
  "msg_id": "<uuid of the failed message>",
  "envelope_hash": "<sha256 of envelope_bytes, base64url, or null if the envelope never parsed>",
  "reason": "<expired | rejected_consent | rejected_identity | link_unlinked | partition_cap | quota_exceeded | unknown_recipient>",
  "detail": "<string, max 256 chars, or null>",
  "issued_at": "<rfc3339>"
}
```

`reason` is a closed enum. Receipt authorization: the receiving relay
checks the signature against the linked relay key **and** that
`issuer_relay_key` equals that key, `audience_relay_key` equals its own
key, and `sender_home_relay_key` equals its own key (an NDR for someone
else's peer is rejected). NDRs are delivered to the sender's inbox —
never silent:

- **Authenticated NDRs:** emitted on expiry, rejection, unlink-with-queued-mail, and partition-cap fail-closed.
- **Status queries:** `GET /v1/federation/status/{msg_id}` returns the
  current outbox state with its evidence (receipts, NDR reason).

## 8. Cross-Relay Consent

**The consent grant** — `grant_id` and `generation` are now **inside** the
signed offer bytes (Zari #1). The consent mode is signed and cannot be
stripped (Zari #2). The credential-like claim commitment is removed;
single-use is enforced by atomic consume (Zari #2).

```json
{
  "v": 1,
  "offer": {
    "grant_id": "<uuid v4, unique per grant>",
    "generation": 1,
    "minter_peer_key": "<stable pubkey>",
    "minter_relay_key": "<stable relay key>",
    "scope": "pairwise",
    "consent_mode": "targeted | open",
    "countersignature_required": false,
    "target_peer_key": "<stable pubkey, or null when mode=open>",
    "expires_at": "<rfc3339, max 30 days>"
  },
  "offer_signature": "<minter signs clack:consent-offer/v1: + canonical offer>",
  "acceptance": {
    "grant_id": "<same as offer>",
    "generation": 1,
    "offer_hash": "<sha256 of canonical offer bytes, base64url>",
    "redeemer_peer_key": "<stable pubkey>",
    "redeemer_relay_key": "<stable relay key>",
    "expires_at": "<rfc3339>"
  },
  "acceptance_signature": "<redeemer signs clack:consent-acceptance/v1: + canonical acceptance>",
  "minter_countersignature": "<or null; REQUIRED when offer.countersignature_required is true>"
}
```

**Countersignature preimage (P1-1).** When required, the minter signs
domain `clack:consent-countersignature/v1:` over this canonical object:

```json
{
  "v": 1,
  "grant_id": "<uuid>",
  "generation": 1,
  "acceptance_hash": "<sha256 of canonical acceptance bytes, base64url>",
  "countersigned_at": "<rfc3339>"
}
```

The verifier checks the signature against the minter's pinned key and
that the `acceptance_hash` matches the acceptance being installed. A
countersignature over a different acceptance is rejected.

**Effective grant expiry (P1-4).** The grant is valid until
`min(offer.expires_at, acceptance.expires_at)`. An acceptance with
`expires_at` later than the offer's is rejected (no extension by the
redeemer). A grant whose effective expiry is already past at install
time is rejected. Measurement anchor: both timestamps are absolute
RFC 3339 UTC; the 300s skew tolerance applies at verification time.
`offer.expires_at` is capped at 30 days from offer creation.

**Flow:**
1. **Offer.** Nugget (Relay A) creates and signs the offer. `consent_mode`
   is `targeted` (names `target_peer_key`) or `open` (null target — the
   offer explicitly preauthorizes any qualifying holder). The
   `countersignature_required` flag is part of the signed bytes: a relay
   cannot strip it to downgrade the consent.
2. **Share.** The offer is public — no secrets. Shared via any channel.
3. **Acceptance.** Mosaic (Relay B) verifies the offer signature against
   Nugget's **pinned** key, checks `grant_id`/`generation` match, then
   signs the acceptance binding the offer hash, both stable peer identities,
   both home relay identities, and the generation.
4. **Installation.** Relay B forwards the acceptance over the link. Each
   relay verifies both signatures **and** the grant identity binding, then
   durably installs the complete grant and returns a signed installation
   receipt. **Install receipt v1** (`clack:install-receipt/v1:`) —
   complete schema (P1-1):

   ```json
   {
     "v": 1,
     "issuer_relay_key": "<installing relay's stable key, base64url>",
     "audience_relay_key": "<other relay's stable key, base64url>",
     "link_epoch": 42,
     "grant_id": "<uuid>",
     "generation": 1,
     "minter_peer_key": "<base64url>",
     "redeemer_peer_key": "<base64url>",
     "offer_hash": "<sha256 of canonical offer bytes, base64url>",
     "acceptance_hash": "<sha256 of canonical acceptance bytes, base64url>",
     "effective_expires_at": "<rfc3339, = min(offer, acceptance) expiry>",
     "installed_at": "<rfc3339>"
   }
   ```

   A relay delivers federated mail only with the complete valid grant
   **and** the remote installation receipt. Missing remote commit =
   pending/retryable, never assumed.
5. **Single-use consumption (no secret).** The offer is consumed atomically
   at the issuing relay on first valid acceptance. There is no claim
   commitment, no reveal, no credential-like artifact — the atomic consume
   *is* the single-use mechanism. Idempotent re-presentation by the same
   accepted claimant is a no-op success. A different claimant after
   consumption receives `already_consumed` carrying the winner's
   acceptance ID (so races are observable, not silent).
6. **Open-invite claimant eligibility.** For `mode=open`, the redeemer must
   be an enrolled peer on a relay linked to the minter's relay, proven by
   the forwarding relay's attestation. "Any qualifying holder" means
   exactly this — not anonymous, not unenrolled.
7. **Atomic winner ordering across relays.** The issuing relay is the
   single serialization point for consumption. The installation receipt
   from the issuing relay is the proof of who won. Both relays install
   the winner's grant; a loser's acceptance is never installed.

**Revocation:**
- Signed **tombstone** (`clack:consent-tombstone/v1:`) — complete field
  spec (P1-1), no shorthand:

  ```json
  {
    "v": 1,
    "grant_id": "<uuid>",
    "generation": 2,
    "revoked_at": "<rfc3339>",
    "reason": "<peer_request | key_compromised | operator_action>",
    "revoker_peer_key": "<base64url>"
  }
  ```

  `generation` is an integer ≥ 1, exactly one greater than the revoked
  grant's generation. `reason` is a closed enum. Signed by the key in
  `revoker_peer_key`, which must be one of the grant's two peer keys.
- Tombstones bind to the grant identity — a relabelled `grant_id` does not
  bypass them, because verifiers check the tombstone's `grant_id` against
  the **signed** grant identity, not against any relay-supplied label.
- Tombstones propagate with retry/receipt semantics and take **durable
  precedence** over old accepts and queued deliveries.
- Grants are rechecked at send, destination enqueue, poll/redelivery, and
  history fetch — plus the §8.1 recheck protocol during partitions.
- Local revocation stops local delivery immediately. Remote revocation
  during partition follows the 24h cap (§7): short leases fail closed.
- **A revoked generation never revives.** Generation numbers are monotonic
  per grant; a superseded generation is ignored after reconnect.

**Remote contact records are not local enrolled accounts.** Mosaic is never
enrolled on Relay A, never issued an A token, and Mosaic's B token never
travels to A.

### 8.1 Revocation Recheck Protocol (P1-4)

The 24h partition cap (§7) is enforced by a defined exchange, not by
liveness inference.

**Recheck request v1** (`clack:recheck-request/v1:`):

```json
{
  "v": 1,
  "from_relay_key": "<requesting relay, base64url>",
  "to_relay_key": "<peer relay, base64url>",
  "link_epoch": 42,
  "grant_ids": ["<uuid>", "..."],
  "watermark": "<rfc3339: requester's last verified recheck per its own clock, or null>",
  "nonce": "<random 32 bytes, base64url>",
  "requested_at": "<rfc3339>"
}
```

**Recheck response v1** (`clack:recheck-response/v1:`):

```json
{
  "v": 1,
  "from_relay_key": "<responding relay, base64url>",
  "to_relay_key": "<requesting relay, base64url>",
  "link_epoch": 42,
  "nonce": "<echoed from request>",
  "grants": [
    {
      "grant_id": "<uuid>",
      "generation": 1,
      "status": "<active | revoked | unknown>",
      "tombstone_hash": "<sha256 of canonical tombstone, base64url, or null>",
      "effective_expires_at": "<rfc3339>"
    }
  ],
  "responded_at": "<rfc3339>"
}
```

**Rules:**
- Each relay persists `last_recheck_verified_at` per grant per link,
  durably across restarts. The cache age resets **only** on a valid
  signed recheck response whose nonce matches an outstanding request.
- **Heartbeats never reset the watermark.** Liveness is not revocation
  knowledge.
- If 24h pass without a verified recheck for a grant, the relay fails
  closed: stops delivery under that grant, NDRs queued mail
  (`reason: partition_cap`).
- On link re-establishment after partition, recheck runs **before** any
  further delivery under cached grants.
- **Scope limit (stated, not hand-waved):** the 24h guarantee covers
  actual partitions and honest recheck behavior. A compromised home
  relay can suppress a peer's revocation while asserting a healthy link
  — the recheck response is only as honest as its signer. The design
  does not claim to detect a lying home relay; it bounds the damage
  window for honest-but-partitioned ones.

## 9. Peer Directory

**What signatures prove:** A signed directory proves **the relay authored
it**. It does not independently prove peer identity.

**Directory v1** (`clack:directory/v1:`):

```json
{
  "v": 1,
  "issuer_relay_key": "<stable relay pubkey>",
  "audience_relay_key": "<stable relay pubkey or null>",
  "epoch": 42,
  "sequence": 101,
  "issued_at": "<rfc3339>",
  "expires_at": "<rfc3339>",
  "is_delta": false,
  "entries": {
    "<peer stable pubkey>": {
      "display_name": "nugget",
      "federation_visible": true,
      "added_at": "<rfc3339>"
    }
  },
  "tombstones": {
    "<peer stable pubkey>": {"removed_at": "<rfc3339>", "reason": "<peer_opt_out | key_compromised | operator_action>"}
  }
}
```

**Rules:**
- Keyed by **stable peer pubkey**. Names are informational. Entries and
  tombstones are in canonical key order (§3). `reason` is a closed enum.
- **Opt-in, per-link, minimal.** Default private. **Visibility is not consent.**
- **Pinned contact keys.** First-accepted key is pinned. Updates require
  either (a) old-key-signed transition + new-key proof of possession, or
  (b) explicit re-verification and fresh grant. Lost-key recovery is a
  visibly distinct flow.
- **First contact** is TOFU in v1 — stated explicitly, claim narrowed:
  TOFU defeats passive attackers, not a malicious home relay substituting
  keys at first contact.
- **Rollback protection.** Monotonic sequence per epoch; high-water marks
  persist across restarts; lower sequence rejected; epoch resets need
  authenticated resync; tombstones durable.
- **Delta binding (P2-8).** A delta (`is_delta: true`) carries
  `base_sequence` and `base_hash` (sha256 of the canonical snapshot it
  applies to). It applies **only if** both match the cached state.
  Base mismatch → the delta is rejected outright; the receiver requests
  a full snapshot. Deltas are never chained on top of other deltas.
- **Equal-sequence conflict (P2-8).** If a directory arrives with
  `sequence` equal to the cached sequence but different content hash,
  **both** are quarantined and a full authenticated resync is required.
  Neither wins by arrival order.
- **Authenticated resync (P2-8).** A full snapshot with a higher
  `sequence` (same epoch) or a new signed epoch replaces cached state.
  Tombstones from the newer snapshot replace cached tombstones — a
  tombstone is never restored to "live" by an older snapshot (durable
  precedence).
- **Queued-mail treatment: planned rotation vs compromised revocation
  (P2-8).** Planned key rotation (old-key-signed transition) drains queued
  mail under the old grant within its remaining lease; the new grant takes
  over on completion. Compromised-key revocation (tombstone,
  `reason: key_compromised`) immediately NDRs queued mail — no drain,
  no grace.
- **Pins on the delivery path.** §7 verifies against the pinned key —
  there is no directory-key fallback at delivery time.

## 10. Trust Model Summary

Scoped per Zari #6: every claim below holds for **independently established
keys and an honest verifier**. First-contact (TOFU) and dishonest-verifier
cases are called out, not hand-waved.

| What | Trusted | Verified how | Limit |
|------|---------|--------------|-------|
| Relay A's identity | By Relay B's operator (manual exchange) | Ed25519 per message, in-domain, in-epoch | Says nothing about A's peers |
| Nugget's authorship | By Relay B, independently | Envelope signature vs **pinned** key | Key must be pinned before attack (TOFU window); verifier must actually check |
| Directory from Relay A | Authorship only | Relay A's signature; sequenced, tombstoned | Not peer identity |
| Consent Nugget↔Mosaic | By both relays | Signed grant: identity inside offer, mode signed, generation-bound | Both relays must verify; no skipping |
| Integrity in transit | TLS + per-attempt attestation | Both | Not confidentiality (v1 plaintext) |
| Link liveness | Heartbeats in-epoch | 3 missed → DEGRADED | Not a delivery promise |
| Custody | Client's signed custody ACK | `clack:custody-ack/v1:` | Proves client custody, not human reading or processing |

**What a compromised Relay A can do:**
- Deny service / censor.
- Substitute a peer's key **at first contact** (TOFU window) — detectable
  afterwards via pinned-key holders and directory history, not prevented
  in v1.
- Lie about link state, quota, or its own poll output (dishonest-verifier
  case — the design does not claim to prevent a relay from lying to its
  own clients about what it received).

**What a compromised Relay A CANNOT do** (each scoped to its mechanism):
- Forge Nugget's messages **after B pinned Nugget's real key** (pinned-key
  verification, §7 step 4).
- Forge or relabel a consent grant (grant identity in signed bytes;
  both peers' keys required).
- Strip `countersignature_required` (mode is signed; verifier enforces).
- Enroll peers on Relay B or issue tokens.
- Revive a revoked generation (tombstone precedence, monotonic generations).
- Extend an expiry by retry (absolute expiries, never rewritten).

## 11. Resolved Open Questions

1. **Directory privacy:** Opt-in, per-link minimal, default private.
   Tombstone-defined removal.
2. **E2E:** v1 plaintext to both home relays, explicitly disclosed.
   Trusted-operator pilot only; confidential payloads need E2E (separate
   feature). E2E would not fix first-contact substitution — pinning is
   needed regardless.
3. **Rate limiting:** Per-link, per-peer, byte, queue, concurrency bounds.
   Per-link negotiated pilot values, not certified defaults.
4. **Retention & partition:** 7-day envelope max, absolute expiry preserved,
   authenticated NDRs never silent drops. Partition cap: 24h without
   revocation recheck, then fail closed. DEGRADED acceptance is explicit
   per-link operator policy.
5. **Relay IDs:** Local display aliases only. Signed fields use stable keys.
   Aliases never change signed meaning.

## 12. Acceptance Tests

Every test is labeled **Tier 1** (static wire-contract check — executable
now against the spec's normative bytes) or **Tier 2** (adapter-driven
stateful scenario — requires a running implementation plus the test
adapter below). Flint's boundary: Tier 2 properties (crash durability,
atomic races, backpressure behavior) cannot be proven by static checks
alone.

### Source→ID mapping (P2-6)

v0.2 carried 23 checklist scenarios; Zari's v0.2 review added 6 contract
categories, which the v0.3 amendment adopted as 23+6. The v0.3 rewrite
assigned fresh IDs without a mapping — corrected here. Original IDs keep
their tests; Flint's v0.3 P1/P2 findings append new IDs (T1-19+,
T2-20+) without renumbering anything.

| Source | Test ID |
|--------|---------|
| v0.2 #1 directory key substitution vs pinned | T1-13 |
| v0.2 #2 directory substitution at first contact | T2-16 |
| v0.2 #3 forged consent grant | T1-05 |
| v0.2 #4 queued revocation under partition | T2-01 |
| v0.2 #5 persisted rollback/replay after restart | T2-02 |
| v0.2 #6 handshake reflection/cross-protocol replay | T1-11 |
| v0.2 #7 conflicting relay aliases | T1-03 |
| v0.2 #8 alternate alias names | T1-04 |
| v0.2 #9 wrong home/audience/role | T1-02 |
| v0.2 #10 reserialized/mutated envelope | T1-01 |
| v0.2 #11 concurrent final-use redeem | T2-03 |
| v0.2 #12 one-sided commit and retry | T2-04 |
| v0.2 #13 revoke racing | T2-05 |
| v0.2 #14 stale-generation resurrection | T2-06 |
| v0.2 #15 lost enqueue ACK | T2-07 |
| v0.2 #16 UUID collision | T1-12 |
| v0.2 #17 delayed delivery beyond nonce validity | T2-08 |
| v0.2 #18 expiry without TTL extension | T2-09 |
| v0.2 #19 unlink/rotation with queued mail | T2-10 |
| v0.2 #20 no-transitive-trust | T2-11 (A), T2-12 (B, corrected per P2-7) |
| v0.2 #21 non-home forwarding | T2-13 |
| v0.2 #22 quota exhaustion | T2-14 |
| v0.2 #23 crash around custody/ACK boundary | T2-15 |
| Zari Z1 grant ID binding (relabelled grant) | T1-06 |
| Zari Z2 generation mismatch | T1-07 |
| Zari Z3 expiry extension | T1-08 |
| Zari Z4 countersignature mode | T1-09 (stripped), T1-10 (absent when required) |
| Zari Z5 custody ACK separation | T1-26 |
| Zari Z6 domain framing completeness | T1-14, T1-15, T1-16, T1-17, T1-18 |
| v0.3 T2-17 simultaneous handshakes | unchanged |
| v0.3 T2-18 lost FINISH_ACK | superseded by T2-20/T2-21/T2-25 (P1-3) |
| v0.3 T2-19 24h partition cap | T2-19 + T2-23/T2-24 (P1-4) |

The Perch gig for Flint (gig_963a9f989404) covers the 23+6 scaffold above.
Expansion tests added by this draft (T1-19+, T2-20+) are new requirements
on the spec, not silently added gig scope — the gig is amended only by
explicit agreement.

### Tier 1 — static wire-contract checks

- [ ] **T1-01** Reserialized/mutated envelope (same content, different bytes) → signature fails
- [ ] **T1-02** Wrong home / audience / role in any signed frame → rejected
- [ ] **T1-03** Conflicting relay aliases for the same stable key → resolved to key
- [ ] **T1-04** Alternate alias names resolving to same identity → accepted
- [ ] **T1-05** Forged consent grant (bad offer signature) → rejected at both relays
- [ ] **T1-06** Relabelled `grant_id` (tombstone references original) → bypass rejected; verifier uses signed identity
- [ ] **T1-07** Generation mismatch (acceptance generation ≠ offer generation) → rejected
- [ ] **T1-08** Expiry extension attempt (modified `expires_at`, original signature) → rejected
- [ ] **T1-09** Stripped `countersignature_required` (flag removed, original signature) → rejected; mode is signed
- [ ] **T1-10** Countersignature required but absent → rejected
- [ ] **T1-11** Handshake reflection / cross-protocol replay (link frames as attestations and vice versa) → rejected via domain separation
- [ ] **T1-12** UUID collision with changed body → rejected, never double-inserted
- [ ] **T1-13** Directory key substitution vs pinned identity → rejected
- [ ] **T1-14** Unknown field in any signed object → rejected
- [ ] **T1-15** Duplicate JSON key in signed bytes → rejected
- [ ] **T1-16** Non-NFC / bad-escaping / float / non-UTC time in signed bytes → rejected
- [ ] **T1-17** Attestation `from_relay_key` ≠ authenticated attester → rejected (confused deputy)
- [ ] **T1-18** Delivery receipt / install receipt / NDR / tombstone with bad schema or missing hash bindings → rejected
- [ ] **T1-19** Attestation `attempt_at` older than 1200s or more than 300s future → rejected (P1-2)
- [ ] **T1-20** Replayed attestation after nonce eviction (valid envelope, stale attempt) → rejected via freshness, not nonce (P1-2)
- [ ] **T1-21** Heartbeat with wrong epoch or `sent_at` outside window → rejected (P1-1/P1-2)
- [ ] **T1-22** `link-error` with unknown reason / bad schema → rejected (P1-1)
- [ ] **T1-23** Tombstone with wrong generation type, missing `grant_id`, or open `reason` → rejected (P1-1)
- [ ] **T1-24** Countersignature over wrong domain or mismatched `acceptance_hash` → rejected (P1-1)
- [ ] **T1-25** Directory with unsorted keys or non-base64url key → rejected (P1-1)
- [ ] **T1-26** Custody ACK with wrong `msg_id`/envelope hash or unsigned → rejected (P1-1)
- [ ] **T1-27** NDR missing issuer/audience/home bindings → rejected (P1-1)
- [ ] **T1-28** Acceptance `expires_at` later than offer's → rejected; effective expiry = min (P1-4)

### Tier 2 — adapter-driven stateful scenarios

- [ ] **T2-01** Queued revocation under partition → tombstone wins after reconnect
- [ ] **T2-02** Persisted rollback/replay after relay restart → rejected via sequence high-water marks + nonce retention
- [ ] **T2-03** Concurrent final-use redeem → exactly one winner installed; loser gets `already_consumed` + winner ID
- [ ] **T2-04** One-sided commit and retry → idempotent, single inbox insertion
- [ ] **T2-05** Revoke racing accept / enqueue / poll / fetch → tombstone precedence at every recheck point
- [ ] **T2-06** Stale-generation resurrection after reconnect → ignored
- [ ] **T2-07** Lost enqueue ACK → retry is idempotent, one inbox insertion
- [ ] **T2-08** Delayed delivery beyond transport nonce validity but within envelope expiry → accepted (fresh attestation)
- [ ] **T2-09** Expiry without TTL extension → authenticated NDR, no silent drop
- [ ] **T2-10** Unlink / rotation while queues exist → defined NDR behavior per §6; rotation drains, revocation NDRs (§9)
- [ ] **T2-11** Transitive rejection, variant A: A→B→C with no B↔C link → rejected
- [ ] **T2-12** Transitive rejection, variant B (corrected, P2-7): A↔B and B↔C linked, A↔C **not** linked. B forwards A's original signed envelope to C. C must reject: attester B is linked, but the envelope's `from_relay_key` (A) is not a linked relay, and B is not A's home — B has no authority to present A's envelope. Reject at C.
- [ ] **T2-13** Non-home forwarding (relay forwarding for a peer it doesn't host) → rejected
- [ ] **T2-14** Quota exhaustion → backpressure signals, bounded retry, no loss
- [ ] **T2-15** Crash around custody/ACK boundary → states reconcile, one durable insertion, no silent loss
- [ ] **T2-16** Directory substitution at first contact → flagged TOFU, anti-impersonation claim narrowed
- [ ] **T2-17** Simultaneous link handshakes → deterministic winner (greater key initiates)
- [ ] **T2-19** 24h partition cap → delivery stops, fail-closed NDRs after cap
- [ ] **T2-20** FINISH retry after committed success → **identical saved FINISH_ACK bytes** replayed (P1-3)
- [ ] **T2-21** FINISH for unknown/expired attempt → `link-error`, initiator starts fresh; no epoch reuse (P1-3)
- [ ] **T2-22** Epoch monotonicity across role-swapped handshakes → new epoch > old, never rewound (P1-3)
- [ ] **T2-23** Revocation recheck protocol → watermark advances only on valid signed response; cache age resets there (P1-4)
- [ ] **T2-24** Heartbeats during partition do not reset the recheck watermark → fail-closed at 24h despite liveness (P1-4)
- [ ] **T2-25** Selective FINISH_ACK loss → initiator retries, responder replays identical bytes; epoch commits exactly once (P1-3, needs adapter fault injection)
- [ ] **T2-26** Compromised home relay suppressing revocation → documented non-guarantee; test asserts the design *states* the limit, not that it prevents it (negative control, P1-4)

### Tier 2 test-adapter interface

The adapter is the contract between the test suite and any implementation.
It must support fault injection — that is the point. (Expanded per P1-5.)

```
create_relay(config) -> handle
destroy_relay(handle)
link_relays(a, b) -> link_id            # performs §6 handshake
unlink_relays(a, b)
partition_link(a, b)                    # drops traffic both ways
heal_link(a, b)                         # re-establishes; triggers revocation recheck
crash_relay(handle)                     # SIGKILL-equivalent: no graceful shutdown
restart_relay(handle)                   # state must come from durable storage
send_envelope(from_peer, to_peer, envelope_bytes, signature)
get_outbox_state(msg_id) -> state
get_inbox(peer) -> [messages]
install_grant(relay, grant) / revoke_grant(relay, tombstone)
set_clock(handle, t)                    # time travel forward for expiry/lease tests
get_pinned_key(relay, contact) -> pubkey
# --- fault injection (new in v0.4) ---
drop_next_response(n, match)            # drop next n responses matching predicate
                                        # (selective: FINISH_ACK only, etc.)
barrier_at_commit_point(point)          # pause before/after commit; point in
                                        # {outbox_commit, inbox_insert, install, tombstone_apply}
schedule_contenders(fn_list)            # run contender functions concurrently
inject_signed_frame(frame_bytes, sig)   # deliver a raw signed frame to a relay
replay_frame(frame_bytes)               # redeliver a captured frame verbatim
inject_directory_update(relay, dir)     # deliver a crafted directory
set_quota(scope, limits)                # configure quota bounds
get_resource_usage(relay)               # inspect queue depth, in-flight counts
get_receipts(relay)                     # inspect persisted receipts
get_attempts(relay)                     # inspect handshake/delivery attempt records
```

**Adapter restart semantics:** identity (keys) and config survive
`restart_relay` from durable storage; all committed state (inbox, outbox,
pins, grants, tombstones, receipts, watermarks, epochs, high-water marks)
survives. In-flight (uncommitted) state may be lost — that is the point
of the crash tests.

**Clock semantics:** `set_clock` moves the clock **forward only**. Clock
rollback is not supported and not tested; implementations must use a
monotonic source for freshness/lease measurement where available.

Tier 2 scenarios are written once against this interface and run against
every implementation. An implementation that cannot host the adapter
cannot claim the Tier 2 properties.

---

**Next steps:**
- [ ] Kin circle reviews this v0.4 draft (Zari, Flint, Clingy Bear)
- [ ] Aaron approves the narrowed trust claims
- [ ] After sign-off: protocol branch with sandbox implementation

**Implementation checkpoint:**
- Sandbox/prototype implementation work MAY proceed in parallel (Aaron's green light, YOLO mode).
- The safety claims in §10 are NOT signed off until Flint's v0.3 P1/P2
  findings are verified as addressed (this draft), the Tier 1 tests pass,
  the Tier 2 adapter + scenarios run green against a sandbox
  implementation, and kin review completes.
- Parallel sandbox work is not safety sign-off. No production rollout
  claims safety properties before the checkpoint clears.
- NO production relay deploys, NO federation implementation in production
  code paths, until the checkpoint clears.
