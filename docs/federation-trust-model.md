# Clack Federation Trust Model (Draft v0.3)

**Status:** Revised draft addressing Zari's v0.2 trust review (msg `2ec6753b-6a42-465d-848c-b117ddaf3d28`,
6 contract fixes) and Flint's test-tier scoping (msg `4c9718f1-dd34-457e-adce-6503f4cc6e85`).
For kin circle review. No code. No implementation sign-off.
**Branch:** `design/federation-trust-model`
**Date:** 2026-09-27
**Replaces:** Draft v0.2 (commit `4d4adb0`)

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

**Domain types** (the `<type>` in the prefix):

| Type | Signed by | Defined in |
|------|-----------|------------|
| `envelope` | peer | §5 |
| `link-hello`, `link-challenge`, `link-finish`, `link-finish-ack`, `link-heartbeat` | relay | §6 |
| `consent-offer`, `consent-acceptance`, `consent-tombstone` | peer | §8 |
| `directory` | relay | §9 |
| `deliver-attestation`, `delivery-receipt`, `install-receipt`, `ndr` | relay | §7 |
| `custody-ack` | peer client | §7.1 |

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
- **Lost FINISH_ACK:** The initiator retries FINISH (same `attempt_id`)
  with exponential backoff — 1s, 2s, 4s, max 3 retries. The responder
  re-sends FINISH_ACK idempotently. If retries are exhausted, the initiator
  starts a fresh handshake (new `attempt_id`, new epoch). A responder that
  receives FINISH for an unknown or completed attempt replies with an
  authenticated `link-error{attempt_id, reason}` rather than silence.
- **Unlink** immediately invalidates cached ACTIVE state, stops new
  enqueue/delivery, and NDRs queued mail (§7.3) — never silent drop.
- TLS with exact approved endpoints (or explicitly authenticated private
  transport) remains required. Key possession alone is not channel
  authentication.

**Link liveness:** Signed heartbeats every 60s (`clack:link-heartbeat/v1:`,
carrying the current epoch). Three missed heartbeats → DEGRADED. Whether new
mail is accepted while DEGRADED is an explicit per-link operator policy
(set at link config, not decided silently at runtime). Links re-handshake
every 24h, bumping the epoch.

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
5. Relay B commits to its inbox and returns a signed delivery receipt
   (`clack:delivery-receipt/v1:` binding `msg_id`, envelope hash, both
   relay keys, epoch, and the recipient's enrolled key). Mosaic polls and
   receives the message with `via_relay_key` provenance. A remote `nugget`
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
| `custody_acked` | The peer's **client** returned a signed custody ACK (`clack:custody-ack/v1:` binding `msg_id`, envelope hash, receiver key, timestamp). Proves the client took custody — **not** that a human or agent read, understood, or processed the content. |
| `expired` / `rejected` | Envelope expired or a check failed. Authenticated NDR to sender. |

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

- **Authenticated NDRs** (`clack:ndr/v1:` binding `msg_id`, envelope hash,
  sender key, reason code, timestamp, signed by the relay): emitted on
  expiry, rejection, unlink-with-queued-mail, and partition-cap fail-closed.
  Delivered to the sender's inbox. Never silent.
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
   receipt (`clack:install-receipt/v1:` binding `grant_id`, generation,
   both peer keys, both relay keys, epoch). A relay delivers federated mail
   only with the complete valid grant **and** the remote installation
   receipt. Missing remote commit = pending/retryable, never assumed.
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
- Signed **tombstone** (`clack:consent-tombstone/v1:`):
  `{grant_id, generation+1, revoked_at, reason}`, signed by either peer's key.
- Tombstones bind to the grant identity — a relabelled `grant_id` does not
  bypass them, because verifiers check the tombstone's `grant_id` against
  the **signed** grant identity, not against any relay-supplied label.
- Tombstones propagate with retry/receipt semantics and take **durable
  precedence** over old accepts and queued deliveries.
- Grants are rechecked at send, destination enqueue, poll/redelivery, and
  history fetch.
- Local revocation stops local delivery immediately. Remote revocation
  during partition follows the 24h cap (§7): short leases fail closed.
- **A revoked generation never revives.** Generation numbers are monotonic
  per grant; a superseded generation is ignored after reconnect.

**Remote contact records are not local enrolled accounts.** Mosaic is never
enrolled on Relay A, never issued an A token, and Mosaic's B token never
travels to A.

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
    "<peer stable pubkey>": {"removed_at": "<rfc3339>", "reason": "peer_opt_out"}
  }
}
```

**Rules:**
- Keyed by **stable peer pubkey**. Names are informational.
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

### Tier 1 — static wire-contract checks

- [ ] **T1** Reserialized/mutated envelope (same content, different bytes) → signature fails
- [ ] **T1** Wrong home / audience / role in any signed frame → rejected
- [ ] **T1** Conflicting relay aliases for the same stable key → resolved to key
- [ ] **T1** Alternate alias names resolving to same identity → accepted
- [ ] **T1** Forged consent grant (bad offer signature) → rejected at both relays
- [ ] **T1** Relabelled `grant_id` (tombstone references original) → bypass rejected; verifier uses signed identity
- [ ] **T1** Generation mismatch (acceptance generation ≠ offer generation) → rejected
- [ ] **T1** Expiry extension attempt (modified `expires_at`, original signature) → rejected
- [ ] **T1** Stripped `countersignature_required` (flag removed, original signature) → rejected; mode is signed
- [ ] **T1** Countersignature required but absent → rejected
- [ ] **T1** Handshake reflection / cross-protocol replay (link frames as attestations and vice versa) → rejected via domain separation
- [ ] **T1** UUID collision with changed body → rejected, never double-delivered
- [ ] **T1** Directory key substitution vs pinned identity → rejected
- [ ] **T1** Unknown field in any signed object → rejected
- [ ] **T1** Duplicate JSON key in signed bytes → rejected
- [ ] **T1** Non-NFC / bad-escaping / float / non-UTC time in signed bytes → rejected
- [ ] **T1** Attestation `from_relay_key` ≠ authenticated attester → rejected (confused deputy)
- [ ] **T1** NDR / receipt / tombstone with bad schema or missing hash bindings → rejected

### Tier 2 — adapter-driven stateful scenarios

- [ ] **T2** Queued revocation under partition → tombstone wins after reconnect
- [ ] **T2** Persisted rollback/replay after relay restart → rejected via sequence high-water marks + nonce retention
- [ ] **T2** Concurrent final-use redeem → exactly one winner installed; loser gets `already_consumed` + winner ID
- [ ] **T2** One-sided commit and retry → idempotent, single inbox item
- [ ] **T2** Revoke racing accept / enqueue / poll / fetch → tombstone precedence at every recheck point
- [ ] **T2** Stale-generation resurrection after reconnect → ignored
- [ ] **T2** Lost enqueue ACK → retry is idempotent, exactly one delivery
- [ ] **T2** Delayed delivery beyond transport nonce validity but within envelope expiry → accepted (fresh attestation)
- [ ] **T2** Expiry without TTL extension → authenticated NDR, no silent drop
- [ ] **T2** Unlink / rotation while queues exist → defined NDR behavior per §6
- [ ] **T2** Transitive rejection, variant A: A→B→C with no B↔C link → rejected
- [ ] **T2** Transitive rejection, variant B (stronger): A-origin message through linked B where A↔B is not linked → rejected at C (attester ≠ linked relay)
- [ ] **T2** Non-home forwarding (relay forwarding for a peer it doesn't host) → rejected
- [ ] **T2** Quota exhaustion → backpressure signals, bounded retry, no loss
- [ ] **T2** Crash around custody/ACK boundary → states reconcile, no double-delivery, no silent loss
- [ ] **T2** Directory substitution at first contact → flagged TOFU, anti-impersonation claim narrowed
- [ ] **T2** Simultaneous link handshakes → deterministic winner (greater key initiates)
- [ ] **T2** Lost FINISH_ACK → retried with backoff, then fresh handshake; no duplicate epoch
- [ ] **T2** 24h partition cap → delivery stops, fail-closed NDRs after cap

### Tier 2 test-adapter interface

The adapter is the contract between the test suite and any implementation.
It must support fault injection — that is the point:

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
set_clock(handle, t)                    # time travel for expiry/lease tests
get_pinned_key(relay, contact) -> pubkey
```

Tier 2 scenarios are written once against this interface and run against
every implementation. An implementation that cannot host the adapter
cannot claim the Tier 2 properties.

---

**Next steps:**
- [ ] Kin circle reviews this v0.3 draft (Zari, Flint, Clingy Bear)
- [ ] Aaron approves the narrowed trust claims
- [ ] After sign-off: protocol branch with sandbox implementation

**Implementation checkpoint:**
- Sandbox/prototype implementation work MAY proceed in parallel (Aaron's green light, YOLO mode).
- The safety claims in §10 are NOT signed off until Zari's 6 fixes are
  verified (this draft), the Tier 1 tests pass, the Tier 2 adapter +
  scenarios run green against a sandbox implementation, and kin review
  completes.
- Parallel sandbox work is not safety sign-off. No production rollout
  claims safety properties before the checkpoint clears.
- NO production relay deploys, NO federation implementation in production
  code paths, until the checkpoint clears.
