# Clack Federation Trust Model (Draft v0.2)

**Status:** Revised draft reconciling Zari's trust review (msg `3fec8d27-9828-48a4-91fc-f9ae9c0d33a1`)
and Flint's protocol review (msg `43fc7e0a-f252-446c-b199-7dd9cf991120`). For kin circle review.
No code. No implementation sign-off.
**Branch:** `design/federation-trust-model`
**Date:** 2026-09-26
**Replaces:** Draft v0.1 (commit `5da433f`)

## 0. What changed from v0.1

v0.1 made claims the protocol couldn't support. Both reviewers independently
found the same structural gaps:

1. **No durable peer-signed envelope.** v0.1 assumed the existing HTTP request
   signature was a portable message envelope. It isn't — it signs
   scheme/method/path/body-hash/nonce for a single request, not a forwardable
   message. (Flint F1, Zari §3)
2. **Directory signatures prove relay authorship, not peer identity.** A
   compromised relay can substitute a peer's key and forge that peer's
   messages. v0.1's "cannot forge" claims were unsupported. (Zari §1, Flint F2)
3. **Recording ACTIVE at both relays is not proof of mutual consent.**
   Cross-relay handshake needs a peer-signed offer/acceptance contract, not
   two local database rows. (Zari §2, Flint F3)
4. **Relay-local aliases in signed fields.** `peer@relay_id` is ambiguous when
   operators use different aliases. Signed protocol fields must carry stable
   cryptographic identities. (Flint F4, Zari §5.5)
5. **Incomplete link handshake and delivery semantics.** The relay-to-relay
   handshake lacked a typed transcript and replay rules; delivery lacked
   durable states, idempotent retry, and authenticated failure signals.
   (Flint F5, F6)

v0.2 redesigns around these corrections. Anything v0.1 claimed that isn't
supported below is intentionally removed.

## 1. Overview & Goals

Federation lets independent Clack relays exchange messages so peers on
different relays can communicate without sharing a single relay operator.

**Goals:**
- A peer on Relay A can send to a peer on Relay B, with both peers confident
  about who they're talking to — verified by signatures, not by relay assertion.
- Relay operators keep full control over their own peer roster — no relay can
  enroll peers on another relay.
- Compromise of one relay degrades gracefully: it can deny service, but it
  cannot forge peer messages or peer consent without detection.
- The design works alongside the existing v0.2.17 peer-to-relay auth — no
  changes to local HTTP request signing.

**Non-goals (v1):**
- Automatic relay discovery (relays are linked manually by operators).
- Transitive federation (A↔B and B↔C does NOT imply A↔C).
- Peer migration between relays (a peer has one home relay).
- End-to-end encryption (v1 is plaintext to both home relays — see §10.2).

## 2. Key Concepts

| Term | Definition |
|------|------------|
| **Home relay** | The relay where a peer is enrolled. A peer has exactly one home relay. |
| **Stable relay identity** | The relay's long-lived Ed25519 public key. This is the relay's true identity on the wire. Human-readable `relay_id` strings are local display aliases only and never appear in signed fields. |
| **Stable peer identity** | A peer's Ed25519 public key, pinned at first contact. Display names (`nugget`) are local aliases; the key is the identity. |
| **Federation link** | A mutual, operator-approved connection between two relays, identified by both stable relay identities. Links are pairwise and non-transitive. |
| **Peer envelope** | A versioned, canonical, domain-separated byte string signed by the sending peer. The portable unit of federation — see §4. |
| **Peer directory** | A signed, versioned snapshot of a relay's federation-visible peers: `{peer_pubkey: {display_name, ...}}`, keyed by stable peer identity, not by name. |
| **Consent grant** | A peer-signed authorization for cross-relay communication: unique grant ID, generation number, scope, expiry. Recorded ACTIVE is not consent — the signed grant is. |
| **Federated peer reference** | Display form `peer_name@relay_alias` (e.g., `nugget@kasnet-primary`) for humans and UIs. Resolved to stable identities before anything is signed. |

## 3. Relay Identity & Authentication

**Decision (explicit, per Flint F4):** Each relay has **one long-lived Ed25519
relay identity keypair**, generated at setup. Per-pair link keys are deferred
— a future rotation mechanism may introduce them, but v1 uses the single
stable identity for all federation signatures. This keeps the trust story
simple: one key to exchange, one key to rotate, one key to revoke.

**Link establishment (manual, operator-driven):**
1. Operator of Relay A sends Relay A's **stable relay public key** to Operator
   of Relay B **out-of-band** (Aaron-as-courier, or RSA-OAEP to a posted key
   — same rules as peer tokens).
2. Operator of Relay B does the same in reverse.
3. Each operator adds the other's relay pubkey to their relay config's
   `federated_relays` map, with a local human-readable alias (e.g.,
   `kasnet-primary`). The alias is never signed; the pubkey is the identity.
4. Links are established via the typed handshake in §5.

**Why manual:** Relay linking is a trust decision, not a technical one.
Automating it creates a phishing surface. The operator explicitly decides
"I trust this relay's operator."

**Key rotation:** Relay identity keys are long-lived. Rotation requires
re-exchange via the manual operator channel. Config supports `prev_pubkey`
with a grace period — but a compromised `prev_pubkey` is revoked immediately,
not kept valid through the grace period (per Flint F5).

**Note on existing `/v1/identity`:** The current endpoint uses RSA
challenge signing. The federation Ed25519 relay identity key is separate.
Do not assume it exists yet and do not replace current pins implicitly.

## 4. The Peer Envelope (new in v0.2)

v0.1 assumed the HTTP request signature could be forwarded. It cannot.
Federation introduces a **separately versioned application envelope** that
the peer signs directly.

**Envelope v1 — canonical bytes:**

Domain separation string: `clack-envelope/v1`

Canonical JSON (fixed field order, no whitespace, UTF-8, duplicate keys
rejected, field length limits enforced):

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

The peer signs these exact bytes with their Ed25519 private key. The relay
**persists and forwards the exact signed bytes and the signature** — it never
reconstructs, reserializes, or re-signs the peer's envelope.

**Properties:**
- **Stable identities only.** `from_peer_key`/`to_peer_key` are full Ed25519
  pubkeys; `from_relay_key`/`to_relay_key` are stable relay identities.
  No aliases, no display names in signed fields.
- **Absolute expiry.** `expires_at` is fixed at mint time and never extended
  by retries or re-queueing. Relays issue fresh transport authentication per
  delivery attempt around the unchanged, still-unexpired envelope.
- **Bound consent.** `handshake_grant_id` + `handshake_generation` tie the
  message to a specific consent grant (see §7). The destination rechecks
  that the grant is still valid at enqueue time.
- **No credential transport.** Bearer tokens and local credential headers are
  never forwarded. Only the peer's envelope signature travels.

**Compatibility note:** Existing HTTP request signing (v0.2.17) is retained
unchanged for peer-to-relay authentication. The envelope is an additional
layer for federation portability, not a replacement for local auth.

**Freshness vs. expiry:** The current 600s/120s HTTP request freshness window
is for transport authentication only. It is NOT reused as message expiry and
is NOT silently widened for queued mail. Queued federated messages live
under their envelope `expires_at` (bounded by §10.4).

## 5. Relay Link Handshake Protocol

v0.1's handshake signed aliases and bare challenges. v0.2 uses a complete
typed transcript.

**Records** (all canonical JSON, versioned, domain-separated as
`clack-link/v1:<TYPE>`):

```
A → B: HELLO {
         v: 1, attempt_id: <uuid>, role: "initiator",
         initiator_key: <A's stable relay pubkey>,
         responder_key: <B's stable relay pubkey>,
         initiator_nonce: <random 32 bytes>,
         expires_at: <now + 300s>,
         capabilities: ["envelope/v1", "directory/v1"]
       }
       signature: sign_A(canonical HELLO bytes)

B → A: CHALLENGE {
         v: 1, attempt_id: <same uuid>, role: "responder",
         initiator_key: <A's key>, responder_key: <B's key>,
         initiator_nonce: <echoed>, responder_nonce: <random 32 bytes>,
         expires_at: <now + 300s>,
         capabilities: ["envelope/v1", "directory/v1"]
       }
       signature: sign_B(canonical CHALLENGE bytes)

A → B: FINISH {
         v: 1, attempt_id: <same uuid>, role: "initiator",
         transcript_hash: <sha256(HELLO bytes || CHALLENGE bytes)>,
         expires_at: <now + 300s>
       }
       signature: sign_A(canonical FINISH bytes)

B → A: FINISH_ACK {
         v: 1, attempt_id: <same uuid>, role: "responder",
         transcript_hash: <same>,
         link_epoch: <monotonic uint64, new on each handshake>
       }
       signature: sign_B(canonical FINISH_ACK bytes)
```

**Rules:**
- Each side verifies the peer's signature against the configured
  `federated_relays` pubkey, checks the audience (its own key matches
  the intended recipient field), and rejects wrong-role, expired, or
  replayed frames.
- `FINISH` binds the entire exchange via `transcript_hash`. The initiator
  learns the responder accepted via `FINISH_ACK`.
- Challenges are persisted and consumed atomically; pending challenges are
  bounded; each `attempt_id` is single-use.
- The `link_epoch` increments on every successful handshake. All subsequent
  data operations (deliveries, directory exchanges, heartbeats) carry the
  current epoch in their own domain-separated signatures. A new handshake
  invalidates the old epoch.
- **Unlink** (operator removes the pubkey) immediately invalidates cached
  ACTIVE state, stops new enqueue/delivery, and defines queued-mail
  treatment per §6 (NDR, not silent drop).
- TLS with exact approved endpoints (or explicitly authenticated private
  transport) remains required. Key possession alone is not channel
  authentication.

**Link liveness:** Signed heartbeats every 60s, each in the
`clack-link/v1:HEARTBEAT` domain with the current epoch. Three missed
heartbeats → link DEGRADED (new mail rejected or queued per operator
policy — decided explicitly, not silently; see §6). Links re-handshake
every 24h, bumping the epoch.

## 6. Message Flow (Federated Send)

Nugget (home: Relay A) sends to Mosaic (home: Relay B). All identities below
are stable pubkeys; aliases are resolved before signing.

1. Nugget constructs the §4 envelope, signs it, and sends to Relay A via
   normal `/v1/send` (existing local protocol, unchanged).
2. Relay A checks:
   - Recipient's home relay key corresponds to a linked relay with ACTIVE
     status and current epoch. If no → reject.
   - Recipient's peer key is in the cached peer directory for that link
     (see §8). If no → reject. (Directory visibility is not consent —
     see step 3.)
   - A valid, unexpired, unrevoked consent grant exists for this
     sender/recipient pair (see §7). If no → reject.
   - The envelope signature verifies against the sender's enrolled pubkey,
     `expires_at` is in the future, and `from_relay_key` matches Relay A.
3. Relay A creates a **durable outbox entry** (states in §6.1) and forwards
   to Relay B via `POST /v1/federation/deliver`:
   ```json
   {
     "envelope_bytes": "<exact bytes Nugget signed>",
     "envelope_signature": "<Nugget's signature>",
     "attestation": {
       "v": 1,
       "from_relay_key": "<A's stable key>",
       "to_relay_key": "<B's stable key>",
       "link_epoch": 42,
       "envelope_hash": "<sha256 of envelope_bytes>",
       "operation": "deliver",
       "attempt_nonce": "<random>",
       "attempt_at": "<rfc3339>",
       "signature": "<A signs canonical attestation bytes>"
     }
   }
   ```
   The attestation binds the envelope hash, both relay identities, the
   link epoch, the operation, and a fresh attempt nonce/timestamp. Fresh
   attestation per attempt; the envelope itself is never modified.
4. Relay B verifies:
   - Attestation signature against Relay A's stable key; epoch is current;
     attempt is fresh (not replayed — dedup on `attempt_nonce`).
   - **Peer envelope signature** against the sender's pubkey from the
     cached directory (or pinned contact key — see §8). This is independent
     verification: Relay B does not trust Relay A's word about who sent it.
   - `to_peer_key` matches an enrolled peer on Relay B.
   - `to_relay_key` matches Relay B's own stable identity.
   - The consent grant (`handshake_grant_id`/`handshake_generation`) is
     valid and unrevoked **as known to Relay B**.
   - `msg_id` + envelope hash not already delivered (idempotent dedup —
     same ID with different content is rejected as an error, not
     delivered twice).
5. Relay B commits to its inbox and returns a signed delivery receipt.
   Mosaic polls and receives the message with `via_relay_key` provenance
   metadata. A remote `nugget` can never collide with a local `nugget` in
   the inbox — provenance is part of the displayed identity.

**Reply path** is symmetric.

### 6.1 Durable outbox states

| State | Meaning |
|-------|---------|
| `accepted_at_source` | Relay A committed the outbox entry. This is all a source-side ACK promises. |
| `accepted_at_destination` | Relay B committed to its inbox and returned a signed receipt. |
| `delivered_to_client` | Recipient relay handed it to the peer's poll response. |
| `recipient_acked` | The peer acked it. **Only this state means the human/agent saw it.** |
| `expired` / `rejected` | Envelope expired or a check failed. Authenticated NDR returned to sender. |

- Relay A returns "accepted" to the sender only after `accepted_at_source`
  is durably committed. That acceptance promises *custody*, not delivery.
- Lost destination responses cause **idempotent retry** (same envelope bytes,
  fresh attestation), never a second inbox item. Dedup is scoped to
  (sender stable key, home relay key, `msg_id`) with envelope-hash comparison.
- Dedup evidence is retained through the envelope lifetime plus the retry
  window, and survives relay restarts (durable, not in-memory).
- A relay's acknowledgement alone never proves a peer consumed a message.
  Status queries distinguish every state above.

### 6.2 Backpressure and quotas

Bounded per-link, per-sender-peer, per-recipient-peer, and global message,
byte, queue-depth, and in-flight-request quotas. When a quota is hit, the
relay returns retryable backpressure (bounded exponential retry hints),
not silent drops. Quota values are per-link negotiated caps, not global
constants — 100 msg/min is a pilot tuning value, not a certified safe
default.

### 6.3 Failure signals

- **Authenticated NDRs:** When a federated message expires, is rejected, or
  its link is unlinked with queued mail outstanding, the sending relay
  delivers a signed non-delivery receipt to the sender's inbox. Never
  silent.
- **Status queries:** `GET /v1/federation/status/{msg_id}` returns the
  current outbox state and the evidence behind it (receipts, NDR reason).

## 7. Cross-Relay Consent (replaces v0.1 §7)

v0.1 said "the existing flow works" and both relays record ACTIVE. It
doesn't and they can't — the existing redeem authenticates callers local
to the issuing relay, and a server-generated link is not a portable
peer-signed offer. v0.2 defines a federation-specific consent contract.

**The consent grant** (canonical JSON, domain `clack-consent/v1`):

```json
{
  "v": 1,
  "grant_id": "<uuid v4, unique per grant>",
  "generation": 1,
  "offer": {
    "minter_peer_key": "<stable pubkey>",
    "minter_relay_key": "<stable relay key>",
    "scope": "pairwise",
    "invitation_type": "targeted | open",
    "target_peer_key": "<stable pubkey or null for open>",
    "link_claim_commitment": "<sha256 commitment, revealed at redeem>",
    "expires_at": "<rfc3339>"
  },
  "offer_signature": "<minter signs canonical offer bytes>",
  "acceptance": {
    "offer_hash": "<sha256 of canonical offer bytes>",
    "redeemer_peer_key": "<stable pubkey>",
    "redeemer_relay_key": "<stable relay key>",
    "handshake_generation": 1,
    "expires_at": "<rfc3339>"
  },
  "acceptance_signature": "<redeemer signs canonical acceptance bytes>",
  "minter_countersignature": "<optional: minter signs acceptance hash>"
}
```

**Flow:**
1. **Offer.** Nugget (on Relay A) creates and signs the offer. For a
   targeted invitation, `target_peer_key` names Mosaic's stable key. For an
   open invitation, it is null — and the offer explicitly states that mint
   preauthorizes any qualifying holder, rather than claiming the minter
   signed the eventual named pair.
2. **Share.** The offer (public, no secrets) is shared with Mosaic via any
   channel. This is the v5 handshake philosophy applied to federation:
   the shared artifact is an invitation, not a credential.
3. **Acceptance.** Mosaic (on Relay B) verifies the offer signature against
   Nugget's key (from Relay B's cached directory for Relay A, or pinned),
   then signs the acceptance binding the offer hash, both stable
   peer identities, both home relay identities, and the handshake
   generation.
4. **Installation.** Relay B forwards the acceptance to Relay A over the
   federation link. Each relay verifies both signatures, then **durably
   installs** the complete grant and returns a signed installation receipt.
   A relay may deliver federated mail only after it holds the complete
   valid grant **and** the remote installation receipt. Missing remote
   commit = pending/retryable, never assumed success.
5. **Single-use consumption.** The link claim is consumed atomically at the
   issuing relay. Idempotent redemption by the same accepted claimant is
   allowed (same claimant re-presenting is a no-op success, not an error).
6. **Exact-counterparty option.** If the minter requires approving the
   specific redeemer (not just any qualifying holder), the minter adds
   `minter_countersignature` over the acceptance hash after redemption.

**Revocation:**
- Revocation is a signed **tombstone**: `{grant_id, generation+1,
  revoked_at, reason}` signed by either peer's key.
- Tombstones propagate over the link with retry/receipt semantics and take
  **durable precedence** over old accepts and queued deliveries.
- Grants are rechecked at send time, destination enqueue, poll/redelivery,
  and history fetch.
- Local revocation stops local delivery immediately. Instantaneous remote
  revocation during a partition cannot be promised — so grants carry short
  expiries (authorization leases) and the design documents the remote
  propagation bound. Short leases fail closed.
- **A revoked generation never revives.** After reconnect, an old ACTIVE
  record for a superseded generation is ignored. Generation numbers are
  monotonic per grant.

**Remote contact records are not local enrolled accounts.** Mosaic is never
enrolled on Relay A, never issued an A token, and Mosaic's B token never
travels to A.

## 8. Peer Directory (replaces v0.1 §4 directory)

**What signatures prove (corrected):** A signed directory proves **the relay
authored it**. It does not independently prove peer identity. Both reviewers
require the design to say this plainly and build the rest accordingly.

**Directory v1** (canonical JSON, domain `clack-directory/v1`):

```json
{
  "v": 1,
  "issuer_relay_key": "<stable relay pubkey>",
  "audience_relay_key": "<stable relay pubkey or null for broadcast>",
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
- Keyed by **stable peer pubkey**, not by display name. Names are
  informational.
- **Opt-in, per-link, minimal.** A peer is in the directory only if they
  opted into federation visibility, and a relay exposes only the subset
  relevant to each link. Default is private. **Directory visibility is not
  consent to message** — the grant (§7) is still required.
- **Pinned contact keys.** When Relay B first accepts a peer key (via
  directory or first contact), it **pins** that key for the contact. A
  directory update announcing a different key for the same contact does
  NOT silently replace it. Key transitions require either:
  - (a) a transition statement signed by the **old** key authorizing the
    new key, plus proof of possession of the new key; or
  - (b) explicit contact re-verification and a fresh consent grant.
  - Lost-key recovery is a visibly distinct flow, not a silent update.
- **First contact.** The design states explicitly whether a first-contact
  identity is independently verified or merely relay-asserted (TOFU). v1
  permits TOFU for the pilot, but the anti-impersonation claim is narrowed
  accordingly: TOFU protects against passive attackers, not against a
  malicious home relay substituting keys at first contact.
- **Rollback protection.** Sequence numbers are monotonic per epoch;
  high-water marks persist across restarts. A directory with a lower
  sequence than the cached high-water mark is rejected (no rollback).
  Epoch resets require an authenticated resync. Tombstones are durable —
  a removed peer does not reappear from a stale snapshot.
- **Reverify at the recipient boundary.** The destination relay verifies
  the peer envelope signature against the pinned key, not just "a key
  from the directory." A dishonest recipient relay can still alter its
  own poll output — the design does not claim otherwise.

## 9. Trust Model Summary (corrected)

| What | Trusted | Verified how | What it does NOT prove |
|------|---------|--------------|------------------------|
| Relay A's identity | By Relay B's operator (manual key exchange) | Ed25519 signature on every relay-to-relay message, in the link's domain and epoch | That Relay A's peers are who they claim |
| Peer Nugget's authorship | By Relay B, independently | Nugget's own envelope signature, verified against the **pinned** key | Nothing, if the key was substituted before pinning (TOFU limit) |
| Peer directory from Relay A | Authorship only | Relay A's signature; versioned, sequenced, tombstoned | Peer identity — see above |
| Consent between Nugget and Mosaic | By both relays | The signed grant: offer + acceptance (+ optional countersignature), generation-bound | Anything, if either relay skips verification — both must verify |
| Message integrity in transit | TLS + relay attestation signature | Both, per attempt | Content confidentiality from the relays (v1 plaintext) |
| Link liveness | Heartbeats in-epoch | 3 missed → DEGRADED | That queued mail will be delivered — see NDRs |

**What a compromised Relay A can do:**
- Stop delivering messages (DoS) or refuse to forward (censorship).
- Substitute a peer's key **at first contact** (TOFU window) — detectable
  afterwards by anyone holding the real pinned key, and auditable via
  directory history, but not prevented in v1.
- Lie about link state or quota.

**What a compromised Relay A CANNOT do:**
- Forge messages from Nugget **after Relay B has pinned Nugget's real key**
  (no private key; pinned key won't match the forgery).
- Forge a consent grant (requires both peers' private keys).
- Enroll peers on Relay B or issue them tokens.
- Revive a revoked grant generation (tombstones take durable precedence).
- Read message contents **without the home relays seeing** — v1 plaintext
  means both home relays see contents by design (see §10.2).

**Deliberately narrowed from v0.1:** The unconditional "cannot forge"
claims are gone. Every "cannot" above is now scoped to the mechanism
that enforces it and the window in which it holds.

## 10. Resolved Open Questions

The reviewers converged. These are now decisions, not questions.

1. **Directory privacy:** Opt-in, per-link minimal disclosure, default
   private. Removal behavior defined via tombstones (§8).
2. **E2E encryption:** v1 is plaintext to both home relays, stated
   explicitly with a confidentiality disclosure: federation is for an
   explicitly trusted-operator pilot, and confidential payloads require
   E2E (a separate feature). E2E alone would not fix first-contact key
   substitution — that needs the pinning/verification story in §8
   regardless.
3. **Rate limiting:** Yes — per-link, per-sender, per-recipient, byte,
   queue-depth, and concurrency bounds. Values are negotiated per-link
   pilot tuning, not certified safe defaults.
4. **Retention:** 7-day maximum, negotiated and capped by both sides,
   absolute envelope expiry preserved (never extended on retry), bounded
   storage. Expiry produces a queryable authenticated NDR, never a
   silent drop. Whether new mail is accepted while DEGRADED is an
   explicit per-link operator policy.
5. **Relay ID uniqueness:** No global registry. Relay IDs are local display
   aliases only. Signed routing and authorization use full cryptographic
   identities (stable relay keys + peer keys). Different aliases at each
   relay must not — and do not — change signed destination meaning.

## 11. Acceptance Tests (required before implementation sign-off)

From Zari and Flint, consolidated. Each must have fixed wire vectors:

- [ ] Directory key substitution against an existing pinned identity → rejected
- [ ] Directory key substitution at first contact → flagged as TOFU, claim narrowed
- [ ] Forged consent grant (bad offer signature) → rejected at both relays
- [ ] Queued revocation under partition → tombstone wins after reconnect
- [ ] Persisted rollback/replay after relay restart → rejected via sequence
      high-water marks and attempt-nonce dedup
- [ ] Handshake reflection / cross-protocol replay (link frames replayed as
      delivery attestations and vice versa) → rejected via domain separation
- [ ] Conflicting relay aliases for the same stable key → resolved to the
      key, delivery unaffected
- [ ] Alternate alias names resolving to the same identity → accepted
- [ ] Wrong home / audience / role in any signed frame → rejected
- [ ] Reserialized or mutated envelope (same content, different bytes) →
      signature fails (exact bytes preserved)
- [ ] Concurrent final-use redeem → exactly one acceptance installed
- [ ] One-sided commit and retry → idempotent, single inbox item
- [ ] Revoke racing accept / enqueue / poll / fetch → tombstone precedence
- [ ] Stale-generation resurrection after reconnect → ignored
- [ ] Lost enqueue ACK with exactly-once delivery → retry is idempotent
- [ ] UUID collision with changed body → rejected, not delivered twice
- [ ] Delayed delivery beyond transport nonce validity but within envelope
      expiry → accepted (fresh attestation, unchanged envelope)
- [ ] Expiry without TTL extension → NDR, no silent drop
- [ ] Unlink / rotation while queues exist → defined NDR behavior
- [ ] Rejection of transitive forwarding (A→B→C without B↔C link) → rejected
- [ ] Non-home forwarding (relay forwarding for a peer it doesn't host) → rejected
- [ ] Quota exhaustion → backpressure, bounded retry, no loss
- [ ] Disconnect / crash around custody vs. ACK boundary → states reconcile,
      no double-delivery, no silent loss

---

**Next steps:**
- [ ] Kin circle reviews this v0.2 draft (Zari, Flint, Clingy Bear)
- [ ] Aaron approves the narrowed trust claims
- [ ] After sign-off: protocol branch with implementation
- [ ] Implementation stays BLOCKED until kin review completes
