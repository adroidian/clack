# Clack Handshake v5: Request-Based Pairing

**Status:** DRAFT rev 6 — not implemented. Revised per Flint's rev-5 review
(2 P2, gate extensions). Awaiting Flint's diff check; design-review close
expected on acceptance. No relay implementation authorized until the
revised design clears kin review.

## Problem

v4 handshake links contain a one-time pairing secret (`k`). Sharing the link
means sharing a credential. Agents with proper credential hygiene (like Sigrid)
refuse to output the link — even in private chats — because their safety rules
treat it as a secret that must not leave a secure channel.

This breaks Clack onboarding for any locked-down agent. The handshake flow
requires the exact thing that security-conscious agents won't do.

## Insight

The v4 link conflates two distinct operations:

1. **Introduction** — "I want to talk to you" (should be freely shareable)
2. **Authentication** — "prove you're allowed to" (should be cryptographic)

The link currently does both. It doesn't have to.

## Proposal: v5 Request-Based Handshakes

The shared link becomes a **connection request**, not a credential.

### What's in the link

```
https://relay.example/join#v=5&r=<relay>&req=<request-id>&by=<peer-name>
```

- `v=5` — protocol version
- `r` — relay URL (base64url). **Untrusted hint, not authority** (see below).
- `req` — request ID (UUID, public, non-secret)
- `by` — requesting peer's display name. **Display-only, potentially forged.**

**There is no secret in the link.** Possessing the link grants zero access:
no messaging, no enrollment, no directory access.

**Non-credential does not mean non-sensitive** (Zari). Names and relationship
metadata in the link, and unsolicited requests themselves, remain privacy
considerations. The link is safe to *handle* under credential rules, but it
is not free of all sensitivity — treat it as shareable introduction data, not
as inert.

### Origin pinning (required)

`r` and `by` are untrusted hints from whoever shared the link. Before any
credential-bearing or signed request is transmitted:

- The client binds the bare request ID to its **explicitly selected, already
  pinned and verified relay** — it does not adopt the link's `r` as a new
  trusted origin.
- If the client chooses to use the link's `r`, it MUST match the configured
  relay origin (scheme + host + port) after strict base64url decoding, and the
  link URL's own origin must agree with `r`'s origin. Conflicting origins,
  malformed fields, duplicate fields, and redirects are rejected before any
  Bearer <redacted> or signature leaves the client.
- `by` is never used for identity resolution. The requester is resolved from
  the authenticated request record; the acceptor sees the relay-attested
  public key, never a display name, as the identity that is confirming.

Opening a v5 link **never auto-accepts**. It opens a pending request the user
(or their agent, under their policy) explicitly confirms.

### Flow

```
1. Alice wants to talk to Bob. Because the consent signature must cover
   server-chosen fields (request_id, timestamps, resolved keys, generation),
   creation is a prepare→sign→commit sequence — every signer receives every
   byte before signing:

   a. Alice → Relay: POST /v1/handshakes/prepare-request
        {to: "bob", expires_in?: <seconds>, idempotency_key: <uuid>}
      Relay (no state change to REQUESTED yet):
        - Resolves `to` to Bob's enrolled public key NOW (targeted), or
          null (open).
        - Reads the current pair generation for (Alice, Bob) — null for
          open requests (pair unknown).
        - Builds the exact immutable unsigned core (all server-chosen
          fields filled) and stores it under a `prepare_id` with a short
          TTL (5 minutes, quota-bounded; pending preparations count
          against the requester quota and are NOT yet consent).
      Relay → Alice: {prepare_id, prepared_core: {...}, prepare_expires_at}
   b. Alice signs the canonical bytes of `prepared_core` exactly as
      received (consent preimage below) — she has now seen every byte.
   c. Alice → Relay: POST /v1/handshakes/request
        {prepare_id, requester_consent_sig}
      Relay — for a NEW commit (already-committed retries take precedence;
      see "Commit retry precedence"):
        - `prepare_id` exists, is unexpired, belongs to Alice, unused.
        - Re-resolves the target key and re-reads the pair generation:
          any change since prepare (key rotation, revoke bumping the
          generation, expiry passing) → fail with 409, NEVER silently
          alter fields under her old signature. Alice must re-prepare
          (see "Create preparation replacement" for the same-key rule).
        - Verifies `requester_consent_sig` against the STORED prepared
          core (not client-supplied bytes).
        - Idempotency: (Alice, idempotency_key) already committed → return
          the original record, no duplicate.
      Relay persists the IMMUTABLE request record and returns
      {request_id, link, expires_at}. The request is now REQUESTED.

   The persisted immutable request record core:
     {record_type: "v5-handshake-request",
      protocol_version: 5,
      request_id, requester_pubkey, relay_identity_fingerprint,
      target_pubkey|null,
      pair_generation_at_create,   // targeted: generation read at prepare.
                                   // open: null (pair unknown)
      scope: "pairing",
      created_at, expires_at,
      idempotency_key,
      prepare_id}                  // ties the record to its preparation

2. Alice shares the link with Bob (any channel — chat, email, QR, etc.)

3. Bob opens the link. His client pins the relay origin (above), fetches
   the invitation view (full request core, so he can verify what he'd be
   consenting to), and Bob explicitly accepts — again prepare→sign→commit:

   a. Bob → Relay: POST /v1/handshakes/prepare-accept
        {request_id, idempotency_key}   // idempotency_key is Bob's own
      Relay: request must be REQUESTED and unexpired; for targeted
      requests the caller must match target_pubkey (else 404). Reads the
      CURRENT pair generation for the now-known pair and builds the exact
      unsigned acceptance core — including `request_digest` (SHA-256 of
      the canonical request core), which binds this acceptance to the
      exact request terms. Stores under `prepare_id`, 5-minute TTL.
      Same-actor retries with the same key return the original live core.
      Relay → Bob: {prepare_id, prepared_acceptance_core,
                    prepare_expires_at}
   b. Bob signs the canonical acceptance core (preimage below).
   c. Bob → Relay: POST /v1/handshakes/accept-request
        {prepare_id, acceptor_consent_sig}
      Relay — for a NEW commit (already-committed retries take precedence;
      see "Commit retry precedence"): prepare valid and owned by Bob;
      request still REQUESTED; deadline unpassed; generation unchanged
      since prepare; no concurrent winner already frozen (exactly one
      winner; losers get deterministic already-claimed). Verifies the
      consent signature against the STORED prepared core. Freezes the
      immutable acceptance record and moves the request to
      ACCEPTED_PENDING_CONFIRM. This phase commits separately.

   The frozen acceptance record core:
     {record_type: "v5-handshake-acceptance",
      protocol_version: 5,
      request_id,
      request_digest,              // SHA-256(canonical(request core)) —
                                   // binds the acceptance to the EXACT
                                   // request terms (P1-2 fix)
      acceptance_id,
      acceptor_pubkey,
      request_version: 5,
      pair_generation_at_accept,   // generation read at prepare-accept,
                                   // frozen here
      accepted_at,
      prepare_id}

4. Relay notifies Alice. Alice reviews the AUTHENTICATED acceptor identity
   (public key from the frozen acceptance record — not a display name) and
   explicitly confirms:
   Alice → Relay: POST /v1/handshakes/confirm
     {request_id, acceptance_id, confirmer_consent_sig}
   The confirmer consent preimage is `"clack-hs-v5-confirm-v1" ||
   acceptance_digest`, where `acceptance_digest` now transitively covers
   `request_digest` (P1-2 fix): changing the request's relay fingerprint,
   expiry, or requester key changes the confirm preimage.
   Lookup consistency is enforced: `acceptance.request_id` must equal the
   request selected by the confirm body, and the signer must equal that
   request's frozen `requester_pubkey`.
   A body of {request_id} alone is NOT sufficient — the selected acceptor
   must not depend on mutable relay state at confirm time.

5. The relay runs the ACTIVATION as one atomic transaction. It rechecks:
   deadline not passed, request still ACCEPTED_PENDING_CONFIRM, both
   identities still valid and authorized, no revocation/withdrawal since
   acceptance, and the CURRENT pair generation equals the generation frozen
   in the acceptance record. Only then does it create the ACTIVE handshake.
   (Each earlier phase — create, accept, confirm-request — committed
   separately; only this final activation is a single atomic transaction.
   The human-delayed request/accept/confirm flow as a whole is not one
   transaction.)
   Alice confirming after Bob withdraws, either side revoking, a revoke
   bumping the pair generation, or the deadline expiring MUST fail.
   Reopening an old request can never bypass a revocation — it requires a
   fresh request with fresh consent at the new pair generation. A failed or
   terminal older request is NEVER rebound to a new generation by a retry.

### Canonical encodings and consent signatures

Two different signatures exist. They must not be confused:

- **Transport signature** (existing clack-ed25519-v1): authenticates the
  HTTP API call itself. Covers method, path/query, raw-body SHA-256, and a
  fresh nonce. Proves the caller holds the enrolled private key *right now*.
  It says nothing about handshake consent.
- **Consent signatures** (new, detached): prove agreement to the specific
  handshake terms. They are computed over canonical digests, not over HTTP
  framing, so they survive transport retries with fresh nonces.

Canonical form: UTF-8 JSON, keys sorted lexicographically by byte,
no whitespace, integers as plain numbers, byte strings as lowercase hex,
UUIDs in canonical 8-4-4-4-12 form. Digests are SHA-256 over the canonical
bytes, rendered lowercase hex. In consent preimages, `||` is byte
concatenation and digests appear as their 64 lowercase ASCII hex bytes
(raw 32-byte form is never used in preimages — one spelling only).

```
request_digest    = SHA-256(canonical(request_record_core))       // hex
acceptance_digest = SHA-256(canonical(acceptance_record_core))    // hex
```

**Canonical validation rules** (applied before any digest or signature
is computed; violation → reject, never coerce):

- Duplicate object keys: reject.
- Floats where an integer field is expected: reject (1.0 ≠ 1).
- Booleans where an integer field is expected: reject (true ≠ 1).
- Integer ranges: `protocol_version`/`request_version` = 5;
  `created_at`/`expires_at`/`accepted_at` within [1, 2^63-1] and
  `expires_at` > `created_at`; `pair_generation_at_create` /
  `pair_generation_at_accept` ≥ 0 or null (null only where the schema
  allows); `expires_in` (prepare input) within [60, relay max].
- UUIDs: version 4, canonical lowercase 8-4-4-4-12; any other form
  rejected.
- Ed25519 public keys: exactly 64 lowercase hex chars (32 bytes).
- `relay_identity_fingerprint`: `sha256:` + 16 lowercase hex chars.
- Strings: ASCII only; control characters, lone surrogates, and
  non-canonical escaping rejected. `record_type` and `scope` must match
  exactly (no case variants).
- Unknown fields in any signed core: reject.

**Request record core** (what the relay stores immutably at commit;
`requester_consent_sig` is stored alongside, not inside the digest).
`prepare_id` IS part of the signed core: consent is tied to the specific
preparation, so a signature cannot be replayed against a different
preparation of the same intent. This is the ONE request-core schema —
every response, view, and vector uses this exact object:

```
{record_type: "v5-handshake-request",
 protocol_version: 5,
 request_id: <uuid>,
 requester_pubkey: <ed25519 hex>,
 relay_identity_fingerprint: <"sha256:..." pinned relay identity>,
 target_pubkey: <ed25519 hex | null>,
 pair_generation_at_create: <int | null>,   // null only for open requests
 scope: "pairing",
 created_at: <unix int>,
 expires_at: <unix int>,
 idempotency_key: <uuid>,
 prepare_id: <uuid>}                        // the preparation this
                                            // consent was given for
```

**Create consent preimage** (signed by the requester at creation):

```
"clack-hs-v5-request-v1" || request_digest
```

The relay recomputes `request_digest` from the fields it persisted —
including the generation it read itself — and verifies the signature. The
client never supplies a hash the relay trusts; the relay hashes what it
stored.

**Acceptance record core** (frozen at accept):

```
{record_type: "v5-handshake-acceptance",
 protocol_version: 5,
 request_id: <uuid>,
 request_digest: <hex>,            // SHA-256(canonical(request core)) —
                                   // binds acceptance to EXACT request terms
 acceptance_id: <uuid>,
 acceptor_pubkey: <ed25519 hex>,
 request_version: 5,
 pair_generation_at_accept: <int>,   // read at prepare-accept, frozen
 accepted_at: <unix int>,
 prepare_id: <uuid>}
```

**Accept consent preimage** (signed by the acceptor):

```
"clack-hs-v5-accept-v1" || request_digest || acceptance_digest
```

The `request_digest` inside the acceptance core (hence inside
`acceptance_digest`) ties the acceptance to the exact immutable request —
the acceptor cannot be tricked into consenting to different terms than the
requester created. Listing it explicitly in the preimage as well keeps
each preimage self-describing.

**Confirm consent preimage** (signed by the original requester):

```
"clack-hs-v5-confirm-v1" || acceptance_digest
```

Because `acceptance_digest` now transitively covers `request_digest`,
changing the request's relay fingerprint, expiry, or requester key changes
the confirm preimage (rev-3 finding fixed and demonstrated).

The relay verifies the confirmer's signature against the requester's
enrolled public key and the `acceptance_digest` it recomputed from the
frozen acceptance record. This is the single consistent confirm shape —
there is no separate `confirm_signature` vs `Signed (envelope)` variant.

**Verification rules:** the relay MUST recompute every digest from its own
stored immutable records and verify each consent signature against the
enrolled public key of the claimed signer. No security property may depend
on an unsigned field supplied by the client and filled in by the relay
later. Unknown fields in signed bodies are rejected.

**Pair generation binding.** The relay maintains a per-pair generation
counter, bumped on every revoke. Capture rules:

- Targeted request: the relay reads the current generation for
  (requester, target) at prepare and freezes it as
  `pair_generation_at_create`. The requester's create consent signature
  covers it (via `request_digest`).
- Open request: `pair_generation_at_create` is null — the pair is unknown
  at prepare, so NO claim is made about revokes between create and accept.
  At prepare-accept the relay reads the current generation for the
  now-known pair and freezes it as `pair_generation_at_accept`. The
  acceptor's accept consent signature covers it.
- **Explicit open-request revocation rule:** a revoke between open-request
  create and accept does NOT invalidate the acceptance — the acceptor's
  fresh consent at the new generation, followed by the requester's explicit
  confirm of that acceptance (which shows the generation), IS new consent
  and may establish the handshake. A revoke between accept and confirm
  bumps the generation, so the atomic activation's comparison
  (current == `pair_generation_at_accept`) fails deterministically.
- For targeted requests, `pair_generation_at_accept` must equal
  `pair_generation_at_create`; any revoke anywhere in the flow fails the
  confirm.
- At confirm, the atomic activation transaction compares the CURRENT
  generation for the pair against the frozen value. A retry of a
  failed/terminal request reuses the frozen generation; it can never
  rebind the request to a newer generation.
```

### State model

```
REQUESTED → ACCEPTED_PENDING_CONFIRM → ACTIVE
    ↓                ↓
CANCELLED        DECLINED
    ↓                ↓
EXPIRED          EXPIRED        (absolute deadline, checked at
                                  accept AND confirm, never renewed)
ACTIVE → REVOKED               (normal handshake lifetime/revocation
                                  policy applies after activation)
```

- Terminal rows/tombstones are retained so stale retries, replays, and
  late confirms are rejected deterministically.
- A revoked/expired/declined state is NEVER transitioned back to active to
  satisfy an old retry.
- Existing active or admin-created handshake rows are NOT retroactively
  labeled v5 mutual consent without the corresponding request/acceptance/
  confirm records.

### Idempotency (not just single-use)

"Single-use" alone does not establish replay safety. The protocol is
idempotent across transport failures:

- **Create:** request-create is idempotent for the same requester + content
  (client-supplied idempotency key). A lost create response returns the
  original request_id, never a duplicate request.
- **Accept/confirm:** each HTTP attempt carries a fresh transport
  signature/nonce, but reuses the logical request/acceptance identity and
  the same consent signatures. A lost response retried by the same actor
  with the same content returns the same committed result. A different
  acceptor or altered content must not succeed.
- **Status lookup:** an owner-scoped `GET /v1/handshakes/requests/{id}`
  returns the authoritative state including terminal states, so clients
  fetch state before acting instead of inferring from notifications.
- Notifications are retriable, deduplicated hints. State is committed before
  notifying.

**Retry after terminal transitions — one rule.** An idempotent retry must
return the immutable operation outcome AND the current state, never a stale
success:

```
POST /v1/handshakes/confirm   (retry, after the handshake was revoked)
→ {outcome: "already_confirmed",
   handshake_id: "a|b|3",
   current_state: "revoked",        // NOT "active"
   current_generation: 4}
```

Returning the original success without `current_state` would advertise a
revoked handshake as active. Clients MUST consult `current_state` (or the
status lookup) before sending traffic, not the cached `outcome`.

**Idempotency key rules:**

- The unique lookup is **(authenticated requester, idempotency_key)**.
  The original normalized intent digest and the prepared record are stored
  as VALUES under that key — the digest is never the lookup key, so a
  changed digest cannot create a second index entry.
- Same key + same digest → return the original prepare/record.
- Same key + DIFFERENT digest (changed `to`, `expires_in`, scope) → `409
  conflict`. The client must use a new key for intentionally new content.
- Generated IDs, timestamps, and generations always come from the retained
  original record on retry — never freshly generated before comparison.
- A new key always permits an intentional new request (subject to quotas).
- Idempotency records are retained for the request's validity window plus
  the allowed retry horizon (default 7 days, relay-configured), then
  swept. Eviction must never silently resurrect old work: a swept key
  behaves as a new key, and any live request state is authoritative.
- Retention and per-requester pending quotas are relay-configured and
  advertised; exceeding quota returns `429` with a `retry_after` hint.

### Key properties

- **No shared secrets.** The request_id is public. Possessing it alone
  cannot enroll, accept as someone else, confirm, read private pending
  details, or send a message. (Precise claim — replaces rev 1's "leaking it
  does nothing," which overstated the case for open requests.)
- **Mutual authenticated consent.** Both sides sign with their existing
  Ed25519 identities, bound to protocol version, domain, relay identity,
  request/acceptance IDs, both full public keys, scope, and expiry. The
  relay verifies both before activating.
- **Credential-rule safe to handle.** The URL contains no Bearer <redacted>
  or pairing secret and cannot activate a handshake by possession alone.
  Real credentials remain in the signed client-to-relay exchange; request
  metadata can still be private depending on how it is shared.
- **Atomic activation.** Create, accept, and the confirm request each commit
  as separate transactions (the human-delayed flow is not one transaction).
  Only the final activation step — rechecking deadline, state, identities,
  and the frozen pair generation, then creating ACTIVE — is a single atomic
  transaction. Races with revoke/withdraw/expire have deterministic
  committed outcomes, durable across restart.

### Targeted vs. open requests

Creation is always prepare→sign→commit (see Flow). The `to` field is
supplied at **prepare** time, with an idempotency key:

```
POST /v1/handshakes/prepare-request {
  "to": "bob",           // targeted (DEFAULT): only Bob's enrolled public
                         // key can accept. Recommended for v1.
  "expires_in": 86400,
  "idempotency_key": "<uuid>"
}
// or
POST /v1/handshakes/prepare-request {
  "to": null,            // open: any enrolled peer can accept.
                         // Explicitly one-use: the first accepted claim
                         // freezes the single winner; the link cannot be
                         // re-claimed or have its acceptance mutated.
  "expires_in": 86400,
  "idempotency_key": "<uuid>"
}
```

For v1, prefer **targeted requests** and **explicitly one-use open
requests** with bounded lifetime and clear claim/decline behavior.

For a stable website contact link, do NOT reuse one open request: use a
public introduction page that creates a **separate bounded per-acceptor
request** per visitor. Never mutate one acceptance underneath an
outstanding confirm.

Public request IDs remain safe when fully known: they confer no access, and
the relay enforces per-requester / per-acceptor / per-pair pending quotas,
notification limits, and authenticated rate limits on creation, accepts,
and pending-notification storage. Public IDs remove the Bearer <redacted>;
they do not remove spam, metadata/privacy, or link-copying considerations.
Unrelated pending identities are never disclosed through a public UUID
lookup.

**Targeted preauthorization and mutual consent** (Zari, Flint): a targeted
signed preauthorization CAN preserve mutual consent — it is not inherently
a loss of it — IF it binds the exact recipient key, scope, and expiry, and
remains revocable before activation. For v1, explicit confirm for ALL
requests is simpler to audit; a signed `auto_activate_on_target_accept`
policy may be defined later, and MUST reject any change to
recipient/key/scope.

### Version negotiation (no silent downgrade)

Rev 1 contradicted itself: "highest mutually supported version" vs "never
mint v4 for a v5 client." Resolved:

- The chosen protocol version and security-relevant capabilities are part of
  the **signed request content** (or an authenticated, identity-bound
  capability record). The current clack-ed25519-v1 signature covers method,
  path/query, raw-body hash, and nonce — it does NOT cover arbitrary
  `X-Clack-Handshake-Versions` headers. Do not rely on that unsigned header
  to prevent downgrade.
- **Explicit v5 endpoints create only v5 requests** and return
  `unsupported_version` / `upgrade_required` for incompatible clients.
- v4 minting/redemption remains an **explicit legacy operation** under a
  defined transition policy — never a silent fallback from a failed v5
  operation.
- Never reinterpret a public `req` as a v4 secret `k`, and never enrich a
  public link with a secret fallback.
- v4 secret handling (`k` as credential) is preserved unchanged during the
  migration period.

### Scope: pairing already-enrolled peers, NOT onboarding

v5 pairs peers that are **already enrolled on the SAME relay**. It does not:

- grant relay membership to a new peer (a new Bob needs a separate
  authenticated enrollment flow; the API returns explicit
  `enrollment_required`),
- enable cross-relay pairing (returns `unsupported_remote_relay`; that is
  the separately reviewed federation protocol's job),
- replace v4's inline enrollment path.

Reopening a v5 link after independent enrollment is fine. Embedding
enrollment tokens or claim secrets in the link defeats the proposal.

Existing relay enrollment establishes identity **only within the
trusted-relay model** (Zari). This proposal claims no resistance to relay
key substitution or forged federation consent — those require independent
key pinning and portable peer-verifiable consent, which are out of scope
here.

### What changes

| Component | v4 | v5 |
|-----------|----|----|
| Link contents | Claim secret (`k`) + authenticated/signed mint and accept (or proof-of-possession for enrollment) | Request ID (public) |
| Shareable via chat | No (credential rules block the secret) | Yes (no secret in URL; metadata still potentially private) |
| Auth mechanism | Claim secret + Ed25519-signed mint/accept | Mutual Ed25519 signatures bound to version/domain/relay/request/acceptance/keys/scope/expiry |
| Relay verification | Checks `k` matches + signatures | Checks immutable request + frozen acceptance + both signatures in one transaction |
| Expiry | Link expiry | Absolute request deadline (24h default, relay-configured max), checked at accept AND confirm |
| Replay handling | Single-use `k` | Idempotent create/accept/confirm with durable results |

(Corrected per Flint: v4 is not possession-only — it already uses signed
mint/accept. v5 removes the *transferable pairing/enrollment capability*
from the shared URL; it does not introduce Ed25519 consent for the first
time.)

### Backwards compatibility

- v4 links continue to work during a transition period, with v4 secret
  handling unchanged.
- Clients advertise supported versions; the relay mints the version the
  client's authenticated capability record supports — explicit per-version
  endpoints, never silent fallback.
- v4 is deprecated but not removed until all known clients support v5.

### Security considerations

- **Request ID enumeration:** 128-bit UUIDs; brute force infeasible. The
  relay rate-limits accept attempts, creation, and pending-notification
  storage.
- **Impersonation:** A targeted link's observer can't accept — they lack
  the recipient's private key, and the relay checks the signer against the
  enrolled public key bound at request creation. Display names are never
  identity.
- **Open request abuse:** first-accepted claim wins immutably; per-acceptor
  and per-pair quotas bound blast radius. Relay operators can disable open
  requests per-relay.
- **No downgrade:** version is in signed content; stripped capability
  headers fail closed.
- **Malicious relay URLs:** rejected at parse time before any credentials
  move (see Origin pinning). No redirects carrying credentials.
- **Relay trust boundary:** the relay is trusted for liveness/ordering
  within the trusted-relay model. Key substitution by the relay itself, and
  cross-relay (federation) consent forgery, are explicitly out of scope
  pending independent key pinning.

### API changes

Creation and acceptance are prepare→sign→commit (P1-1). Pending
preparations are NOT consent and are never REQUESTED state.

```
POST /v1/handshakes/prepare-request
  Body: {to: <peer-name|null>, expires_in?: <seconds>,
         idempotency_key: <uuid>}
  # Idempotency: (requester, idempotency_key) already committed → return
  # the committed record. Already prepared and LIVE → return the existing
  # prepare. Prepared but EXPIRED/CAS-failed and uncommitted → same-key
  # REPLACEMENT (see "Create preparation replacement"): new prepare_id
  # and core, atomic mapping update, old preparation invalidated.
  # The normalized intent digest is compared before returning anything
  # retained: changed TTL or target → 409.
  # Targeted requests resolve `to` to the enrolled public key NOW.
  # Generation read NOW (null for open).
  Returns: {prepare_id: <uuid>,
            prepared_core: {<exact immutable unsigned request core>},
            prepare_expires_at: <unix int>}     // 5-min TTL
  # The client signs canonical(prepared_core) — every byte seen.

POST /v1/handshakes/request
  Body: {prepare_id: <uuid>,
         requester_consent_sig: <ed25519 hex>}
  # Consent preimage: "clack-hs-v5-request-v1" || request_digest,
  # where request_digest = SHA-256(canonical(STORED prepared_core)).
  # Precedence: consumed-prepare → result map is consulted BEFORE the
  # checks below (see "Commit retry precedence") — a lost success
  # response retried after prepare expiry returns the saved result.
  # For NEW commits: prepare valid/owned/unexpired/unused; target key
  # and generation re-read and compared — any change → 409, never
  # silent field alteration; signature verified against the STORED
  # core, never client-supplied bytes.
  Returns: {request_id, link, expires_at}

GET /v1/handshakes/requests/{id}/view   (invitation view, pre-accept)
  Returns the LITERAL request_core object (the exact signed schema above),
  with request state OUTSIDE it — never a partially duplicated field list:
    {request_core: {<exact v5-handshake-request core>},
     state: "requested"}                   // REQUESTED only; terminal
                                           // states give the terminal
                                           // name and nothing else
  Authorization:
    - The requester: always.
    - The targeted recipient (key matches target_pubkey): yes.
    - Any enrolled peer, for OPEN requests only: yes (eligible claimant).
    - Unrelated peers: 404 (indistinguishable from nonexistent).
    - Never exposes other pending acceptors, claimant counts, or
      unrelated request metadata.

GET /v1/handshakes/requests/{id}            (owner-scoped status)
  Returns:
    {request_core: {<exact v5-handshake-request core>},
     acceptance_core: {<exact v5-handshake-acceptance core> | null},
     state: <state>}
  The requester in ACCEPTED_PENDING_CONFIRM receives the exact frozen
  acceptance_core — the full signed input she needs to verify before
  confirming. Terminal states include the terminal name; the cores
  remain available to the owner for audit.

POST /v1/handshakes/prepare-accept
  Body: {request_id: <uuid>, idempotency_key: <uuid>}   // acceptor-supplied
  # Request must be REQUESTED and unexpired. Targeted: caller must match
  # target_pubkey (else 404). Same-actor retries with the same
  # (acceptor, request_id, idempotency_key) return the original LIVE
  # prepared core. Server reads CURRENT pair generation and
  # computes request_digest = SHA-256(canonical(request core)).
  Returns: {prepare_id: <uuid>,
            prepared_acceptance_core: {<exact unsigned acceptance core,
                                       incl. request_digest>},
            prepare_expires_at: <unix int>}

POST /v1/handshakes/accept-request
  Body: {prepare_id: <uuid>,
         acceptor_consent_sig: <ed25519 hex>}
  # Consent preimage: "clack-hs-v5-accept-v1" || request_digest ||
  #                   acceptance_digest (64-hex ASCII each).
  # Server compare-and-swap: prepare valid/owned/unexpired; request still
  # REQUESTED; deadline unpassed; generation unchanged; exactly one
  # winner (losers → deterministic already-claimed).
  Returns: {status: "pending-confirmation",
            acceptance_id, request_id, expires_at}

POST /v1/handshakes/confirm
  Body: {request_id, acceptance_id,
         confirmer_consent_sig: <ed25519 hex>}
  # Consent preimage: "clack-hs-v5-confirm-v1" || acceptance_digest.
  # Single consistent shape — no envelope variant.
  # Body {request_id} alone is rejected for open requests.
  Returns: {outcome: "active", handshake_id,
            current_state: "active", current_generation: <int>}
  # On retry after a later revoke, outcome stays "already_confirmed"
  # but current_state reports "revoked" (see Idempotency).

POST /v1/handshakes/requests/{id}/cancel    (requester, before ACTIVE)
POST /v1/handshakes/requests/{id}/decline   (acceptor, before confirm)
GET  /v1/handshakes/requests/pending
  Returns: {incoming: [...], outgoing: [...]}
```

All endpoints require existing signed authentication. Requester and
acceptor must already be enrolled peers.

### Commit retry precedence

A lost success response must not strand the client: the commit endpoints
check in this exact order, and already-committed work always wins over
preparation checks.

**Create commit** (`POST /v1/handshakes/request`, body
`{prepare_id, requester_consent_sig}`):

1. Authenticate the actor (transport signature). The actor must equal the
   enrolled key that owns `prepare_id`.
2. Look up `prepare_id` in the **consumed-prepare → result** map
   (persisted for the full retry horizon, same retention as idempotency
   records). If present AND the presented `requester_consent_sig` matches
   the stored signature for that prepare_id: return the saved result
   (`{request_id, link, expires_at}`) plus current request state —
   REGARDLESS of prepare TTL expiry. A used-then-expired preparation is
   still a committed operation.
3. If not consumed: the prepare must exist, be unexpired, be owned by the
   actor, and be unused. Then compare-and-swap (target key, generation,
   expiry) and verify the consent signature against the STORED core.
4. A different actor, or an altered signature/core for the same
   `prepare_id`, NEVER receives success — 401/409 as appropriate.

**Accept commit** (`POST /v1/handshakes/accept-request`, body
`{prepare_id, acceptor_consent_sig}`):

1. Authenticate the actor; actor must own `prepare_id`.
2. Consumed-prepare lookup first: if this exact accept already committed,
   return the saved `{status: "pending-confirmation", acceptance_id,
   request_id, expires_at}` plus current request state — even though the
   request has advanced past REQUESTED to ACCEPTED_PENDING_CONFIRM.
   The "request must be REQUESTED" check applies only to NEW commits.
3. Otherwise: prepare valid/owned/unexpired/unused; request still
   REQUESTED; deadline unpassed; generation unchanged; exactly one winner.
4. Different actor or altered signature/core → never success.

Consumed-prepare mappings persist for the full retry horizon (default 7
days, relay-configured) and are swept only after; a swept mapping behaves
as unknown, and live request state (via idempotency key or status lookup)
remains authoritative so eviction cannot resurrect old work.

**Prepare-accept retry identity:** `prepare-accept` takes
`{request_id, idempotency_key: <uuid>}` (acceptor-supplied). Same-actor
retries with the same `(acceptor, request_id, idempotency_key)` return the
original LIVE prepared core — no new `acceptance_id`/timestamps per
retry, no quota consumed twice. An expired or CAS-failed uncommitted
preparation is REPLACED: new `prepare_id`, new core bytes, requiring a
new consent signature (the old signature cannot be reused). A re-prepare
never revives a terminal request — if the request left REQUESTED, the
prepare fails. The normalized create-intent digest is defined in
"Normalized create intent" below — so identical retries with
omitted/defaulted fields are judged consistently, and any semantic
change → 409.

### Normalized create intent

`prepare-request` normalizes the client's `{to, expires_in?}` before any
retention comparison:

- `target_pubkey` = the alias-resolved enrolled public key for `to`
  (or null for open requests). Alias resolution is part of the intent:
  two different aliases resolving to the same key are the same intent.
- `ttl_normalized` = `expires_in` if supplied, else the relay default
  (86400s). The TTL — not an absolute timestamp — is part of the intent.
- `created_at_anchor` = `created_at` of the FIRST preparation under
  this (requester, idempotency_key). Retained, never recomputed.
- `normalized_intent_digest` =
  `SHA-256(canonical({target_pubkey, scope, ttl_normalized}))`.
  Absolute timestamps are excluded so that a retry issued at a different
  wall clock with the same semantic intent produces the same digest.
- `expires_at_effective` = `created_at_anchor + ttl_normalized`.
  Computed from the RETAINED initial time anchor plus the normalized
  TTL — never from retry wall clock.

Same-key retry behavior: the relay recomputes the digest from the NEW
request's normalized fields and compares it to the retained digest
BEFORE returning anything retained. A changed TTL or a changed target
(alias or resolved key) → 409 Conflict, even if a retained prepare or
record exists. Identical default-TTL retries match and return the
retained result.

### Create preparation replacement

Specified outcome for an uncommitted expired or CAS-failed create
preparation: **same-key replacement** (not a terminal error).

1. The (requester, idempotency_key) mapping still points at an
   UNCOMMITTED preparation whose TTL has expired, or whose stored
   target/generation no longer matches current state (CAS drift).
2. The relay creates a fresh preparation in ONE atomic transaction:
   new `prepare_id`, new core bytes with `created_at` = replacement
   time, `pair_generation_at_create` and target re-read from CURRENT
   state, and `expires_at` = the RETAINED `expires_at_effective`
   (created_at_anchor + ttl_normalized) — the deadline is NOT renewed
   by replacement. The key→prepare mapping is updated atomically and
   the old `prepare_id` is invalidated, so concurrent replacements
   cannot both commit: exactly one winner, the loser receives the
   winner's prepare (or a deterministic conflict).
3. The replacement requires a FRESH consent signature — the old
   signature covered different core bytes and is unusable.
4. If the retained `expires_at_effective` has already passed → 410
   Gone. A new logical request (new idempotency key, new anchor) is
   required to extend the deadline. Repeated replacement can therefore
   never silently renew a request's lifetime.
5. NEVER replace a committed operation: if (requester,
   idempotency_key) maps to a committed REQUESTED record, the record
   is returned as-is; the same-key path is idempotent success, not
   replacement.

This closes the gap where an expired-unused preparation's key kept
returning an unusable core: the same operation recovers with the same
key, a fresh signature, and the original deadline.

### Worked transcripts (machine-readable vectors)

SYNTHETIC TEST VECTORS ONLY. The keys below are derived from fixed
test seeds (`a0`*32, `b0`*32) — they are not real identities. All three
consent signatures were generated with Ed25519 and independently
verified against the exact preimage bytes shown. Recompute any digest
or signature from the literal cores to check.

**Test identities**

- Alice (requester) pubkey: `b533d8ad9fcfbdde0b481c1b334ddc3c53412fd614564e7e5afd020368d382c3`
- Bob (acceptor) pubkey: `705fbac01f5519899f437bc42e40255ae9ab54bff00de3433af7d687d9e71ad5`
- Relay identity fingerprint: `sha256:92b1401c584b74d0`

**Transcript 1 — targeted create: prepare → sign → commit.**

```
→ POST /v1/handshakes/prepare-request
  {"to": "bob", "expires_in": 86400,
   "idempotency_key": "33333333-3333-4333-8333-333333333333"}
← 200
  {"prepare_id": "22222222-2222-4222-8222-222222222222",
   "prepared_core": {"created_at":1780000000,"expires_at":1780086400,"idempotency_key":"33333333-3333-4333-8333-333333333333","pair_generation_at_create":3,"prepare_id":"22222222-2222-4222-8222-222222222222","protocol_version":5,"record_type":"v5-handshake-request","relay_identity_fingerprint":"sha256:92b1401c584b74d0","request_id":"11111111-1111-4111-8111-111111111111","requester_pubkey":"b533d8ad9fcfbdde0b481c1b334ddc3c53412fd614564e7e5afd020368d382c3","scope":"pairing","target_pubkey":"705fbac01f5519899f437bc42e40255ae9ab54bff00de3433af7d687d9e71ad5"},
   "prepare_expires_at": 1780000300}
```

`request_digest = SHA-256(canonical(prepared_core))`:

```
9dd2fb06c9bbb36ec16f32179bc8b7f6442b2376fc3678040f118769ec0c29f4
```

Create consent preimage (ASCII — domain separator concatenated with the
64 hex digest bytes):

```
clack-hs-v5-request-v19dd2fb06c9bbb36ec16f32179bc8b7f6442b2376fc3678040f118769ec0c29f4
```

Alice's Ed25519 signature over those exact bytes:

```
37713eb2175009347968d79795de1450ed3a53ce3dd1663ba758906dbbc6643c2b600ecd722ef120af661018a8cc3d016e53f41619bb6de30015af492b80240e
```

```
→ POST /v1/handshakes/request
  {"prepare_id": "22222222-2222-4222-8222-222222222222",
   "requester_consent_sig": "37713eb2175009347968d79795de1450ed3a53ce3dd1663ba758906dbbc6643c2b600ecd722ef120af661018a8cc3d016e53f41619bb6de30015af492b80240e"}
← 200 {"request_id": "11111111-1111-4111-8111-111111111111",
       "link": "https://relay.example/join#v=5&r=aHR0cHM6Ly9yZWxheS5leGFtcGxl&req=11111111-1111-4111-8111-111111111111",
       "expires_at": 1780086400}
```

Relay-side compare-and-swap at commit: prepare valid/owned/unexpired;
target key still resolves to the same enrolled key; pair generation for
(Alice, Bob) still 3; signature verifies against the STORED prepared
core. Any drift → 409, Alice re-prepares. The link uses the single
specified public format `/join#v=5&r=<base64url>&req=<uuid>` — no token
placeholder, no secret in the URL.

**Transcript 2 — accept: prepare → sign → commit, with request-digest
binding.**

Bob fetches the invitation view (`{"request_core": {...exact...},
"state": "requested"}`), verifies it matches what Alice showed him
out-of-band, then prepares (note the acceptor-supplied idempotency key):

```
→ POST /v1/handshakes/prepare-accept
  {"request_id": "11111111-1111-4111-8111-111111111111",
   "idempotency_key": "66666666-6666-4666-8666-666666666666"}
← 200
  {"prepare_id": "55555555-5555-4555-8555-555555555555",
   "prepared_acceptance_core": {"acceptance_id":"44444444-4444-4334-8444-444444444444","accepted_at":1780000100,"acceptor_pubkey":"705fbac01f5519899f437bc42e40255ae9ab54bff00de3433af7d687d9e71ad5","pair_generation_at_accept":3,"prepare_id":"55555555-5555-4555-8555-555555555555","protocol_version":5,"record_type":"v5-handshake-acceptance","request_digest":"9dd2fb06c9bbb36ec16f32179bc8b7f6442b2376fc3678040f118769ec0c29f4","request_id":"11111111-1111-4111-8111-111111111111","request_version":5},
   "prepare_expires_at": 1780000400}
```

`acceptance_digest = SHA-256(canonical(prepared_acceptance_core))`:

```
d0caa11bee4a96250356c13a8d45b9955fab5ec75908b1805ac29d8b5e6e7210
```

Accept consent preimage (ASCII):

```
clack-hs-v5-accept-v19dd2fb06c9bbb36ec16f32179bc8b7f6442b2376fc3678040f118769ec0c29f4d0caa11bee4a96250356c13a8d45b9955fab5ec75908b1805ac29d8b5e6e7210
```

Bob's Ed25519 signature over those exact bytes:

```
e60db20455c0604cd1861a67175916e3dde4844c7b59f51aaa5caad251995698e35d684912c9a1e26556540eac4f5bbf3edcfb28be84212af316641d2d43930d
```

```
→ POST /v1/handshakes/accept-request
  {"prepare_id": "55555555-5555-4555-8555-555555555555",
   "acceptor_consent_sig": "e60db20455c0604cd1861a67175916e3dde4844c7b59f51aaa5caad251995698e35d684912c9a1e26556540eac4f5bbf3edcfb28be84212af316641d2d43930d"}
← 200 {"status": "pending-confirmation",
       "acceptance_id": "44444444-4444-4334-8444-444444444444",
       "request_id": "11111111-1111-4111-8111-111111111111",
       "expires_at": 1780086400}
```

**Transcript 3 — confirm binds the request terms (P1-2 fixed).**

Alice fetches the owner status lookup and receives the exact frozen
`acceptance_core`. She signs the confirm preimage (ASCII):

```
clack-hs-v5-confirm-v1d0caa11bee4a96250356c13a8d45b9955fab5ec75908b1805ac29d8b5e6e7210
```

Her Ed25519 signature:

```
8739d5941dc38e201c731ad09b64faff049af8b9da4ff0f89ccdec1609c86932ec708479dd62f9fa2afe2e2132c2ca223b7d8149428660c57ccf02c0a860810f
```

```
→ POST /v1/handshakes/confirm
  {"request_id": "11111111-1111-4111-8111-111111111111",
   "acceptance_id": "44444444-4444-4334-8444-444444444444",
   "confirmer_consent_sig": "8739d5941dc38e201c731ad09b64faff049af8b9da4ff0f89ccdec1609c86932ec708479dd62f9fa2afe2e2132c2ca223b7d8149428660c57ccf02c0a860810f"}
← 200 {"outcome": "active",
       "handshake_id": "pair@gen3",
       "current_state": "active", "current_generation": 3}
```

Binding check: changing the request's `relay_identity_fingerprint`,
`expires_at`, or `requester_pubkey` changes `request_digest` → changes
`acceptance_digest` → changes BOTH the accept and confirm preimages.
The rev-3 gap (confirm unchanged) is closed.

**Transcript 4 — open request, revoke BEFORE accept (P2-3 rule).**

1. Alice creates an open request (`target_pubkey: null`,
   `pair_generation_at_create: null`), shares the link publicly.
2. Alice and Mallory's OLD handshake is revoked → pair generation for
   (Alice, Mallory) bumps 3 → 4.
3. Mallory opens the link and prepares accept with her own idempotency
   key. The relay reads the CURRENT generation (4) and freezes
   `pair_generation_at_accept: 4` in her prepared acceptance core.
   Same-key retries return this same live core; an expired core is
   replaced with a new `prepare_id` requiring a new signature. Mallory
   signs — fresh consent at generation 4.
4. Alice is notified: acceptor key, generation 4. She confirms
   explicitly. Activation compares current (4) == frozen (4) → ACTIVE.
   This is legitimate: both parties consented with full knowledge of the
   post-revoke generation.
5. Contrast — revoke AFTER accept: same setup, but the revoke lands after
   Mallory's acceptance is frozen at generation 3 and before Alice
   confirms. Activation compares current (4) ≠ frozen (3) → confirm FAILS
   deterministically. Alice must wait for a fresh accept at generation 4.

**Transcript 5 — lost-response commit retries (precedence order).**

1. Alice's create-commit succeeds but the response is lost. Her prepare
   is now consumed AND (5 minutes later) expired. She retries
   `POST /v1/handshakes/request` with the same prepare_id and signature.
   The relay authenticates her, finds the prepare_id in the
   consumed-prepare → result map, signature matches → returns the saved
   result plus current state. No duplicate request.
2. Same, but the handshake was revoked after activation. The retry
   returns the saved outcome AND `current_state: "revoked"`.
3. Bob's accept-commit succeeds, response lost, request now
   ACCEPTED_PENDING_CONFIRM. His retry hits the consumed-prepare map
   FIRST — before the "must be REQUESTED" check — and returns the saved
   acceptance. The phase-advanced state does not break the retry.
4. An attacker replays Alice's prepare_id and signature with a different
   transport identity → 401. With an altered signature → 409. Consumed
   prepares never grant success to a different actor.

### Migration path

1. Implement v5 endpoints on relay (additive, no breaking changes).
2. Update reference client (`clack_client`) with v5 support.
3. Authenticated capability records advertise v5; explicit v5 endpoints
   only.
4. Deprecate v4 minting (still accept v4 redemptions, secret handling
   unchanged).
5. Remove v4 after all active clients confirm v5 support.

## Open questions — resolved per kin review

- **Explicit confirm or pre-authorized activation?** Explicit confirm for
  ALL requests in v1 (simpler to audit). The acceptor's authenticated
  public key is shown before activation; never auto-confirm from a relay
  notification. Targeted preauthorization with exact key/scope/expiry
  binding remains a valid later optimization, not a v1 feature.
- **Show acceptor identity before activation?** Yes — the authenticated
  public key from the frozen acceptance record, not a display name.
- **Request expiry default?** 24h default, relay-configured bounded
  maximum. Absolute deadline returned at creation, checked at accept AND
  confirm, never silently renewed. Notification latency/retry behavior is
  visible so a late confirm fails clearly.

## Verification gate (required before release)

Isolated executable tests must demonstrate, adversarially:

1. Public `req` possession alone cannot enroll, accept as someone else,
   confirm, read private pending details, or send a message.
2. Target name reuse / key rotation and forged `by` cannot substitute
   another identity; wrong-signer accepts fail.
3. Two concurrent open accepts freeze exactly the defined winner; the
   loser's result cannot change the acceptance Alice sees or confirms.
4. Lost create/accept/confirm responses plus fresh signed retries return
   the original outcome — no duplicate requests/handshakes, no extra
   notifications.
5. Accept then expire/cancel/withdraw/revoke before confirm stays inactive;
   a delayed or re-signed stale confirm cannot resurrect the pair.
6. Activation racing revoke has a deterministic committed result, durable
   across restart; queued/polled/fetched messages follow existing
   revocation rules.
7. Downgraded/stripped capability headers, unsupported peers, missing or
   duplicate `r` fields, malicious origins, and redirects fail before any
   credentials leave the client.
8. A new unenrolled peer receives explicit `enrollment_required`, never
   hidden access from a public `req`; remote-relay peers get explicit
   `unsupported_remote_relay` until federation is defined.
9. Exact signed preimages: accept and confirm consent signatures verify
   against recomputed canonical digests; tampering with any bound field
   (domain, relay identity, keys, scope, expiry, generation) invalidates
   the signature. Transport-signature replay without the consent signature
   cannot accept or confirm.
10. Generation binding for open offers: the frozen
    `pair_generation_at_accept` is compared atomically at confirm; a
    revoke between accept and confirm (or a concurrent confirm/revoke
    across restart) fails the confirm deterministically.
11. Retry after revocation: an idempotent confirm retry returns the
    original outcome AND `current_state: "revoked"` — never a stale
    `"active"`.
12. Idempotency-key conflicts: same key + changed content → `409
    conflict`; new key + same content → new request (quotas permitting).
13. Invitation-view access: requester, targeted recipient, and eligible
    open claimants can view; unrelated peers get 404; no claimant
    enumeration.
14. Prepare/commit integrity: a client cannot sign without the prepare
    step — commit with a `prepare_id` whose stored core was altered (or a
    forged `prepare_id`) fails; revoke/expiry/key-change between prepare
    and commit yields 409 and never commits altered fields under the old
    signature. Prepare responses are quota-bounded and expire in 5 min.
15. Confirm binding (P1-2 regression): mutating the request's relay
    fingerprint, expiry, or requester key changes the confirm preimage;
    `acceptance.request_id` must equal the confirm body's request and the
    signer must equal the frozen `requester_pubkey`.
16. Open-request revocation rule (P2-3): revoke-before-accept trace
    establishes the handshake at the NEW generation with both parties'
    explicit consent; revoke-after-accept fails the confirm
    deterministically. Both cases tested separately.
17. Idempotency lookup (P2-4): same `(requester, idempotency_key)` with
    changed content → 409 without creating a second index entry; retries
    reuse the retained original record's IDs/timestamps/generation.
18. Canonical validation (P2-5): duplicate keys, floats/bools for integer
    fields, bad UUID forms, wrong key lengths, and non-ASCII are rejected
    before digest computation; fixed vectors from the worked transcripts
    verify byte-for-byte.
19. Commit retry precedence: a lost create/accept success retried after
    prepare expiry returns the saved result + current state (including
    after a later revoke/cancel); the consumed-prepare map is consulted
    before TTL/phase checks; a different actor or altered signature never
    receives success.
20. Prepare-accept retry identity: same `(acceptor, request_id,
    idempotency_key)` retries return the original live prepared core;
    expired/CAS-failed preparations are replaced with a new prepare_id
    requiring a new signature; re-prepare never revives a terminal
    request.
21. Create preparation replacement: an uncommitted expired/CAS-failed
    create preparation is replaced same-key with a new prepare_id and
    fresh signature, atomically, retaining the original absolute
    deadline (never renewed; 410 Gone if passed); committed operations
    are never replaced. Normalized intent digest uses
    `{target_pubkey, scope, ttl_normalized}`; `expires_at_effective` =
    retained `created_at_anchor + ttl_normalized`; changed TTL/target
    → 409 before any retained result is returned.
22. Machine-readable vectors: the worked transcripts' literal cores,
    preimages, and Ed25519 signatures verify independently from the
    document bytes alone; the sample link uses the declared
    `/join#v=5&r=<base64url>&req=<uuid>` format.

## Review history

- **Rev 1** (6a3f5b3d): initial proposal. Reviewed by Flint (6 items, 8-test
  gate) and Zari (5 required revisions). Direction supported by both.
- **Rev 2** (d1d4e63): integrates both reviews. Reviewed by Flint: 2 P1
  (signed API shapes vs security claims; pair-generation capture fields)
  and 2 P2 (retry-after-terminal semantics; pre-accept read path and
  transaction wording) remain, plus gate extensions.
- **Rev 3** (859ac41): exact canonical encodings, digests, and
  consent-signature preimages; transport vs consent signature distinction;
  explicit `pair_generation_at_create` / `pair_generation_at_accept`
  persisted fields with capture rules; retry responses carry both outcome
  and current terminal state; idempotency-key conflict semantics;
  invitation-view endpoint with authorization rules; per-phase commit
  wording (only activation is atomic). Reviewed by Flint: NOT ready —
  2 P1 (clients cannot construct the required signatures through the API;
  confirm does not bind request terms), 3 P2 (open-request revocation
  rule; idempotency lookup key; canonical validation + fixed vectors).
- **Rev 4** (b22a0e4): prepare→sign→commit for create and accept;
  `request_digest` in the acceptance core; explicit open-request revocation
  rule; idempotency lookup keyed by (requester, idempotency_key); exact
  canonical validation rules; worked transcripts with fixed synthetic
  vectors. Reviewed by Flint: no sign-off — 2 P1 (single request-core
  schema with prepare_id signed; commit-retry precedence over preparation
  checks), 2 P2 (prepare-accept retry identity; machine-readable vectors
  with real signatures + correct link format).
- **Rev 5** (a597974): ONE request-core schema — `prepare_id` signed and
  present in every response, view, and vector; invitation view and owner
  status lookup return literal `request_core` / `acceptance_core` objects
  with state outside; explicit commit-retry precedence (consumed-prepare
  → result map consulted before TTL/phase checks, persisted for the full
  retry horizon); prepare-accept takes an acceptor idempotency key with
  same-actor retry and replacement rules; normalized create-intent
  digest defined; worked transcripts rebuilt as machine-readable vectors
  with real Ed25519 signatures (all three independently verified by
  Flint) and the declared `/join#v=5&r=<base64url>&req=<uuid>` link
  format. Reviewed by Flint: signatures verify, all architectural
  findings closed — 2 bounded P2 corrections before design-review close.
- **Rev 6** (this document): removed the obsolete second request schema
  (exactly one request-core object now); Targeted/Open examples call
  `prepare-request` with an idempotency key; flow/API commit
  preconditions marked as NEW-commits-only with pointers to the
  authoritative retry-precedence section; specified same-key replacement
  for expired/CAS-failed CREATE preparations (atomic, fresh signature,
  original deadline retained never renewed, 410 Gone when passed,
  committed operations never replaced); explicit normalized-intent
  formula (`digest` over `{target_pubkey, scope, ttl_normalized}`,
  `expires_at_effective = created_at_anchor + ttl_normalized`,
  changed TTL/target → 409). Awaiting Flint's diff check. No
  implementation authorized.

## Status

DRAFT rev 6 — not implemented. Revised per Flint's rev-5 review (2 P2,
gate extensions). Awaiting Flint's diff check; design-review close
expected on acceptance.
