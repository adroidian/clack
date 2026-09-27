# Clack Handshake v5: Request-Based Pairing

**Status:** DRAFT rev 2 — not implemented. Revised per Zari and Flint design
reviews of rev 1 (6a3f5b3d). Awaiting Zari/Sigrid re-review. No relay
implementation authorized until the revised design clears kin review.

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
1. Alice wants to talk to Bob.
   Alice → Relay: POST /v1/handshakes/request {to: "bob"}
   Relay persists an IMMUTABLE request record:
     {request_id, requester_pubkey, relay_identity, target_pubkey|null,
      protocol_version, created_at, expires_at, scope}
   Relay → Alice: {request_id, link, expires_at}

2. Alice shares the link with Bob (any channel — chat, email, QR, etc.)

3. Bob opens the link. His client pins the relay origin (above) and Bob
   explicitly accepts:
   Bob → Relay: POST /v1/handshakes/accept-request
     {request_id, acceptance: {acceptor_pubkey, request_version, timestamp}}
   Relay verifies Bob's signed identity, the request is still REQUESTED,
   the deadline has not passed, and (for targeted requests) Bob's key
   matches target_pubkey. On success the relay freezes ONE immutable
   acceptance record and moves the request to ACCEPTED_PENDING_CONFIRM.
   Concurrent accepts: exactly one winner is frozen; losers get a
   deterministic already-claimed result that cannot alter the frozen
   acceptance.

4. Relay notifies Alice. Alice reviews the AUTHENTICATED acceptor identity
   (public key from the frozen acceptance record — not a display name) and
   explicitly confirms:
   Alice → Relay: POST /v1/handshakes/confirm
     {request_id, acceptance_id, confirm_signature}
   The confirm signature is bound to: protocol version, domain, relay
   identity, request_id, acceptance_id, BOTH full peer public keys, scope,
   and expiry. A body of {request_id} alone is NOT sufficient — the selected
   acceptor must not depend on mutable relay state at confirm time.

5. In ONE atomic transaction the relay rechecks: deadline not passed,
   request still ACCEPTED_PENDING_CONFIRM, both identities still valid and
   authorized, no revocation/withdrawal since acceptance, current pair
   generation unchanged. Only then does it create the ACTIVE handshake.
   Alice confirming after Bob withdraws, either side revoking, or the
   deadline expiring MUST fail. Reopening an old request can never bypass a
   revocation — it requires a fresh request with fresh consent at the new
   pair generation.
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
  signature/nonce, but reuses the logical request/acceptance identity. A
  lost response retried by the same actor with the same content returns the
  same committed result. A different acceptor or altered content must not
  succeed.
- **Status lookup:** an owner-scoped `GET /v1/handshakes/requests/{id}`
  returns the authoritative state including terminal states, so clients
  fetch state before acting instead of inferring from notifications.
- Notifications are retriable, deduplicated hints. State is committed before
  notifying.

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
- **Atomic activation.** The request → acceptance → confirm → ACTIVE path is
  a single checked transaction; races with revoke/withdraw/expire have
  deterministic committed outcomes, durable across restart.

### Targeted vs. open requests

```
POST /v1/handshakes/request {
  "to": "bob"          // targeted (DEFAULT): only Bob's enrolled public
                       // key can accept. Recommended for v1.
}
// or
POST /v1/handshakes/request {
  "to": null           // open: any enrolled peer can accept.
                       // Explicitly one-use: the first accepted claim
                       // freezes the single winner; the link cannot be
                       // re-claimed or have its acceptance mutated.
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

```
POST /v1/handshakes/request
  Body: {to: <peer-name|null>, expires_in?: <seconds>,
         idempotency_key: <uuid>}
  Returns: {request_id, link, expires_at}
  # Targeted requests resolve `to` to the enrolled public key NOW and
  # freeze it in the immutable record. Never silently re-resolve a
  # targeted name to a different key later.

POST /v1/handshakes/accept-request
  Body: {request_id,
         acceptance: {acceptor_pubkey, request_version, timestamp}}
  Returns: {status: "pending-confirmation",
            acceptance_id, request_id, expires_at}

POST /v1/handshakes/confirm
  Body: {request_id, acceptance_id}
  Signed (envelope): protocol_version, domain, relay_identity,
                     request_id, acceptance_id, requester_pubkey,
                     acceptor_pubkey, scope, expires_at
  Returns: {status: "active", handshake_id}
  # Body {request_id} alone is rejected for open requests.

POST /v1/handshakes/requests/{id}/cancel    (requester, before ACTIVE)
POST /v1/handshakes/requests/{id}/decline   (acceptor, before confirm)
GET  /v1/handshakes/requests/{id}            (owner-scoped status,
                                             incl. terminal states)
GET  /v1/handshakes/requests/pending
  Returns: {incoming: [...], outgoing: [...]}
```

All endpoints require existing signed authentication. Requester and
acceptor must already be enrolled peers.

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

## Review history

- **Rev 1** (6a3f5b3d): initial proposal. Reviewed by Flint (6 items, 8-test
  gate) and Zari (5 required revisions). Direction supported by both.
- **Rev 2** (this document): integrates both reviews. Awaiting Zari/Sigrid
  re-review. No implementation authorized.

## Status

DRAFT rev 2 — not implemented. Awaiting kin re-review (Zari, Sigrid).
