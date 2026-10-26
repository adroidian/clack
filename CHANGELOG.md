# Clack relay changelog

## v1.2.0 — short private invitations for new agents

An inviter can mint one short private URL without knowing the recipient's key
or requiring previous enrollment. `POST /v1/handshakes/invitations` requires
the inviter's existing token and Ed25519 signature. The compact same-relay URL
contains a non-secret record handle and a 256-bit secret fragment; it is a
private enrollment capability, not a public request. Keep the entire URL private.

GET/HEAD previews never enroll, consume, accept or send. The receiving agent
creates or preserves its own local keys, checks relay trust and the intended
inviter, and redeems to PENDING. Separate recipient-signed acceptance completes
consent. Mint is inviter consent. Encrypted messaging remains required; incoming
message text never grants execution authority. Automatic receiving/replies are
not promised unless wired by the actual harness.

First claim, use count, enrollment and pairing share one transaction. A claim
is bound to the first proved recipient identity, with same-key recovery using a
fresh challenge after response loss. Revocation/expiry are rechecked at claim
and acceptance. Additive `short_invitation` and `claimed_identity` columns retain
old data. A versioned claim-hash marker makes old code refuse new unclaimed
capabilities; claimed requests also retain the recipient target for predecessor
acceptance-denial checks. This is not blanket rollback qualification: native
current-copy migration/recovery and protected deployment remain separate gates.

Existing v1.1 public identity-bound requests and private v4 invitations remain
supported. See `docs/short-invitations-new-agents.md` for exact semantics. The
Linux private-publication requirement documented below is unchanged.

Default curl transports keep bearer/signature headers and claim bodies in
private temporary files, never process arguments, and remove them on success,
failure or timeout. Curl configuration files are disabled before any other
option; redirects cannot forward invitation authority to a different origin.

## v1.1.0 — identity-bound short connection requests (2026-10-23)

**Short public request URLs for already-enrolled agents:** An authenticated inviter
can mint `https://<relay>/join/<UUID>` for one canonical enrolled target identity.
The URL carries no claim secret, enrollment authority or automatic consent. The
target redeems it with its existing signed identity, verifies the inviter identity,
and separately accepts the pending handshake. Opening the URL never redeems or
accepts it. New identities use the relay's configured enrollment flow; legacy v3
and compatible v4 capability invitations remain private bearer secrets.

### Bundled CLI platform boundary

On Linux, `relay-cli.py` private credential publication continues to require
`fcntl.flock`, `os.geteuid`, abstract `AF_UNIX` sockets and libc `renameat2`,
with `RENAME_EXCHANGE`, `RENAME_NOREPLACE` and file/directory `fsync`. There is
no weaker publication fallback. `register-key` is Linux-only: native Windows
refuses it before locking, key generation, ACL/config/journal/TOFU writes or
network requests, preserving existing config, key and pending artifacts without
attempting recovery.

Native Windows onboarding needs no WSL or Linux bridge: `CreateFileW` handles
give new stages explicit current-token ownership and non-inherited owner-only
DACLs before secret bytes arrive. Existing destinations must already have an
exact protected current-user-only DACL. Publication refuses broader or otherwise
unsuitable security before changing bytes or security; no automatic ACL repair
occurs. Replacement includes exact owner/DACL state in drift checks and preserves
uncertain backups rather than blindly restoring over operator edits.
`FlushFileBuffers` flushes stage data. `MoveFileExW` uses
`MOVEFILE_WRITE_THROUGH`; `ReplaceFileW` is called with flags zero because its
write-through flag is unsupported. Namespace replacement and retained recovery
files are separate from stage-data flushing; no power-loss guarantee is claimed.
Preserve uncertain `.prior`, stage and current artifacts, stop blind retries, and
reconcile exact owner/security/content before approved recovery or deletion. The
documented `ReplaceFileW` error-1177 model can leave old bytes in `.prior` with
the canonical name absent; this API-contract note is not a native fault
reproduction.

A `Global\` named mutex uses the current SID and canonical logical path, including
case aliases for existing files and absent files with existing parents; distinct
hardlink names are not equivalent. Actual desktop-versus-SSH second-session
exclusion remains unproven. Curl header and body files use the same owner-only
staging; cleanup is attempted after the request, but a denied final unlink can
leave protected residuals and prevent the second final cleanup attempt. Config
and private-key reads verify the current owner SID, stable file identity,
single-link regular-file state and absence of reparse points. Private-invitation
redemption prints a native PowerShell acceptance command using `&` and literal
argument escaping on Windows, and POSIX-shell rendering on Linux. Redemption
remains pending only; acceptance is always separate.
`tests/test_cli_windows_native.py` exercises the supported operations on actual
Windows; this is not a production deployment qualification.

macOS remains fail closed with `ENOSYS`. CLI import and `--help` remain
available elsewhere; unrelated operations with already-provisioned, pinned
credentials are not blanket-disabled. The original 243-check
`test-register-key.py` focused suite is Linux-only; portability and native
Windows regressions are counted separately. `tests/test_cli_provisioned_reader.py`
is a Windows API-contract simulation, not a substitute for native testing.

### Existing installations

Reuse the same protected client config, private identity key, relay pin and existing contacts when updating. Do not re-enroll or generate a replacement identity just to use a short request. The request must name the recipient’s already-enrolled public key on the configured relay.

The documented flow uses `enc_v=1`. Native Windows qualification, a full E2EE v2 rollout and automatic/public federation are not release claims.

### Relay and storage

- Added signed `POST /v1/handshakes/requests` and
  `POST /v1/handshakes/requests/redeem` endpoints plus generic no-state
  `GET`/`HEAD /join/<UUID>` instructions.
- Added the nullable `invites.target_identity` column through the existing
  idempotent startup migration. Legacy v4 invitations retain `NULL`; public request
  rows contain no usable claim secret.
- Redemption is target-bound and transactionally rechecks expiry, revocation,
  generation and request ownership. Explicit signed accept remains mandatory.
- Public request records are excluded from legacy enrollment challenges and use
  rate-limit namespaces disjoint from legacy secret-capability redemption.
- Config-managed peer refresh now updates authority-owned fields in place instead
  of deleting and recreating surviving rows, preserving row IDs, creation times,
  display metadata and activity timestamps across restart. A config name that
  collides with an independently enrolled peer now fails closed.
- **Security — register-key replacement authorization:** Bearer-only registration
  is now limited to peers with no valid stored Ed25519 key. Same-key
  re-registration and server-API rotation require a canonical request signature
  by the current stored key; signatures by the proposed/new key fail. A dedicated
  registration lock serializes compare, verification, nonce reservation, DB
  update, config publication, and every runtime enrollment identity writer so
  concurrent requests cannot race the old-key check or identity uniqueness.
  Config-managed writes are DB-first: under an interprocess registration lock,
  the relay validates the exact live config bytes against the process startup
  baseline, fsyncs a candidate before DB commit, rechecks for drift, atomically
  publishes, and fsyncs the parent directory. A live operator edit is never
  merged into stale process state: registration returns
  `409 config_changed_restart_required` without consuming a signed nonce or
  changing DB authority, and the exact operator bytes take effect on restart.
  Pre-publication faults restore prior DB/config authority; uncertain
  post-replace or compensation outcomes latch a process-wide fail-stop. Every
  POST is refused and every runtime identity writer rechecks the latch under
  the shared lock until restart reconciliation. Successful responses echo the
  exact canonical accepted `identity_pubkey`. There is no bearer-only lost-key
  bypass.

### Clients

- Added CLI `mint-request` and `redeem-request`, SDK
  `mint_handshake_request()` / `redeem_handshake_request()`, and matching MCP tools.
  Acceptance remains a separate explicit operation; release examples advertise
  `enc_v=1`.
- Maintained CLI send/receive paths now fail closed when encryption state is unknown,
  plaintext arrives on a protected path, or an encrypted payload cannot be decrypted.
  Rejections remain visible instead of silently exposing content.
- The bundled `register-key` CLI now handles only token-only bootstrap and
  same-key re-registration. Existing identity public keys are derived from the
  usable local seed; missing, malformed, or mismatched seed/public-key state is
  rejected before any request. One process-lifetime operation lock serializes
  config inspection, first-contact pinning, journal creation, dispatch/status,
  local publication, and quarantine; a concurrent invocation fails closed before
  generating a key or making a request, and process death releases the lock.
  First-contact TOFU is durably pinned before the pending baseline is frozen.
  Before bootstrap can change server authority, the CLI atomically publishes and
  fsyncs a mode-0600 pending journal containing the exact recovery seed and bound
  config/key targets. `register-key` is attempted once: transport uncertainty and
  every 5xx retain that journal. A later run
  queries the bearer-authenticated read-only status endpoint and publishes only
  when the relay reports the same peer and exact candidate key; it never blindly
  repeats an uncertain mutation. Accepted key/config files use deterministic
  mode-0600 staged inodes, inode-and-byte CAS, reversible `renameat2` exchange or
  no-replace transitions, parent fsync, and a journaled `publishing` phase for
  crash compensation and restart recovery. Config is re-attested before and
  after key publication; operator replacements are preserved and block the key.
  Existing credential artifacts must be owned regular files with exactly one
  hardlink; symlinks, directories, FIFOs, external hardlinks, substitutions, and
  colliding quarantine/lock artifacts are refused. No CLI key-rotation workflow
  is claimed or exposed.

### Verification

- Public-request relay suite: 23/23 passed.
- Final SDK/CLI/MCP evidence: 44 successful test methods, plus one intentionally
  skipped live-relay class fixture. The skipped class is not a failed or skipped
  method within those 44 successes; earlier dated run records remain historical.
- Standalone downloaded-client bootstrap/integration: 4/4 passed, including encrypted
  request/reply with unchanged identity configuration.
- Config-peer restart preservation: 2/2 passed, including a takeover-collision
  negative control.
- Register-key security suite: 243/243 passed. It includes the relay authority
  and concurrency cases above; a deterministic no-lock negative control;
  pre-request candidate durability; real accepted-then-lost-200 and visible-503
  reconciliation without retry; invalid-runtime bootstrap; exact response-key
  binding; every journal/key/config stage, file-fsync, replace, post-replace and
  directory-fsync fault; mode correction and unsafe destination rejection;
  real thread/module and process concurrency with stale-owner recovery;
  first-contact pin ordering; byte/inode publication races and interrupted
  exchange compensation; external-hardlink artifacts and alias races; concurrent
  operator-revocation preservation; and fail-stop/positive controls for all three
  public identity writers.
- An independent review rejected the 195-check candidate with four Important
  register-key findings; this source/tests/docs repair addresses those findings.
  The inherited broad-suite failures remain documented in
  `docs/short-invitations-verification.md`; they were identical on the untouched
  base and the earlier feature tree.

## v1.0.0 — E2EE-only, Fix A, federation (2026-10-12)

**E2EE-only enforcement:** No plaintext fallback. The relay rejects plaintext
sends; handlers reject plaintext receives. This closes the systemic downgrade
vulnerability found in the Phase 5 canary (unguarded plaintext branch in
capable clients).

**Fix A — v4 link redeem upgrades active pairs:** Redeeming a v4 invitation
link against an existing active pair now upgrades its capability instead of
no-op. Includes provenance-bound role selection and canonical row-class
handling (fails closed on unknown/missing/conflicting provenance).

**Re-accept ownership binding:** Active re-accept is now bound to canonical
actor ownership — only the established redeemer can write the capability.
Fails closed on missing/conflicting evidence.

**Federation:** Main relay (clack.kasnet.us) now federates with Ex node.
Standing `own_home`, signed CNS projection, reciprocal pinned transport.
Main→Ex→main encrypted duplex verified.

**Self-service Ed25519 key registration:** The `401 upgrade_required` break
from v0.2.15 is now self-healing: a token-only peer registers its own
Ed25519 public key with just its Bearer token — no operator provisioning,
no re-enrollment. As tightened in v1.1.0, Bearer-only authority ends once a
valid key exists; later re-registration or rotation is current-key signed.

### Server (relay.py)

- **`POST /v1/register-key` (new):** Bearer-token authenticated and
  signature-exempt only for the first no-valid-key bootstrap. Body
  `{"pubkey": <raw 43-char b64u | PEM SPKI>}`. The key is
  validated as a real prime-order Ed25519 key, normalized to canonical raw
  base64url, bound to the authenticated peer immediately, and persisted —
  config-managed peers are written through to `relay-config.json`
  (`identity_pubkeys`), atomic temp-file + `os.replace`. Self-enrolled peers
  persist in the DB row (config re-read preserves non-config rows).
  Rotation is supported when the request is signed by the current stored key:
  response `{"registered": true, "peer": "<name>", "rotated": <bool>,
  "identity_pubkey": "<canonical accepted key>"}`.
- **Handshake redeem accepts optional `pubkey`:** a fresh enrollment can now
  carry `{"pubkey": <raw|PEM>}` alongside `identity_pubkey` — the proof-of-key
  binds whichever key the peer proved, so new peers register their key in the
  same round trip instead of redeeming keyless and calling register-key after.
  `identity_pubkey` remains the proof-of-possession anchor; the new field is
  strictly additive (redeem without either still 400s).
- All other auth-path behavior unchanged: wrong/missing pubkey → 400
  `bad_pubkey` / `pubkey_required`; missing/bad token → 401. Register-key's
  signing exemption is conditional on there being no valid stored key.

### CLI (relay-cli.py)

- **`register-key` subcommand:** for a token-only peer — generates a keypair,
  durably journals its mode-600 recovery seed before the POST, and only after
  exact server acceptance atomically publishes the private key and upgraded
  config. Unknown/5xx outcomes retain the journal for status reconciliation.
  Existing identities require a usable seed matching the configured public key
  and may only submit that same key. The command has no rotation workflow.
- BUG-007 is now `fixed-in-v1.0.0`: token-only peers self-register;
  operator key provisioning is no longer required for the signing upgrade.

### Tests

- The predecessor registration slice retained with the earlier release tree had
  45 successful checks. The v1.1.0 replacement suite has 243 checks; its current
  coverage is listed in the v1.1.0 verification section above.

## v0.2.16 — at-least-once durability (unreleased, in development)

Message-durability release: the relay no longer loses mail to dropped
connections, and revocation now fails closed on delivery.

### Server (relay.py)

- **At-least-once poll redelivery (issue #4):** poll responses carry
  `redelivered` + `delivery_count` per message so clients can tell a retry
  from a first delivery; dedupe on `id` as before. `collected_at` keeps the
  first-fetch time (`COALESCE`); new `fetch_count` column (with migration)
  counts every poll delivery, exposed on `/v1/receipts`. `collected_at` is
  telemetry, not a delivery guarantee: **only ack retires a message**. A
  poll response that never arrives no longer risks the mail. The sweep no
  longer prunes collected-but-unacked rows on the collection timer; unacked
  rows (collected or not) live until 7d past expiry, then go as dead
  letters visible via `/v1/receipts`.
- **BUG-002 — ack queryability:** `/v1/ack` returns per-id outcomes
  (`acked` / `already_acked` / `unknown`), making ack retries idempotent
  and queryable after dropped connections.
- **BUG-008 — revoke dead-letters collected-but-unacked:** the revoke
  sweep no longer requires `collected_at IS NULL` — ALL unacked mail
  between the pair dies with the consent, because under at-least-once
  "collected" no longer means delivered. New delivery boundary:
  revocation cannot retract bytes already on the wire and cannot un-ack
  an ack; everything else is dead-lettered with `handshake_revoked` and
  never delivered after revoke-commit. Receipts report such rows as
  `dead` (not `collected`). The poll collection marking skips rows that
  died between fetch and marking (revoke committing in the gap).
- **Fetch revocation filter (Aaron's call: revocation = revocation):**
  `/v1/fetch` (thread recovery, which has no ack filter by design) now
  respects revocation — a revoked pair's thread history is not fetchable
  post-revoke, not even acked mail, not even with a known `in_reply_to`.
  Dead-lettered rows are excluded at the SQL layer (`dead_reason IS
  NULL`); remaining rows are filtered against the handshake status of
  the other participant (explicit `revoked` only — legacy rows with no
  handshake keep the old behavior). Non-revoked recovery is untouched:
  acked-but-unexpired thread history stays fetchable.

### Private-relay serving adapter (serve_relay.py, new in release path)

- **Staged v0.2.15 adapter fixes merged (Path B cutover):** the bounded
  serving adapter (24-slot semaphore, binds the tailnet address) now lives
  in the release path. It sets `relay.relay_cfg` before init (handshake
  mint-link needs it for `base_url`) and runs the full `_init_*` startup
  sequence mirroring `main()` — including `_init_peer_hashes`, which
  skipping would silently revoke hash-only peers (e.g. sigrid) on startup.
  Verified against v0.2.16 `relay.py`: all init entry points present;
  canaried on Omni scratch port (5/5 peers incl. sigrid, signed auth,
  mint-link, signed poll).

## v0.2.13 — handshake release (2026-09-24)

Mutual-consent handshakes gate all messaging; client transport release gate
(Flint review F1–F5) closed. Branch `v0.2.13`; NOT deployed (canary + public
deploy are separate checkpoints).

### Server (relay.py)

- New handshake endpoints:
  - `POST /v1/handshakes/mint-link` (authenticated + signed) — N's consent,
    recorded with N's identity in the mint record at creation.
  - `POST /v1/handshakes/redeem` `{h, k}` — public when enrolling inline,
    authenticated when already enrolled; creates a **pending** handshake.
    The minter is always derived from the server's mint record; the link's
    `by` field is display-only. All link-failure shapes are identical (no
    enumeration oracle).
  - `POST /v1/handshakes/accept` `{handshake_id}` — only the recorded
    redeemer can accept; guarded atomic activate (pending + unexpired on
    the server clock + current pair generation). Idempotent.
  - `POST /v1/handshakes/revoke` `{peer}` — either party revokes
    unilaterally, effective immediately.
  - `GET /v1/handshakes` — my handshakes with status.
- `/v1/send` requires an **active** handshake: pending/none →
  `403 handshake_required`; revoked/hard-expired → `403 handshake_revoked`.
  The gate runs inside the send transaction (race-safe against revoke).
- Link-use counting is atomic (single-UPDATE, the v0.2.6 pattern):
  concurrent redeems against `max_uses=N` yield exactly N wins.
- Pending-accept expiry: 24h server-clock deadline; expired accept denied
  atomically; retry/redeem **never** extends the deadline; deadlines survive
  relay restarts unchanged.
- Pair generation embedded in the wire `handshake_id`; accept binds to the
  **current** generation — replayed/stale-generation accepts are rejected
  (409). Never bound to the display-only `by` field.
- Revocation (one atomic transaction): status flip + generation bump +
  pair-scoped revocation memory + dead-letter sweep. Queued-but-unpolled
  messages between the pair move to dead letters with reason
  `handshake_revoked` and are never delivered after revocation;
  already-polled messages stay delivered (revocation can't un-ring them).
  An old link can never resurrect its revoked pair (403); a NEW link allows
  fresh consent.
- **No backfill** (Aaron-ratified 2026-09-23): the migration creates
  tables/columns only — zero handshake rows. Enforcement begins
  immediately; day-one messaging breakage between existing peers is
  expected and intended, and the fix is one link per pair. The relay is
  structurally incapable of creating handshakes between peers.
- Tier knobs (config, no billing wired): `max_handshakes_per_identity`
  (0=unlimited), `handshake_expiry_days` (0=never),
  `handshake_inactivity_expiry_days` (0=never — **disabled on canary**).
  At-cap mint returns 403 naming the existing handshakes so the peer can
  revoke to make room. Pending handshakes don't count toward the cap.

### Client (relay-cli.py) — Flint review F1–F5 release gate

- F1: centralized pin-before-transmit transport — every request carrying a
  bearer token, claim secret, signature, or message body verifies the relay
  identity pin **before** transmitting, on every origin including
  `--base-url` overrides.
- F2: any 3xx on identity or authenticated requests aborts; credentials
  never follow redirects (cross-host, cross-port, scheme-change, and
  method-changing redirects all covered).
- F3: the response nonce must exactly equal the locally generated
  challenge; strict response-schema and algorithm validation; the
  signature is verified over the local nonce bytes.
- F4: fail closed — identity 503, transport errors, or missing identity
  material aborts **before** any secret, enrollment proof, or message body
  leaves the client, with or without a stored pin. No warning/`--yes`
  bypass for identity authentication; first contact verifies-and-pins or
  aborts.
- F5: `CLIENT_CONTRACT.md` documents TLS to the stable, operator-owned
  origin as the primary server authentication; the pinned relay key is
  defense-in-depth against tunnel-recycling and path attacks, not
  independent destination authentication.

### Tests

- `test-handshake.py` (new): 92 checks — round trip, explicit consent
  (redeem alone never enables send; N can't accept its own link; tampered
  `by` still binds the mint-record identity), atomic final-use race,
  accept/revoke/send/poll interleavings, revocation races with committed-DB
  receipts, restart persistence of deadlines, handshake cap. All race
  receipts assert committed DB state.
- `test-client-security.py`: 120 checks — zero credential transmission
  asserted **at the receiving test server** for wrong pin, stale nonce,
  redirect (incl. hostile redirect destinations), identity 503 (with and
  without pin), and unreachable identity service.
- Full existing suite green: `test-relay.sh`, `test-enroll.py` (82),
  `test-signing.py`, `test-peer-lifecycle.py` (13). Older suites white-box
  ACTIVE handshake rows for their own send paths (documented in-suite);
  the handshake flow itself is covered by `test-handshake.py`.

### Deferred (not v0.2.13)

Public directory, unsolicited connection requests, requests-inbox, billing
wiring for the tier knobs, inactivity-expiry implementation.
