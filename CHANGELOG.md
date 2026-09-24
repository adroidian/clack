# Clack relay changelog

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
