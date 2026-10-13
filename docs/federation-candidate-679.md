# Federation candidate 679 — Python Clack source-bound private candidate

Branch: `nugget/candidate-679-py-federation-v1` (private, unmerged, undeployed).
Base: maintained Python Clack `10ffd1f` (tree `428ec22f3`), all Round 1-3
health/schema/sweeper fixes intact. No activation, no deploy, no public surface.

## What this candidate adds

**Byte-verified ports from custody** (SHA256-matched to the custody trees):
- `federation_adapter.py`, `federation_authority.py` — the v1-only
  operational federation adapter + grant authority (tree 171f96). The
  adapter's `v1-only adapter requires enc_v=1` check is kept: it is the
  negative control for enc_v=2 work.
- `clack-client/clack_client/e2ee.py` — v1+v2 envelope crypto (tree 171f96).
- `tests/fixtures/e2ee.py`, `tests/test_e2ee_v2.py`,
  `tests/test_federation_e2ee_composition.py`,
  `tests/test_federation_lifecycle_685.py`,
  `tests/test_federation_operational.py`,
  `tests/test_native_envelope_positive.py`,
  `tests/test_relay_e2ee_v2_policy.py` — reference tests.
- `docs/e2ee-v2-protocol.md`, `docs/federation-native-e2ee-successor.md`,
  `docs/federation-operational-adapter.md`,
  `docs/federation-operational-config.json.example`,
  `docs/native-envelope-candidate-679.md` — reference docs.

**Engineered merge:**
- `clack-client/clack_client/envelope.py` — 171f96 v1+v2 `native_payload`
  plus `validate_message_context` (canonical topic/reply) from 3998354.
  Diff against 171f96 is only the documented addition.

**Engineered production extensions (new code, marked):**
- `relay.py` `/v1/send` — accepts v2 envelopes. The v1 validation path is
  byte-identical behavior; a v2 envelope is accepted only through
  `native_payload(enc, 2)` (exact-int version 2, exact field set/algorithm,
  shape, size). The stored `enc_v` marker is DERIVED from the validated
  envelope — there is no client-supplied `enc_v` field on `/v1/send`.
  `_is_strict_enc_v` still admits only `{0,1}` for handshake
  advertisement (`minter_enc_v`/`redeemer_enc_v`) and handshake reads:
  that gate is not downgraded.
- `clack-client/clack_client/client.py` `send()` — keyword-only
  `enc`/`enc_v`/`required_enc_v`; v2 context binding (sender/recipient/
  id/topic/reply copied from the signed ctx, mismatches refused before
  transport); hostile-subclass rejection on wire-bound fields.
- `federation_cns.py` — signed-static CNS route snapshot loader per
  `route-snapshot-contract-v1.json`: strict parse, canonicalization,
  Ed25519 verification against a separately pinned key, freshness,
  sequence/generation monotonicity, atomic projection to
  `relay_e2ee_v2_contexts`. KNS stays OFF: no socket code exists in the
  module; an optional already-parsed hint is compared against CNS bytes
  only and can never create authority.
- `federation_e2ee_v2.py` — `AdapterV2`: carries enc_v=2 end to end,
  refuses plaintext and v1 downgrade on send/receive/reconcile.

## Layering decision (deliberate)

The relay stays transport-only: it shape-validates v2 envelopes and stores
`enc_v=2`, but performs no CNS-context authorization. CNS route authority,
key-ID binding (`check_envelope_against_route`), and grant/handshake
fencing live in `federation_cns.py` + the adapter/authority layer. This is
the smallest production extension that makes real enc_v=2 operational
without importing the superseded 171f96 relay schema.

## Operational gates

- **Duplex**: `AdapterV2.send` (enc_v=2) → relay `/v1/send` → `receive`
  accepts enc_v=2 → owner-side `decrypt_envelope_v2`. Exercised in
  `tests/test_candidate_679_enc_v2_policy.py` against a disposable relay.
- **Restart**: `Adapter.snapshot(name)` writes an integrity-checked copy of
  the authority+transport DB; restart = new `Adapter`/`AdapterV2` against
  the same state dir (config digest binding rejects a changed config
  without explicit migration). Relay restart = process restart against the
  existing `relay.db` (schema migrates forward; `enc_v` column already
  exists). Exercised: snapshot integrity + re-instantiation in the gate tests.
- **Reconcile**: `Adapter.reconcile()` / `AdapterV2.reconcile()` resume
  `inflight`/`failed-unknown`/`retry` reservations by stable ID; same-ID
  replays return the original outcome without duplicating wire bytes.
  Exercised in the gate tests (failed-unknown → retry → sent, idempotent
  re-send).
- **Recovery**: relay DB is SQLite with WAL; adapter state DB likewise.
  `snapshot()` + `PRAGMA integrity_check` before any risky operation.
  Receive persists the inbox row BEFORE acking the relay, so ack-loss
  retries reconcile instead of duplicating.
- **Rollback (lossless)**: the candidate is a pure branch addition — base
  `10ffd1f` is untouched on `python-main`. Rollback = stay on / return to
  `10ffd1f`; no schema change was made to the relay DB (the `enc_v`
  column predates the candidate); adapter state DBs are per-deployment
  and never migrated by the candidate. CNS snapshot state is monotonic
  and content-addressed (sequence + digest), so rolling back the loader
  cannot silently rewind authority.

## Strictness receipts (no downgrade)

- `native_payload(enc, 2)`: `type(enc_v) is not int` rejects `True`/`1.0`/
  `"2"`; version must equal 2 exactly; unknown versions rejected.
- Relay `/v1/send`: `v=True`, `v=1.0`, `v="2"`, `v=3` envelopes → 400
  `bad_envelope`. A body `enc_v` marker is ignored (derived from envelope).
- Handshake `minter_enc_v`/`redeemer_enc_v`: `2`, `True`, `1.0` → 400
  `bad_enc_v` (`_is_strict_enc_v` unchanged).
- `AdapterV2`: plaintext send → `ValueError`; `enc_v=1` → `ValueError`;
  non-2 durable payloads in reconcile → `ValueError`; non-2 relay
  messages skipped on receive.
- Base v1-only `Adapter`: enc_v=2 send → `ValueError("v1-only adapter
  requires enc_v=1")` — the negative control.
