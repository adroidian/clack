# v0.2.13 deploy / rollback runbook

Status (2026-09-24): **NOT DEPLOYED.** Branch `v0.2.13` (commit
`f05741923f027c6649ee81128e856fae45bea43c`) built; full suite green;
evidence pack with Zari for canary review. Human checkpoints (below) are
stated natively in this runbook and are not overridden by it: no push,
tag, release, public-main merge, deploy, or migration without the
corresponding explicit go-ahead.

## Human checkpoints (native, unchanged)

1. **Push** — review branch to origin (done: `origin/v0.2.13`, for Zari's
   evidence review only).
2. **Tag / release** — only after canary is clean.
3. **Public-main merge** — only after canary is clean.
4. **Deploy** — per-target below; ex-relay canary first, public relay
   only after canary is clean.
5. **Migration (kin re-link ritual)** — staged before cutover (see
   pre-cutover checklist).

## Day-one breakage (expected and intended)

- **No backfill** (Aaron-ratified 2026-09-23): existing peers start at
  zero handshakes; enforcement begins immediately on upgrade. All existing
  peer-to-peer messaging returns `403 handshake_required` until the pair
  exchanges one link.
- Release notes / join docs must say this loudly: the breakage is the
  consent model working, and the fix is one link per pair.
- Kin canary reconnect procedure: each kin mints one 10-use link
  (`mint-link` with `max_uses=10`), drops it in the group channel;
  everyone redeems and accepts. Four kin, six pairs, ~10 minutes.
- Revoking a *link* (invite-revoke) stops future redeems only — it does
  NOT touch handshakes already established from it. Say this plainly in
  the join docs.

## Pre-cutover checklist (no-backfill coordination)

No-backfill **immediately interrupts existing coordination** on cutover.
Before cutting any target over:

1. **Stage the required pair relinks.** Mint the canary links and
   distribute them over an out-of-band channel BEFORE stopping the old
   relay, so pairs can re-consent the moment the new relay is up.
2. **Test an independent recovery channel.** Confirm a second,
   unaffected coordination path works end-to-end first (e.g. verify the
   *other* relay carries traffic before touching the target relay, or a
   tested direct channel). If the cutover goes wrong, this is how the
   team coordinates the fix — it must be proven working, not assumed.

## Rollback preference order (Zari, 2026-09-24)

If v0.2.13 misbehaves in canary/production, prefer in this order:

1. **Fail-closed service suspension FIRST.** Stop the relay by exact PID
   from its pidfile (never broad `pkill -f`; that killed production once
   on 2026-09-22). No traffic is better than unconsented traffic.
2. **Consent-preserving fix-forward.** A build that keeps the handshake
   gate while fixing the defect. Preferred over any rollback that drops
   the gate.
3. **Pre-handshake rollback LAST RESORT.** Restoring pre-handshake code
   (v0.2.12 or earlier) **DISABLES consent enforcement** — the old code
   ignores handshake state entirely and would deliver messages without
   consent. Emergency-only, with explicit operator awareness that
   messaging will flow ungated. This is NOT a clean revert.

**Downgrade is not automatic recovery.** Any rollback is a manual,
checkpointed operator decision — never an automated step. Ungated
downgrade must never be wired as a self-healing action.

## Artifacts

- Deploy: `dist/clack-relay-bundle-v0.2.13.tar.gz`
  sha256 `5ce8eff4452cff109a369051e82ab27f84512a4e77f251a57eac1ef466efa75d`
  (verify with `sha256sum` before deploying; must match this file; see
  `bundle-digest-receipt-2026-09-24.txt` for the recorded verification)
- Rollback reference: `dist/clack-relay-bundle-v0.2.12.tar.gz`
  (known-good code; **consent enforcement OFF** — see preference order)

## Deploy — Target A: ex-relay canary (https://clack.kasnet.us)

Owner: Zari (her host, her deploy). Steps:

1. `sha256sum` the v0.2.13 bundle — must match the digest above.
2. Validate supervisor/PID ownership: read the pidfile, confirm
   `/proc/<pid>/cmdline` is the relay (not a scratch test instance),
   and note which supervisor owns it. Pause supervision for the deploy
   window so it cannot restart mid-deploy.
3. Quiesce, then back up: stop the relay by exact PID; then take the
   backup with the SQLite backup API
   (`sqlite3 relay.db ".backup 'relay-backup-<ts>.db'"`) — a live
   data-dir copy is **not** a consistent SQLite/WAL backup. Verify the
   backup opens and the handshakes/messages row counts match.
4. Deploy into a **clean versioned directory** (e.g.
   `.../clack-relay/v0.2.13/`), never an overlay onto the running code
   dir. Point the supervisor at the new directory; keep the previous
   version directory for reference.
5. Restart; confirm `/health` reports `"version":"0.2.13"`.
6. Identity check (ex-relay): `GET /v1/identity?nonce=<32 random hex
   bytes>`; verify the per-nonce signature, then compare the returned
   **full** public key (`n` and `e`, entire values) against the
   operator's known-good full key. Short-fingerprint comparison alone is
   not sufficient.
7. Handshake smoke: enroll two scratch identities, mint-link → redeem →
   accept → send → poll → ack round trip. Confirm a pre-handshake send
   returns `403 handshake_required`.
8. Kin exchange links once (procedure above); run the handshake matrix
   against the canary (T1–T8 in `HANDSHAKE_SPEC_DRAFT.md`, implemented
   in `test-handshake.py`).
9. Re-enable supervision. Watch logs ~10 min for
   `handshake_required` spikes (expected from legacy clients) vs
   `nonce_store_full` / `upgrade_required` anomalies.

## Deploy — Target B: public relay (https://relay.tryclack.com → 127.0.0.1:18802)

Only after the ex-relay canary is clean. Same steps 1–5 as Target A
(bundle verify, PID-ownership validation, quiesced SQLite-backup,
clean versioned directory, restart), then:

6. Identity check (public relay): `GET
   /v1/identity?nonce=<32 random hex bytes>`; verify the per-nonce
   signature, then compare the returned **full** public key against the
   known-good values below — the entire `n` and `e`, not the short
   fingerprint. The relay's identity key is stable across upgrades; if
   the full key differs, STOP — do not proceed.

   Known-good public-relay identity key (verified 2026-09-24 against
   the pinned deploy fingerprint `sha256:bdc8a616f41b4397`):
   - `e`: `10001`
   - `n`: `a20e6d89c22723ba35488d615d4a76943e9bc02aca99fd94a15a5602887d76dcaed58fad598fe9c7a05b7da12071683114154e55a67cf6d1ccb4f5f8acf366fbb2d07245187091a3d836fb535a108e1f65cd641d271986883fdac2a090c791741f77214732ff7035d724b2f1143664995e7be8036e1617183f1bcfe11225fca1bb4d37cfa43cb8ad70ef2c54edafa088ca907d27792dd87847544015bce568d6eede98c70e7cd28946ab63b3509ed9d4d21ff0d33519ea2eb622be3b6f1fe010d07aa43fa80ee68baaa51dff645f0cf24ed09b149384f8b54ee1b3ea37801177db66e5f027b492af80f31deff92c159ac9cf55902cc18187ca1180f45b7e96c7`

   Fingerprint construction (for independent recomputation):
   `sha256("clack-relay-identity-v1" || ":" || n_be || ":" || e_be)`,
   displayed `sha256:<first 16 hex>`, with `n_be`/`e_be` the minimal
   big-endian encodings of the hex `n`/`e`.

7. Confirm `curl https://relay.tryclack.com/health` reports
   `"version":"0.2.13"`. The v0.2.13 client fails closed on identity
   503/unreachable: monitor `/v1/identity` availability as a rollout
   health signal.
8. Public handshake smoke (scratch identities only): mint-link →
   redeem → accept → send → poll → ack; stranger send (no handshake)
   returns `403 handshake_required`.
9. Re-enable supervision.

**Never verify identity by short fingerprint alone, and never confuse
the two targets' checks**: Target A compares against the ex-relay
operator's known-good full key; Target B compares against the full key
recorded above. A key that verifies on one target says nothing about
the other.

## Canary → public sequence

1. Target A canary deploy (steps above).
2. Kin exchange links once; handshake matrix green on the canary.
3. Target B public deploy only after canary is clean.
4. Tag / release / public-main merge only after public deploy verifies.

## pow-canary-1/2 cleanup

No operator removal API is verified. Do NOT improvise live DB deletion.
Keep those identities inert. Cleanup implementation is a tracked item,
not part of this release.

## Notes

- `trusted_proxies` / Cloudflare notes from the v0.2.12 runbook still
  apply (per-IP rate-limit buckets collapse at the tunnel socket).
- The v0.2.13 client fails closed on identity 503/unreachable: if the
  relay's identity endpoint is unhealthy, clients stop — they do not
  downgrade. Monitor `/v1/identity` availability as a rollout health
  signal.
- Scratch-port rule: local verification uses scratch ports only —
  never production port 18802.
