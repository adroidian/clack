# v0.2.13 deploy / rollback runbook

Status (2026-09-24): **NOT DEPLOYED.** Branch `v0.2.13` built and
committed locally; full suite green. Handoff evidence pack (bundle digest
tied to the source commit + test receipts + this runbook) goes to Zari for
review **before** canary. No push, tag, release, or deploy without the
human checkpoints.

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

## Artifacts

- Deploy: `dist/clack-relay-bundle-v0.2.13.tar.gz`
  sha256 `5ce8eff4452cff109a369051e82ab27f84512a4e77f251a57eac1ef466efa75d`
  (verify with `sha256sum` before deploying; must match this file)
- Rollback: `dist/clack-relay-bundle-v0.2.12.tar.gz` (known-good;
  **consent enforcement OFF** — see preference order above)

## Deploy (production: 127.0.0.1:18802, behind Cloudflare)

1. `sha256sum dist/clack-relay-bundle-v0.2.13.tar.gz` — must match above.
2. Back up the production DB: copy the relay data dir (config + relay.db)
   to a timestamped backup first.
3. Stop the production relay by exact PID from its pidfile.
4. Extract the v0.2.13 bundle over the production code dir.
5. Restart per the production start procedure; confirm
   `curl https://relay.tryclack.com/health` reports `"version":"0.2.13"`.
6. Verify `/v1/identity` fingerprint unchanged (`sha256:bdc8a616f41b4397`
   on the public relay) — the client now fails closed if it can't verify.
7. Handshake smoke: enroll two scratch identities, mint-link → redeem →
   accept → send → poll → ack round trip. Confirm pre-handshake send
   returns `403 handshake_required`.
8. Watch logs ~10 min for `handshake_required` spikes (expected from
   legacy clients) vs `nonce_store_full` / `upgrade_required` anomalies.

## Canary (ex-relay) before public

1. Deploy to ex-relay per the steps above (scratch ports only for any
   local verification — never 18802).
2. Kin exchange links once (procedure above).
3. Run the handshake matrix against it (T1–T8 in
   `HANDSHAKE_SPEC_DRAFT.md`, implemented in `test-handshake.py`).
4. Public relay deploy only after canary is clean.

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
