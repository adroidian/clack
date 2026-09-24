# v0.2.12 deploy / rollback runbook

Status (2026-09-23, updated post-deploy): **DEPLOYED.** Zari deployed
v0.2.12 to the public relay (`https://relay.tryclack.com`) on 2026-09-23;
verified live: `/health` reports `"version":"0.2.12"`, identity fingerprint
`sha256:bdc8a616f41b4397` unchanged, PoW enrollment + signed
send/poll/ACK round trip pass after the deploy, rollback bundle retained
on the host. Bundle was rebuilt 2026-09-23 ~21:55 CDT from the final tree
to include the CLI User-Agent fix (a623293) — the earlier bundle's
`relay-cli.py` predated it and would have been 403'd by Cloudflare on the
identity check.

## Artifacts

- Deploy: `dist/clack-relay-bundle-v0.2.12.tar.gz`
  sha256 `ad6f5a3c0b2f095c0d2615fe31d6a997b59e875b9346b1d56b36f10be0cd1229`
  (verify with `sha256sum` before deploying; must match this file)
- Rollback: `dist/clack-relay-bundle-v0.2.11.tar.gz` (known-good, currently
  running in production)

## Deploy (production: 127.0.0.1:18802, behind Cloudflare)

1. `sha256sum dist/clack-relay-bundle-v0.2.12.tar.gz` — must match above.
2. Back up the production DB: copy the relay data dir (config + relay.db)
   to a timestamped backup first.
3. Stop the production relay by exact PID from its pidfile (never broad
   `pkill -f`; that killed production once on 2026-09-22).
4. Extract the v0.2.12 bundle over the production code dir.
5. Restart per the production start procedure; confirm
   `curl https://relay.tryclack.com/health` reports `"version":"0.2.12"`.
6. Signed round trip: enroll a scratch identity via `/join`, send, poll,
   ack. Confirm a legacy token-only request now gets `401
   missing_signature`.
7. Watch logs ~10 min for `nonce_store_full` / `upgrade_required` spikes.

## Rollback (code-only; no DB migration needed)

Verified 2026-09-23: v0.2.11 boots clean against a v0.2.12-created DB —
the extra `retired_names` table is ignored, `/health` returns
`"version":"0.2.11"`. So rollback is:

1. Stop the relay by exact PID.
2. Extract `dist/clack-relay-bundle-v0.2.11.tar.gz` over the code dir.
3. Restart; confirm `/health` reports `"version":"0.2.11"`.
4. No DB restore required (the schema change is additive and ignored by
   the old code). Keep the pre-deploy DB backup anyway.

## Notes

- The tunnel deployment dials 127.0.0.1:18802, so every remote client
  shares the socket peer address and all per-IP rate-limit buckets
  collapse into one (Flint P2-deploy). Before going live, set in
  relay-config.json: `"trusted_proxies": ["127.0.0.1/32"]` — then the
  relay keys buckets on `CF-Connecting-IP` (else the first
  `X-Forwarded-For` entry) for connections arriving via the tunnel.
  Forwarded headers from any other source are never honored; leave the
  list empty and the socket IP is always used.
- Mandatory signing is backward-compatible at the protocol level, but
  legacy token-only clients get `401 missing_signature` after the upgrade
  — confirm Clingy Bear's key is registered and her client signs before
  deploying.
- `retired_names` tombstones persist across the rollback; on re-deploy
  of v0.2.12 they are honored again. No operator action needed.
