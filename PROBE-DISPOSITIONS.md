# Probe Dispositions P05–P18 — Python Relay

Branch: `nugget/python-safety-audit-20261010` (Round 3).
Each checklist property P05–P18 is either ADAPTED to the Python relay's actual
seams and verified, or explicitly N/A with rationale. No absent seam is silently
marked PASS. (Per Mercedes's REQUEST_CHANGES verdict 2026-10-10: the supplied
matrix named the obsolete Go handler's prepare/activate/abort/instance-bound
snapshots, not APIs of this Python transport relay.)

Incorporates Mercedes's evidence-clarification (2026-10-10,
topic `python-safety-round2-verdict-evidence-clarification`): three disposition
nuances below, marked [M-CLARIFY].

## N/A — no such seam exists in the Python relay

These mean the **absent Go-style guarded admission/rollback/snapshot APIs**
(prepare/activate/abort, instance-bound snapshots, migration journals with
phases). They do NOT mean the relay lacks all migration/backup/recovery
mechanics. What actually exists [M-CLARIFY]:

- **Startup schema migration:** `init_db()` runs `CREATE TABLE IF NOT EXISTS`
  plus ensure-column `ALTER TABLE ... ADD COLUMN` guards (messages:
  collected_at/fetch_count/dead_reason/enc_v; peers: identity_pubkey,
  invited_by, display_name, enroll_gate, enroll_ip, last_poll_at, last_send_at;
  handshakes: generation, enc_capable, minter_enc_v, redeemer_enc_v; invites:
  grant_handshake, note, minter_enc_v). There is no version journal, no
  phases, no rollback — the guards are idempotent forward-only repairs.
- **Durability:** SQLite WAL journaling (`PRAGMA journal_mode=WAL`) is the
  crash-recovery mechanism; there is no separate journal file to corrupt or
  verify beyond the DB itself.
- **Backup/recovery:** manual file-level backup/restore only (copy relay.db
  while the relay is stopped, or via SQLite backup API); no in-product
  backup feature, no restore path, no state binding to verify.

| # | Property | Rationale |
|---|----------|-----------|
| P06 | Rejected opens preserve orphan WAL | No per-request open seam. One process owns the DB for its lifetime; there is no open-then-reject path that could drop WAL/SHM. (WAL journaling itself exists as the durability mechanism — the property's guarded-admission API does not.) |
| P08 | Rollback is lossless | No migration/rollback system exists. Schema evolves via the idempotent startup guards above; nothing to roll back. |
| P09 | Rollback reachable every phase | Same — no migration lifecycle, no phases. |
| P10 | Phase-aware schema verification | No migration journal. Schema evolves via `CREATE TABLE IF NOT EXISTS` + ALTER guards in `init_db()`; there is no version journal to verify or tamper with. |
| P11 | Corrupt/truncated journals stay rejected | Same — no journal exists beyond SQLite WAL, which is the engine's own recovery, not a relay API. |
| P12 | Backups bind full recoverable state | No backup/restore feature in the relay; backup is a manual file operation. |
| P13 | Row counts/UUIDs are not a state binding | Same — no backup verification digest exists. |
| P14 | Validate and mutate under one ownership boundary | Same — no backup-then-prepare window exists. |
| P15 | Never restore stale state over accepted work | Same — no restore path exists. |
| P16 | Backups/snapshots bound to exact instance | Same — no snapshot feature exists. |

If the Python relay ever gains versioned migration, rollback, or backup/restore
features, the checklist properties above apply directly to the new code before
it ships.

## ADAPTED — applies to the Python relay's actual seams, verified

| # | Property | Python seam | Evidence |
|---|----------|-------------|----------|
| P05 | Authorize before ANY mutation | Per-request auth (Bearer/signature verification) runs before any **message/business-state** mutation; rejected requests (401/400) insert zero message rows. Startup validates config + identity key before binding the port. [M-CLARIFY] "No insertion" here means no message/business state — NOT "no state change at all." Two intentional security bookkeeping writes commit before downstream rejections, by design: (a) valid signed auth records the nonce (prune-expired + insert into `seen_nonces`, relay.py `_nonce_record`) before a later send-400/handshake-403 — this is the replay-protection store, and recording before the business decision is what makes replay detection work; (b) enrollment marks the challenge `used=1` before proof rejection — this burns single-use challenges so a failed proof cannot be retried into a different attack. These are deliberate anti-replay/anti-abuse measures, explicitly disclosed; they must NOT be removed to satisfy an overly broad zero-state reading. | Round-1 probes: 401/400 paths → zero message rows inserted. |
| P07 | Sequential process restart/persistence | [M-CLARIFY] Labeled "sequential process restart/persistence" — NOT "concurrent handle-transfer linearizability." There is no in-process close/restart API (unlike Go's Core.Close/Restart) and no handle transfer between processes. Restarts are process-level (systemd `Restart=always`); the test stops the old process and waits for termination before starting the replacement (test-real-restart.py: `stop()` terminates and `wait()`s). What is verified: queued/peer/handshake state survives a real stop→start cycle via the on-disk DB. | `test-real-restart.py`: 30/0 in Round 1. |
| P17 | Guarded mutations fail closed | Send-validation guards, handshake_required/handshake_revoked enforcement. | Round-1 probes: 12 validation errors → 400 + zero rows; revoked/missing handshake → 403 + zero rows; idempotent retry → single row. |
| P18 | Overflow/representation bounds fail closed | Input bounds on `ttl_secs`, text size, etc. | Round-1 probes: negative/zero/huge/string/bool `ttl_secs` → 400; oversize text → 400. |

## APPLIES directly (verified in Round 1 + Round 2, re-verified Round 3)

P01, P02, P03 (diagnostics fail closed, no silent discards, sibling paths),
P04 (diagnostics read-only), P19 (positive controls paired with every negative
probe). Round 2 closed the P01/P03 sibling gap Mercedes reproduced
(DROP TABLE peers/challenges): `/health` synchronously verifies every table
in `REQUIRED_TABLES` on every query. Round 3 closes the schema boundary she
then proved (RENAME COLUMN peers.token_hash): `/health` now verifies every
required **column** too, derived from the declared schema (`_SCHEMA_DDL` +
`_SCHEMA_MIGRATION_COLUMNS`) by construction — see
`relay.py::_required_schema_ok()`. Round 3 also starts the same sweep
lifecycle in every serving entrypoint (`serve_relay.py` now calls
`relay._start_sweep_thread()` via `run()`).
