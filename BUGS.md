# Clack Bug Ledger

**The single ledger of all known Clack bugs.** Fixes get documented where they
happen (git log, CHANGELOG, AGENTS.md), but this file is the index: what's
broken, how bad, and where it stands.

**Severity:**
- **P0** — message loss / durability. A message can be lost, duplicated without
  detection, or left unrecoverable. Release gate: Aaron's directive is "cut iff
  messages down — relays are okay on day 3 not day 30." All P0s must be fixed
  and proven before the Path B private-relay cutover.
- **P1** — auth / enrollment / consent breakage. Peers can't connect, or
  consent semantics are wrong.
- **P2** — client robustness / UX. The relay is correct but clients guess,
  crash, or need manual recipes.
- **P3** — ops / docs / known limitations.

**Status values:** `open` · `fixed-in-<version|commit>` · `parked` (fixed, not
deployed) · `mitigated` (workaround exists, root cause open) · `by-design`
· `known-limitation`.

**Confidence note (2026-09-25, per Aaron):** observations taken only from the
Muse VM's vantage are marked **lower-confidence** — this VM has an uncontrolled
lifecycle (host migrations, reboot cycles) and can't reach the tailnet
directly, so VM-observed drops conflate Cloudflare edge, VM egress/lifecycle,
and relay causes. Hosted-relay diagnosis (from Omni/Unraid directly) is
authoritative. See "Hosted diagnosis" below.

## Hosted diagnosis (2026-09-25) — drops are in the Cloudflare tunnel, not the relay

Isolation tests, all from the relay hosts themselves:

- **Relay HTTP stack healthy:** 20/20 `GET /health` from Omni directly to
  `100.83.31.74:7331` (bypassing Cloudflare), 0 drops. The relay is not the
  problem.
- **Omni cloudflared (named tunnel, serves `clack.kasnet.us` → `100.83.31.74:7331`):**
  at 13:39:13 UTC both QUIC edge connections dropped simultaneously
  (`failed to accept QUIC stream: timeout: no recent network activity`),
  auto-recovered in ~18s. Any in-flight long-poll or request in that window
  would drop mid-response — exactly the `IncompleteRead` / `RemoteDisconnected`
  pattern in the field incidents.
- **Unraid cloudflared (also routes `clack.kasnet.us` → `100.83.31.74:7331`):**
  at 13:30:58 UTC a `GET /v1/poll?timeout=25` "ended abruptly: context
  canceled" — a second, independent tunnel-side drop of a long-poll.
- **Dual-tunnel setup flagged:** BOTH the Omni named tunnel AND the Unraid
  tunnel carry `clack.kasnet.us` ingress rules pointing at the Omni relay.
  Cloudflare load-balances between them; the Unraid path adds an extra hop
  (Unraid → tailnet → Omni). Whether this is intentional redundancy or drift
  is unknown — worth an explicit decision, not a silent config.
- **Public relay (`relay.tryclack.com`, Unraid container `clack-relay:0.2.15-3a9506a`):**
  0 failures in 2.5h of 5-minute watch runs; container healthy 21h; logs clean.
  No relay-side errors.

**Bottom line:** the transport drops are a Cloudflare tunnel/edge phenomenon.
The relay code cannot prevent them; the protocol must survive them. That's
what v0.2.16 (at-least-once redelivery, BUG-001/BUG-005) and the BUG-002 ack
queryability fix are for. **Lower-confidence (VM vantage only):** the original
2026-09-24 `IncompleteRead` field incident was observed from this VM and
conflates the causes above — the server-side redelivery it demonstrated is
real, but the drop itself can't be attributed from that vantage.

**Doc gap (flagged):** `CHANGELOG.md` stops at v0.2.13. There are no entries
for v0.2.14 or v0.2.15. Release notes for those versions exist only in git
commit messages (`8c563d7`, `3a9506a`) and the cutover runbook.

**Forbidden artifacts (do not deploy):** commit
`f05741923f027c6649ee81128e856fae45bea43c`, bundle
`5ce8eff4452cff109a369051e82ab27f84512a4e77f251a57eac1ef466efa75d`
(superseded by the `8ccfa49` rebuild).

---

## P0 — message loss / durability

### BUG-001: Poll marks messages collected before the response reaches the client
- **Severity:** P0 · **Status:** `fixed-in-v0.2.16` (`aa98987`, parked — not deployed)
- **Repro/evidence:** 2026-09-24 field incident on `relay.tryclack.com`: a
  `GET /v1/poll` returned a partial payload then dropped (`IncompleteRead` —
  695 of 6320 bytes). The relay had already marked those 8 messages collected;
  follow-up polls returned zero and the bytes never reached the client.
  **Attribution is lower-confidence (VM vantage only)** — the drop was observed
  from the Muse VM and conflates Cloudflare edge, VM egress, and relay causes.
  Hosted diagnosis (2026-09-25, from Omni/Unraid) shows the relay HTTP stack
  healthy (20/20 direct) while the Cloudflare tunnels drop QUIC connections and
  cancel in-flight long-polls; the tunnel is the flaky layer. The redelivery the
  incident demonstrated (second poll redelivered all 8) is real and is the
  at-least-once semantic this fix relies on.
- **Root cause:** `collected_at` was treated as a delivery guarantee, and the
  sweep pruned collected-but-unacked rows 7 days after collection.
- **Fix:** v0.2.16 makes collection telemetry-only: poll responses carry
  `redelivered` + `delivery_count`, `fetch_count` column counts every delivery,
  only `ack` retires a message, and the sweep never prunes unacked rows on the
  collection timer (unacked rows live until 7d past expiry, then dead-letter).
  `CLIENT_CONTRACT.md` documents the at-least-once protocol. Tests: mid-read
  drop simulation, first-delivery flags, receipts `fetch_count`, ack retires —
  194 passed.
- **Fix location:** `relay.py` (`fetch_pending`, poll handler, `sweep`,
  `init_db` migration), `CLIENT_CONTRACT.md`, `test-relay.sh`.

### BUG-002: `/v1/ack` dropped connection leaves outcome ambiguous
- **Severity:** P0 · **Status:** `open` → fixed by BUG-002 patch (see below)
- **Repro/evidence:** `POST /v1/ack` on `clack.kasnet.us` closed the connection
  with no response (`RemoteDisconnected`) — but the ack had already applied
  server-side. A retry returned `{"acked": []}`, which is indistinguishable
  from "those ids never existed." The client cannot tell applied from unknown
  without an extra poll.
- **Fix:** `/v1/ack` now returns per-id outcomes:
  `{"acked": [...], "already_acked": [...], "unknown": [...]}`. `acked` = newly
  acked by this call; `already_acked` = the recipient already acked it (a prior
  call applied — the dropped-connection case); `unknown` = no such message for
  this recipient. Ack is now idempotent *and* queryable: retry after any drop
  and the outcome is unambiguous.
- **Fix location:** `relay.py` (`/v1/ack` handler). Tests in `test-relay.sh`.

### BUG-003: `/v1/send` dropped connection after server-side processing
- **Severity:** P0 · **Status:** `mitigated`
- **Repro/evidence:** `POST /v1/send` connection dropped with no response;
  retry succeeded. Without a stable id, a blind retry could deliver twice.
- **Mitigation:** sends carry an explicit UUID `id`; the relay dedupes on
  `(id, sender)` and a retry returns `{"accepted": true, "duplicate": true}`
  instead of storing a second copy. The loop is closable: retry with the same
  id, `duplicate:true` means the original applied. Documented in AGENTS.md
  ("always echo MSG_ID so a retry can reuse it").
- **Residual:** the dedup window is bounded by retention — a retry with the
  same id more than 7 days after the original was acked-and-swept would insert
  a fresh copy. Real clients retry promptly; recorded as BUG-018
  (known limitation), not a live defect.

### BUG-004: `serve_relay.py` adapter silently revokes hash-only peers (sigrid)
- **Severity:** P0 · **Status:** `fixed-in-staged-serve_relay.py.v0215` (parked)
- **Repro/evidence:** Found 2026-09-25 during Path B staging canary. The
  `serve_relay.py` adapter bypasses `relay.main()`, skipping
  `_init_peer_hashes()` — so `_PEER_HASHES` stayed empty and sigrid (a
  hash-only peer, present in DB but not in config) was treated as a removed
  peer: **peer row deleted, its queued message deleted, name retired.**
  Caught on staging (pending 3 vs expected 4).
- **Fix:** the staged adapter mirrors `main()`'s `_init_*` calls. Verified:
  5/5 peers preserved, 4/4 queued messages intact, 0 wrongful retirements.
- **Fix location:** `~/workspace/clack-private-relay/serve_relay.py.v0215`
  (staged on Omni at `/home/aaron/muse-clack-relay/serve_relay.py.v0215`).
  Must be merged into the `serve_relay.py` maintained in this repo before any
  cutover that uses the adapter.

### BUG-005: Sweep deleted collected-but-unacked mail 7d after collection
- **Severity:** P0 · **Status:** `fixed-in-v0.2.16` (`aa98987`, parked)
- **Repro/evidence:** Same root as BUG-001. A poll response that never arrives
  still counted as "collected," and the sweep deleted the row 7 days later —
  silent loss of unconfirmed mail.
- **Fix:** v0.2.16 sweep only deletes expired rows with `acked_at IS NOT NULL`
  promptly; unacked rows (collected or not) live until 7d past expiry, then go
  as dead letters visible via `/v1/receipts`.
- **Fix location:** `relay.py` (`sweep`).

---

## P1 — auth / enrollment / consent

### BUG-006: `serve_relay.py` adapter never sets `relay_cfg` → mint-link crashes
- **Severity:** P1 · **Status:** `fixed-in-staged-serve_relay.py.v0215` (parked)
- **Repro/evidence:** Found 2026-09-25 during Path B staging. `relay.main()`
  sets the `relay_cfg` global; the adapter didn't, so
  `POST /v1/handshakes/mint-link` raised `AttributeError` → dropped connection.
- **Fix location:** `~/workspace/clack-private-relay/serve_relay.py.v0215`.
  Same merge requirement as BUG-004.

### BUG-007: v0.2.15 mandates Ed25519 request signing — all token-only peers break
- **Severity:** P1 · **Status:** `by-design` (migration in progress)
- **Evidence:** v0.2.15 returns `401 upgrade_required` on ALL authenticated
  endpoints for token-only peers. No config knob to disable. Every peer needs:
  (1) Ed25519 keygen, (2) operator provisions pubkey in `identity_pubkeys`,
  (3) signing client upgrade, (4) fresh handshakes (no backfill).
- **Location:** `~/workspace/clack-private-relay/CUTOVER-RUNBOOK.md` has the
  peer checklist (zari, nugget, clingy_bear, flint, sigrid). Cutover is staged,
  awaiting Aaron's go-ahead after peer key provisioning.

### BUG-008: Revoke doesn't dead-letter collected-but-unacked messages
- **Severity:** P1 · **Status:** `fixed-in-v0.2.16` (2026-09-25, commit on
  `fix/poll-redelivery`)
- **Evidence (code read):** the revoke dead-letter sweep only touched rows
  with `collected_at IS NULL`. Pre-v0.2.16 "collected" meant "delivered,"
  but under v0.2.16 at-least-once semantics a collected-but-unacked message
  may never have reached the client — and it stayed pollable after revoke,
  violating "never delivered after revocation" (`relay.py` revoke handler).
- **Fix:** dead-letter sweep now covers ALL unacked mail between the pair
  (dropped the `collected_at IS NULL` condition); new delivery boundary —
  revocation can't retract bytes already on the wire or un-ack an ack, but
  everything else dies with the consent. Receipts report such rows as
  `dead` even when `collected_at` is set (state machine now checks
  `dead_reason` before `collected_at`). Poll collection marking skips rows
  that died between fetch and marking. Docs: `CHANGELOG.md` v0.2.16,
  `relay.py` revoke-handler boundary comment. Tests: new phase 5c
  (collect → revoke → no redelivery, DB dead-lettered with collected_at
  set, receipt "dead") and phase 12 race invariant rewritten
  (always dead-lettered, never re-fetched) in `test-handshake.py`.

### BUG-009: Stale origin-verdict cache broke redeem/enroll hello
- **Severity:** P1 · **Status:** `fixed-in-v0.2.12` (`b13d698`)

### BUG-010: CLI identity check ignored configured UA → Cloudflare 403
- **Severity:** P1 · **Status:** `fixed-in-v0.2.12` (`a623293`)
- **Evidence:** `fetch_relay_identity()` didn't pass the config's `user_agent`,
  so the TOFU check went out as Python-urllib and Cloudflare 403'd it on
  `clack.kasnet.us`. Every `send`/`poll` then aborted at identity verification.

### BUG-011: `init_db` didn't union config `peer_hashes` (hash-only peer defect)
- **Severity:** P1 · **Status:** `fixed-in-v0.2.13` (`8ccfa49`, verified by
  `17da8d5` real-restart acceptance)
- **Evidence:** "target-A" defect: hash-only peers (in DB, not in config)
  mishandled at init. Same family as BUG-004.

### BUG-012: v4 handshake-link redeem mismatch with onboarding client
- **Severity:** P1 · **Status:** `fixed-in-v0.2.14` (`8c563d7`, hotfix Flint found)

---

## P2 — client robustness / UX

### BUG-013: CLI `poll` sent float timeout → ex-relay dropped connection
- **Severity:** P2 · **Status:** `mitigated`
- **Evidence:** `relay-cli.py poll` sent `timeout=25.0`; `clack.kasnet.us`
  `/v1/poll` closed the connection instantly on that format. Integer form
  works. CLI now formats whole-number timeouts as int (`t_str`).
- **Residual:** non-integer timeouts still send float form; the relay clamps
  them fine, but the ex-relay's pickiness is server-side. Use integer timeouts
  against the ex-relay (the inbox-watch script does).

### BUG-014: CLI doesn't auto-salvage `IncompleteRead` partials on poll
- **Severity:** P2 · **Status:** `open`
- **Evidence:** AGENTS.md documents the manual recipe (catch `IncompleteRead`,
  salvage complete messages from `e.partial`, ack what you got, poll again),
  but `relay-cli.py`'s `req()` lets the exception propagate and crash. The
  relay side is now at-least-once (BUG-001 fix), so a crash is recoverable by
  re-polling — but the CLI should do the salvage + re-poll itself.
- **Fix direction:** catch `http.client.IncompleteRead`/`RemoteDisconnected`
  in `req()`; on poll, parse `e.partial`, return salvaged messages with a
  `partial:true` marker; document "re-poll for the rest."

### BUG-015: Cloudflare 403s Python-urllib default UA
- **Severity:** P2 · **Status:** `fixed-in-v0.2.12` (CLI); `mitigated` elsewhere
- **Evidence:** `clack.kasnet.us` sits behind Cloudflare, which 403s (code
  1010) Python-urllib's default UA on `/v1/poll`. CLI now defaults to
  `ClackRelay-CLI/0.2.12` UA. The inbox-watch script uses a browser UA.

---

## P3 — ops / docs / known limitations

### BUG-016: CHANGELOG.md stops at v0.2.13
- **Severity:** P3 · **Status:** `open`
- **Gap:** no entries for v0.2.14 (`8c563d7`) or v0.2.15 (`3a9506a`).
  Reconstruct from commit messages before the next release cut.

### BUG-017: `BrokenPipeError` tracebacks on client disconnect
- **Severity:** P3 · **Status:** `open`
- **Evidence (code read):** `Handler._json` does `self.wfile.write(body)` with
  no exception handling. A client that disconnects mid-response kills the
  handler thread with a traceback. No data loss (all writes commit before
  `_json`), but every Cloudflare-dropped poll/response logs a full traceback.
- **Fix direction:** wrap `wfile.write` in try/except
  `(BrokenPipeError, ConnectionResetError)` and return quietly.

### BUG-018: Send dedup window bounded by retention (known limitation)
- **Severity:** P3 · **Status:** `known-limitation`
- **Note:** idempotent retry on `(id, sender)` only works while the original
  row exists. A retry >7d after the original was acked-and-swept inserts a
  fresh copy. Real clients retry promptly; not a live defect.

### BUG-019: Relay base env var renamed (`KINDRED_RELAY_BASE` → `CLACK_RELAY_BASE`)
- **Severity:** P3 · **Status:** `documented` (runbook)
- **Note:** v0.2.1 requires `KINDRED_RELAY_BASE`; v0.2.15 requires
  `CLACK_RELAY_BASE`. Restarting with the wrong var crashes on a nonexistent
  default config path. The cutover runbook covers both; rollback restores the
  old var.

### BUG-020: Split-horizon DNS on `clack.kasnet.us`
- **Severity:** P3 · **Status:** `documented` (AGENTS.md)
- **Note:** from the public internet, Cloudflare → tunnel → Omni:7331. From
  Omni's LAN it resolves to 192.168.0.3 (Unraid Caddy, 401s on `/v1/*`).
  Never test the public URL from Omni itself.

---

## Gate status for Path B cutover (message durability)

| Gate | State |
|---|---|
| BUG-001 poll redelivery | fixed in `aa98987` (parked, 194 tests green) |
| BUG-002 ack ambiguity | fixed by BUG-002 patch (this ledger's session) |
| BUG-003 send idempotency | mitigated (UUID dedup + `duplicate:true`) |
| BUG-004 adapter peer wipe | fixed in staged adapter (must merge before cutover) |
| BUG-005 sweep pruning | fixed in `aa98987` (parked) |
| BUG-008 revoke vs redelivery | fixed in v0.2.16 BUG-008 patch (this session) |

The durability gate is clear when: `aa98987` + the BUG-002 ack patch + the
BUG-008 revoke patch + the two staged adapter fixes are all in the cutover
build, and the suites below are green.
