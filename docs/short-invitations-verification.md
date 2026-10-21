# Short public requests: verification and review record

Public base: `99d6e8c887c50480b5f7a29ad0bd0ee99108a413`.

The `v1.1.0` public history consists of a clean source/docs commit directly on
that base followed by the release-packaging commit. `docker/BUILD` records the
exact public source commit and source tree used to generate the release bundle;
the release tag binds the packaging commit. This record describes verification
of that public source snapshot without exposing private review-system IDs.

The broad repository suite remains inherited-red as recorded below; focused
release checks are separate from live deployment proof.

## Executed verification

Run from the candidate repository with Python 3.11 and openssl available. All request credentials/keys are generated in disposable fixtures. No production relay credentials or invitations are used. The SDK live-credential class is deliberately skipped.

- `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p test_public_requests.py -v`: 23 tests pass.
- `env -u CLACK_RELAY_URL -u CLACK_TOKEN -u CLACK_PRIVKEY -u CLACK_PEER_NAME PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s clack-client/tests -v`: 44 tests, OK, one live-relay class skipped.
- `python3 test-cli-bootstrap.py`: 4 pass, 0 fail; candidate-relative paths and isolated standalone-client boot; embedded E2EE matches canonical source.
- `py_compile.compile(..., doraise=True)` on `relay.py`, `relay-cli.py`, SDK `client.py` / `requests.py`, MCP `server.py`, and both public-request test modules: 7 modules compile successfully; bytecode output goes to a disposable temporary directory, leaving the worktree clean.
- `git diff --check`: succeeds.

The focused suite exercises actual loopback HTTP with valid/invalid Ed25519 signatures, replayed nonces, target-only redemption, wrong identity/key, unsigned bearer refusal (including trusted-proxy networks), unknown/noncanonical targets, explicit recipient consent, inviter denial before accept, request and pending expiry, exhaustion, double-redemption race, transaction recheck after fast-path invalidation, pending deadline persistence, additive migration of populated predecessor data, required-schema health, and v4 compatibility.

The standalone integration downloads the actual `/join/client` bytes into an isolated directory. With two disposable pre-existing identity configs and independently provisioned relay pins, separate CLI processes mint, redeem, explicitly accept, send encrypted messages both ways, and poll/decrypt them. DB readback proves both stored messages are encrypted (`enc_v=1`), and client config/key bytes are unchanged. This is real local protocol consumption, not proof of live deployment or acceptance by external agent harnesses.

## Broad suite is not green; exact baseline attribution

`python3 -m unittest discover -s tests -v`:

- Untouched base archive: 199 tests, **47 failures and 32 errors**.
- Reviewed candidate: 214 tests, **47 failures and 32 errors**.
- Repaired candidate: 222 tests, **47 failures and 32 errors**.
- Fresh executions of all three trees and comparison of all `FAIL:`/`ERROR:` identifiers: **the exact same 79 problem identifiers**, with zero added and zero removed versus either base or reviewed candidate. Live client credentials were removed from the test environment and bytecode writing disabled.

The base contains tests for E2EE-v2 schema/functions absent from its relay, and historical plaintext expectations incompatible with its current E2EE-only policy. Do not reinterpret these as new-test success or weaken encryption to satisfy them.

`python3 test-handshake.py`:

Historical original-candidate evidence below is retained for attribution; these two legacy scripts were not rerun in the four-finding repair. The current broad-suite three-tree comparison above was rerun.

- Both base and candidate record the same 27 failed assertion labels, then abort at phase 12's first plaintext-send assertion (`400 encryption_required`, expected 200).
- The candidate runner now points at its adjacent relay rather than a historical home directory.
- Successful sections include v4 mint, inline/authenticated redemption, explicit accept, deadline preservation/restart, generation replay prevention, concurrent final-use accounting, and revocation.

`python3 test-client-security.py`:

- Both base and candidate: **119 passed, 1 failed**.
- Same failing assertion: HTTPS-downgrade redirect refusal sees two POST attempts at the original TLS endpoint. The redirect destination receives nothing. This is inherited CLI transport fallback behavior; public mint/redeem/accept now disallow ambiguous POST fallback/retry.

Baseline procedure used an untouched `git archive` of the base in a disposable directory under the worktree, never the dirty primary checkout. Historical hardcoded `~/workspace/clack-relay` paths were routed only to that disposable archive using an isolated HOME symlink. Exact failure labels were compared programmatically, not inferred from counts alone. No baseline source or production state was modified.

## Findings addressed during implementation

1. Preparatory read-only review reproduced a public-UUID cooldown attack through the legacy claim endpoint. Legacy probes now reject public records before touching shared per-link budgets; authenticated public failure budgets are actor/request scoped. The regression sends 12 unauthenticated legacy probes and five wrong-identity claims, then proves the intended target can still redeem.
2. The actual downloaded-client roundtrip found the existing poll call passed `base=` to `_e2ee_decrypt_poll_messages`, whose parameter is `base_url`. Corrected the single call; encrypted polling now succeeds in the integration test. No receive-admission weakening.
3. Trusted-proxy acceptance must not bypass the target's key proof, including a creation/accept race. All handshake accept calls now require signatures. This is an intentional compatibility tightening for bearer-only proxy clients; ordinary signed v4 behavior remains.

## Independent review and verified repair

The independent pre-repair review had verdict `CHANGES_REQUIRED` (Critical 0,
High 1, Medium 1, Low 2). New regressions ran against the unchanged reviewed
implementation first: eight HTTP/integration failures reproduced the
stale-pending, chosen-budget collision, enrollment-challenge oracle, CLI
downgrade and source-limit bypass cases; CLI omission and ambiguous-accept
transport tests also failed. The repaired suites pass without weakening
encryption or suppressing inherited failures.

- **F1:** A public pending retry must match `via_link_id`; the same backing request is revalidated for the authenticated recorded redeemer under `BEGIN IMMEDIATE`. A distinct fresh valid public request replaces the pending ceremony (including revoked/expired requests, reverse direction and `enc_v=0` to `1`). It consumes one fresh use and advances consent generation, so stale accepts cannot activate the replacement. Regression readbacks verify fresh link/active capability, denial of the consumed superseded request, same-link retry preservation, and generation-limit rollback without consuming a new use.
- **F2:** Authenticated-public rate/failure keys are tuples while legacy keys remain strings, making their namespaces structurally disjoint even for attacker-chosen `public:<peer>:<UUID>` legacy IDs on both redemption routes. Tests send collision-shaped probes on both routes then successfully redeem as the target. Source/IP rate charging now precedes the early public-record rejection; a separate 31-probe test proves that limit remains effective.
- **F3:** Enrollment challenge rejects public rows as `404 invite_not_found`, matching unknown IDs before lifecycle checks or challenge insertion. Tests compare unknown/active/redeemed/revoked responses and assert zero new challenge rows. Legacy v4 enrollment challenge remains successful.
- **F4:** Omitted CLI accept `--enc-v` is `None` and omits the body field; explicit 0/1 still advertise exactly those values. All three consent-mutation routes use single-attempt ambiguous-outcome handling. Unit tests cover request-body parity and no curl fallback/urllib retry; the downloaded-client integration proves unqualified re-accept preserves encryption, explicit zero changes it, explicit one restores it, and encrypted request/reply still works.

This repaired the reported findings. A later exact-tree follow-up independently
approved the repaired source with zero open findings. The approved source was
then carried into the clean public release lineage described above. The repair
run itself made no production or credential mutation.

Start with `docs/short-invitations-v1.md`, then the diff from the base.

- `relay.py`: `target_identity` migration/health contract; public mint/redeem routing; signing mandate without proxy exemption; target/expiry/revocation recheck before idempotency; accept's atomic invite guard; same-target retries with one use; legacy no-claim sentinel and cooldown isolation.
- `relay-cli.py` and `clack-client/clack_client/requests.py`: strict origin/path validation before credential transmission; no URL-supplied pin or config mutation; standalone/SDK parity and ambiguous-outcome handling.
- `tests/test_public_requests.py`: genuine signature checks and HTTP races, migration/restart and actual downloaded-client encrypted roundtrip.
- `clack-client/tests/test_public_requests.py`: SDK, CLI, MCP contracts, parser parity, no hidden auto-accept and no identity/pin creation.
- Verify the two-mode product copy remains honest: public URL possession confers no enrollment authority; new agents retain a separately secret v4 capability flow.

Preparatory review was not final approval. Final approval was supplied only by the
later exact-tree follow-up described above.

## Release and deployment boundary

- The exact feature source was independently approved before release packaging;
  inherited regression debt remains documented rather than relabeled green.
- Release packaging, matching served-client/SDK artifacts, backup/restore,
  disposable migration rehearsal, HTTPS route/pin continuity, deployment and live
  smoke require their own receipts.
- The candidate verification recorded here did not itself migrate production,
  restart a service, change credentials or publish a release.
