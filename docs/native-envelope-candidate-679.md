# #679 isolated native envelope transport candidate

Status: source-only candidate, pending independent integration and operator review. No installation, runtime selection or live combined-pilot acceptance.

## Provenance and scope

Source-only candidate overlay, pending independent integration and operator review. No installation, runtime selection, or live acceptance. This document describes the candidate's wire and persistence behavior as source only; it creates no operational grants, keys, contacts, capabilities, advertisement, or bootstrap authority. Provenance details, operator receipts, and review records live with the operator review process, not in this document.

A reviewed crypto helper is copied unchanged ONLY to `tests/fixtures/e2ee.py` as a test fixture. Production transport does not load its encryption/decryption code or private keys. `clack_client/envelope.py` reuses its shape validation/serialization, with bounded exact v1 fields as transport policy. This is not a new cryptographic construction or security review.

## Wire and persistence

- Native SDK call: `send(to, msg_id=stable_uuid, enc=owner_envelope, enc_v=1)`; `text` must not be provided. Uses existing signed/pinned request machinery and acceptance validation.
- Adapter call: `send(grant, stable_uuid, enc=owner_envelope, enc_v=1)`; CLI adds mutually exclusive `--enc-file` / existing `--text-file`. Crypto belongs to the owner, never the relay/adapter.
- Native wire send: top-level `enc` object, omitted plaintext `text`. No plaintext downgrade on the encrypted branch; malformed/unsupported native fields are refused, not sent as ordinary text.
- Reviewed storage contract: canonical envelope JSON in the existing `text` column AND `enc_v=1`. Poll/fetch retain `text` plus `enc_v`; this text is ciphertext, never decrypted content. Unmarked JSON-envelope-in-text (`enc_v=0`) is NOT native encrypted acceptance. The clarified reference explicitly distinguishes native marked storage from disguising ciphertext as plaintext.
- Adapter runtime_payloads is the durable outbox payload journal, linked by stable msg_id/grant_id to the unchanged authority outbox/reservation lifecycle. Persist canonical original envelope and enc_v before transport; reconcile reconstructs the same envelope, never calls encryption. Same-ID retries compare the immutable grant/payload/version. Relay dedup also compares original sender/recipient/topic/reply binding and envelope/version, without replacing the original expiry.
- Durable inbox preserves raw ciphertext text, enc_v, stable event/correlation metadata and supplied recipient. Receive is accepted only under the existing cap/grant-generation action boundaries; durable commit precedes ACK. Relay telemetry is excluded from immutable inbox comparisons. Owner decrypt is later; adapter collection is not native substantive execution.
- Existing plaintext compatibility remains a separate v0 path; there is no encryption negotiation or capability advertising added here. Owners must supply encrypted payloads when their authorized route requires native encryption.

## Migration and rollback boundary

Additive source migration: relay messages.enc_v and adapter runtime_payloads.enc_v, INTEGER NOT NULL DEFAULT 0. Old rows stay v0; no content or authority backfill. Fresh migrations and idempotent adapter journal migration are exercised offline. No operational database migration is performed.

Do not revert to text-only code against state containing v1 envelopes: old consumers would lose/ignore the marker. Any later operator activation requires an independently reviewed exact source manifest, compatible consumers and owner-approved finite scope. Preserve a pre-activation source/database snapshot; rollback must restore compatible source and its matching pre-activation state under operator control, not reinterpret v1 records as plaintext or replay old pilot effects. No rollback command is executed by this candidate.

## Focused offline proof

From candidate directory:

```sh
env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p test_native_envelope_positive.py -v
```

Only this new positive suite runs; no full baseline suites or supplied negative-probe harness. Fixture tests cover shape, signed body retry bytes/fresh nonce, actual relay send/storage/poll/fetch/reopen/same-ID dedup, pre-handoff durable adapter outbox, uncertain-delivery restart/reconciliation, terminal no-replay, inbox restart/redelivery, additive journal migration, and in-process adapter→SDK→relay→poll→inbox→reviewed owner decrypt with freshly generated synthetic owner keys. Synthetic shape-only envelopes are labeled, not claimed decryptable. The copied reviewed helper performs the actual positive roundtrip.

All fixture state is disposable and contained under this candidate's parent directory. Socket construction is explicitly prohibited during tests; auth, pin and transport seams are stubbed. Fixture adapters use __new__ and the real transport schema/authority methods: operational constructor/bootstrap/pin validation is NOT exercised. Authority fixture rows and keys are synthetic, not the live grant. No profile secrets or identity/session/persona databases are read. Final exact execution output, source hashes and diff are parent-side reports alongside candidate.

## Remaining gates / limitations

Offline proof is not a live two-runtime/native participant interoperability verdict, security acceptance, soak or activation grant. No authentication/pinning integration, capability negotiation, receiver runtime attention/work/response route, canary-to-principal binding, key custody migration or main-session injection is tested or installed. The unchanged reviewed crypto helper has its own documented pure-Python/non-constant-time limitations. Independent source review and original finite operator authorization remain required for any later native runtime trial. No commits, pushes, deployments, listeners, live network calls, wakes or peer mutations are performed.
