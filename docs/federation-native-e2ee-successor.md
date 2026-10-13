# Native E2EE-over-Federation successor candidate

Status: local source candidate on `refs/heads/federation/native-e2ee-successor-20261006`. It is not pushed, merged, installed, or selected by any live runtime. Executed evidence and the final commit/tree bindings live with the operator review process; this document intentionally does not embed a self-referential final tree hash.

## Provenance

This successor is based directly on the reviewed Federation transport commit `d636f3e9c279ffbd09aee60fe12c546c5bf3c67c`, tree `9137213b988bb937eee7f15508c1ba035a92bdaa`. That commit retains the Flint-cleared lifecycle overlay and the operational authority, persistence, retry, deduplication, ACK, and reconciliation boundaries.

The native-envelope input was reproduced from source manifest SHA256 `f67fadece6c17daf1e79284c6144e3390d1c4354db57c26e09ded739f07c9386`. All 43 manifest members were independently rehashed before composition; the 39 baseline members matched the reviewed transport tree, and the exact seven-file native delta was imported before successor-only edits.

The accepted client E2EE input remains read-only at `e2ee-kit-v1.0.2`, manifest SHA256 `ebab4aff5de61a45aa0d1ab3b5e72186e1ced94824f748669b65ecf6d97b53a5`. Its `e2ee.py` SHA256 `ebe5517464f28b34dc0662ff06ccc9e059039d64f19f6e0f1a6216b41845c90e` exactly matches this repository's test-only fixture. Production relay and Federation adapter code validate and preserve opaque envelopes; they do not load decryption keys.

## Composed contract

- Owner-side E2EE produces the accepted v1 `x25519-chacha20poly1305` envelope.
- Native SDK send uses top-level `enc` plus exact integer `enc_v=1`; cleartext `text` is omitted.
- Relay storage retains canonical ciphertext JSON in `text` and the explicit `enc_v=1` marker. Poll/fetch preserve sender, recipient, correlation fields, ciphertext, and marker.
- Federation journals the canonical ciphertext and version before transport. A retry or restart reloads the same bytes; it never re-encrypts.
- Stable message ID is bound to grant, payload, and version in the authority journal and to sender, recipient, topic, reply reference, ciphertext, and version at relay deduplication.
- Relay retry acceptance does not replace the original expiry.
- Unsupported durable payload versions and malformed retained native envelopes are refused before reservation reconciliation or retry lifecycle advancement; they never select the plaintext branch.
- Receive commits immutable ciphertext to the durable Federation inbox before relay ACK. That ACK is a transport durability boundary only. Owner decrypt/application completion and semantic agent ACK remain separate and are not inferred.
- Existing authority states, generation fences, partition caps, NDRs, terminal outbox states, configuration binding, and explicit migration requirement remain unchanged.

## Verification surfaces

The focused source test and finite canary use fresh synthetic `test-peer-a` and `test-peer-b` keys on two stock loopback relay processes. They prove signed native encrypted duplex, distinct key custody, post-acceptance uncertainty followed by same-ID reconciliation, unchanged ciphertext/expiry, one-row relay deduplication, relay-process restart persistence, durable inboxes, both owner decrypts, wrong-principal decrypt refusal, three pre-wire malformed/ambiguous-send refusals, relay transport ACKs, terminal authority rows, zero unfinished reservations, and ownership-verified listener/process/scratch cleanup.

Run from the repository root:

```sh
env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest -v tests.test_federation_e2ee_composition

env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 \
  python3 reviews/run_federation_e2ee_canary.py
```

The full candidate suite remains:

```sh
env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest discover -s tests -v

env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 \
  python3 reviews/test-v098-successor-regressions.py

env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest discover -s clack-client/tests -v
```

The accepted E2EE kit is verified and tested in place without modification:

```sh
sha256sum -c MANIFEST.sha256
env -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 \
  python3 -W error::ResourceWarning -m unittest discover -s tests -v
```

## Evidence boundary and remaining gate

This candidate proves transport, native envelope handling, accepted E2EE cryptography in a synthetic owner context, and local E2EE-over-Federation composition. It does **not** prove an actual named team agent received, decrypted, performed useful work, replied, or emitted a semantic ACK. It also does not prove remote server installation, real-principal configuration migration, live key custody, runtime selection, fleet rollout, or peer acceptance.

The remaining remote/human gate is an owning-operator trial on two authorized private relays with existing real principals and keys: back up compatible source/state, perform the explicit configuration/state migration rather than relabeling canary bindings, install the exact reviewed successor, run one correlated encrypted useful-work duplex, read back transport ACK and semantic result separately, verify restart/same-ID reconciliation, then stop or promote under the existing owner grant. No public push, deployment, credentials, identities, production relay, or external listener is authorized by this local candidate.
