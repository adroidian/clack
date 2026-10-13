# Private Federation operational adapter — #679

## Delivery boundary

This implementation lane begins at reviewed commit
`0d4cad64f860d424f46a0ee2de1cd6fb851b4fa0`, tree
`a64162d1cca302265c3b03bb2eedff3423a2bbaa`. The reviewed successor6 files,
shared main, relay implementation, and client implementation are unchanged.
The new adapter is an executable configurable Python runtime, not another
scenario-driver CLI. No service has been installed and no live identity,
key, grant, endpoint, profile, or production state has been changed.

The evidence is **disposable private loopback fixture proof**, not real
Labkin dogfood, pair-bootstrap approval, operator proof, independent review,
NDR recipient-delivery proof, or permission to merge/push/deploy.

## Runtime files and authority

- `federation_adapter.py`: `send`, `receive`, `reconcile`, signed `recheck`,
  `snapshot`, and configuration `status` CLI; also the `Adapter` Python API.
- `federation_authority.py`: mechanically retained reviewed authority
  algorithms, with explicit persistent-root/key/verifier binding and required
  transport injection. No fixture installer, default fixture identity,
  fixture transport, fixture CLI, or environment-selected authority remains.
- `docs/federation-operational-config.json.example`: secret-free references,
  no credentials and no operationally provisioned identities.
- `tests/test_federation_operational.py`: real HTTP/Ed25519/pin/SQLite fixture
  integrations against unmodified stock relays, including fresh processes.

The authority core is intentionally separate rather than changing the frozen
review candidate or importing its environment-dependent fixture module.
AST parity tests pin every retained function exactly except `_require_base`
(persistent root instead of `/tmp`-only, with configured inode replacement
refusal), `action` (mandatory transport, no fixture fallback or intentional
crash mode; fresh in-fence partition-cap evaluation), `authority_lock`
(pinned root identity rechecked after the blocking flock acquisition, before
any pathname DB open; Flint 685 R2), and `apply_partition_cap` (trusted
clock sampled inside the lock when `now=None`, transition statements shared
verbatim with the in-fence helper; Flint 685 R1). Future authority fixes must
be carried deliberately to both modules and pass parity or document a newly
reviewed divergence. This is bounded code duplication to preserve the
reviewed source and make the operational module independently importable.

One uid-owned mode-0700 canonical directory and its mode-0600
`federation-authority.db`/lock hold authoritative grants, generation,
watermarks, reservations, outbox, nonces, holds, tombstones and local NDRs.
The runtime adds only configuration binding, immutable message payloads, and
local inbox tables in that same database. It does not mirror grant state.
The configured directory device/inode is pinned for each process and
rechecked after every blocking lock acquisition, before the database is
opened by pathname; a root replaced during an ordinary lock wait refuses
subsequent mutation. The existing cross-process flock covers each
authoritative send fence through
transport completion. Delivery IDs are stable UUIDs; a different body or grant
cannot reuse an ID. All sends, retries, and receive acceptance evaluate the
configured finite partition cap with a fresh trusted-clock sample inside the
final serialized decision boundary itself: the `action` fence and the receive
acceptance transaction each re-evaluate the cap under the authority lock and
apply a due CAPPED transition atomically with that fence's
generation/NDR/hold/replay outcome, so ordinary serialization can never
carry a grant across expiry while only re-reading stored authority. The eager
pre-check passes `now=None` so its trusted timestamp is also sampled inside
the lock. The action point re-reads current authority.

`receive` maps authenticated relay sender + configured endpoint to exactly
one grant, re-reads that grant under the authority lock, and durably inserts
before relay ack. SUSPECT/CAPPED/REVOKED/unknown authority is not acknowledged
or delivered into the local inbox. Redelivery counters are excluded from
stable payload comparison. API `inbox_messages()` exposes locally accepted
messages to an explicitly scoped caller; there is no shell execution,
autonomous agent dispatch, or application-processing acknowledgement here.

`reconcile` handles durable payload-only checkpoints, ordinary authoritative
holds, and `reserved`/`inflight`/`failed-unknown`/`retry` reservations. Unknown
acceptance becomes a same-ID retry through the normal authority fence, never
a new ID. Terminal sent/released/NDR-resolved work remains terminal. An
ordinary SUSPECT hold can continue after a valid signed reopen; CAPPED work
without valid live hold lineage is not laundered into new authority.
Exactly-once claims stop at stock-relay `(sender,id)` deduplication. An inbox
consumer still needs its own application-level processing/ack discipline.

## Configuration and prerequisites (NOT executed here)

Use the example only after the designated operator separately approves the
real pair and provides **existing** compatible authority, approved grants,
identity/key/token/pin references, and verifier identity/public key. Copying
or relabeling any fixture store, keys, grants, or identity is prohibited.
The adapter refuses marked fixtures and `/tmp` roots in operational mode,
requires a separately supplied bootstrap reference of matching purpose/root,
and will not create/install a grant or mint a key.

The bootstrap reference has this exact JSON shape, created by the approved
bootstrap operator, not this runtime:

```json
{
  "schema": "clack-federation-bootstrap-reference-v1",
  "purpose": "operational",
  "approval_ref": "EXISTING OPERATOR APPROVAL RECEIPT",
  "state_dir": "/var/lib/clack-federation/operator-owned-pair"
}
```

This local reference is an operator-provided prerequisite, not a cryptographic
approval protocol or independent reviewer attestation. Existing authority DB
provisioning and its provenance must be checked by the operator separately;
the runtime intentionally supplies no bootstrap importer/installer.

Config, bootstrap, keys, token files, pin stores, evidence and text inputs
must be canonical uid-owned regular files, mode 0600, with no symlink
components. State is private and outside the repository. JSON schemas are
exact; duplicate keys and nonfinite numbers are denied. `timeout` is finite
and >0 through 60 seconds, `partition_cap_s` >0 through 86400 seconds.

Each endpoint explicitly selects an existing peer and separate token/key/pin
references. Pins map the exact URL origin to the existing relay fingerprint.
The stock client's challenge-response/pin verification is mandatory before
credentials; auto-pin is never enabled. Only numeric loopback/Tailscale
origins are allowed; port 18802 is conservatively excluded. Public origins,
URL credentials, alternate path/query/fragment transport routing, and
fixture access to non-loopback are refused. No relay discovery or peer grant
creation occurs. An endpoint's existing identity must already be enrolled and
have the approved handshake on the relay to which that route sends.

The complete configuration digest is bound once into the authority DB. Any
route, endpoint, identity reference, proof purpose, cap policy or timeout
change refuses existing state and needs an explicitly reviewed configuration
migration, not deletion of the binding row. Token content rotation behind an
existing reference is not a configuration migration; its permission gate
still belongs to the operator. Do not pass secrets in argv or JSON config.
The CLI sanitizes failure output and transport errors before durable recording.

Operational command shapes, to run only in the approved operator scope:

```sh
python3 federation_adapter.py --config /PRIVATE/runtime.json status
python3 federation_adapter.py --config /PRIVATE/runtime.json snapshot --name before-canary
python3 federation_adapter.py --config /PRIVATE/runtime.json send --grant APPROVED_GRANT --id STABLE_UUID --text-file /PRIVATE/message.txt
python3 federation_adapter.py --config /PRIVATE/runtime.json receive --endpoint CONFIGURED_RECEIVE
python3 federation_adapter.py --config /PRIVATE/runtime.json reconcile
python3 federation_adapter.py --config /PRIVATE/runtime.json recheck --evidence-file /PRIVATE/STATE/recheck.json
```

`status` proves local configuration/state binding only, not relay reachability,
real-pair consent, independent review, or deployment authorization. Successful
send prints relay-acceptance outcome only, not recipient application delivery.
Send returns exit 2 for held/uncertain/rejected, 1 for refused/configuration
errors. Reconcile emits per-message outcomes; inspect them even if its process
returns zero. Receive prints IDs only after durable local acceptance and ack.
Recheck accepts only the reviewed exact-schema signed evidence within the
state root and configured verifier identity/key; no raw generation/watermark
reopen argument, evidence minting, or terminal resurrection is exposed.

## Rollback and private checkpoint

1. Before an approved runtime canary, take `snapshot --name before-canary`.
   SQLite backup runs under the same authority flock, produces a new mode-0600
   file only, checks integrity, and fsyncs it. No key is included in the DB
   snapshot. Message payloads are private, so snapshots are private too.
2. To abort, stop **only the owned adapter invocations** through the approved
   operator's process handles. This runtime has no process killer, service
   installer, port cleanup, or cron creation. Preserve the current DB, lock,
   immutable payloads, held lineage and unknown-acceptance reservations.
3. Roll back code/config by returning to the last approved implementation
   while retaining the current authority ledger. This lane's base is the exact
   commit above; the new files can remain inert without affecting reviewed
   successor6. Do not run git reset against shared work or overwrite main.
4. **Never restore an older authority snapshot after any wire handoff.** That
   could erase tombstones, generations or dedup/reconciliation provenance.
   Quarantine a bad ledger and require an explicit reviewed recovery/migration
   with same-ID transport reconciliation. The snapshot is forensic/recovery
   evidence, not authority to erase newer transitions. No automatic destructive
   DB restore command is provided.
5. Real-pair activation still requires independent review of this exact lane,
   approved operator/pair-bootstrap proof and existing authority provenance,
   explicit private runtime/service-install scope, then a correlated signed
   duplex canary and rollback receipt. None is replaced by fixture results.

## Verification

The fixture suite owns fresh loopback relays per case and ownership-verifies
teardown. Fresh relays avoid exceeding the stock no-auth identity-proof rate
limit; no relay limit is weakened. Compatible fixture-only Python must expose
`Connection.iterdump`. In this host the following command scopes the existing
Python away from the injected profile overlay for fixtures only; the overlay
itself is not changed or weakened:

```sh
env PYTHONPATH= PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
env PYTHONPATH= PYTHONDONTWRITEBYTECODE=1 python3 reviews/test-v098-successor-regressions.py
```

Logs and exact commit/tree are recorded privately in the parent execution
receipt outside this source repository. This document records the runnable
contract, not self-certification by an independent reviewer.
