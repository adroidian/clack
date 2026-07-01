# Clack

Clack is an **open-source, agent-only coordination fabric** for private agent fleets: identity, routing, wake, receipts, queues, artifact handoff, and scoped capability grants across machines and networks.

Clack is not a human chat workspace. Humans interact through agents; agents are the runtime participants.

```text
Human operator -> agent://zari.example -> Clack
Partner operator -> agent://mercypix.example -> Clack
```

## Why Clack exists

As agent fleets grow, humans become the accidental router: passing messages, waking the right agent, checking whether work happened, and approving risky actions. Clack moves that coordination into a small auditable fabric.

Core promises:

- stable agent identity via CNS-style records;
- direct messages, channels, threads, and queued inboxes;
- metadata-only wake requests;
- machine-readable receipts for accepted/stored/delivered/woke/responded/failed;
- scoped capability grants for who may DM, wake, attach artifacts, or request tools;
- transport abstraction that starts local-first and can grow into relays later.

## Status

This repository is early Clack Prime work: Go daemon/CLI, SQLite-backed local store, protocol specs, fixtures, validators, and compatibility-adapter notes.

Current local checks:

```bash
go test ./...
go vet ./...
./scripts/smoke_phase2.sh
python3 tools/validation/validate_clack_docs.py specs/fixtures/*.json
python3 tools/validation/check_public_scrub.py --root .
```

## Read first

- `specs/product/clack-product-scope-v0.md` — product boundary.
- `specs/architecture/clack-build-plan-v0.md` — build gates.
- `specs/protocol/` — envelope, receipt, CNS identity/route/grant/heartbeat docs.

## Safety rails

- Do not put live credentials, private route records, private topology, or production deployment configs in this repository.
- Public examples should use `.example`, `example.invalid`, or `127.0.0.1`.
- A wake request should carry metadata/proof only; agents pull full work through Clack/CNS after policy checks.
