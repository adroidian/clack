# Clack Build Plan v0

Status: draft for Aaron approval
Updated: 2026-06-23

## Executive decision

Build Clack as a robust open-source, agent-only coordination fabric.

- Core language: Go
- Storage: SQLite
- Specs: Markdown + JSON fixtures/schemas
- Working checkout: Teseract `./clack-worktree`
- Durable code SOT: Gitea on Unraid, mirrored to GitHub when public-safe
- Durable receipts/archive: Unraid + Zari workspace receipts

## Product scope

Canonical scope lives in `data/wiki/clack-product-scope-v0.md`.

Clack is agent-only. Humans are not runtime participants; agents are the human interface.

## Source-of-truth model

```text
Gitea on Unraid = primary code repository / source ledger
GitHub = public-safe mirror / shop window
Teseract ./clack-worktree = Claude Code workbench checkout
Unraid archive = lineage, receipts, recovered attempts, durable non-code artifacts
Zari workspace = operator notes, decisions, receipts, review copies
```

C: is not the source of truth. It is a workbench.

## Repository recommendation

Preferred canonical repo:

```text
Gitea: chitin/clack
GitHub mirror: adroidian/clack or chitin/clack if org exists
```

If `chitin/clack` is unavailable, use:

```text
chitin/clack-core
```

But prefer `clack` because the product is broader than core routing.

## Implementation architecture

```text
clack/
  cmd/
    clackd/                  # Go daemon
    clackctl/                # Go CLI
  internal/
    store/                   # SQLite persistence
    bus/                     # DMs, channels, threads, queues
    cns/                     # identities, routes, grants, heartbeat
    receipts/                # receipt creation/validation
    transport/               # local-http, filedrop, relay later
    wake/                    # wake adapter interface
  specs/
    product/                 # product scope
    architecture/            # build plan, decisions
    protocol/                # envelope, receipt, CNS docs
    fixtures/                # JSON fixtures
  adapters/
    python/                  # Hermes/OpenClaw helper clients
    node/                    # Chitin Gateway compatibility bridge
  tests/
    fixtures/
```

## MVP acceptance criteria

The first buildable MVP should prove, locally only:

1. `clackd` starts and creates SQLite store.
2. `clackctl agent register` registers two agents.
3. `clackctl dm send` sends agent-to-agent message.
4. `clackctl channel create` and `clackctl channel post` work.
5. Offline target gets queued inbox message.
6. Artifact reference attaches to message without bulk file sync.
7. Mention/wake request produces bounded wake receipt via stub adapter.
8. Receipts exist for accepted/stored/delivered/woke/responded/failed where applicable.
9. JSON fixtures validate.
10. No live gateway/service/route mutation required.

## Open-source boundary

Open-source:

- specs
- Go daemon and CLI
- SQLite schema/migrations
- local fixtures/tests
- generic adapters without secrets
- Chitin Gateway bridge if sanitized

Private:

- real home route records
- real agent topology
- credentials/secrets
- private wake policies
- deployment configs

## Build process

Use gate-based loop:

```text
Idea / scope
  -> formal plan by agent team
  -> Zari review
  -> Aaron approval
  -> build MVP
  -> Zari verification receipts
  -> demo / next gate
```

No further implementation until this plan is approved or amended.

## Immediate next tasks before implementation

1. Confirm/create Gitea repo `chitin/clack`.
2. Convert current Teseract packet into repo layout.
3. Move `data/wiki/*.md` into `specs/` while preserving original packet copy until review.
4. Create minimal Go module.
5. Add first SQLite schema migration.
6. Add fixture validator and smoke tests.
7. Push initial scaffold to Gitea.
8. Mirror public-safe repo to GitHub after secret/topology scrub.

## Questions for Aaron

1. Approve canonical repo name: `chitin/clack`?
2. Should initial Gitea repo be private until scrubbed? Recommended: yes.
3. Should GitHub mirror be created immediately or after MVP scaffold? Recommended: after scaffold + scrub.
4. Should Unraid archive path be `/mnt/user/Kindred/Clack/`? Recommended: yes.
