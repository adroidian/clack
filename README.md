# Clack

> **The sound of the keys a user never needs to press.**

Clack is an **open-source coordination fabric for private agent fleets**: identity, routing, wake, receipts, queues, artifact handoff, and scoped capability grants across machines and networks.

It is not a chat app. It is not a Slack clone. It is not another place for humans to babysit bots.

Clack is the quiet layer underneath: agents finding each other, waking each other, handing off work, proving what happened, and asking for approval before they touch anything sharp.

```text
human intent -> trusted agent -> Clack -> target agent -> receipt
```

The name started with crabs clacking their claws to communicate. The theme moved on; the signal stayed. **Clack** is the small sound of coordination happening without turning a human into the router.

## Why Clack exists

As agent fleets grow, humans become accidental infrastructure:

- copy the message;
- wake the right agent;
- paste the file;
- check if work actually happened;
- decide whether the risky action is allowed;
- ask for the receipt later, usually too late.

Clack moves that coordination into a small auditable fabric.

| Human bottleneck | Clack primitive |
|---|---|
| “Can someone wake Nora?” | metadata-only wake request |
| “Did the task land?” | delivery receipt |
| “Who is allowed to do this?” | scoped capability grant |
| “Where does this agent live?” | CNS route record |
| “Can this wait offline?” | inbox / queue |
| “Which file are we talking about?” | artifact reference |
| “Did the agent respond?” | response receipt |

## What Clack does

Clack gives agents a shared coordination spine:

- **Agent identity** — stable `agent://...` identities instead of loose names.
- **CNS route records** — where an agent can currently be reached, with proof freshness.
- **DMs and channels** — agent-to-agent messages, task rooms, and threads.
- **Queues** — store-and-forward when the target is offline.
- **Wake** — metadata-only nudges; the target agent pulls full work under its own policy.
- **Receipts** — machine-readable proof for accepted, stored, delivered, woke, responded, or failed.
- **Capability grants** — scoped permission for DM, channel, wake, artifact, or tool-request actions.
- **Artifact references** — hand off file references without pretending Clack is a sync engine.

## What Clack is not

Clack is deliberately small.

- Not a human chat workspace.
- Not a Discord or Slack replacement.
- Not a general pub/sub bus.
- Not a credential broker.
- Not a production control plane by itself.
- Not “agents can run arbitrary commands on each other now.” Nice try, chaos goblin.

Humans stay outside the runtime. Agents are the interface when humans matter:

```text
Human operator -> agent://zari.example -> Clack
Partner operator -> agent://mercypix.example -> Clack
```

## The wake pattern

Clack wake is intentionally boring. Boring is how we avoid incident reports with dramatic music.

```text
1. Source agent sends a message or task into Clack.
2. Clack stores the work and emits receipts.
3. Clack sends a content-free wake hint to the target adapter.
4. Target agent wakes and pulls scoped work using its own identity.
5. Target agent replies or records a receipt.
```

Wake hints should not carry secrets, task bodies, or giant blobs of context. They prove that work exists. The agent comes to Clack to fetch the actual work.

## Architecture sketch

```text
                 ┌──────────────────────┐
                 │      Agent Fleet      │
                 │  Hermes / OpenClaw /  │
                 │  other local agents   │
                 └──────────┬───────────┘
                            │
                            ▼
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   clackctl   │────▶│    clackd    │────▶│ SQLite store │
└──────────────┘     └──────┬───────┘     └──────────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │ CNS + policy + routes │
                 │ receipts + queues     │
                 └──────────┬───────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │ Wake / transport      │
                 │ local HTTP, relay,    │
                 │ filedrop, adapters    │
                 └──────────────────────┘
```

## Repository status

This repository contains early **Clack Prime** work:

- Go daemon and CLI skeleton;
- SQLite-backed local store and migrations;
- protocol specs;
- JSON fixtures;
- validators;
- compatibility-adapter notes;
- public scrub tooling for keeping private topology out of the open-source repo.

It is useful today as a working protocol/spec + local skeleton. It is not yet a polished production service.

## Quick start

Requirements:

- Go
- Python 3

Run the local smoke path:

```bash
git clone https://github.com/adroidian/clack.git
cd clack
./scripts/smoke_phase2.sh
```

Expected tail:

```text
PHASE2_SMOKE_OK db=/tmp/clack-phase2-....db
```

Run the full local checks:

```bash
go test ./...
go vet ./...
./scripts/smoke_phase2.sh
python3 tools/validation/validate_clack_docs.py specs/fixtures/*.json
python3 tools/validation/check_public_scrub.py --root .
```

The public scrub gate should end with:

```text
PUBLIC_SCRUB_FINDINGS=0
```

## Read first

- [`specs/product/clack-product-scope-v0.md`](specs/product/clack-product-scope-v0.md) — product boundary.
- [`specs/architecture/clack-build-plan-v0.md`](specs/architecture/clack-build-plan-v0.md) — build gates.
- [`specs/protocol/`](specs/protocol/) — envelope, receipt, CNS identity, route, grant, and heartbeat docs.
- [`docs/registry-schema.md`](docs/registry-schema.md) — registry schema notes.

## Design principles

1. **Agents are first-class.** Humans are external policy/provenance, not runtime members.
2. **Wake is metadata-only.** Full work is pulled after identity and policy checks.
3. **Receipts are not vibes.** Coordination should leave machine-readable proof.
4. **Capabilities are scoped.** Permission is explicit, narrow, and reviewable.
5. **Local-first beats cloud-first.** Prove the spine before selling the cockpit.
6. **No private topology in public.** Examples use `.example`, `example.invalid`, or `127.0.0.1`.

## Safety rails

Do not put live credentials, private route records, private topology, production deployment configs, or real fleet receipts in this repository.

A wake request should carry metadata/proof only. Agents pull full work through Clack/CNS after policy checks.

## Tagline candidates

The working favorite:

> **Clack: the sound of the keys a user never needs to press.**

Other acceptable little gremlins:

- **Agent coordination without making humans the courier.**
- **Wake, route, approve, and prove agent work.**
- **The private nervous system for agent fleets.**
- **Small signal. Real receipt. No human router.**

Crab lore remains permitted in tiny doses. Full crustacean cosplay is not required for network reliability. Regrettably.
