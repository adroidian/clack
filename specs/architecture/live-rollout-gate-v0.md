# Live Rollout Gate v0

Status: hard gate
Updated: 2026-06-29

## Purpose

Separate local Clack Prime readiness from live agent rollout.

This document is intentionally conservative. It lets Clack get close to other-agent testing without accidentally mutating Ex, Omni, Teseract, Unraid, DNS, ingress, credentials, wake receivers, or production gateway state.

## Hard boundary

No live rollout is authorized by Phase 2/local MVP work.

Specifically, do **not** change any of the following until Aaron separately approves a rollout packet:

- Ex/Omni/Teseract/Unraid gateway services;
- Hermes receiver services;
- wake receiver bindings;
- CNS/registry route records for real agents;
- DNS, ingress, reverse proxy, firewall, Tailscale ACLs, or production ports;
- credential handles, tokens, bootstrap secrets, Authole grants, a secret manager paths, or secret injection;
- systemd/s6/user service enablement;
- public GitHub mirror publication.

## What is allowed before rollout approval

Allowed without separate rollout approval:

1. local SQLite store/schema/model work;
2. local CLI smoke tests;
3. docs/spec/fixture validation;
4. static adapter inventory and scrub gates;
5. fake/stub wake adapters that do not bind a real receiver or call a live agent;
6. read-only fleet inventory and rollout planning;
7. generating a rollout packet for review.

## Rollout packet requirement

Before testing with other live agents, prepare a rollout packet that names:

| Field | Required content |
|---|---|
| Target agents | Exact `agent://` IDs and host/lane. |
| Target hosts | Exact machine names and whether access is local, SSH, Tailscale, or other. |
| Services touched | systemd/s6/user service names, ports, paths. |
| Route records | New/changed route IDs, kinds, TTLs, endpoints, status. |
| Capability grants | Subject, target, capabilities, expiry, owner approval. |
| Credentials | Handles only; no raw values. Include required scopes and injection path. |
| Rollback | Commands/files needed to disable/revert. |
| Smoke test | Exact command/request and expected receipt. |
| Blast radius | What can receive messages, wake, or expose endpoints after change. |
| Receipt path | Where verification output will be saved. |

## Minimum rollout sequence

1. **Read-only preflight** — inspect target host state, ports, service files, and existing routes without changing anything.
2. **Single-host local bind** — bind to localhost only, prove local health.
3. **Single-agent store-only route** — prove inbox/store receipt without wake.
4. **Single-agent wake stub** — prove `woke` receipt via stub/fake runner, not live model wake.
5. **Single-agent live wake** — only after explicit approval; produce bounded receipt.
6. **Two-agent route test** — only after single-agent proof; use lowest-risk agents first.
7. **Mesh rollout** — separate approval after two-agent proof.

## Required verification before any rollout packet is eligible

The private Gitea `main` branch must pass:

```bash
go test ./...
./scripts/smoke_phase2.sh
go vet ./...
git diff --check
```

The local source state must be clean and remote-verified:

```bash
git status --short --branch
git rev-parse HEAD
git rev-parse origin/main
```

If public mirror is involved, the public mirror scrub gate must be completed separately.

## Explicit non-goals

This gate does not:

- publish a public mirror;
- deploy a gateway;
- start a receiver;
- create or rotate secrets;
- update route records for real agents;
- approve live wake tests;
- approve DNS/ingress/Tailscale changes.

## Agent testing readiness definition

"Ready to roll out to other agents for testing" means:

1. local model and store behavior are verified;
2. public/private scrub boundaries are known;
3. live rollout packet exists;
4. Aaron has approved the specific packet;
5. the first live test has a rollback and receipt path.

Until then, the correct status phrase is:

```text
local-ready; live rollout pending packet approval
```

## Current recommendation

Proceed next with resolving open design questions, then prepare a small first rollout packet for one low-risk local/stub agent path.

Tiny leash on the rocket. It may be a rocket, but it is still wearing the leash.
