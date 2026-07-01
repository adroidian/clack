# Public Mirror Scrub Gate v0

Status: pre-mirror gate
Updated: 2026-06-29

## Purpose

Define the required scrub gate before any Clack repository content is mirrored to a public GitHub repository.

This gate is not a mirror action and does not authorize publishing. It defines the proof required before publishing can be requested.

## Hard rule

No public mirror until the tree passes a private-topology scrub and any remaining findings are either removed, rewritten to public-safe examples, or explicitly quarantined outside the public mirror set.

## Forbidden in public mirror content

Public mirror content must not include:

1. live hostnames or internal domains;
2. live private IPs or Tailscale `100.x.x.x` addresses;
3. route records that point at real hosts, wake URLs, receiver endpoints, or internal mesh services;
4. credential handles, token names that identify live secret paths, bootstrap secret paths, or Authole/a secret manager lookup coordinates;
5. personal agent/human identifiers when public anonymization is required, including `agent://*.aaron` and `human://example` examples;
6. deployment docs that read as current operational instructions rather than legacy/private archaeology;
7. live gateway, wake receiver, DNS, ingress, or production rollout commands.

## Public-safe replacements

Use neutral examples:

| Private/live shape | Public-safe replacement |
|---|---|
| `agent://zari.example` | `agent://zari.example` |
| `agent://vesper.example` | `agent://vesper.example` |
| `human://example` | `human://example` |
| `100.x.x.x` | `127.0.0.1` only in documentation that clearly says TEST-NET/example, otherwise `127.0.0.1` |
| internal domain names | `example.invalid` |
| live wake URL | `http://127.0.0.1:15300/wake` or `http://example.invalid/wake` |
| real secret path | `secret-manager://example/path` |

## Mirror set policy

Before public mirror, each file must be classified as one of:

- `public-safe`: may be mirrored as-is.
- `rewrite-first`: must be rewritten/anonymized before mirror.
- `private-archaeology`: keep in private Gitea only; exclude from public mirror.
- `delete-before-mirror`: remove from public mirror branch.

Legacy deployment docs are presumed `private-archaeology` unless a scrubbed public version is written.

## Required pre-mirror checks

Run the scrub scanner:

```bash
python3 tools/validation/check_public_scrub.py
```

The scanner searches for high-signal private topology patterns:

- Tailscale/private IPs like `100.x.x.x`;
- internal/private domains such as `*.internal` and configured private hostnames;
- `agent://*.aaron` and `human://example`;
- live wake/receiver URL variable names and known secret-path phrases;
- tokens/secrets in documentation/examples.

Scanner findings are not automatically fatal for private-only branches, but they are fatal for a public mirror candidate unless each finding is eliminated or the file is excluded from the mirror set.

## Receipt requirement

A public mirror PR must include a receipt with:

1. scanner command and output;
2. list of excluded private files;
3. list of rewritten/anonymized files;
4. confirmation that no live service, DNS, ingress, wake receiver, route, production config, or credential changed;
5. remote mirror target and pushed commit SHA, if publishing is separately approved.

## Current known private/high-risk files

These files currently require special handling before any public mirror:

| File | Default mirror verdict | Reason |
|---|---|---|
| `docs/current-deployment.md` | `private-archaeology` | Live fleet snapshot and topology. |
| `docs/hermes-receiver.md` | `rewrite-first` or `private-archaeology` | Live-style receiver endpoint and wake examples. |
| `config/gateway.example.yml` | `rewrite-first` | Private hostnames, agent names, token-path vocabulary. |
| `adapters/hermes-receiver.env.example` | `rewrite-first` | Tailscale receiver host example. |
| `specs/architecture/clack-relay-v0.md` | `rewrite-first` | Personal agent/human IDs and internal relay examples. |
| legacy registry/config docs | `rewrite-first` | Route/wake URL field lineage and secret-path vocabulary. |

## Rollout boundary

Public mirror scrub is separate from agent rollout testing.

- Public mirror approval does not approve live rollout.
- Agent rollout approval does not approve public mirror.
- Both require separate receipts.

Subtlety status: intentionally alive. These gates are different doors.
