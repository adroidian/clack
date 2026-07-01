# Clack artifact index v0

Status: canonical Phase 0 consolidation index
Updated: 2026-06-27

## Purpose

One card catalog for the Clack fossil pile. Every artifact below is classified before it is allowed to influence Clack Prime.

Classification key:

- `canonical-seed` — current design source.
- `reusable` — proven logic/pattern worth porting or wrapping.
- `legacy` — lineage/migration context only.
- `stale` — known mismatch; preserve but do not build from it.
- `unknown` — inspect before relying on it.

## Canonical seeds

| Artifact | Class | Status | Next use |
|---|---:|---|---|
| `specs/product/clack-product-scope-v0.md` | canonical-seed | Present | Product boundary and language discipline. |
| `specs/architecture/clack-build-plan-v0.md` | canonical-seed | Present | Source-of-truth model and MVP gates. |
| `specs/architecture/clack-artifact-index-v0.md` | canonical-seed | Present | This artifact catalog. |
| `specs/protocol/clack-envelope-v0.md` | canonical-seed | Present | Protocol implementation target. |
| `specs/protocol/clack-receipt-v0.md` | canonical-seed | Present | Proof/receipt implementation target. |
| `specs/protocol/clack-capability-policy-v0.md` | canonical-seed | Present | Capability tiers and guardrails. |
| `specs/protocol/cns-agent-identity-v0.md` | canonical-seed | Present | CNS identity schema. |
| `specs/protocol/cns-route-record-v0.md` | canonical-seed | Present | CNS route schema. |
| `specs/protocol/cns-capability-grant-v0.md` | canonical-seed | Present | Grant schema. |
| `specs/protocol/cns-heartbeat-v0.md` | canonical-seed | Present | Liveness/TTL semantics. |
| `specs/architecture/clack-relay-v0.md` | canonical-seed/design | Present | Future relay design only; no live deploy. |
| `specs/architecture/adapter-salvage-inventory-v0.md` | canonical-seed/inventory | Present | Keep/port/retire gate for legacy adapters before porting. |
| `specs/architecture/public-mirror-scrub-gate-v0.md` | canonical-seed/gate | Present | Public mirror scrub policy and scanner requirements. |
| `specs/architecture/live-rollout-gate-v0.md` | canonical-seed/gate | Present | Live rollout approval packet and no-mutation boundary. |
| `specs/architecture/clack-prime-design-decisions-v0.md` | canonical-seed/decision | Present | Resolved v0 identity, route, trust, TTL, relay, and grant decisions. |

## Reusable implementation lineage

| Artifact | Class | Status | Next use |
|---|---:|---|---|
| `adapters/hermes-receiver.py` | reusable | Present in repo | Hermes wake adapter seed; requires explicit live-service approval before deployment. |
| `docs/current-deployment.md` | reusable/legacy | Present in repo | Deployment archaeology; label as legacy/private before public mirror. |
| `docs/hermes-receiver.md` | reusable/legacy | Present in repo | Receiver behavior notes; not a Clack Prime spec. |
| Zari workspace `tools/clack_server.ex-current.py` | reusable | Archived outside repo | Compare against Clack 1.0 server before porting store/dedupe/retry semantics. |
| Zari workspace `tools/clack_send.py` | reusable | Archived outside repo | Salvage sender/fallback semantics; scrub secret handling. |
| Zari workspace `tools/clack_multi_server.py` | reusable | Archived outside repo | Multi-agent host receiver pattern. |
| Zari workspace `tools/agent_registry.py` | reusable | Archived outside repo | Registry/card field lineage for CNS migration. |
| Zari workspace `unraid-sources/kindred/workspace-pacs/projects/clack-1.0/` | reusable | Archived outside repo | Compare tests/server/client against current tools. |
| Zari workspace `unraid-sources/kindred/workspace-pacs/chitin-os/packages/clack/` | unknown → inspect | Archived outside repo | Review before porting package code. |
| Zari workspace `unraid-sources/kindred/workspace-pacs/.clone-clack-v2/projects/clack-router/` | unknown → inspect | Archived outside repo | Review router ideas only after Phase 1 docs are frozen. |

## Legacy / stale lineage

| Artifact | Class | Status | Rule |
|---|---:|---|---|
| Zari workspace `tools/kns_clack_heartbeat.py` | legacy/stale | Archived outside repo | Rename/migrate to CNS; do not expose KNS forward-facing. |
| Zari workspace `unraid-sources/kindred/workspace-pacs/projects/kns/` | legacy | Archived outside repo | Migration reference for CNS heartbeat/route semantics. |
| `config/env.example` route env shape | compatibility/stale-risk | Present in repo | Env-driven routes are compatibility only, not future identity. |
| `tailscaleIp` / live host route fields | stale direction | Seen in legacy docs | Route record fallback only; never primary identity. |

## Validation assets

| Asset | Status |
|---|---|
| `specs/fixtures/valid-envelope.json` / `invalid-envelope.json` | Present |
| `specs/fixtures/valid-receipt.json` / `invalid-receipt.json` | Present |
| `specs/fixtures/valid-agent-identity.json` / `invalid-agent-identity.json` | Present |
| `specs/fixtures/valid-route-record.json` / `invalid-route-record.json` | Present |
| `specs/fixtures/valid-capability-grant.json` / `invalid-capability-grant.json` | Present |
| `tools/validation/validate_clack_docs.py` | Present; latest check count: 10 |

## Hard rails

- No live Clack, gateway, route, wake, credential, ingress, or production service changes during Phase 0.
- Store-only/dead-drop is partial Clack, not full Clack.
- Direct health is not delivery proof.
- Wake requires wake-output receipt.
- Full Clack means routing + push + wake + receipts under CNS capability policy.

## Public mirror scrub notes

Before GitHub mirror, replace or remove:

- live host names and topology in legacy deployment docs;
- internal domains such as `example.invalid`;
- personal personal/private agent and human namespaces examples if public anonymization is required;
- any IPs, route records, credential handles, or private wake URLs.
