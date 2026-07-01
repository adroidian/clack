# Adapter Salvage Inventory v0

Status: Phase 0/1 inventory
Updated: 2026-06-29

## Purpose

Compare legacy Python/Node Clack lineage against Clack Prime before porting.
This document is an inventory gate, not a porting plan and not rollout permission.

Hard rail: no live gateway, wake receiver, route, DNS, ingress, credential, or production service changes are authorized by this inventory.

## Sources inspected

In-repo sources:

- `specs/architecture/clack-artifact-index-v0.md`
- `specs/architecture/clack-build-plan-v0.md`
- `docs/current-deployment.md`
- `docs/hermes-receiver.md`
- `adapters/hermes-receiver.py`
- `config/gateway.example.yml`
- `config/registry.schema.json`
- `docs/registry-schema.md`
- `systemd/clack-hermes-receiver.service`
- `systemd/clack-gateway.service`

Local search result for named legacy files under the available checkout/workspace:

- `clack_server*`: not present in this checkout.
- `clack_send.py`: not present in this checkout.
- `clack_multi_server.py`: not present in this checkout.
- `agent_registry.py`: not present in this checkout.
- Python files currently present in repo: `tools/validation/validate_clack_docs.py`, `adapters/hermes-receiver.py`.

Outside-repo lineage listed by the artifact index remains authoritative for later archaeology, but those files must be fetched/inspected before code is ported.

## Verdict key

- `keep` — preserve as documentation/design lineage.
- `port` — salvage behavior into Clack Prime after tests/spec alignment.
- `wrap` — keep as compatibility adapter around new Clack Prime model.
- `retire` — do not port; preserve only as fossil/rollback context.
- `inspect-first` — known lineage but unavailable in this checkout; no implementation decisions until read.

## Inventory

| Artifact | Current availability | Verdict | Salvage target | Notes |
|---|---:|---|---|---|
| `adapters/hermes-receiver.py` | Present | `wrap` then selective `port` | Future `wake` adapter interface and `hermes-wake` receipt behavior | Reusable sidecar pattern. Keep local-only until separately approved rollout packet. Do not bind live services from this PR. |
| `docs/hermes-receiver.md` | Present | `keep` | Wake adapter contract notes | Contains live-style examples and private topology; must be scrubbed before public mirror. Not a Clack Prime spec. |
| `docs/current-deployment.md` | Present | `keep` as legacy/private archaeology | Migration checklist only | Documents live fleet snapshot. Must not drive runtime mutation. Public scrub required. |
| `config/gateway.example.yml` | Present | `inspect-first` / `retire env-shape as authority` | Config compatibility notes | Useful for old gateway vocabulary, but CNS route records are the future source for liveness/routes. |
| `config/registry.schema.json` + `docs/registry-schema.md` | Present | `port concepts selectively` | CNS identity/route/grant migration fields | Useful field lineage. Do not preserve live host/IP examples as public contract. |
| `systemd/clack-hermes-receiver.service` | Present | `keep` as deployment archaeology | Future deployment packet template | Not active in local MVP. Requires explicit live-service approval before use. |
| `systemd/clack-gateway.service` | Present | `keep` as deployment archaeology | Future deployment packet template | Not active in local MVP. Requires explicit live-service approval before use. |
| `tools/clack_server.ex-current.py` | Archived outside repo | `inspect-first`, likely `port` store/dedupe semantics | Store-only receive path, idempotency, fallback receipts | Artifact index marks reusable, but file is unavailable here. Do not port blind. |
| `tools/clack_send.py` | Archived outside repo | `inspect-first`, likely `port` client fallback semantics | Sender retries, store-only fallback, receipt expectations | Scrub credential handling before any port. Do not port blind. |
| `tools/clack_multi_server.py` | Archived outside repo | `inspect-first`, likely `wrap`/`port` host multiplexing ideas | Multi-agent host receiver pattern | Useful for many agents per host, but Prime should express this via CNS identities/routes. |
| `tools/agent_registry.py` | Archived outside repo | `inspect-first`, likely `port` field mapping only | CNS identity/route/grant migration mapping | Registry/card fields may inform migration scripts; CNS schema is authoritative. |
| `kns_clack_heartbeat.py` | Archived outside repo | `retire` name, `port` TTL lesson only | CNS heartbeat TTL compatibility | KNS naming is stale. Preserve 300s `clack-http` TTL continuity; do not expose KNS as future surface. |
| `workspace-pacs/projects/clack-1.0/` | Archived outside repo | `inspect-first` | Tests/server/client behavior comparison | Compare tests before porting behavior. |
| `workspace-pacs/chitin-os/packages/clack/` | Archived outside repo | `inspect-first` | Package/deployment lineage only | Unknown until inspected. |
| `workspace-pacs/.clone-clack-v2/projects/clack-router/` | Archived outside repo | `inspect-first` | Future relay/router design ideas | Must not precede local Prime skeleton gates. |

## Porting order recommendation

1. **Hermes receiver contract extraction** — create adapter interface and fake/stub wake runner first; no live receiver.
2. **Legacy sender/server read-through** — inspect archived `clack_server*` and `clack_send.py` before porting retry/idempotency behavior.
3. **Registry field mapping** — map old registry/cards to CNS identity/route/grant migration docs.
4. **Multi-agent host pattern** — port only after CNS routes can model many agents per host without live topology leakage.
5. **Deployment templates** — keep systemd/config files quarantined until live rollout packet is approved.

## Keep/port/retire summary

| Category | Artifacts |
|---|---|
| Keep as archaeology | `docs/current-deployment.md`, `docs/hermes-receiver.md`, systemd units |
| Wrap now / port later | `adapters/hermes-receiver.py` |
| Port only after inspection | `clack_server*`, `clack_send.py`, `clack_multi_server.py`, `agent_registry.py`, `clack-1.0/` |
| Retire as forward-facing concept | KNS naming, env-driven routes as route authority, live IP/topology examples |

## Public mirror scrub impacts

Before any public mirror, scrub or rewrite:

- live hostnames, IPs, and private topology examples;
- personal/private agent and human namespaces if public anonymization is required;
- internal domains and route URLs;
- credential handles, token variable names that imply live secret paths, and wake URLs;
- deployment docs that read like current instructions rather than archaeology.

## Next gate

Do not port archived adapters until their source files are present in the working context and reviewed against:

- `specs/protocol/clack-envelope-v0.md`
- `specs/protocol/clack-receipt-v0.md`
- `specs/protocol/cns-agent-identity-v0.md`
- `specs/protocol/cns-route-record-v0.md`
- `specs/protocol/cns-capability-grant-v0.md`
- `specs/protocol/cns-heartbeat-v0.md`
