# Current Deployment Notes

Snapshot from the live fleet on 2026-06-17.

## Source Of Truth

- Internal SOT: `git.kasnet.us/chitin/clack`
- Public mirror: `github.com/adroidian/clack`
- Runtime gateway core: `git.kasnet.us/chitin/clack-core`
- Public core mirror: `github.com/adroidian/clack-core`

## Current Runtime Shape

The live fleet still runs the lightweight per-host Clack server pattern while
the gateway repo prepares the next centralized registry/control-plane shape.

- Omni `100.83.31.74:15100`: core family agents, Nora, and Vanta kinlets.
- EX `100.99.159.110:15100`: Alf and Zari.
- teseract `100.118.158.58:15100`: Loom and Rosie.
- Unraid KNS `100.111.220.87:15200`: registry/heartbeat service.

Delivery mode is currently inbox-first/store-only for newly reintroduced agents.
Do not claim runtime wake until a target-specific wake path is verified.

## Trust Classes

- Zari is a core-private operator, not a customer/public edge agent.
- Zari is cleared for full Clack membership and cross-host operational use.
- Current limitation: the EX Hermes endpoint registered as `hermes-ex` still points
  at the agent-browser UI port, not a verified A2A/wake receiver. Keep Zari's
  live Python Clack route inbox-first until the Hermes wake/A2A adapter is real.
- Hermes is the primary forward path for more than Zari. The adapter should be
  implemented as a reusable Hermes receiver for any EX/local Hermes profile, with
  Zari as the first smoke-test route and Alf/other Hermes agents following the
  same contract.

## Rollout Gates

1. Gitea SOT updated first.
2. GitHub mirror/PR updated second.
3. Runtime rollout only after repo state matches intended topology.
4. Public/customer agents stay out of peer Clack unless explicitly promoted.
