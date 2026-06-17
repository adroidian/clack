# Observability

Clack Gateway exposes four read-only HTTP endpoints for human inspection and monitoring.
All endpoints are **unauthenticated** on the loopback interface.

> **Security requirement before tunnel exposure:** If you add a CF tunnel pointing at
> `localhost:15200` (e.g. `clack-next.kasnet.us`), these endpoints become internet-reachable.
> You MUST add CF Access in front of the tunnel AND configure gateway token auth before
> enabling the tunnel. Never expose these endpoints publicly without both layers:
> CF Access (zero-trust identity gate) + gateway token auth (per-request credential).
> Vesper owns the CF Access policy; coordinate before enabling the tunnel.

## Endpoints

### GET /health

Service liveness + component status.

```json
{
  "status": "ok",
  "uptime_seconds": 3600,
  "registry_agents": 10,
  "registry_stale": 0,
  "version": "2.0.0"
}
```

`status` is `"ok"` | `"degraded"` | `"unhealthy"`.
`degraded` = service running but one or more agents stale or unreachable.
`unhealthy` = service cannot route (registry empty, critical error).

### GET /registry

Full current registry state. Shows all registered agents, their URLs, harness type,
capabilities, and whether their heartbeat TTL is still valid.

```json
{
  "agents": [
    {
      "agentId": "sable",
      "hostId": "omni",
      "harnessType": "openclaw",
      "tailscaleUrl": "http://100.x.x.x:15100",
      "publicUrl": null,
      "capabilities": ["memory", "search"],
      "expiresAt": "2026-04-28T17:00:00Z",
      "status": "active"
    }
  ],
  "total": 10,
  "stale": 0,
  "as_of": "2026-04-28T16:58:42Z"
}
```

`status` per agent: `"active"` | `"stale"` | `"offline"`.

### GET /routes

Current routing table — which agentId maps to which resolved endpoint, and which
URL (tailscale vs public) is currently preferred.

```json
{
  "routes": [
    {
      "agentId": "sable",
      "resolvedUrl": "http://100.x.x.x:15100",
      "via": "tailscale",
      "fallbackAvailable": false
    }
  ]
}
```

### GET /deliveries/recent

Last N delivery attempts (default 500, configurable in `gateway.yml`).
Shows message ID, sender, target, status, retry count, and timing.

```json
{
  "deliveries": [
    {
      "messageId": "abc123",
      "from": "loom",
      "to": "sable",
      "status": "delivered",
      "attempts": 1,
      "durationMs": 42,
      "timestamp": "2026-04-28T16:55:01Z"
    },
    {
      "messageId": "def456",
      "from": "vesper",
      "to": "daisy",
      "status": "failed",
      "attempts": 3,
      "error": "timeout",
      "timestamp": "2026-04-28T16:54:00Z"
    }
  ],
  "total_shown": 2,
  "retention": 500
}
```

`status` values: `"delivered"` | `"failed"` | `"retrying"` | `"dead-lettered"`.

## Useful one-liners

```bash
# Quick health check
curl -s http://localhost:15200/health | jq .status

# List all active agents
curl -s http://localhost:15200/registry | jq '.agents[] | select(.status=="active") | .agentId'

# Show stale agents
curl -s http://localhost:15200/registry | jq '.agents[] | select(.status=="stale")'

# Show recent failures
curl -s http://localhost:15200/deliveries/recent | jq '.deliveries[] | select(.status=="failed")'

# Show dead-lettered messages
curl -s http://localhost:15200/deliveries/recent | jq '.deliveries[] | select(.status=="dead-lettered")'
```

## Notes on upstream coverage

These endpoint contracts are defined by Chitin. `openclaw-a2a-gateway` provides `/health`
and basic registry state natively. If `/routes` or `/deliveries/recent` are not provided
by the upstream, a thin shim middleware layer in `app/chitin-shim.js` will implement them
before the gateway is promoted to prod. Vesper owns the decision on when the shim is
sufficient for cutover.
