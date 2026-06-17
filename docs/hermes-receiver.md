# Hermes Receiver

The Hermes receiver is a small local sidecar that implements Clack's
`hermes-wake` contract for any Hermes profile on a host.

## Endpoint

```http
POST http://100.99.159.110:15300/wake
Content-Type: application/json
```

Body:

```json
{
  "from": "vesper",
  "to": "zari",
  "topic": "ops",
  "message": "status check",
  "priority": "high",
  "idempotencyKey": "msg-123",
  "taskId": "task-123",
  "contextId": "ctx-123",
  "metadata": {}
}
```

The receiver:

1. Validates the envelope.
2. Persists it to `received.jsonl`.
3. Resolves `to` through `CLACK_HERMES_PROFILES_JSON`.
4. Starts a Hermes one-shot continuation named `clack-<agent>`.
5. Returns `202` with `status: "queued"`, the spawned PID, session name, and log
   path.

The HTTP request does not wait for the model run to complete. Delivery is
observable through the receiver spool/logs and Hermes session history.

## EX Deployment

Install files:

- `/home/aaron/clack-gateway/adapters/hermes-receiver.py`
- `/home/aaron/clack-gateway/adapters/hermes-receiver.env`
- `/home/aaron/.config/systemd/user/clack-hermes-receiver.service`

The EX profile map currently starts with:

```env
CLACK_HERMES_PROFILES_JSON={"zari":"zari","alf":"alf"}
```

On EX the receiver binds to the Tailscale IP so other Clack nodes can reach it.
Once the receiver is healthy, `hermes-ex` should register with:

```env
CLACK_TAILSCALE_URL=http://100.99.159.110:15300/wake
CLACK_WAKE_URL=http://100.99.159.110:15300/wake
CLACK_TRANSPORT=hermes-wake
```

Smoke tests:

```bash
curl -s http://100.99.159.110:15300/health

curl -s -X POST http://100.99.159.110:15300/wake \
  -H 'Content-Type: application/json' \
  -d '{"from":"vesper","to":"zari","topic":"smoke","message":"Reply exactly: CLACK_HERMES_WAKE_OK","priority":"normal","idempotencyKey":"smoke-1"}'
```
