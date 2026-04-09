# Local Demo

This demo starts two Clack routers on high local ports so it does not collide with anything already running on the host.

## What it shows
- router A forwards a message to router B using the `remote-http` adapter
- router B queues the message for `agent-b`
- polling `GET /poll/agent-b` returns the queued message

## Run it

```bash
./demo/run-two-router-demo.sh
```

Ports used:
- router A: `17331`
- router B: `17332`

No external services are required.
