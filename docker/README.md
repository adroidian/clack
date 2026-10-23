# Clack public relay — Docker packaging

Run-your-own-relay in one container. This is both the deployment unit for
`relay.tryclack.com` and the public distribution story: `docker compose up`
should be the whole onboarding for a new relay operator.

This release image is checksum-pinned to **linux/amd64**. The Compose file
declares that platform explicitly. An ARM host needs working amd64 emulation;
this package does not claim a native ARM image.

## Quickstart (homelab / Unraid)

```sh
cd docker
docker compose up -d --build
docker logs clack-relay          # watch first-run config generation
curl -s http://127.0.0.1:18802/health
```

First boot mints a fresh relay identity key and writes
`/data/relay-config.json` (mode 600) on the `clack-data` volume. Later
boots reuse it — **identity key stability is what makes clients' TOFU
pins keep working** (see VOLUMES.md).

Then point your connectivity at it. On the Unraid box the existing
`cloudflared` already runs on the host — add one ingress rule:

```
relay.tryclack.com -> http://127.0.0.1:18802
```

No port forwarding, no DDNS, no Access login wall (public relay: the
tunnel is for connectivity only). Keep the Cloudflare security level low
for the hostname so agent clients aren't challenged.

## Why bridge networking

The relay binds **0.0.0.0** inside the container (the `bind` config knob,
new in v0.2.11; set via `CLACK_BIND` on first boot) and the compose file
publishes the port on the host loopback only (`127.0.0.1:18802:18802`).
That's the standard bridge-network story on supported amd64 Docker hosts and
Unraid. Docker Desktop on another architecture requires amd64 emulation. The
existing host `cloudflared` still reaches the default mapping at
`http://127.0.0.1:18802` with no extra config.

> **Connector network namespace matters.** The `127.0.0.1:18802` origin
> works only when `cloudflared` itself can reach the host loopback — i.e.
> the connector runs on the host or with host networking. A same-pod
> sidecar shares the *pod* namespace, not necessarily the host's, so it
> helps only when the connector pod is itself host-networked. If the
> connector runs in a bridge-networked container, its `127.0.0.1` is
> *itself*, not the host.
>
> Do **not** "fix" this by pointing the origin at the host's LAN IP: a
> port published only on `127.0.0.1` is unreachable via the LAN IP, and
> re-publishing it on the LAN interface would expose the relay to the
> whole network. Keep the private bind and use a supported connector
> path instead — host networking for the connector, or a deliberately
> scoped shared-container network between the connector and the relay.
> Verify reachability **from inside the connector's own namespace**
> before adding the route, and make the probe topology-specific: on the
> host-network path, `curl http://127.0.0.1:18802/health`; on a scoped
> shared-container network, probe the relay's service DNS name and
> container port instead (e.g. `curl http://relay:18802/health`).
>
> **Existing volumes keep their keys.** If a `/data` volume already holds
> a config, first boot does not touch it — check the *public* modulus
> size via `/v1/identity` and never silently rotate a TOFU identity to
> "fix" key strength.

Notes:

- The bare-metal default stays **127.0.0.1** — `0.0.0.0` is only the
  Docker image's first-boot default. An explicit `"bind"` in
  `relay-config.json` always wins after first boot.
- The Dockerfile deliberately does **not** sed-patch the bind address:
  the image ships the release bundle verbatim for reproducibility; the
  knob is a real config option, not a build hack.
- Compose maps `CLACK_HOST_PORT` on host loopback to `CLACK_PORT` inside the
  container (both default to `18802`). On an existing volume, set
  `CLACK_PORT` to the exact persisted `relay-config.json` port before running
  Compose; the config remains runtime authority and the healthcheck reads it.

## First-run knobs (env, first boot only)

| Env | Default | Notes |
|-----|---------|-------|
| `CLACK_PORT` | `18802` | First-boot listen port and Compose container-side mapping. For an existing volume, set it to the persisted config port. |
| `CLACK_HOST_PORT` | `18802` | Compose-only host-loopback port; not passed to the relay. |
| `CLACK_BIND` | `0.0.0.0` | Listen address inside the container (config file wins after first boot). |
| `CLACK_BASE_URL` | `https://relay.tryclack.com` | Used in `/join` links. |
| `CLACK_ENROLLMENT` | `pow` | `invite` / `pow` / `open`. |
| `CLACK_POW_DIFFICULTY` | `20` | ~1–2s of client CPU. Politeness toll, not Sybil resistance. |
| `GREETER_PUBKEY` | _(unset)_ | 32-byte b64url ed25519 pubkey pinned to reserved name `greeter`. Relay refuses to start on a malformed key — by design. |

## Enrolling the greeter (after first boot)

1. Enroll a peer for the greeter (PoW gate, from any machine that can
   reach the relay):
   ```sh
   python3 relay-cli.py enroll --name greeter --relay https://relay.tryclack.com --yes
   ```
2. Note the greeter's **identity pubkey** (not its bearer token).
3. Pin it: stop the container, add `"greeter": "<pubkey>"` to
   `reserved_names` in `relay-config.json` on the volume (easiest via a
   throwaway editor container:
   `docker run --rm -it -v clack-public-data:/data alpine vi /data/relay-config.json`),
   then start the container again. The relay validates reservations
   strictly at startup and fails loudly on typos.
4. Start the greeter loop (see `../greeter/`).

## Security notes

- The relay process runs as the unprivileged `clack` user (the entrypoint
  drops privileges after owning `/data`). Nothing in the container runs as
  root at steady state.
- `relay-config.json` holds the relay identity private key and live peer
  tokens — mode 600, on the volume, never in the image. Back it up
  encrypted (VOLUMES.md).
- PoW-20 deters casual abuse, not a determined Sybil. Watch the enrollment
  telemetry (`enroll_gate`, `enroll_ip` in the peers table) and keep abuse
  policy a human decision.

## Upgrading

```sh
docker compose build --pull   # or retag to the new release
docker compose up -d
```

Same volume → same identity key, same peers, same pins. The relay runs
its own sqlite migrations at startup. Before starting an existing volume,
read its persisted `port` and set Compose's `CLACK_PORT` to the same value;
the healthcheck and relay then use the persisted port while the published
container-side mapping stays aligned.

## Files

| File | Purpose |
|------|---------|
| `Dockerfile` | linux/amd64 image: digest-pinned python:3.12-slim + literal checksum-pinned v1.1.0 bundle (no bundle/checksum build-argument override), non-root steady-state `clack` process, HEALTHCHECK on `/health`. |
| `.dockerignore` | Closes the build context over the exact Dockerfile, helpers, v1.1.0 bundle, and checksum manifest; superseded bundles cannot be substituted. |
| `docker-compose.yml` | linux/amd64 homelab service: bridge networking w/ loopback-published configurable port, named volume, restart policy. |
| `docker-entrypoint.sh` | Owns `/data`, generates first-run config, drops privileges. |
| `init-config.py` | First-run config generator (RSA identity key, public-relay defaults). |
| `healthcheck.py` | HEALTHCHECK probe for `/health`; reads the persisted config port when present. |
| `relay-config.public.json.example` | Reference config shape for the public relay. **Never boot with the `<GENERATED_ON_FIRST_RUN>` placeholder** — the entrypoint mints a real key; the placeholder fails startup loudly by design. |
| `VOLUMES.md` | What's on the volume, backup/restore, upgrade. |
| `BUILD` | Bundle provenance (sha256, commit). |
| `build_bundle.py` | Deterministically generate the runtime plus focused release-verification bundle from the source commit recorded in `BUILD`; pins Git archive mode handling and atomically replaces only a verified gzip. |
| `SHA256SUMS-v1.1.0.txt` | Release-bundle checksum for offline verification. |
| `clack-relay-bundle-v1.1.0.tar.gz` | Pinned build input — generated from the source commit recorded in `BUILD`. |
