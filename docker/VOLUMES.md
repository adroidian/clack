# Clack relay — persistent volume layout

All relay state lives under `CLACK_RELAY_BASE` (default `/data` in the
image, mounted as the `clack-data` named volume). The relay code itself
(`/app`) is stateless and replaceable; **the volume is the relay**.

```
/data/
├── relay-config.json        # operator config — MODE 600, contains secrets
├── relay.db                 # sqlite database (WAL mode)
├── relay.db-wal             # sqlite write-ahead log (runtime, ephemeral)
└── relay.db-shm             # sqlite shared memory  (runtime, ephemeral)
```

## relay-config.json

Generated on first boot by the entrypoint (never shipped with a key).
Treat it like a password vault:

| Field            | Contents |
|----------------|----------|
| `identity_key` | RSA private signing key (`n`/`e`/`d` hex). **This IS the relay's identity.** Every client's TOFU pin (`/v1/identity` fingerprint) is derived from it. Lose it → every peer must re-pin; leak it → someone can impersonate the relay's identity endpoint. |
| `peers`        | `{name: bearer token}` — live service tokens, plaintext. |
| `operators`    | Operator peer names (elevated endpoints). |
| `reserved_names` | `{name: 32-byte b64url identity pubkey}` — squat protection. |
| `enrollment` / `pow_difficulty` / `port` / `base_url` | Policy + addressing. |

## relay.db

SQLite, WAL journal mode. Tables: `peers`, `messages`, `webhooks`,
plus v0.2.5+ invite-link tables. Only **sha256 hashes** of bearer tokens
are stored here (plaintext tokens live in the config, not the db) —
but message *content* is here, so it is still private data.

## Backup

- **What to back up:** `relay-config.json` + `relay.db`. That's the whole relay.
- **How:** `docker stop clack-relay`, copy both files off the volume,
  `docker start clack-relay`. (Or `sqlite3 /data/relay.db ".backup main /backup/relay.db"`
  against a live container for the db, plus a straight copy of the config —
  the config is only rewritten by the operator, never by the relay.)
- **Encrypt the backup.** The config holds a private key and live tokens.
- **Restore:** fresh volume, drop the two files in, start the container.
  Identity key unchanged → clients' TOFU pins keep working.

## Upgrade

Pull/build the new image tag, recreate the container against the **same
volume**. The entrypoint only generates config when none exists, so the
identity key and peer roster survive upgrades untouched. The relay runs
its own sqlite migrations at startup (`init_db`).
