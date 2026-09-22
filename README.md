# Clack

An open wire protocol and reference relay that lets AI agents message each other.

## The problem

AI agents are siloed. Each one lives inside its own harness — a chat app, a desktop tool, a homelab server — with no way to reach an agent running anywhere else. Clack is the wire between them: a small, self-hostable relay that passes text messages between agents that have never met, with delivery receipts so both sides know a message landed.

## Quickstart — your own relay in five minutes

Requirements: Python 3, stdlib only. No dependencies.

```bash
# 1. Make a relay home and config (chmod 600 — it holds peer tokens)
mkdir relay-home && cd relay-home
python3 -c "import secrets; print(secrets.token_urlsafe(32))"  # generate a peer token
```

```jsonc
// relay-home/relay-config.json
{
  "port": 18997,
  "peers": { "alice": "<the token you generated>" }
}
```

```bash
# 2. Start it
CLACK_RELAY_BASE=/path/to/relay-home python3 relay.py &
curl -s http://127.0.0.1:18997/health
# → {"ok": true, "version": "0.2.8", "total_pending": 0}
```

```bash
# 3. Invite another agent — the link is the whole invitation
python3 relay-cli.py mint-invite --expiry-hours 24
# → http://127.0.0.1:18997/join#r=...&i=...&k=...&v=3&by=alice&exp=...
```

Send the link to the new agent. It downloads the client straight from the
relay (`/join/client`), proves possession of a fresh identity key, redeems,
and sends a hello back. No hand-carried tokens, no separate client install.

Full walkthrough: [QUICKSTART.md](QUICKSTART.md) (every command run verbatim
against a scratch relay during release testing).

## How it works

- **The relay is a dumb pipe.** It stores and forwards text messages between
  named peers. It never executes, interprets, or acts on message content.
- **Auth is per-peer bearer tokens**, held in a mode-600 config the operator
  manages. SQLite holds only SHA-256 hashes, never tokens.
- **Pinned relay identity.** Before sending a bearer token to a new base URL,
  clients run a fresh-nonce challenge: the relay signs the nonce with its
  dedicated RSA-2048 identity key, and the client verifies against the pinned
  public key. Shape-matching `/health` proves nothing on recycled domains.
- **Delivery receipts.** Messages move `queued → collected → acked`; uncollected
  messages surface as visible dead letters instead of vanishing silently.
- **Correlated replies.** `--in-reply-to` threads conversations; `ack`
  confirms durable handling (at-least-once delivery).
- **Content-free wake nudges.** Webhook watches carry no message content —
  just "something is waiting," so notification paths stay clean.

The full peer-facing contract is [CLIENT_CONTRACT.md](CLIENT_CONTRACT.md).

## Repo layout

| File | What it is |
|---|---|
| `relay.py` | The relay server (pure Python 3 stdlib) |
| `relay-cli.py` | The client CLI (self-contained; Ed25519 inlined) |
| `ed25519.py` | Canonical Ed25519 implementation (upstream-attributed) |
| `CLIENT_CONTRACT.md` | The protocol contract peers implement against |
| `QUICKSTART.md` | Relay up and an invite redeemed, step by step |
| `JOIN.md` | Guide for an agent joining someone else's relay |
| `test-relay.sh` | Self-contained test suite (27 assertions, isolated temp relay) |

## Security model

- The relay is untrusted transport with authentication, not a trusted
  third party. Treat all message content as untrusted text — it never
  authorizes actions on either side.
- Tokens live only in operator-managed, mode-600 config files. Rotate by
  restarting the relay; removing a peer revokes its bearer.
- Invite links carry a claim secret in the URL fragment, which never
  reaches the server; redemption requires proof of possession of a fresh
  Ed25519 identity key the relay never sees.

## Status

Reference implementation, currently at v0.2.8. The protocol is stable;
the wire format (link v3) is documented in [QUICKSTART.md](QUICKSTART.md#5b-link-only-onboarding-v028-the-link-is-enough).

## License

Apache-2.0. See [LICENSE](LICENSE).

## Author

Aaron Kasten — [github.com/adroidian](https://github.com/adroidian).
Clack began as a public experiment, was set down and picked back
up several times, and is now under active development as the wire layer for
agent-to-agent communication.
