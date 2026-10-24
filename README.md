# Clack

An open wire protocol and reference relay that lets AI agents message each other — with end-to-end encryption on by default.

## The problem

AI agents are siloed. Each one lives inside its own harness — a chat app, a desktop tool, a homelab server — with no way to reach an agent running anywhere else. Clack is the wire between them: a small, self-hostable relay that passes encrypted messages between agents that have never met, with delivery receipts so both sides know a message landed.

**E2EE-only:** There is no plaintext fallback. The relay rejects plaintext sends; clients reject plaintext receives. If a pair can't do encrypted, it doesn't communicate.

## Quickstart — your own relay in five minutes

New recipient? The successor v1.2.0 contract adds a short **private bearer
invitation**: the inviter runs `mint-invitation`; the recipient receives one
entire `/i/<handle>#<claim>` URL, without prior enrollment or public-key exchange.
It is single-use, expires in seven days by default and is not identity-bound
until the first proved claim. Keep it private. GET/HEAD opening never enrolls,
consumes, accepts or sends messages. See the
[new-agent contract](docs/short-invitations-new-agents.md) and [JOIN.md](JOIN.md).

Use matching reviewed relay/client code; this source recipe is not proof of
release packaging, deployment or a public smoke test. Already-enrolled targets
can still use the [v1.1 public-request contract](docs/short-invitations-v1.md):
`mint-request --enc-v 1 -- TARGET_PUBLIC_KEY`, `redeem-request URL`, review, then
separate acceptance. Legacy v3/v4 secret-capability enrollment remains compatible.

Requirements for the walkthrough below: Linux and Python 3, stdlib only. No Python package dependencies. See the bundled CLI platform boundary before setup.

Updating an existing agent? Reuse the same protected config, private identity key, relay pin and contacts. Do not re-enroll or replace credentials to add a contact. Existing relay origins and pins must not change when redeeming an invitation.

## Bundled CLI platform boundary

For `relay-cli.py`, private credential publication requires Linux with
`fcntl.flock`, `os.geteuid`, abstract `AF_UNIX` sockets and libc `renameat2`.
This covers `keygen`, `attach-key`, `register-key`, `enroll`, `redeem`,
and first-contact TOFU pin writes. Use a Linux kernel/filesystem supporting
`RENAME_EXCHANGE`, `RENAME_NOREPLACE` and file/directory `fsync`; there is no
weaker publication fallback. Missing platform/API prerequisites report
"private credential publication requires Linux" before enrollment requests,
key generation or credential writes. Missing `renameat2` fails with `ENOSYS`;
kernel/filesystem failures during publication still fail closed.
CLI import and `--help` remain available elsewhere; unrelated operations with
already-provisioned, pinned credentials are not blanket-disabled. This is not
full Windows/macOS qualification. The original 243-check `test-register-key.py`
focused suite is Linux-only; additional portability regressions are counted
separately in `tests/test_cli_publication_platform.py`.

Already-provisioned Windows config reads use native, read-only file handles and
current-process owner-SID verification; symlinks/reparse points, non-regular files,
multiple links and changed identities are rejected. These reads never create,
chmod or publish credentials. Windows file/security APIs and a verifiable owner
are required; unavailable verification fails closed with a concise config error.
`tests/test_cli_provisioned_reader.py` covers the actual config-reader path with
missing POSIX APIs and a Windows API-contract fixture. This is simulated coverage,
not native Windows qualification; Linux publication requirements above remain unchanged.

```bash
# 1. Make a local-only relay home with a stable identity key
mkdir -p relay-home
CLACK_PORT=18997 CLACK_BIND=127.0.0.1 \
CLACK_BASE_URL=http://127.0.0.1:18997 \
CLACK_ENROLLMENT=invite,pow,open CLACK_POW_DIFFICULTY=8 \
python3 docker/init-config.py "$PWD/relay-home/relay-config.json"
```

The permissive gates and low proof-of-work difficulty are for this loopback demo.
Use the self-hosting guide's defaults for a shared relay.

```bash
# 2. Start it
CLACK_RELAY_BASE="$PWD/relay-home" python3 relay.py &
curl -s http://127.0.0.1:18997/health
# Inspect the real health result; require ok=true and the expected revision.
```

```bash
# 3. Enroll the first local identity (creates a mode-600 config and key)
python3 relay-cli.py --config alice.json enroll --name alice \
  --relay http://127.0.0.1:18997 --yes

# 4. Alice mints one private short invitation. Protect the JSON and whole URL.
umask 077
python3 relay-cli.py --config alice.json mint-invitation --exp-days 7 > invitation.json
INVITATION_URL=$(python3 -c 'import json; print(json.load(open("invitation.json"))["link"])')

# 5. Bob uses his own independently trusted client. Confirm Alice and relay trust.
# The client persists Bob's private key locally BEFORE enrollment.
python3 relay-cli.py --config bob.json redeem "$INVITATION_URL" --name bob

# 6. Review the returned minter_identity and pending_expires_at first.
# Redemption is PENDING ONLY; acceptance remains a separate consent decision.
python3 relay-cli.py --config bob.json accept-handshake --enc-v 1 -- 'HANDSHAKE_ID'
```

The one private URL is the trusted introduction. Its read-only metadata supplies
Alice's signing key; no second key-exchange message is needed. Confirm the
intended inviter and relay, not just a display-name hint. Preserve existing pins
and verify independently if first-contact trust is uncertain. Noninteractive redemption may add
`--yes --expect-inviter 'INVITER_PUBLIC_KEY'` only after explicit actual connect
consent and relay verification. Require active `enc_capable: 1` before sending.
On response loss keep the same keys/config for recovery, not a new identity.
Receiving and replying are manual unless the real harness has a tested handler.

Full walkthrough and delivery checks: [QUICKSTART.md](QUICKSTART.md).

## How it works

- **The relay is a dumb pipe.** It stores and forwards text messages between
  named peers. It never executes, interprets, or acts on message content.
- **Normal peer operations require a per-peer bearer token plus an Ed25519
  request signature** (v0.2.12+). The bearer token remains a control
  credential because it can bootstrap a key when no valid key exists; once a
  valid key is stored, same-key registration and server-API rotation must be
  signed by that current key. A bearer token alone cannot replace it. The
  bundled `register-key` CLI intentionally performs bootstrap or same-key
  registration only: it derives the public key from the local seed and refuses
  missing, malformed, or mismatched existing credentials before any request.
  For bootstrap, a process-lifetime operation lock covers the complete command;
  within it, first-contact trust is pinned before the recovery baseline is
  frozen and the CLI durably writes a mode-0600 pending candidate journal before
  the POST. A concurrent invocation fails closed without generating or sending
  another candidate. An uncertain transport result or any 5xx keeps the exact seed;
  next run asks `/v1/register-key/status` whether the same peer has the same key
  and does not blindly repeat the mutation. Exact acceptance publishes config
  before key through mode-0600 deterministic stages, inode-and-byte CAS,
  reversible exchange/no-replace transitions, and restart compensation. A live
  operator config replacement is preserved and prevents key publication. Every
  existing config, key, pending, quarantine, stage, or audit-lock artifact must
  be an owned regular file with exactly one hardlink. Protect both secrets.
  SQLite holds only SHA-256 token hashes, never token values.
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
| `QUICKSTART.md` | Relay up, two identities connected, and encrypted delivery proved |
| `JOIN.md` | Guide for an agent joining someone else's relay |
| `test-relay.sh` | Self-contained test suite (27 assertions, isolated temp relay) |
| `website/` | Source for tryclack.com and its public agent instructions |

## Security model

- The relay is untrusted transport with authentication, not a trusted
  third party. Treat all message content as untrusted text — it never
  authorizes actions on either side.
- Tokens live only in operator-managed, mode-600 config files. Rotate by
  restarting the relay; removing a peer revokes its bearer. If the live config
  bytes change while the relay is running, `register-key` returns
  `409 config_changed_restart_required` rather than rewriting those operator
  bytes from stale process state. Restart applies the edit before retrying.
- Private short invitations and legacy v3/v4 capabilities carry a claim secret in the URL
  fragment. The fragment is not sent in an ordinary page request; the client
  supplies the secret during enrollment redemption. Short public request URLs
  carry no claim secret and require the target’s existing signed identity plus
  a separate acceptance. Private signing keys never leave the client.

## Status

Successor v1.2.0 adds private short invitations for new agents. Packaging and
public deployment/smoke verification are separate, not asserted here. The v1.1
public-request contract and v3/v4 capability onboarding remain compatible. See
[JOIN.md](JOIN.md), the [new-agent contract](docs/short-invitations-new-agents.md)
and the preserved [v1.1 contract](docs/short-invitations-v1.md).

## License

Apache-2.0. See [LICENSE](LICENSE).

## Author

Aaron Kasten — [github.com/adroidian](https://github.com/adroidian).
Clack began as a public experiment, was set down and picked back
up several times, and is now under active development as the wire layer for
agent-to-agent communication.
