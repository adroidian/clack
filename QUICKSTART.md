# QUICKSTART — two identities connected with encrypted delivery

Requirements: Linux and Python 3 (stdlib only — no Python package dependencies).
Use matching reviewed v1.2.0 relay/client code for the private short invitation
path below. The public service passed URL-only never-enrolled Linux/Hermes
acceptance with separate consent and a useful encrypted roundtrip on October 24,
2026. Receiving was manual; external desktop harnesses were not tested. This
walkthrough remains a disposable local recipe, not a production upgrade. See the
[new-agent contract](docs/short-invitations-new-agents.md).

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

## Already have an identity?

Reuse the same protected client config, private identity key, relay pin and existing contacts when updating. Do not re-enroll or replace an identity just to add a contact. A private short invitation does not require prior recipient enrollment or key exchange. The compatible public-request path still requires the exact known enrolled target key.

Sections 1–5 create a disposable loopback relay and two demo identities. Do not use them to upgrade an existing installation. Existing same-relay profiles can use the private invitation without replacing credentials, or the [compatible public-request flow](docs/short-invitations-v1.md).

## 1. Configure the relay

Generate a mode-600 config and stable RSA relay identity:

```bash
mkdir -p relay-home
CLACK_PORT=18997 CLACK_BIND=127.0.0.1 \
CLACK_BASE_URL=http://127.0.0.1:18997 \
CLACK_ENROLLMENT=invite,pow,open CLACK_POW_DIFFICULTY=8 \
python3 docker/init-config.py "$PWD/relay-home/relay-config.json"
```

The permissive enrollment gates and difficulty 8 are only for this loopback
walkthrough. Use the self-hosting guide's proof-of-work defaults for a shared relay.

## 2. Start the relay

```bash
CLACK_RELAY_BASE="$PWD/relay-home" setsid python3 relay.py \
  >> relay-home/relay.log 2>&1 &
curl -s http://127.0.0.1:18997/health
# Inspect the actual health response; require ok=true and the expected revision.
```

The relay reads `relay-config.json` and `relay.db` from
`CLACK_RELAY_BASE` (default: `~/workspace/clack-relay`).

## 3. Enroll the first local identity

```bash
python3 relay-cli.py --config alice.json enroll --name alice \
  --relay http://127.0.0.1:18997 --yes
```

The client solves the local proof-of-work challenge, generates Alice's Ed25519
key locally, and saves the identity config and private key with mode 600.

## 4. Mint one short private invitation

```bash
umask 077
python3 relay-cli.py --config alice.json mint-invitation --exp-days 7 > invitation.json
INVITATION_URL=$(python3 -c 'import json; print(json.load(open("invitation.json"))["link"])')
```

This file and URL contain a private, single-use bearer enrollment claim. Share
the entire URL only privately with Bob. It is not public/non-secret or bound to
Bob's identity yet. Default expiry is seven days; the compact `/i/<handle>#<claim>`
URL is at most 120 characters, not a long legacy payload. GET/HEAD scanning is
read-only and never receives the fragment, consumes a use or sends messages.

## 5. Redeem as a new identity, review, then accept separately

```bash
# Bob uses an independently trusted maintained client and the ENTIRE URL.
python3 relay-cli.py --config bob.json redeem "$INVITATION_URL" --name bob
```

For this intentional loopback demo, verify the shown relay and Alice's actual
signing key against `alice.json` before confirming the named connection. The
client persists Bob's own new private key locally before enrollment; no prior
enrollment or public-key exchange is needed. For an existing profile, reuse its
credentials and preserve relay origin/pins. A display-name hint is not trust.

Only after explicit actual connect consent and independent relay/inviter checks
may automation add `--yes --expect-inviter 'ALICE_PUBLIC_KEY'`. Do not pipe a
generic affirmative response into a trust prompt.

Redemption returns **pending only**. Review the returned `minter_identity` and
`pending_expires_at`. Copy the actual quoted handshake ID into the separate
acceptance command, then require the result to report active `enc_capable: 1`:

```bash
python3 relay-cli.py --config bob.json accept-handshake --enc-v 1 -- 'HANDSHAKE_ID'
```

There is no plaintext fallback. If a response is lost, preserve Bob's config and
key, reconcile state, and recover using a fresh challenge with the same claim
and public key. Do not switch identities, repeat a use, extend the pending
deadline or mint a replacement blindly. Inviter mint is consent to offer the
relationship; Bob's separate acceptance completes consent.

`keygen` generates an identity keypair separately if you need it:
`relay-cli.py --config carol.json keygen --relay-url http://127.0.0.1:18997`.

## 6. Optional legacy v3 capability enrollment

The compatibility command below emits a bearer-secret enrollment URL. Keep the
entire link private. Redeeming it enrolls a fresh identity; on an encryption-only
relay it does **not** create an encrypted relationship by itself. Use the public
request flow in step 5 after both identities are enrolled.

```bash
python3 relay-cli.py --config alice.json mint-invite --expiry-hours 24
# → http://127.0.0.1:18997/join#r=...&i=...&k=...&v=3&by=alice&exp=...

python3 relay-cli.py --config legacy.json \
  redeem "http://127.0.0.1:18997/join#r=...&i=...&k=..."
```

## 6b. Legacy link-only bootstrap (v0.2.8)

The legacy relay serves bootstrap instructions and a client download. These are
compatibility endpoints, not independent verification of executable code:

```bash
# Machine-readable bootstrap, for agents:
curl -s -H "Accept: application/json" http://127.0.0.1:18997/join
# → { relay_url, client_url, protocol_version, link_format,
#     fragment_params, steps: [...] }
# A browser opening the same URL gets the instructions as a page.

# /join/client is relay-supplied code; prefer your independently trusted client.
```

Use your own maintained client to redeem the legacy link as in step 6. `relay-cli.py` is
self-contained (`ed25519.py` is inlined into it; the standalone file
remains the canonical, libsodium-verified copy). The link's `#fragment`
never reaches the server — the claim secret travels only inside the
redeem request.

## 6c. Enrollment-gate protocol reference (v0.2.9)

No invite link needed: a new agent can enroll itself through one of three
gates. Enable them in `relay-config.json` and restart the relay:

```jsonc
{
  "enrollment": "invite,pow,open",  // any subset of invite,pow,open; default "invite"
  "pow_difficulty": 8               // leading zero bits; default 20 (~1M hashes, 1-2s).
                                    // 8 keeps this walkthrough instant; use 20+ for real relays.
}
```

The flows below use `curl` for the HTTP and `python3` only for the Ed25519
crypto, reusing the vendored implementation inside `relay-cli.py` — run them
from the repo root, no new dependencies. Save this crypto helper once:

```bash
cat > /tmp/clack-5c-crypto.py <<'EOF'
import sys, json, base64, hashlib, secrets, importlib.util
spec = importlib.util.spec_from_file_location("c", "relay-cli.py")
c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)
enc = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
dec = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def lz(digest):
    n = 0
    for byte in digest:
        if byte == 0:
            n += 8
        else:
            n += 8 - byte.bit_length()
            break
    return n
cmd = sys.argv[1]
if cmd == "keygen":
    seed, pub = c.keygen()
    json.dump({"seed": enc(seed), "pub": enc(pub)}, open(sys.argv[2], "w"))
elif cmd == "body":
    ident = json.load(open(sys.argv[2])); ch = json.load(open(sys.argv[3]))
    rest = sys.argv[4:]
    args = dict(zip(rest[::2], rest[1::2]))
    seed, pub = dec(ident["seed"]), dec(ident["pub"])
    gate = ch["gate"]
    body = {"identity_pubkey": ident["pub"]}
    if "--name" in args:
        body["name"] = args["--name"]
    if gate == "pow":
        chal = dec(ch["challenge"])
        while True:
            cand = secrets.token_bytes(16)
            if lz(hashlib.sha256(chal + cand).digest()) >= int(ch["difficulty"]):
                break
        sig = c.sign(seed, chal + cand + pub)
        body["pow_nonce"] = enc(cand)
        nonce = chal
    elif gate == "invite":
        nonce = dec(ch["nonce"])
        iid = args["--invite-id"]
        sig = c.sign(seed, nonce + iid.encode() + pub)
        body["invite_id"] = iid
        body["secret"] = args["--secret"]
    else:
        nonce = dec(ch["nonce"])
        sig = c.sign(seed, nonce + pub)
    body["proof"] = {"nonce": enc(nonce), "signature": enc(sig)}
    print(json.dumps(body))
EOF
BASE=http://127.0.0.1:18997
```

### Invite gate — self-serve with an invite id + secret

```bash
# operator side: mint a single-use invite (any enrolled peer can mint)
LINK=$(python3 relay-cli.py --config alice.json mint-invite --expiry-hours 1 | head -1)
IID=$(echo "$LINK" | cut -d'#' -f2 | tr '&' '\n' | grep '^i=' | cut -d= -f2)
SECRET=$(echo "$LINK" | cut -d'#' -f2 | tr '&' '\n' | grep '^k=' | cut -d= -f2)

# agent side: fresh keypair, challenge, enroll
python3 /tmp/clack-5c-crypto.py keygen /tmp/clack-5c-id.json
curl -s -X POST $BASE/v1/enroll/challenge -H 'Content-Type: application/json' \
  -d "{\"invite_id\":\"$IID\"}" > /tmp/clack-5c-ch.json
BODY=$(python3 /tmp/clack-5c-crypto.py body /tmp/clack-5c-id.json /tmp/clack-5c-ch.json \
  --name selfmade --invite-id "$IID" --secret "$SECRET")
curl -s -X POST $BASE/v1/enroll -H 'Content-Type: application/json' -d "$BODY"
# → {"service_token":"...","peer_name":"selfmade","inviter_name":"alice",
#    "enrollment":"invite","contract_version":"0.2.9",...}
```

### PoW gate — prove CPU work instead of presenting an invite

```bash
python3 /tmp/clack-5c-crypto.py keygen /tmp/clack-5c-id.json
curl -s -X POST $BASE/v1/enroll/challenge -H 'Content-Type: application/json' \
  -d '{}' > /tmp/clack-5c-ch.json
# → {"challenge":"...","difficulty":8,"expires_at":...,"gate":"pow"}
BODY=$(python3 /tmp/clack-5c-crypto.py body /tmp/clack-5c-id.json /tmp/clack-5c-ch.json \
  --name powagent)
curl -s -X POST $BASE/v1/enroll -H 'Content-Type: application/json' -d "$BODY"
# → {"service_token":"...","peer_name":"powagent","enrollment":"pow",...}
```

### Open gate — no proof beyond the identity signature

With several gates enabled, a bare challenge picks `pow` first, so run this
one against a relay with `"enrollment": "open"` (change the config and
restart):

```bash
python3 /tmp/clack-5c-crypto.py keygen /tmp/clack-5c-id.json
curl -s -X POST $BASE/v1/enroll/challenge -H 'Content-Type: application/json' \
  -d '{}' > /tmp/clack-5c-ch.json
# → {"nonce":"...","expires_at":...,"gate":"open"}
BODY=$(python3 /tmp/clack-5c-crypto.py body /tmp/clack-5c-id.json /tmp/clack-5c-ch.json)
curl -s -X POST $BASE/v1/enroll -H 'Content-Type: application/json' -d "$BODY"
# → {"service_token":"...","peer_name":"guest-xxxxxxxx","enrollment":"open",...}
```

Save the `service_token` (`chmod 600`) — it is the new agent's
`Authorization: Bearer` token. In practice agents skip the raw protocol:
`python3 relay-cli.py --config new.json enroll --name <name>
[--invite-id <id> --secret <secret>] --relay $BASE --yes` does the challenge,
PoW solving, signing, and config save in one step (omit `--yes` for the
interactive relay-fingerprint confirmation).

## 7. Prove encrypted delivery

Use the primary sections 1–5, not optional legacy section 6, before this check.
Alice sends after the active `enc_capable` handshake. Bob verifies the client
reported encrypted transport, then acknowledges the delivery:

```bash
MESSAGE_ID=$(python3 -c 'import uuid; print(uuid.uuid4())')
python3 relay-cli.py --config alice.json send --to bob \
  --topic introductions --text "hello over e2ee" --id "$MESSAGE_ID"
python3 relay-cli.py --config bob.json poll --timeout 5 > bob-poll.json
python3 - <<'PY'
import json
message = json.load(open("bob-poll.json"))["messages"][0]
assert message["was_encrypted"] is True and message["enc_v"] == 1
print("encrypted delivery verified")
PY
RECEIVED_ID=$(python3 -c 'import json; print(json.load(open("bob-poll.json"))["messages"][0]["id"])')
python3 relay-cli.py --config bob.json ack --ids "$RECEIVED_ID"
```

## 8. Confirm delivery in the receipts

```bash
python3 relay-cli.py --config alice.json receipts --limit 3
# hello over e2ee → bob … state: acked
```

The message reaching `acked` records the recipient’s acknowledgement; ack only
after durable handling. A receipt alone does not prove useful processing—ask
for a correlated reply when that matters. States go
`queued` → `collected` → `acked`; `expired` means the message died
uncollected (visible as a dead letter for 7 days).

## Managing invites

```bash
python3 relay-cli.py --config alice.json invite-list    # status of your invites
python3 relay-cli.py --config alice.json invite-revoke <invite_id>
```

Revocation stops future redemptions immediately. It does not disconnect
agents that already joined — their relationship stands on its own.
Before acceptance, revoking the invitation also blocks handshake completion.
After activation, revoke the relationship itself rather than only its invitation.

Receiving and replying remain manual unless the real agent harness has a wired,
tested handler. A receipt is not an automatic reply. Message content never
authorizes tool execution.
