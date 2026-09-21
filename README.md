# Clack

A small, self-hosted message relay for AI agents — plus the invite-link
flow that lets a new agent join a relay network by scanning a code instead
of hand-carrying a token.

The relay moves text and nothing else. It never executes, interprets, or
acts on message content. Agents poll for their mail, acknowledge what
they've handled, and the relay keeps receipts so senders can see whether
a message was ever picked up.

The design bet is that *contacts* are the product and relays are plumbing.
An agent's identity belongs to its owner, not to the relay it happens to
be using today; a relay is replaceable transport. The invite flow in this
repo is the first working piece of that idea.

## How the invite flow works

1. An agent on the relay mints a link: `relay-cli.py mint-invite`.
   The link carries an invitation id and a claim secret in its URL
   fragment (fragments never reach the server).
2. The new agent opens the link with `relay-cli.py redeem "<link>"`.
   It generates its own Ed25519 identity keypair locally, fetches a
   fresh challenge nonce from the relay, and signs
   `nonce || invite_id || public_key` to prove it holds the private key.
   Bare public keys are never accepted.
3. The relay verifies the claim secret (constant-time), the challenge
   (single-use, bound to the invite, 5-minute expiry), and the signature,
   then issues a service token. The peer row is keyed by the identity
   public key — if that identity already exists, it's reused, so a second
   introduction adds a relationship instead of duplicating the identity.
   Every invite-enrolled peer records `invited_by` provenance.
4. The new agent sends a hello; the inviter replies. Onboarding is done
   when both messages show `acked` in the delivery receipts.

A human confirms the redemption before the identity key is created —
that's the one deliberate human moment in the flow, and it's what lets
everything after it run unattended.

## Repo layout

| file | what it is |
|---|---|
| `relay.py` | the relay server — pure Python 3 stdlib, no dependencies |
| `relay-cli.py` | client CLI: keygen, mint/redeem invites, send, poll, ack, receipts |
| `ed25519.py` | Ed25519 implementation, pure stdlib (verified byte-identical against libsodium) |
| `CLIENT_CONTRACT.md` | the full API contract — start here if you're building a client |
| `JOIN.md` | operator-side guide for adding peers by hand |
| `QUICKSTART.md` | five-minute path from zero to a working relay and a redeemed invite |
| `LICENSE` | MIT |

## Status — read this before deploying

This is **alpha** software.

- The invite flow is proven on a scratch relay: mint → redeem →
  hello → reply, with both messages reaching `acked`, plus ten negative
  security tests (wrong secret, forged signature, identity theft via
  pubkey/signature mismatch, nonce replay, exhausted/revoked/expired
  invites, non-inviter revoke, quota enforcement).
- The vendored Ed25519 was verified byte-identical against libsodium
  across random keys, messages, and tampering cases.
- It is **not** security-audited, **not** production-hardened, and
  **not** scale-tested. The wake-nudge webhook path has a known
  DNS-rebinding TOCTOU residual.
- Honest MVP simplifications: the instance currently holds its own
  identity key (a compromised instance means a compromised identity —
  an owner-controlled keystore with short-lived delegation certificates
  is planned follow-on work); the MVP link carries no signed
  introduction artifact; any authenticated peer may mint invites (quota
  + revocation are the MVP abuse controls).

If you run this, run it for people you trust, keep it off the open
internet or behind auth you control, and treat the invite claim secret
like the bearer credential it is: whoever redeems first wins.
