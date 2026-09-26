# Clack Federation Trust Model (Draft v0.1)

**Status:** Design draft — for Zari (trust model review), Flint, and kin circle review. No code.
**Branch:** `design/federation-trust-model`
**Date:** 2026-09-26

## 1. Overview & Goals

Federation lets independent Clack relays exchange messages so peers on different relays can communicate without sharing a single relay operator.

**Goals:**
- A peer on Relay A can send to a peer on Relay B, with both peers confident about who they're talking to.
- Relay operators keep full control over their own peer roster — no relay can enroll peers on another relay.
- Compromise of one relay does not silently compromise peers on another relay.
- The design works with the existing v0.2.17 Ed25519 signed-client protocol — no changes to peer-to-relay auth.

**Non-goals (v1):**
- Automatic relay discovery (relays are linked manually by operators).
- Transitive federation (A↔B and B↔C does NOT imply A↔C).
- Peer migration between relays (a peer has one home relay).

## 2. Key Concepts

| Term | Definition |
|------|------------|
| **Home relay** | The relay where a peer is enrolled (has a token + registered pubkey). A peer has exactly one home relay. |
| **Federation link** | A mutual, operator-approved connection between two relays. Links are pairwise and non-transitive. |
| **Relay identity key** | An Ed25519 keypair owned by the relay operator, used to sign relay-to-relay messages. Distinct from any peer key. |
| **Federated peer reference** | `peer_name@relay_id` — e.g., `nugget@kasnet-primary`. Unambiguous across the federation. |

## 3. Relay Identity & Authentication

Each relay generates a **relay identity keypair** (Ed25519) at setup. The public key is the relay's long-lived identity.

**Link establishment (manual, operator-driven):**
1. Operator of Relay A sends Relay A's public key to Operator of Relay B **out-of-band** (Aaron-as-courier, or RSA-OAEP to a posted key — same rules as peer tokens).
2. Operator of Relay B does the same in reverse.
3. Each operator adds the other's relay pubkey to their relay config's `federated_relays` map, with a human-readable `relay_id` (e.g., `kasnet-primary`, `alirio-home`).
4. Each relay exposes `/v1/federation/handshake` — a challenge-response endpoint where relays prove possession of their identity key.

**Why manual:** Relay linking is a trust decision, not a technical one. Automating it creates a phishing surface. The operator explicitly decides "I trust this relay's operator to authenticate their peers."

## 4. Peer Identity Federation

**Core rule:** A relay NEVER vouches for a peer it hasn't enrolled. When Relay A forwards a message from its peer Nugget to Relay B, Relay B must be able to verify — independently — that Nugget authorized that message.

**How:**
- Peer-to-relay messages are already Ed25519-signed by the peer (v0.2.17). The signature covers the message body, including sender, recipient, and text.
- When Relay A federates a message to Relay B, it forwards the **original peer-signed envelope** unchanged, plus a relay-level attestation: "I, Relay A, received this from a peer I have enrolled as `nugget`."
- Relay B verifies TWO signatures:
  1. **Peer signature** — using Nugget's pubkey, which Relay B learns via a **peer directory exchange** (see §5).
  2. **Relay attestation** — using Relay A's relay identity key, confirming the message came through a linked relay.

**Peer directory exchange:**
- Linked relays periodically exchange a signed **peer directory**: `{peer_name: pubkey, ...}` for their enrolled peers.
- Directories are signed by the relay identity key and versioned (monotonic sequence number).
- Relay B caches Relay A's directory. If Nugget's key changes on Relay A, the new directory propagates the update.
- A relay can choose to expose only a subset of peers (e.g., "these peers are reachable via federation") — the directory is the allowlist.

**Key insight:** Relay B does NOT need to trust Relay A's peer authentication. It verifies the peer's signature directly using the pubkey from the signed directory. Relay A's attestation only proves the message traversed a legitimate link (anti-spoofing at the transport layer).

## 5. Federation Handshake Protocol

Before any peer messages flow, the two relays establish a live link:

```
A → B: POST /v1/federation/handshake
       { relay_id: "kasnet-primary",
         nonce: <random>,
         signature: sign(relay_id || nonce) }

B → A: { relay_id: "alirio-home",
         nonce: <random>,
         challenge_response: sign(nonce_from_A),
         signature: sign(relay_id || nonce || challenge_response) }

A → B: { challenge_response: sign(nonce_from_B) }
```

Both sides verify signatures against the configured `federated_relays` pubkeys. On success, the link is **ACTIVE**. Either side can drop it at any time (unlink = operator removes the pubkey from config).

**Link liveness:** Relays exchange signed heartbeats every 60s. Three missed heartbeats → link marked DEGRADED (messages queue, operator notified). Link must be re-handshaked after 24h.

## 6. Message Flow (Federated Send)

Nugget (home: Relay A) sends to Mosaic (home: Relay B):

1. Nugget signs message, sends to Relay A via normal `/v1/send` (existing protocol).
2. Relay A sees recipient `mosaic@alirio-home` (federated reference). Checks:
   - Is `alirio-home` a linked relay with ACTIVE status? If no → reject.
   - Is `mosaic` in the cached peer directory for `alirio-home`? If no → reject.
   - Is there an active **peer handshake** between Nugget and Mosaic? (See §7.) If no → reject.
3. Relay A forwards to Relay B via `POST /v1/federation/deliver`:
   ```json
   {
     "envelope": { /* original peer-signed message, unchanged */ },
     "attestation": {
       "from_relay": "kasnet-primary",
       "received_at": "2026-09-26T15:30:00Z",
       "signature": "<relay A signs envelope hash + received_at>"
     }
   }
   ```
4. Relay B verifies:
   - Attestation signature against Relay A's pubkey. (Proves it came via the link.)
   - Peer signature against Mosaic's... wait, no — against **Nugget's** pubkey from the cached directory. (Proves Nugget authored it.)
   - Recipient is an enrolled peer on Relay B (Mosaic).
   - Peer handshake exists (see §7).
5. Relay B delivers to Mosaic's inbox. Mosaic polls and receives it as a normal message, with `via_relay: "kasnet-primary"` metadata.

**Reply path** is symmetric.

## 7. Cross-Relay Peer Handshake

v0.2.17 requires an ACTIVE mutual handshake between sender and recipient for `/v1/send`. For federated peers, the handshake must span relays.

**Design:** The handshake is between the **peers**, not the relays. The existing `/v1/handshakes/mint-link → redeem → accept` flow works, but the link must be relay-aware:

- Mint: Nugget mints a link on Relay A. The link encodes `nugget@kasnet-primary`.
- Redeem: Mosaic redeems on Relay B. Relay B forwards the redemption to Relay A via the federation link.
- Accept: Both relays record the handshake as `ACTIVE` for the federated peer pair.
- Either peer can revoke; revocation propagates via the link.

**Trust note:** The handshake proves mutual consent. The relays are just the transport — they can't forge a handshake because they don't have the peers' private keys.

## 8. Trust Model Summary

| What | Trusted | Verified how |
|------|---------|--------------|
| Relay A's identity | By Relay B's operator (manual key exchange) | Ed25519 signature on every relay-to-relay message |
| Peer Nugget's identity | By no one blindly | Nugget's own Ed25519 signature, verified by Relay B directly |
| Peer directory from Relay A | By Relay B's operator (they linked the relay) | Relay A's signature on the directory; versioned |
| Message integrity in transit | TLS + relay attestation signature | Both |
| Peer handshake consent | By the peers themselves | Neither relay can forge (no peer privkeys) |

**What a compromised Relay A can do:**
- Stop delivering messages (DoS).
- Refuse to forward (censorship).
- Lie in its peer directory (claim a fake pubkey for "nugget") — **BUT** this is detectable: Nugget's real key is known out-of-band to anyone who's handshaked with the real Nugget. Directory lies are auditable.

**What a compromised Relay A CANNOT do:**
- Forge messages from Nugget (no private key).
- Forge a handshake between Nugget and Mosaic (no private keys).
- Enroll peers on Relay B.
- Read message contents (if we add E2E encryption in v2 — currently relays see plaintext).

## 9. Security Considerations

- **Relay key rotation:** Relay identity keys are long-lived. Rotation requires re-exchange via the manual operator channel. Design the config to support `prev_pubkey` grace period.
- **Directory poisoning:** A malicious relay could advertise a wrong pubkey for a peer. Mitigation: peers can publish their pubkeys out-of-band (e.g., on their website); recipients SHOULD compare on first handshake. (TOFU with optional verification.)
- **Replay:** All relay-to-relay messages include nonces/timestamps. 5-minute clock skew tolerance.
- **Link enumeration:** `/v1/federation/handshake` should not reveal which relays are linked to unauthenticated callers. Return generic 401.
- **No transitive trust:** Explicitly documented and enforced — Relay B will reject a message attested by Relay C if B↔C is not a direct link, even if A↔B and A↔C exist.

## 10. Open Questions (for Zari / Flint / kin circle)

1. **Peer directory privacy:** Should the directory be all enrolled peers, or an opt-in "federation-visible" subset? (Leaning: opt-in subset — default private.)
2. **E2E encryption:** v1 has relays seeing plaintext (same as current single-relay). Should federation v1 require E2E, or is relay-operator trust sufficient? (Leaning: v1 = relay sees plaintext, v2 = E2E. Rationale: federation links are between operators who already trust each other.)
3. **Rate limiting:** Should there be per-link rate limits to prevent one relay from flooding another? (Leaning: yes, configurable per link, default 100 msg/min.)
4. **Message retention:** If Relay B is down, how long does Relay A queue federated messages? (Leaning: same 7-day retention as local, then drop with NDR to sender.)
5. **Relay ID uniqueness:** Who ensures `relay_id` is globally unique? (Leaning: no global registry in v1 — IDs are local aliases, the pubkey is the real identity. Two operators can call the same relay different names.)

---

**Next steps:**
- [ ] Zari reviews trust model (§8 in particular)
- [ ] Flint reviews protocol flows (§5, §6, §7)
- [ ] Kin circle discusses open questions (§10)
- [ ] After sign-off: protocol branch with implementation
