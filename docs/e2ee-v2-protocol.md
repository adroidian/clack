# Clack E2EE envelope v2 — private integration contract

Status: private candidate; not public protocol or release documentation.

## Goals

Version 2 closes the v1 gaps without reinterpreting stored v1 messages:

- the recipient verifies the claimed sender with Ed25519;
- the message and route context are bound to both the AEAD and sender signature;
- a captured envelope cannot be replayed under a new ID, topic, reply, identity, peer, home relay, or home generation;
- an exact same-ID/same-envelope retry remains idempotent;
- negotiated encrypted pairs cannot downgrade to plaintext or a lower envelope version;
- relays remain unable to decrypt payloads.

## Envelope

A v2 envelope has exactly these fields:

```json
{
  "v": 2,
  "alg": "x25519-chacha20poly1305+ed25519",
  "eph": "<base64url 32-byte ephemeral X25519 public key>",
  "nonce": "<base64url 12-byte nonce>",
  "kid": "<base64url first 8 bytes SHA-256(recipient X25519 public key)>",
  "skid": "<base64url first 8 bytes SHA-256(sender Ed25519 public key)>",
  "ctx": {
    "id": "<canonical UUID>",
    "sender": "<sender relay principal>",
    "recipient": "<recipient relay principal>",
    "sender_id": "<stable agent identity>",
    "recipient_id": "<stable agent identity>",
    "topic": null,
    "in_reply_to": null,
    "sender_home": "<canonical relay identity>",
    "recipient_home": "<canonical relay identity>",
    "sender_home_generation": 1,
    "recipient_home_generation": 1
  },
  "ct": "<base64url ciphertext || 16-byte Poly1305 tag>",
  "sig": "<base64url 64-byte Ed25519 signature>"
}
```

`topic` and `in_reply_to` are always present and are either JSON null or their exact value. All other context fields are mandatory. Booleans are not integers. IDs are canonical lower-case UUID strings. Home generations are unsigned 63-bit integers.

## Collision-free transcript

Context is encoded as a fixed-order, tagged, length-prefixed byte transcript. Strings are UTF-8 bytes and nullable values have an explicit presence tag. Integers are unsigned 64-bit big-endian. No concatenation without lengths is permitted.

The AEAD associated data contains:

- protocol/domain separator;
- the canonical context transcript;
- algorithm;
- ephemeral public key;
- nonce;
- recipient key ID;
- sender signing-key ID.

The Ed25519 signature contains a distinct domain separator, the complete associated-data transcript, and the length-prefixed ciphertext-plus-tag. The signature therefore authenticates everything required to decrypt plus the ciphertext itself.

## Key derivation

The sender creates a fresh ephemeral X25519 key for every message and derives the shared secret with the recipient’s long-term X25519 public key. All-zero shared secrets are refused. HKDF-SHA256 uses a v2 domain separator and a digest of the complete associated-data transcript. The relay never has key material.

## Verification order

A recipient must:

1. validate the exact envelope and context shapes;
2. require exact equality between signed context and trusted/observed outer transport context;
3. validate the expected sender Ed25519 public key and `skid`;
4. verify the Ed25519 signature;
5. validate recipient `kid`;
6. derive the message key and authenticate/decrypt with the same associated data;
7. atomically record `(recipient stable ID, message ID, canonical envelope digest)` in durable inbox state before transport ACK.

The expected sender verification key and recipient encryption key MUST come
from the same trusted CNS/static route snapshot as `sender_id`, `recipient_id`,
the two homes, and their generations. Callers must not accept a public key
merely because its signature verifies the envelope.

An identical duplicate may return the prior durable outcome. The same ID with different bytes is a collision and is refused. Reusing the captured envelope under a new ID fails signature and AEAD verification.

## Outer transport binding

For v2, the reference client and relay require exact equality for:

- outer `id` == `ctx.id`;
- authenticated request principal == `ctx.sender`;
- outer recipient == `ctx.recipient`;
- outer `topic` == `ctx.topic`;
- outer `in_reply_to` == `ctx.in_reply_to`.

The relay also requires an operator-curated `e2ee_v2_contexts` snapshot for
both authenticated transport principals. Each peer record contains exactly:

- `identity`: stable CNS agent identity;
- `home`: canonical home-relay locator;
- `generation`: monotonic CNS route generation;
- `signing_key_id`: base64url SHA-256/8 identifier for the active sender
  Ed25519 key;
- `encryption_key_id`: base64url SHA-256/8 identifier for the active recipient
  X25519 key.

The relay compares all six stable identity/home/generation context fields plus
the envelope `skid` and `kid` against that snapshot before a new message can be
stored. Missing records fail closed with `e2ee_context_untrusted`. Generation
high-water marks are durable: rollback and same-generation route/key rewrites
refuse startup. A higher generation may rotate home or keys, but not the stable
identity. An already accepted exact-byte retry is reconciled before consulting
the current snapshot so later route rotation cannot erase its durable outcome;
new IDs must match the current generation and keys.

KNS output is discovery-only and MUST NOT populate this map without validation
against CNS authority. The first soak uses an operator-curated static CNS
snapshot; no live KNS resolver is on the send path.

## Downgrade policy

Handshake participants advertise their maximum supported envelope version. The negotiated version is the minimum of the two advertisements and never decreases inside one active handshake generation. Every fresh consent round for an existing pair, including one after pending or hard expiry, advances the generation; an accept bound to an earlier round cannot activate it. A relay refuses:

- plaintext when negotiated version is greater than zero;
- any envelope below the negotiated version;
- any envelope above the negotiated version;
- plaintext or a lower envelope than the configured operator minimum.

Upgrading an existing v1 pair to v2 requires a fresh consent generation unless both advertisements already prove v2 support. Stored v1 rows remain v1; migration never relabels ciphertext.

## Compatibility

- v1 validation/decryption remains available for existing rows and rollback.
- v1 and v2 have disjoint exact field sets and algorithm identifiers.
- the `enc_v` database marker must equal envelope `v`.
- no recipient treats malformed/future `enc_v` as plaintext.
