# Clack Roadmap

Where Clack is going. Items move from Idea → Proposed → In flight → Done.
Protocol changes need Zari's scheduling; client changes are Nugget's lane.

## In flight

- **E2EE pilot completion** — kit accepted, Mavis's kit passed. Remaining gates:
  consent, custody, retirement, and native encrypted-duplex. Clingy Bear pair
  re-mint on hold pending Aaron's go (drain 102 pending messages first).

## Proposed (next)

- **Content-addressed blob attachments** (Aaron, Oct 6 2026) — the long-term
  answer to the 64KB message cap (TEXT_MAX). Today large payloads get chunked
  across many messages or handed off to Drive; neither is the real solution.
  - Message stays small: carries a manifest (blob hash, size, media type,
    decryption envelope). Bytes live in a blob store.
  - One primitive covers both UX shapes: "email-style attachments" = a blob
    referenced from a message; "relay file share" = a set of referenced blobs
    with a folder UX on top.
  - Non-negotiables: E2EE (blob encrypted with a random key, key wrapped in
    the message for the recipient), capability-gated fetch (only the
    conversation's participants), retention tied to message expiry (GC
    orphans), per-file and per-sender size quotas.
  - Sketch: `POST /v1/blobs` (authenticated upload → blob ID + hash),
    `GET /v1/blobs/<id>` (participant-only fetch). Protocol change — needs
    Zari's design review before build.

## Ideas

- **Federation** — Mercedes drives federation implementation (primary since
  Sep 29). Cross-relay trust model doc exists (`docs/federation-trust-model.md`).
- **Relay-side delivery receipts** — sender-visible ack/collection states are
  coarse today ("collected but never acked" confusion). Richer receipts would
  cut down on redelivery-chasing.
- **Client robustness** — continued relay-cli hardening (non-UTF-8 consoles
  fixed Oct 6; more platform edges surely lurk).

## Done (recent)

- E2EE kit accepted (101 tests green, five blockers cleared); Mavis's kit passed.
- relay-cli ASCII fallback for non-UTF-8 consoles (0fbbeda).
- Mavis E2EE client bundle (v0.2.17 + e2ee.py).
- Inbox-watch thread-aware routing (`in_reply_to` printing).
