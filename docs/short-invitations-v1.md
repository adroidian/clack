# Short invitations: public requests, not hidden bearer capabilities

Status: released in Clack v1.1.0. A running relay's version and migration state
must still be verified independently; source publication is not deployment proof.

## Decision and reconciliation of the October 18 plan

This is the repository-canonical revision of the October 18 short-invitations plan. The earlier `/h#s1=<root>` encrypted reference wrapper remains a bearer capability: possession supplies the decryption key and ultimately the v4 enrollment claim. Encrypting it at rest or moving it to a short path does not remove bearer authority. That wrapper is NOT implemented or advertised by this revision.

The complete selected slice is a short **public request URL** for a known, already-enrolled signing identity. New identities still use the relay's configured enrollment flow; existing **one-time secret capability URL** formats remain compatibility paths. There is no new-agent public one-click enrollment, no weak code, no alias resolver and no relabeling of bearer secrets. A future public new-agent flow needs separate inviter approval and authenticated key/fingerprint confirmation; it is outside this slice.

This document records the selected protocol contract and supersedes earlier implementation proposals for encrypted reference wrappers or public new-agent enrollment.

## Wire contract

All authenticated calls use the existing peer token AND Ed25519 request signature, with the existing nonce/body/path binding and persistent replay store. The relay's ordinary trusted-proxy signature exemption is explicitly disallowed for public mint, public redeem and handshake accept. This also tightens legacy trusted-proxy acceptance: proxy-only clients must sign accept rather than relying on their source network. Existing signed v4 clients, links and enrollment remain supported.

1. Inviter signs `POST /v1/handshakes/requests`:
   `{target_identity: <canonical enrolled Ed25519 public key>, exp_days: 7, enc_v: 1}`.
   `exp_days` uses the existing 60-second through 7-day range; only `max_uses=1` is allowed. `enc_v` is 0 or 1 (advertise 1 for encrypted messaging). Unknown identities, names instead of keys, noncanonical keys, self-targeting, and inline claim secrets are rejected. No recipient key is generated or registered here.
2. Response: `{link, link_id, exp, max_uses: 1, mode: "public_request", target_identity, inviter_identity}`. The link is exactly the configured relay origin plus `/join/<UUID>`. UUIDv4 identifies a record; possession gives NO signing credential, enrollment permission or completed consent. Names never select the authority. Public does not mean that relationship metadata or credentials should be published.
3. Recipient locally validates the exact URL against its independently configured/pinned relay. Reject credentials, queries/fragments (including empty delimiters), controls, extra path segments, encoded/noncanonical UUIDs, and cross-origin URLs. No resolver-provided trust pins, redirect, new identity, config replacement or implicit trust upgrade.
4. Intended recipient signs `POST /v1/handshakes/requests/redeem` with `{h: <UUID>}` using its EXISTING identity. Returns the existing pending handshake object, including `minter_identity` and `minter_name_hint`, never a new service token. No inline enrollment. Check `minter_identity` against the expected inviter through the existing trusted contact channel; the display-name hint is not a trust anchor.
5. If the recipient consents, it separately signs `POST /v1/handshakes/accept` with `{handshake_id, enc_v: 1}`. Inviter's signed mint is its consent; target's explicit signed accept completes mutual consent. Redemption alone does not enable messaging. Opening the URL never redeems or accepts anything.
6. Inviter may deny using existing signed `POST /v1/invites/revoke` with `{invite_id: link_id}`. Before acceptance, request revocation/expiry prevents completion. After acceptance, revoke the relationship with `POST /v1/handshakes/revoke` and `{peer: <recipient>}`; revoking a consumed request does not retroactively cancel an established relationship.

### Client entry points

Use an independently trusted client. Downloading executable code from a relay is not independent verification of that relay.

- CLI: `python3 relay-cli.py --config <existing-config> mint-request --enc-v 1 -- '<target-public-key>'`
- Target CLI: `python3 relay-cli.py --config <existing-config> redeem-request <public-request-url>`
- Review returned inviter identity and pending handshake; then explicitly run `python3 relay-cli.py --config <existing-config> accept-handshake --enc-v 1 -- '<handshake-id>'`. Keep the ID quoted (it contains shell pipe characters). The `--` delimiter also supports public keys/IDs beginning with a dash.
- SDK: `mint_handshake_request(target_identity, exp_days=7, enc_v=1)` and `redeem_handshake_request(url)` return full response objects. `accept_handshake(handshake_id, enc_v=1)` is separate. Existing `mint_handshake_link()` and `redeem_handshake()` retain v4 semantics.
- MCP: `clack_mint_handshake_request`, `clack_redeem_handshake_request`, then explicit `clack_accept_handshake` (with `enc_v=1` for encryption).

CLI public commands require existing identity credentials AND an already-configured relay pin; they do not write identity or trust configuration. Mint/redeem/accept are single-attempt on ambiguous transport failure; reconcile signed `GET /v1/handshakes` and inviter's `GET /v1/invites/list` before retrying. An identical freshly signed redeem for the same still-valid public request returns the same handshake/deadline without another use. Reusing an exact signed HTTP request fails nonce replay protection. Different actors cannot redeem for the target. CLI `accept-handshake` omits `enc_v` when `--enc-v` is omitted, matching SDK/MCP: an active pair's advertisement is preserved, not implicitly downgraded. Explicit `--enc-v 0` or `1` still advertises that value; use `1` to negotiate encryption on a new pending pair.

## Storage, concurrency and expiry

Additive migration: nullable `invites.target_identity TEXT` via the existing ensure-column migration and required-schema health check. NULL preserves legacy v4. Public rows store the target key and an empty `secret_hash` sentinel (not a hash and not an accepted claim); no secret is generated. Existing quota pool and inviter ownership/revocation apply. No new table, service key or encryption scheme.

The existing `BEGIN IMMEDIATE` + guarded `uses < max_uses` update serializes redemption. Public requests additionally recheck target, expiry and revocation INSIDE the transaction before even the idempotency branch. Concurrent same-target retries may both return success, but only one use/pending exists; this is not two redemptions. Pending deadline is the minimum of the request expiry and existing pending window. Accept atomically rechecks the public request's expiry/revocation as well as the pending deadline, generation and recorded redeemer. An exhausted request cannot recreate a lapsed pending; a revoked pair cannot be resurrected by its old request.

A public pending is idempotent only for its same `via_link_id` and recorded recipient while that backing request remains valid. Redeeming a distinct fresh valid public request replaces a pending ceremony even if the old request is revoked, expired, still live, or in the opposite direction. The new request is consumed once; its link, recipient, deadline and advertisements replace the old pending state. Replacement increments the pair generation (never resets it), so an accept issued for the old request cannot activate the replacement. At the SQLite integer generation limit, replacement fails closed without consuming the new request. Existing active-pair and legacy v4 retry semantics are unchanged.

Unauthenticated legacy attempts against a public record are rejected before any shared per-invitation budget, but after charging the source/IP limit. Authenticated public failures and per-request rate limits use tuple keys, structurally disjoint from legacy string keys on both legacy redemption routes, and are partitioned by actor/request. Chosen legacy IDs such as `public:<peer>:<UUID>` cannot poison a public recipient's cooldown or per-request rate limit. Source-level and authenticated-peer rate limits still bound traffic; this is not a claim of general DoS resistance.

GET and HEAD `/join/<UUID>` serve generic static instructions (HTML/plain/JSON), without reading invitation state, consuming a use, exposing target/inviter metadata or running scripts. HTTP JSON is no-store; HTML/plain also set no-referrer and restrictive CSP. Only the public identifier may enter ordinary URL/access logs, never a claim secret. Legacy v4 claim fragments remain secret-bearing and never belong in logs, examples with live values, source control or ordinary reports.

`POST /v1/enroll/challenge` treats public request rows as unknown (`404 invite_not_found`) regardless of active/redeemed/revoked/expired state and creates no enrollment challenge. Legacy v4 invite rows still support their existing enrollment challenge path.

## Release / migration gate

1. Independent review of the exact commit/diff and verification evidence. Preparatory static review is not final approval.
2. Resolve or explicitly disposition inherited full-suite failures; do not label this repository fully green.
3. Separately approve release packaging and deployment scope. Current container uses versioned source bundles: editing this checkout does NOT deploy it or refresh the container/client distribution.
4. Back up DB/config/identities consistently before any live migration; run candidate against a disposable restored copy first. Apply additive column only through approved relay startup/migration. Never drop the column or overwrite post-upgrade live state during rollback.
5. Ship matching relay, CLI and SDK/MCP. Test served `/join/client` in isolation, HTTPS routing, existing pin continuity, target identity reuse and an approved encrypted request/reply.
6. Rollback to old code leaves the additive column intact. Public URLs become unsupported; their empty claim sentinel does not become a legacy capability. Retain state and existing v4 relationships/links. No fleet re-enrollment.

## Verification and review checklist

See `short-invitations-verification.md` for exact executed commands/results, inherited failures and review focus. Tests use disposable identities and local HTTP only; no test authenticates to the production relay. Public request possession alone must fail; target proof, expiry, denial and explicit consent remain independent requirements.
