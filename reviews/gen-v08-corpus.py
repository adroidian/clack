#!/usr/bin/env python3
"""Generate the v0.8 federation trust model machine-readable test corpus.

Writes reviews/federation-v08-test-corpus.json: real synthetic Ed25519
keys, exact canonical/preimage bytes, computed sha256 hashes, genuine
detached signatures for the §13 wire examples, plus an exchange fixture
manifest (§13.5) tying each recheck case to its request, installed
grant, pinned relay identities, clock, preexisting state, and expected
result.

v0.8 changes (Flint's v0.7 review, bounded P2 completion):
- The recheck exchange runs between the grant's actual home relays:
  minter_relay (requester X) -> redeemer_relay (responder Y). The
  v0.7 relay_x/relay_y stand-ins are kept only for the directory pair.
- Coherent timeline: grant issued 06:00, countersigned 06:05; active
  recheck sampled 06:57 (inside its 06:55-07:00 request window);
  tombstone revoked_at 07:00; revoked recheck sampled 07:57 (inside its
  07:55-08:00 window, AFTER the revocation); late negative sampled
  09:05 (3900s past the 08:00 deadline).
- Each exchange starts from a FRESH pending nonce context — the three
  cases carry distinct nonces and cannot be applied successively as
  independent first responses to one consumed nonce.

TEST-ONLY KEYS. Deterministic: seed = sha256(b"clack-v08-test/<label>"),
so the corpus is byte-reproducible by anyone with the repo's vendored
ed25519.py. The corpus also embeds the raw seeds (RFC 8032 style test
vectors) — these keys must NEVER be used outside the test corpus.

Self-verifying: every signature and hash is re-checked after generation;
any mismatch exits nonzero.
"""

import base64
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)
import ed25519  # noqa: E402  (repo's vendored pure-stdlib implementation)

GRANT_ID = "9f2c4a1e-7b3d-4e8f-a2c1-5d6e7f8090a1"
ACCEPTANCE_ID = "b7e1d903-2a4c-4f5d-9e6a-1c2b3d4e5f60"
# Three FRESH pending nonce contexts — one per exchange case (v0.8: the
# positive, revoked, and late-negative cases must not share a nonce)
NONCES = {
    "active": b"clack-v08-nonce-0000000000000001",
    "revoked": b"clack-v08-nonce-0000000000000002",
    "late": b"clack-v08-nonce-0000000000000003",
}
for _k, _n in NONCES.items():
    assert len(_n) == 32, _k


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def canonical(obj):
    """§3 canonical JSON: fixed field order (insertion order), no
    whitespace, minimal escaping, literal UTF-8, NFC-normalized."""
    return json.dumps(
        obj,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def domain(typ):
    return ("clack:" + typ + "/v1:").encode("ascii")


KEY_LABELS = {
    "minter_peer": "minter-peer",
    "minter_relay": "minter-relay",
    "redeemer_peer": "redeemer-peer",
    "redeemer_relay": "redeemer-relay",
    "relay_x": "directory-relay-x",
    "relay_y": "directory-relay-y",
}

keys = {}
for name, label in KEY_LABELS.items():
    seed = hashlib.sha256(b"clack-v08-test/" + label.encode("ascii")).digest()
    pub = ed25519._publickey(seed)  # private API of the vendored reference impl
    keys[name] = {
        "label": label,
        "seed_b64u": b64u(seed),
        "pubkey_b64u": b64u(pub),
    }


def vec(name, typ, signer, obj, role="positive"):
    canon = canonical(obj)
    pre = domain(typ) + canon
    seed = hashlib.sha256(
        b"clack-v08-test/" + KEY_LABELS[signer].encode("ascii")).digest()
    sig = ed25519.sign(seed, pre)
    return {
        "name": name,
        "role": role,  # "positive" or "negative:<violated rule>" — a negative
                       # vector carries a valid signature; rejection is by rule
        "domain": "clack:" + typ + "/v1:",
        "signer": signer,
        "signer_pubkey_b64u": keys[signer]["pubkey_b64u"],
        "canonical_json": canon.decode("utf-8"),
        "canonical_hex": canon.hex(),
        "preimage_hex": pre.hex(),
        "object_sha256_b64u": b64u(hashlib.sha256(canon).digest()),
        "signature_b64u": b64u(sig),
    }


vectors = []

# --- 1. consent-offer (§8 / §13.1 shape) ---
offer = {
    "v": 1,
    "grant_id": GRANT_ID,
    "generation": 1,
    "minter_peer_key": keys["minter_peer"]["pubkey_b64u"],
    "minter_relay_key": keys["minter_relay"]["pubkey_b64u"],
    "scope": "pairwise",
    "consent_mode": "targeted",
    "countersignature_required": True,
    "target_peer_key": keys["redeemer_peer"]["pubkey_b64u"],
    "issued_at": "2026-09-27T06:00:00Z",
    "expires_at": "2026-10-27T06:00:00Z",
}
vectors.append(vec("consent-offer", "consent-offer", "minter_peer", offer))
offer_hash = vectors[-1]["object_sha256_b64u"]

# --- 2. consent-acceptance ---
acceptance = {
    "v": 1,
    "acceptance_id": ACCEPTANCE_ID,
    "grant_id": GRANT_ID,
    "generation": 1,
    "offer_hash": offer_hash,
    "redeemer_peer_key": keys["redeemer_peer"]["pubkey_b64u"],
    "redeemer_relay_key": keys["redeemer_relay"]["pubkey_b64u"],
    "expires_at": "2026-10-20T06:00:00Z",
}
vectors.append(vec("consent-acceptance", "consent-acceptance", "redeemer_peer",
                   acceptance))
acceptance_hash = vectors[-1]["object_sha256_b64u"]

# --- 3. consent-countersignature ---
countersig = {
    "v": 1,
    "grant_id": GRANT_ID,
    "generation": 1,
    "acceptance_hash": acceptance_hash,
    "countersigned_at": "2026-09-27T06:05:00Z",
}
vectors.append(vec("consent-countersignature", "consent-countersignature",
                   "minter_peer", countersig))

# --- 4. consent-tombstone (generation = installed 1 + 1) ---
tombstone = {
    "v": 1,
    "grant_id": GRANT_ID,
    "generation": 2,
    "revoked_at": "2026-09-27T07:00:00Z",
    "reason": "peer_request",
    "revoker_peer_key": keys["minter_peer"]["pubkey_b64u"],
}
vectors.append(vec("consent-tombstone", "consent-tombstone", "minter_peer",
                   tombstone))
tombstone_hash = vectors[-1]["object_sha256_b64u"]
tombstone_sig = vectors[-1]["signature_b64u"]

# --- Recheck exchanges (v0.8): minter_relay (X, requester) -> redeemer_relay
# (Y, responder) — the grant's actual home relays, link epoch 42. ---
# Exchange A: active recheck, sampled 06:57 inside the 06:55-07:00 window,
# BEFORE the 07:00 revocation. ---
req_active = {
    "v": 1,
    "from_relay_key": keys["minter_relay"]["pubkey_b64u"],
    "to_relay_key": keys["redeemer_relay"]["pubkey_b64u"],
    "link_epoch": 42,
    "grant_ids": [GRANT_ID],
    "watermark": "2026-09-26T06:00:00Z",
    "nonce": b64u(NONCES["active"]),
    "requested_at": "2026-09-27T06:55:00Z",
    "deadline": "2026-09-27T07:00:00Z",
}
vectors.append(vec("recheck-request/active", "recheck-request", "minter_relay",
                   req_active))

resp_active = {
    "v": 1,
    "from_relay_key": keys["redeemer_relay"]["pubkey_b64u"],
    "to_relay_key": keys["minter_relay"]["pubkey_b64u"],
    "link_epoch": 42,
    "nonce": b64u(NONCES["active"]),
    "grants": [
        {
            "grant_id": GRANT_ID,
            "generation": 1,
            "status": "active",
            "tombstone": None,
            "tombstone_signature": None,
            "tombstone_hash": None,
            "effective_expires_at": "2026-10-20T06:00:00Z",
        }
    ],
    "responded_at": "2026-09-27T06:57:00Z",
}
vectors.append(vec("recheck-response/active", "recheck-response",
                   "redeemer_relay", resp_active))

# --- Exchange B: revoked recheck, sampled 07:57 inside the 07:55-08:00
# window, AFTER the 07:00 revocation. ---
req_revoked = {
    "v": 1,
    "from_relay_key": keys["minter_relay"]["pubkey_b64u"],
    "to_relay_key": keys["redeemer_relay"]["pubkey_b64u"],
    "link_epoch": 42,
    "grant_ids": [GRANT_ID],
    "watermark": "2026-09-27T06:57:00Z",  # carried from exchange A
    "nonce": b64u(NONCES["revoked"]),
    "requested_at": "2026-09-27T07:55:00Z",
    "deadline": "2026-09-27T08:00:00Z",
}
vectors.append(vec("recheck-request/revoked", "recheck-request", "minter_relay",
                   req_revoked))

resp_revoked = {
    "v": 1,
    "from_relay_key": keys["redeemer_relay"]["pubkey_b64u"],
    "to_relay_key": keys["minter_relay"]["pubkey_b64u"],
    "link_epoch": 42,
    "nonce": b64u(NONCES["revoked"]),
    "grants": [
        {
            "grant_id": GRANT_ID,
            "generation": 2,
            "status": "revoked",
            "tombstone": tombstone,
            "tombstone_signature": tombstone_sig,
            "tombstone_hash": tombstone_hash,
            "effective_expires_at": None,
        }
    ],
    "responded_at": "2026-09-27T07:57:00Z",
}
vectors.append(vec("recheck-response/revoked", "recheck-response",
                   "redeemer_relay", resp_revoked, role="positive"))

# --- Exchange C: revoked recheck, LATE (negative fixture: 3900s past the
# 08:00 deadline). Fresh nonce — a distinct pending context, not a replay
# of exchange B. ---
req_late = {
    "v": 1,
    "from_relay_key": keys["minter_relay"]["pubkey_b64u"],
    "to_relay_key": keys["redeemer_relay"]["pubkey_b64u"],
    "link_epoch": 42,
    "grant_ids": [GRANT_ID],
    "watermark": "2026-09-27T06:57:00Z",
    "nonce": b64u(NONCES["late"]),
    "requested_at": "2026-09-27T07:55:00Z",
    "deadline": "2026-09-27T08:00:00Z",
}
vectors.append(vec("recheck-request/revoked-late", "recheck-request",
                   "minter_relay", req_late))

resp_late = {
    "v": 1,
    "from_relay_key": keys["redeemer_relay"]["pubkey_b64u"],
    "to_relay_key": keys["minter_relay"]["pubkey_b64u"],
    "link_epoch": 42,
    "nonce": b64u(NONCES["late"]),
    "grants": [
        {
            "grant_id": GRANT_ID,
            "generation": 2,
            "status": "revoked",
            "tombstone": tombstone,
            "tombstone_signature": tombstone_sig,
            "tombstone_hash": tombstone_hash,
            "effective_expires_at": None,
        }
    ],
    "responded_at": "2026-09-27T09:05:00Z",
}
vectors.append(vec("recheck-response/revoked-late", "recheck-response",
                   "redeemer_relay", resp_late,
                   role="negative:responded_at_past_deadline"))

# --- 8a. directory snapshot-100 (§9 full snapshot): the base the delta applies to ---
anchor_peer = hashlib.sha256(b"clack-v08-test/anchor-peer").digest()
anchor_peer_key = b64u(ed25519._publickey(anchor_peer))
gone_peer = hashlib.sha256(b"clack-v08-test/gone-peer").digest()
gone_peer_key = b64u(ed25519._publickey(gone_peer))
snapshot_entries = dict(sorted({
    anchor_peer_key: {
        "display_name": "anchor",
        "federation_visible": True,
        "added_at": "2026-09-27T05:00:00Z",
    },
    gone_peer_key: {
        "display_name": "gone-peer-demo",
        "federation_visible": True,
        "added_at": "2026-09-27T05:00:00Z",
    },
}.items()))
snapshot = {
    "v": 1,
    "issuer_relay_key": keys["relay_x"]["pubkey_b64u"],
    "audience_relay_key": keys["relay_y"]["pubkey_b64u"],
    "epoch": 42,
    "sequence": 100,
    "issued_at": "2026-09-27T06:00:00Z",
    "expires_at": "2026-09-28T06:00:00Z",
    "is_delta": False,
    "base_sequence": None,
    "base_hash": None,
    "entries": snapshot_entries,
    "tombstones": {},
}
vectors.append(vec("directory/snapshot-100", "directory", "relay_x", snapshot,
                   role="positive"))
snapshot_hash = vectors[-1]["object_sha256_b64u"]

# --- 8b. directory delta (§9 / §13.2 shape): base_hash is the sha256 of the
# supplied snapshot-100 canonical bytes, not a test string ---
new_peer = hashlib.sha256(b"clack-v08-test/new-peer").digest()
new_peer_key = b64u(ed25519._publickey(new_peer))
entries = {new_peer_key: {
    "display_name": "vesper",
    "federation_visible": True,
    "added_at": "2026-09-27T06:10:00Z",
}}
tombstones_dir = {gone_peer_key: {
    "removed_at": "2026-09-27T06:09:00Z",
    "reason": "peer_opt_out",
}}
# canonical key order: lexicographic by UTF-8 bytes of the b64u key string
entries = dict(sorted(entries.items()))
tombstones_dir = dict(sorted(tombstones_dir.items()))
directory = {
    "v": 1,
    "issuer_relay_key": keys["relay_x"]["pubkey_b64u"],
    "audience_relay_key": keys["relay_y"]["pubkey_b64u"],
    "epoch": 42,
    "sequence": 101,
    "issued_at": "2026-09-27T06:10:00Z",
    "expires_at": "2026-09-28T06:10:00Z",
    "is_delta": True,
    "base_sequence": 100,
    "base_hash": snapshot_hash,
    "entries": entries,
    "tombstones": tombstones_dir,
}
vectors.append(vec("directory/delta", "directory", "relay_x", directory,
                   role="positive"))

# --- Exchange fixture manifest (§13.5): machine-readable per-case context.
# Each exchange pins its request vector, response vector, relay identities
# (key labels), installed-grant state at the requester, requester clock,
# preexisting state, and expected result. Every exchange starts from a
# FRESH pending nonce context. ---
exchanges = [
    {
        "name": "active-recheck",
        "request_vector": "recheck-request/active",
        "response_vector": "recheck-response/active",
        "from_relay": "minter_relay",
        "to_relay": "redeemer_relay",
        "link_epoch": 42,
        "installed_grant": {"grant_id": GRANT_ID, "generation": 1,
                            "tombstone_present": False},
        "prior_watermark": "2026-09-26T06:00:00Z",
        "state_note": "Intentionally seeded STALE: at request time the "
                      "prior watermark is 55 min past the 24h cap, so no "
                      "delivery is allowed under the grant until this "
                      "recheck succeeds and re-anchors the watermark to "
                      "06:57:00Z. This exchange is the fail-closed-then-"
                      "recover path, not an 'approaching the cap' timeline.",
        "requester_clock": {
            "requested_at": "2026-09-27T06:55:00Z",
            "deadline": "2026-09-27T07:00:00Z",
            "commit_at": "2026-09-27T06:58:00Z",
        },
        "expected": {
            "outcome": "accept",
            "watermark": "2026-09-27T06:57:00Z",
            "tombstone_installed": False,
            "nonce_consumed": True,
        },
    },
    {
        "name": "revoked-recheck",
        "request_vector": "recheck-request/revoked",
        "response_vector": "recheck-response/revoked",
        "from_relay": "minter_relay",
        "to_relay": "redeemer_relay",
        "link_epoch": 42,
        "installed_grant": {"grant_id": GRANT_ID, "generation": 1,
                            "tombstone_present": False},
        "prior_watermark": "2026-09-27T06:57:00Z",
        "requester_clock": {
            "requested_at": "2026-09-27T07:55:00Z",
            "deadline": "2026-09-27T08:00:00Z",
            "commit_at": "2026-09-27T07:58:00Z",
        },
        "expected": {
            "outcome": "accept",
            "watermark": "2026-09-27T06:57:00Z",
            "tombstone_installed": True,
            "nonce_consumed": True,
        },
    },
    {
        "name": "revoked-recheck-late",
        "request_vector": "recheck-request/revoked-late",
        "response_vector": "recheck-response/revoked-late",
        "from_relay": "minter_relay",
        "to_relay": "redeemer_relay",
        "link_epoch": 42,
        "installed_grant": {"grant_id": GRANT_ID, "generation": 1,
                            "tombstone_present": False},
        "prior_watermark": "2026-09-27T06:57:00Z",
        "requester_clock": {
            "requested_at": "2026-09-27T07:55:00Z",
            "deadline": "2026-09-27T08:00:00Z",
            "commit_at": "2026-09-27T09:06:00Z",
        },
        "expected": {
            "outcome": "reject",
            # A conforming processor may reject at the pending-context
            # expiry / commit-time check (commit_at=09:06 is past the
            # 08:00 local deadline) BEFORE reaching the responded_at
            # predicate — either rejection path is acceptable. The exact
            # responded_at <= deadline assertion is the static predicate
            # test (T2-31). Required outcome is identical on every path:
            # no grant/tombstone/watermark updates, and no nonce consumed
            # by a successful response.
            "reject_rule": ["pending_context_expired",
                            "responded_at_past_deadline"],
            "state_changed": False,
            "nonce_consumed": False,
        },
    },
]

corpus = {
    "corpus": "clack-federation-v08-test-corpus",
    "version": 1,
    "warning": "TEST-ONLY synthetic keys. Never use on any real relay.",
    "generated_by": "reviews/gen-v08-corpus.py",
    "source_spec": "docs/federation-trust-model.md v0.8",
    "fixture_classes": "Vectors carry a 'role': 'positive' vectors are "
                       "cryptographically valid records (signature, hashes, "
                       "references, and — for exchange cases — deadline "
                       "placement all check out); 'negative:<rule>' vectors "
                       "carry a VALID signature and must be rejected on the "
                       "named rule (timing, not crypto). A 'positive' role "
                       "does NOT mean the record must be accepted in any "
                       "state — live acceptance additionally requires the "
                       "pending nonce context, installed-grant state, and "
                       "preconditions the exchange fixture manifest pins per "
                       "case. The offer/acceptance/countersignature/tombstone/"
                       "snapshot vectors are standalone signed records; each "
                       "recheck request/response pair is a complete exchange "
                       "fixture tied to its manifest entry.",
    "canonical_encoding": "preimage = ASCII('clack:<type>/v1:') || canonical JSON per §3; "
                          "sha256 fields cover the canonical JSON bytes only (no domain prefix)",
    "key_derivation": "seed = sha256(b'clack-v08-test/' + label); pubkey = Ed25519(seed)",
    "keys": keys,
    "exchanges": exchanges,
    "vectors": vectors,
}

# --- self-verification: recompute everything from the recorded bytes ---
fails = []
for v in vectors:
    canon = v["canonical_json"].encode("utf-8")
    if canon.hex() != v["canonical_hex"]:
        fails.append((v["name"], "canonical_hex mismatch"))
    if b64u(hashlib.sha256(canon).digest()) != v["object_sha256_b64u"]:
        fails.append((v["name"], "object_sha256 mismatch"))
    pre = bytes.fromhex(v["preimage_hex"])
    if pre != v["domain"].encode("ascii") + canon:
        fails.append((v["name"], "preimage framing mismatch"))
    pub = base64.urlsafe_b64decode(
        v["signer_pubkey_b64u"] + "=" * (-len(v["signer_pubkey_b64u"]) % 4))
    sig = base64.urlsafe_b64decode(
        v["signature_b64u"] + "=" * (-len(v["signature_b64u"]) % 4))
    if not ed25519.verify(pub, sig, pre):
        fails.append((v["name"], "signature verify failed"))

# cross-checks required by the spec
by_name = {v["name"]: v for v in vectors}
acc = json.loads(by_name["consent-acceptance"]["canonical_json"])
if acc["offer_hash"] != by_name["consent-offer"]["object_sha256_b64u"]:
    fails.append(("consent-acceptance", "offer_hash != sha256(canonical offer)"))
cs = json.loads(by_name["consent-countersignature"]["canonical_json"])
if cs["acceptance_hash"] != by_name["consent-acceptance"]["object_sha256_b64u"]:
    fails.append(("consent-countersignature",
                  "acceptance_hash != sha256(canonical acceptance)"))
rev = json.loads(by_name["recheck-response/revoked"]["canonical_json"])
entry = rev["grants"][0]
ts = json.loads(by_name["consent-tombstone"]["canonical_json"])
if entry["tombstone"] != ts:
    fails.append(("recheck-response/revoked", "embedded tombstone != canonical"))
if entry["tombstone_hash"] != by_name["consent-tombstone"]["object_sha256_b64u"]:
    fails.append(("recheck-response/revoked",
                  "tombstone_hash != sha256(canonical tombstone)"))
if entry["tombstone_signature"] != by_name["consent-tombstone"]["signature_b64u"]:
    fails.append(("recheck-response/revoked",
                  "tombstone_signature != tombstone signature"))
if entry["generation"] != ts["generation"] or ts["generation"] != 2:
    fails.append(("recheck-response/revoked", "generation != grant generation + 1"))

# v0.8 exchange-manifest coherence checks (P2 completion):
# (a) every exchange's nonces are unique — fresh pending contexts;
# (b) recheck relay identities are the grant's home relays;
# (c) timeline order: grant issued < countersigned < active sample <
#     revocation < revoked sample; late sample 3900s past its deadline;
# (d) manifest clock fields match the vectors; expected outcomes match
#     the deadline placement; expected watermark = min(responded_at,
#     commit_at) for accepted active cases.
grant_relays = {acc["redeemer_relay_key"],
                json.loads(by_name["consent-offer"]["canonical_json"])["minter_relay_key"]}
seen_nonces = {}
for ex in exchanges:
    req = json.loads(by_name[ex["request_vector"]]["canonical_json"])
    resp = json.loads(by_name[ex["response_vector"]]["canonical_json"])
    nq, ns = ex["request_vector"], ex["response_vector"]
    # (a) fresh nonce per exchange, request/response agree
    if req["nonce"] != resp["nonce"]:
        fails.append((nq, "request/response nonce mismatch"))
    if req["nonce"] in seen_nonces:
        fails.append((nq, "nonce reused across exchanges (%s)" % seen_nonces[req["nonce"]]))
    seen_nonces[req["nonce"]] = ex["name"]
    # (b) home-relay identities
    if {req["from_relay_key"], req["to_relay_key"]} != grant_relays:
        fails.append((nq, "recheck relays are not the grant's home relays"))
    if resp["from_relay_key"] != req["to_relay_key"] or \
            resp["to_relay_key"] != req["from_relay_key"]:
        fails.append((ns, "response relay direction not reversed from request"))
    if ex["link_epoch"] != req["link_epoch"] or req["link_epoch"] != resp["link_epoch"]:
        fails.append((nq, "link_epoch mismatch across exchange"))
    # (d) manifest clock == vector clock
    rc = ex["requester_clock"]
    if req["requested_at"] != rc["requested_at"] or req["deadline"] != rc["deadline"]:
        fails.append((nq, "manifest clock != request vector clock"))
    # deadline placement vs expected outcome
    in_deadline = req["requested_at"] <= resp["responded_at"] <= req["deadline"]
    if ex["expected"]["outcome"] == "accept" and not in_deadline:
        fails.append((ns, "expected accept but response outside deadline"))
    if ex["expected"]["outcome"] == "reject" and in_deadline:
        fails.append((ns, "expected reject but response inside deadline"))
    if ex["expected"]["outcome"] == "accept" and \
            resp["grants"][0]["status"] == "active":
        wm = min(resp["responded_at"], rc["commit_at"])
        if ex["expected"]["watermark"] != wm:
            fails.append((ns, "expected watermark != min(responded_at, commit_at)"))
    # (c) timeline order for the positive revoked case
    if ex["name"] == "revoked-recheck":
        t_r = ts["revoked_at"]
        if not (t_r < resp["responded_at"]):
            fails.append((ns, "tombstone revoked_at not before response sample"))
        t_c = cs["countersigned_at"]
        act = json.loads(by_name["recheck-response/active"]["canonical_json"])
        if not (t_c < act["responded_at"] < t_r):
            fails.append(("recheck-response/active",
                          "active sample not between countersign and revocation"))

# v0.8 delta cross-check: base_hash must be the sha256 of the supplied
# snapshot-100 canonical bytes — not a test string
delta = json.loads(by_name["directory/delta"]["canonical_json"])
if delta["base_sequence"] != 100:
    fails.append(("directory/delta", "base_sequence != 100"))
if delta["base_hash"] != by_name["directory/snapshot-100"]["object_sha256_b64u"]:
    fails.append(("directory/delta",
                  "base_hash != sha256(canonical snapshot-100 bytes)"))
snap = json.loads(by_name["directory/snapshot-100"]["canonical_json"])
if snap["is_delta"] is not False or snap["sequence"] != 100:
    fails.append(("directory/snapshot-100", "not a full snapshot at seq 100"))
# the delta's tombstoned key must exist in the base snapshot's entries
for tk in delta["tombstones"]:
    if tk not in snap["entries"]:
        fails.append(("directory/delta",
                      "tombstoned key not present in base snapshot"))

if fails:
    print("SELF-CHECK FAILED:")
    for name, why in fails:
        print("  - %s: %s" % (name, why))
    sys.exit(1)

out_path = os.path.join(HERE, "federation-v08-test-corpus.json")
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(corpus, f, indent=2, ensure_ascii=False)
    f.write("\n")
print("wrote %s (%d vectors, %d exchanges, all signatures/hashes verified)"
      % (out_path, len(vectors), len(exchanges)))
