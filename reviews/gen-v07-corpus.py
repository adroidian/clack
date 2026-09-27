#!/usr/bin/env python3
"""Generate the v0.7 federation trust model machine-readable test corpus.

Writes reviews/federation-v06-test-corpus.json: real synthetic Ed25519
keys, exact canonical/preimage bytes, computed sha256 hashes, and genuine
detached signatures for the §13 wire examples (offer, acceptance,
countersignature, tombstone, recheck request/response active+revoked,
directory delta).

TEST-ONLY KEYS. Deterministic: seed = sha256(b"clack-v07-test/<label>"),
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
import unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)
import ed25519  # noqa: E402  (repo's vendored pure-stdlib implementation)

GRANT_ID = "9f2c4a1e-7b3d-4e8f-a2c1-5d6e7f8090a1"
ACCEPTANCE_ID = "b7e1d903-2a4c-4f5d-9e6a-1c2b3d4e5f60"
NONCE = b"clack-v07-nonce-0000000000000001"  # exactly 32 bytes
assert len(NONCE) == 32


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
    "relay_x": "requester-relay-x",
    "relay_y": "responder-relay-y",
}

keys = {}
for name, label in KEY_LABELS.items():
    seed = hashlib.sha256(b"clack-v07-test/" + label.encode("ascii")).digest()
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
        b"clack-v07-test/" + KEY_LABELS[signer].encode("ascii")).digest()
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

# --- 5. recheck-request (relay_x -> relay_y) ---
request = {
    "v": 1,
    "from_relay_key": keys["relay_x"]["pubkey_b64u"],
    "to_relay_key": keys["relay_y"]["pubkey_b64u"],
    "link_epoch": 42,
    "grant_ids": [GRANT_ID],
    "watermark": "2026-09-26T06:00:00Z",
    "nonce": b64u(NONCE),
    "requested_at": "2026-09-27T05:55:00Z",
    "deadline": "2026-09-27T06:00:00Z",
}
vectors.append(vec("recheck-request", "recheck-request", "relay_x", request))

# --- 6. recheck-response, active grant (relay_y -> relay_x) ---
resp_active = {
    "v": 1,
    "from_relay_key": keys["relay_y"]["pubkey_b64u"],
    "to_relay_key": keys["relay_x"]["pubkey_b64u"],
    "link_epoch": 42,
    "nonce": b64u(NONCE),
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
    "responded_at": "2026-09-27T05:57:00Z",
}
vectors.append(vec("recheck-response/active", "recheck-response", "relay_y",
                   resp_active))

# --- 7. recheck-response, revoked grant (nested signed wrapper) ---
resp_revoked = {
    "v": 1,
    "from_relay_key": keys["relay_y"]["pubkey_b64u"],
    "to_relay_key": keys["relay_x"]["pubkey_b64u"],
    "link_epoch": 42,
    "nonce": b64u(NONCE),
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
    "responded_at": "2026-09-27T05:57:00Z",
}
vectors.append(vec("recheck-response/revoked", "recheck-response", "relay_y",
                   resp_revoked, role="positive"))

# --- 7b. recheck-response, revoked grant, LATE (negative fixture: 3900s past deadline) ---
resp_revoked_late = dict(resp_revoked)
resp_revoked_late["responded_at"] = "2026-09-27T07:05:00Z"
vectors.append(vec("recheck-response/revoked-late", "recheck-response",
                   "relay_y", resp_revoked_late,
                   role="negative:responded_at_past_deadline"))

# --- 8a. directory snapshot-100 (§9 full snapshot): the base the delta applies to ---
anchor_peer = hashlib.sha256(b"clack-v07-test/anchor-peer").digest()
anchor_peer_key = b64u(ed25519._publickey(anchor_peer))
gone_peer = hashlib.sha256(b"clack-v07-test/gone-peer").digest()
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
new_peer = hashlib.sha256(b"clack-v07-test/new-peer").digest()
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

corpus = {
    "corpus": "clack-federation-v07-test-corpus",
    "version": 1,
    "warning": "TEST-ONLY synthetic keys. Never use on any real relay.",
    "generated_by": "reviews/gen-v07-corpus.py",
    "source_spec": "docs/federation-trust-model.md v0.7",
    "fixture_classes": "Vectors carry a 'role': 'positive' vectors must be "
                       "accepted; 'negative:<rule>' vectors carry a VALID "
                       "signature and must be rejected on the named rule "
                       "(timing, not crypto). A negative vector is a complete "
                       "exchange fixture (request context + response); the "
                       "offer/acceptance/countersignature/tombstone/snapshot "
                       "vectors are standalone signed records.",
    "canonical_encoding": "preimage = ASCII('clack:<type>/v1:') || canonical JSON per §3; "
                          "sha256 fields cover the canonical JSON bytes only (no domain prefix)",
    "key_derivation": "seed = sha256(b'clack-v07-test/' + label); pubkey = Ed25519(seed)",
    "keys": keys,
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

# v0.7 timing cross-checks (P2-4): the positive revoked case must sit inside
# the request's deadline; the late variant must sit 3900s past it
req = json.loads(by_name["recheck-request"]["canonical_json"])
rev_pos = json.loads(by_name["recheck-response/revoked"]["canonical_json"])
rev_late = json.loads(by_name["recheck-response/revoked-late"]["canonical_json"])
if not (req["requested_at"] <= rev_pos["responded_at"] <= req["deadline"]):
    fails.append(("recheck-response/revoked",
                  "positive revoked case outside request deadline"))
if rev_late["responded_at"] != "2026-09-27T07:05:00Z":
    fails.append(("recheck-response/revoked-late",
                  "expected 07:05:00Z (3900s past the 06:00:00Z deadline)"))
if by_name["recheck-response/revoked-late"]["role"] != \
        "negative:responded_at_past_deadline":
    fails.append(("recheck-response/revoked-late", "role not marked negative"))

# v0.7 delta cross-check (P2-4): base_hash must be the sha256 of the supplied
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

out_path = os.path.join(HERE, "federation-v07-test-corpus.json")
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(corpus, f, indent=2, ensure_ascii=False)
    f.write("\n")
print("wrote %s (%d vectors, all signatures/hashes verified)"
      % (out_path, len(vectors)))
