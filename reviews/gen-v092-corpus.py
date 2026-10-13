#!/usr/bin/env python3
"""Generate the v0.9.2 federation trust model machine-readable test corpus.

Writes reviews/federation-v092-test-corpus.json: 14 of the 15 v0.9.1
vectors byte-identical, `directory/expired` REBUILT with a valid
interval (Zari N1 / Clingy N1), plus four new vectors:

- directory/invalid-interval  (negative:directory_invalid_interval)
  preserves the static interval check the old broken vector
  accidentally covered (expires_at <= issued_at -> rejected).
- directory/unicode-display-name  (positive)
  non-ascii display_name ("nugget <crow><zwj><black square>"), NFC-normalized
  literal UTF-8 per section 3 — Clingy's N5 counter-proposal. utf-8
  handshake vectors are NOT added (his dissent stands: the v5 signed
  cores are fixed-alphabet).
- recheck-request/unknown + recheck-response/unknown  (positive pair)
  the signed material for the unknown->SUSPECT in-flight/crash tests
  (N4): status "unknown" with the generation-0 sentinel per section 8.1
  rule 5b, on a fresh nonce and its own request window.
- exchange fixture `unknown-suspect-recheck` pins the crash-recovery
  and stale-read expectations for the SUSPECT path.

Z1/N1 fix detail: the v0.9.1 `directory/expired` vector used an INVALID
interval (expires_at = issued_at - 1s) — it tested the interval rule,
not expiry. The rebuilt vector has a VALID 1-day interval
(issued 2000-01-01, expires 2000-01-02): timelessly expired at receipt
for any sane receiver clock, so it tests exactly the
`expires_at <= now - 300s` receipt rule (rejected, not cached).

New vectors reuse the v0.8 deterministic TEST-ONLY keys
(seed = sha256(b"clack-v08-test/<label>")) so the corpus stays in one
key family.

TEST-ONLY KEYS. These keys must NEVER be used outside the test corpus.

Self-verifying: every signature (all 19) is re-checked after assembly;
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


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64u_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canonical(obj):
    """Section 3 canonical JSON: fixed field order (insertion order), no
    whitespace, minimal escaping, literal UTF-8, NFC-normalized."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


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

V09 = json.load(open(os.path.join(HERE, "federation-v09-test-corpus.json")))
assert V09["corpus"] == "clack-federation-v09-test-corpus", V09["corpus"]
assert len(V09["vectors"]) == 15, len(V09["vectors"])

# --- Self-check: all 15 v0.9.1 vectors verify independently -----------------
for v in V09["vectors"]:
    pub = b64u_decode(v["signer_pubkey_b64u"])
    sig = b64u_decode(v["signature_b64u"])
    pre = bytes.fromhex(v["preimage_hex"])
    assert pre == domain(v["domain"].split("clack:")[1].split("/v1:")[0]) + \
        bytes.fromhex(v["canonical_hex"]), v["name"]
    assert ed25519.verify(pub, sig, pre), "v0.9.1 vector failed: %s" % v["name"]
    assert v["canonical_hex"] == canonical(json.loads(v["canonical_json"])).hex(), \
        "v0.9.1 canonical bytes drift: %s" % v["name"]

V09_BY_NAME = {v["name"]: v for v in V09["vectors"]}
GRANT_ID = "9f2c4a1e-7b3d-4e8f-a2c1-5d6e7f8090a1"


def vec(name, typ, signer, obj, role="positive"):
    canon = canonical(obj)
    pre = domain(typ) + canon
    seed = hashlib.sha256(
        b"clack-v08-test/" + KEY_LABELS[signer].encode("ascii")).digest()
    sig = ed25519.sign(seed, pre)
    pub = ed25519._publickey(seed)
    return {
        "name": name,
        "role": role,
        "domain": "clack:" + typ + "/v1:",
        "signer": signer,
        "signer_pubkey_b64u": b64u(pub),
        "canonical_json": canon.decode("utf-8"),
        "canonical_hex": canon.hex(),
        "preimage_hex": pre.hex(),
        "object_sha256_b64u": b64u(hashlib.sha256(canon).digest()),
        "signature_b64u": b64u(sig),
    }


DIR_ORDER = ["v", "issuer_relay_key", "audience_relay_key", "epoch",
             "sequence", "issued_at", "expires_at", "is_delta",
             "base_sequence", "base_hash", "entries", "tombstones"]


def base_directory():
    minter_peer_key = V09["keys"]["minter_peer"]["pubkey_b64u"]
    return {
        "v": 1,
        "issuer_relay_key": V09["keys"]["relay_x"]["pubkey_b64u"],
        "audience_relay_key": V09["keys"]["relay_y"]["pubkey_b64u"],
        "epoch": 42,
        "sequence": None,  # filled per vector
        "issued_at": None,
        "expires_at": None,
        "is_delta": False,
        "base_sequence": None,
        "base_hash": None,
        "entries": {
            minter_peer_key: {
                "display_name": "anchor",
                "federation_visible": True,
                "added_at": "2026-09-27T05:00:00Z",
            }
        },
        "tombstones": {},
    }


new_vectors = []

# --- Z1/N1: rebuild directory/expired with a VALID interval ----------------
# Valid 1-day interval, timelessly expired at receipt (both timestamps in
# year 2000): rejected on expires_at <= now - 300s, NOT on the interval
# rule. The v0.9.1 bytes (invalid interval) move to directory/invalid-interval.
fixed_expired = base_directory()
fixed_expired["sequence"] = 102
fixed_expired["issued_at"] = "2000-01-01T00:00:00Z"
fixed_expired["expires_at"] = "2000-01-02T00:00:00Z"
assert list(fixed_expired.keys()) == DIR_ORDER, "noncanonical field order"
assert fixed_expired["expires_at"] > fixed_expired["issued_at"], "must be a valid interval"
iv = fixed_expired["expires_at"]
ii = fixed_expired["issued_at"]
assert iv <= "2000-01-08T00:00:00Z", "must respect the 7d pilot cap"
assert ii < "2026-01-01T00:00:00Z", "timelessly expired for any sane clock"
new_vectors.append(vec("directory/expired", "directory", "relay_x",
                       fixed_expired, role="negative:directory_expired"))

# --- Companion: the old broken bytes, honestly renamed ----------------------
invalid_interval = base_directory()
invalid_interval["sequence"] = 103
invalid_interval["issued_at"] = "2026-09-27T06:00:00Z"
invalid_interval["expires_at"] = "2026-09-27T05:59:59Z"  # <= issued_at
assert list(invalid_interval.keys()) == DIR_ORDER, "noncanonical field order"
new_vectors.append(vec("directory/invalid-interval", "directory", "relay_x",
                       invalid_interval,
                       role="negative:directory_invalid_interval"))

# --- Clingy N5 counter-proposal: non-ascii directory display_name ----------
UNICODE_NAME = "nugget \U0001F426\u200D\u2B1B"
assert unicodedata.normalize("NFC", UNICODE_NAME) == UNICODE_NAME, \
    "display_name not NFC-stable"
unicode_dir = base_directory()
unicode_dir["sequence"] = 104
unicode_dir["issued_at"] = "2026-09-27T06:00:00Z"
unicode_dir["expires_at"] = "2026-09-28T06:00:00Z"
peer_key = V09["keys"]["minter_peer"]["pubkey_b64u"]
unicode_dir["entries"][peer_key]["display_name"] = UNICODE_NAME
assert list(unicode_dir.keys()) == DIR_ORDER, "noncanonical field order"
v_uni = vec("directory/unicode-display-name", "directory", "relay_x",
            unicode_dir, role="positive")
assert "\\u" not in v_uni["canonical_json"].lower().replace("\\\\u", ""), \
    "canonical bytes must carry literal UTF-8, never \\uXXXX escapes"
assert unicodedata.normalize("NFC", v_uni["canonical_json"]) == \
    v_uni["canonical_json"], "canonical bytes not NFC-stable"
new_vectors.append(v_uni)

# --- N4: unknown->SUSPECT exchange pair (fresh nonce, own window) ------------
# Section 8.1 rule 5b: `unknown` entries carry the generation-0 sentinel
# and claim no match. Grant timeline stays coherent with the v0.8
# fixtures: grant issued 06:00, countersigned 06:05; this exchange runs in
# the 08:55-09:00 window on an installed generation-1 grant.
UNKNOWN_NONCE = b"clack-v092-nonce-" + b"000000000000004"
assert len(UNKNOWN_NONCE) == 32, len(UNKNOWN_NONCE)

req_unknown = {
    "v": 1,
    "from_relay_key": V09["keys"]["minter_relay"]["pubkey_b64u"],
    "to_relay_key": V09["keys"]["redeemer_relay"]["pubkey_b64u"],
    "link_epoch": 42,
    "grant_ids": [GRANT_ID],
    "watermark": "2026-09-27T06:57:00Z",
    "nonce": b64u(UNKNOWN_NONCE),
    "requested_at": "2026-09-27T08:55:00Z",
    "deadline": "2026-09-27T09:00:00Z",
}
new_vectors.append(vec("recheck-request/unknown", "recheck-request",
                       "minter_relay", req_unknown))

resp_unknown = {
    "v": 1,
    "from_relay_key": V09["keys"]["redeemer_relay"]["pubkey_b64u"],
    "to_relay_key": V09["keys"]["minter_relay"]["pubkey_b64u"],
    "link_epoch": 42,
    "nonce": b64u(UNKNOWN_NONCE),
    "grants": [
        {
            "grant_id": GRANT_ID,
            "generation": 0,  # the 0 sentinel: unknown claims no match
            "status": "unknown",
            "tombstone": None,
            "tombstone_signature": None,
            "tombstone_hash": None,
            "effective_expires_at": None,
        }
    ],
    "responded_at": "2026-09-27T08:57:00Z",
}
new_vectors.append(vec("recheck-response/unknown", "recheck-response",
                       "redeemer_relay", resp_unknown, role="positive"))

# --- Assemble the v0.9.2 corpus ---------------------------------------------
out = dict(V09)
out["corpus"] = "clack-federation-v092-test-corpus"
out["version"] = 3
out["source_spec"] = "docs/federation-trust-model.md v0.9.2"
out["generated_by"] = "reviews/gen-v092-corpus.py"
out["fixture_classes"] = (
    "Vectors carry a 'role': 'positive' vectors are cryptographically valid "
    "records (signature, hashes, references, and -- for exchange cases -- "
    "deadline placement all check out); 'negative:<rule>' vectors carry a "
    "VALID signature and must be rejected on the named rule (timing, not "
    "crypto). A 'positive' role does NOT mean the record must be accepted in "
    "any state -- live acceptance additionally requires the pending nonce "
    "context, installed-grant state, and preconditions the exchange fixture "
    "manifest pins per case. The offer/acceptance/countersignature/tombstone/"
    "snapshot vectors are standalone signed records; each recheck "
    "request/response pair is a complete exchange fixture tied to its "
    "manifest entry. `recheck-response/unknown` is a positive signed record: "
    "'unknown' is a protocol status, not a rejection -- it drives the "
    "SUSPECT transition, not a reject predicate.")

# 14 of 15 v0.9.1 vectors byte-identical; directory/expired is rebuilt
# (Z1/N1); the four new vectors are appended.
preserved = [v for v in V09["vectors"] if v["name"] != "directory/expired"]
assert len(preserved) == 14, len(preserved)
for v in preserved:
    assert v == V09_BY_NAME[v["name"]], "v0.9.1 vector mutated: %s" % v["name"]
out["vectors"] = preserved + new_vectors

# --- Exchange fixture manifest: the 3 v0.9.1 exchanges byte-identical, -----
# --- plus the unknown-suspect-recheck in-flight/crash fixture (N4). ---------
out["exchanges"] = list(V09["exchanges"])
out["exchanges"].append({
    "name": "unknown-suspect-recheck",
    "request_vector": "recheck-request/unknown",
    "response_vector": "recheck-response/unknown",
    "from_relay": "minter_relay",
    "to_relay": "redeemer_relay",
    "link_epoch": 42,
    "installed_grant": {"grant_id": GRANT_ID, "generation": 1,
                        "tombstone_present": False},
    "prior_watermark": "2026-09-27T06:57:00Z",
    "state_note": "In-flight/crash fixture (N4): the `unknown` response is "
                  "the signed material for the SUSPECT path's single durable "
                  "commit (T2-40), the crash-recovery pass (T2-41), and the "
                  "concurrent stale-read linearization rule (T2-42, M1). The "
                  "response is a positive signed record inside its deadline; "
                  "'unknown' is a protocol status, not a rejection.",
    "requester_clock": {
        "requested_at": "2026-09-27T08:55:00Z",
        "deadline": "2026-09-27T09:00:00Z",
        "commit_at": "2026-09-27T08:58:00Z",
    },
    "expected": {
        "outcome": "suspect-transition",
        "grant_state": "SUSPECT",
        # unknown verifies no sample: the watermark does NOT advance.
        "watermark": "2026-09-27T06:57:00Z",
        "nonce_consumed": True,
        "delivery_suspended": True,
        "queue_held": True,
        "fresh_recheck_opened": True,
        # Crash-recovery expectation (T2-41): crash after the SUSPECT
        # commit, before the fresh recheck's response arrives -> recovery
        # finds the grant SUSPECT with no live recheck pending and opens a
        # new recheck before any delivery decision. Crash between the
        # commit and the fresh-recheck opening -> exactly one recheck is
        # opened, never duplicated.
        "crash_recovery": "SUSPECT grant with no live recheck pending opens "
                          "a new recheck before any delivery decision; the "
                          "fresh recheck is opened exactly once",
    },
})

# --- Self-verification: every signature, hash, and cross-reference ----------
fails = []
by_name = {v["name"]: v for v in out["vectors"]}

for v in out["vectors"]:
    canon = v["canonical_json"].encode("utf-8")
    if canon.hex() != v["canonical_hex"]:
        fails.append((v["name"], "canonical_hex mismatch"))
    if b64u(hashlib.sha256(canon).digest()) != v["object_sha256_b64u"]:
        fails.append((v["name"], "object_sha256 mismatch"))
    pre = bytes.fromhex(v["preimage_hex"])
    if pre != v["domain"].encode("ascii") + canon:
        fails.append((v["name"], "preimage framing mismatch"))
    pub = b64u_decode(v["signer_pubkey_b64u"])
    sig = b64u_decode(v["signature_b64u"])
    if not ed25519.verify(pub, sig, pre):
        fails.append((v["name"], "signature verify failed"))
    # negative check: a mutated preimage must NOT verify
    if ed25519.verify(pub, sig, pre + b"!"):
        fails.append((v["name"], "mutated preimage accepted"))

# v0.9.1 byte-identity: the 14 preserved vectors must be byte-identical to
# the v0.9.1 corpus; directory/expired must differ (it was rebuilt).
for v in preserved:
    old = V09_BY_NAME[v["name"]]
    for field in ("canonical_hex", "preimage_hex", "object_sha256_b64u",
                  "signature_b64u"):
        if v[field] != old[field]:
            fails.append((v["name"], "v0.9.1 byte-identity drift: " + field))
new_expired = by_name["directory/expired"]
old_expired = V09_BY_NAME["directory/expired"]
if new_expired["canonical_hex"] == old_expired["canonical_hex"]:
    fails.append(("directory/expired", "was not rebuilt (Z1/N1)"))
if new_expired["role"] != "negative:directory_expired":
    fails.append(("directory/expired", "role drift"))

# Named-rule semantics: each negative vector must actually violate its
# named rule (and ONLY the structural rules it claims to).
neg = {
    "directory/expired": ("expired", "2000-01-01T00:00:00Z",
                          "2000-01-02T00:00:00Z"),
    "directory/invalid-interval": ("invalid_interval", "2026-09-27T06:00:00Z",
                                   "2026-09-27T05:59:59Z"),
    "directory/ttl-cap-exceeded": ("ttl_cap", "2026-09-27T06:00:00Z",
                                   "2026-10-05T06:00:00Z"),
    "directory/future-issued": ("issued_in_future", "2036-01-01T00:00:00Z",
                                "2036-01-02T00:00:00Z"),
}
for name, (rule, issued, expires) in neg.items():
    obj = json.loads(by_name[name]["canonical_json"])
    if list(obj.keys()) != DIR_ORDER:
        fails.append((name, "noncanonical field order"))
    if obj["issued_at"] != issued or obj["expires_at"] != expires:
        fails.append((name, "timestamp drift"))
    if by_name[name]["role"] != "negative:directory_" + rule:
        fails.append((name, "role != negative:directory_" + rule))
# the rebuilt expired vector must have a VALID interval (Z1/N1 core)
obj = json.loads(by_name["directory/expired"]["canonical_json"])
if not (obj["expires_at"] > obj["issued_at"] and
        obj["expires_at"] <= "2000-01-08T00:00:00Z"):
    fails.append(("directory/expired", "interval still invalid (Z1/N1)"))

# unknown pair: section 8.1 rule 5b sentinel + positive placement
req = json.loads(by_name["recheck-request/unknown"]["canonical_json"])
resp = json.loads(by_name["recheck-response/unknown"]["canonical_json"])
entry = resp["grants"][0]
if entry["status"] != "unknown" or entry["generation"] != 0:
    fails.append(("recheck-response/unknown", "not the 0-sentinel form"))
if not (req["requested_at"] <= resp["responded_at"] <= req["deadline"]):
    fails.append(("recheck-response/unknown", "outside its deadline"))
if req["nonce"] != resp["nonce"]:
    fails.append(("recheck-request/unknown", "request/response nonce mismatch"))
if req["nonce"] in {json.loads(v["canonical_json"])["nonce"]
                    for v in V09["vectors"] if "nonce" in v["canonical_json"]}:
    fails.append(("recheck-request/unknown", "nonce reused from an older exchange"))

# exchange-manifest coherence (extends the v0.8 checks to the new exchange)
grant_relays = {V09["keys"]["minter_relay"]["pubkey_b64u"],
                V09["keys"]["redeemer_relay"]["pubkey_b64u"]}
seen_nonces = {}
for ex in out["exchanges"]:
    rq = json.loads(by_name[ex["request_vector"]]["canonical_json"])
    rs = json.loads(by_name[ex["response_vector"]]["canonical_json"])
    if rq["nonce"] != rs["nonce"]:
        fails.append((ex["name"], "request/response nonce mismatch"))
    if rq["nonce"] in seen_nonces:
        fails.append((ex["name"], "nonce reused across exchanges"))
    seen_nonces[rq["nonce"]] = ex["name"]
    if {rq["from_relay_key"], rq["to_relay_key"]} != grant_relays:
        fails.append((ex["name"], "recheck relays are not the grant's home relays"))
    if rs["from_relay_key"] != rq["to_relay_key"] or \
            rs["to_relay_key"] != rq["from_relay_key"]:
        fails.append((ex["name"], "response direction not reversed"))
    rc = ex["requester_clock"]
    if rq["requested_at"] != rc["requested_at"] or rq["deadline"] != rc["deadline"]:
        fails.append((ex["name"], "manifest clock != request vector clock"))
    in_deadline = rq["requested_at"] <= rs["responded_at"] <= rq["deadline"]
    outcome = ex["expected"]["outcome"]
    if outcome in ("accept", "suspect-transition") and not in_deadline:
        fails.append((ex["name"], "expected %s but response outside deadline" % outcome))
    if outcome == "reject" and in_deadline:
        fails.append((ex["name"], "expected reject but response inside deadline"))
    if outcome == "accept" and rs["grants"][0]["status"] == "active":
        wm = min(rs["responded_at"], rc["commit_at"])
        if ex["expected"]["watermark"] != wm:
            fails.append((ex["name"], "watermark != min(responded_at, commit_at)"))
    if outcome == "suspect-transition":
        # unknown verifies no sample: the watermark must be unchanged
        if ex["expected"]["watermark"] != ex["prior_watermark"]:
            fails.append((ex["name"], "unknown must not advance the watermark"))

if fails:
    print("SELF-CHECK FAILED:")
    for name, why in fails:
        print("  - %s: %s" % (name, why))
    sys.exit(1)

dest = os.path.join(HERE, "federation-v092-test-corpus.json")
with open(dest, "w", encoding="utf-8") as f:
    json.dump(out, f, indent=2, ensure_ascii=False)
    f.write("\n")
print("wrote %s: %d vectors (%d v0.9.1 byte-identical, directory/expired "
      "rebuilt, %d new), %d exchanges, all signatures verified"
      % (dest, len(out["vectors"]), len(preserved),
         len(new_vectors), len(out["exchanges"])))
