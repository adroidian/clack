#!/usr/bin/env python3
"""Generate the v0.9 federation trust model machine-readable test corpus.

Writes reviews/federation-v09-test-corpus.json: all 12 v0.8 vectors
byte-identical (self-verified, not regenerated), plus three new
negative directory vectors for Zari's v0.8 P1-2 finding (T1-42):
directory/expired, directory/ttl-cap-exceeded, directory/future-issued.

The v0.8 vectors are preserved exactly — the negative vectors are
additive only. New vectors reuse the v0.8 deterministic TEST-ONLY keys
(seed = sha256(b"clack-v08-test/<label>")) so the corpus stays in one
key family.

The three new vectors are timeless rejections (no receiver clock
needed):
- expired:            expires_at = issued_at - 1s   -> rejected (expires_at <= issued_at)
- ttl-cap-exceeded:   expires_at = issued_at + 8d   -> rejected (expires_at > issued_at + 7d cap)
- future-issued:      issued_at  = 2036-01-01T00:00:00Z, expires_at = issued_at + 1d
                      -> rejected (issued_at > receiver-now + 300s at any sane clock)

Field order in the new vectors is the canonical §9 order
(v, issuer_relay_key, audience_relay_key, epoch, sequence, issued_at,
expires_at, is_delta, base_sequence, base_hash, entries, tombstones) —
issued_at/expires_at sit after sequence, not appended at the end.
(Zari's v0.9 P1: the v0.9.0 vectors appended them after tombstones,
which is noncanonical.)

Per the corpus convention, negative:<rule> vectors carry a VALID
signature and must be rejected on the named rule — crypto validity
never rescues a freshness failure.

TEST-ONLY KEYS. These keys must NEVER be used outside the test corpus.

Self-verifying: every signature (all 15) is re-checked after assembly;
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


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64u_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canonical(obj):
    """§3 canonical JSON: fixed field order (insertion order), no
    whitespace, minimal escaping, literal UTF-8."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def domain(typ):
    return ("clack:" + typ + "/v1:").encode("ascii")


V08 = json.load(open(os.path.join(HERE, "federation-v08-test-corpus.json")))
assert V08["corpus"] == "clack-federation-v08-test-corpus", V08["corpus"]

# --- Self-check: all 12 v0.8 vectors verify independently ------------------
for v in V08["vectors"]:
    pub = b64u_decode(v["signer_pubkey_b64u"])
    sig = b64u_decode(v["signature_b64u"])
    pre = bytes.fromhex(v["preimage_hex"])
    assert pre == domain(v["domain"].split("clack:")[1].split("/v1:")[0]) + \
        bytes.fromhex(v["canonical_hex"]), v["name"]
    assert ed25519.verify(pub, sig, pre), "v0.8 vector failed: %s" % v["name"]
    assert v["canonical_hex"] == canonical(json.loads(v["canonical_json"])).hex(), \
        "v0.8 canonical bytes drift: %s" % v["name"]

# --- Build the three v0.9 negative directory vectors -----------------------
RELAY_X_LABEL = "directory-relay-x"
seed = hashlib.sha256(b"clack-v08-test/" + RELAY_X_LABEL.encode("ascii")).digest()
pub = ed25519._publickey(seed)
assert b64u(pub) == V08["keys"]["relay_x"]["pubkey_b64u"], "key derivation drift"

BASE_DIR = {
    "v": 1,
    "issuer_relay_key": V08["keys"]["relay_x"]["pubkey_b64u"],
    "audience_relay_key": V08["keys"]["relay_y"]["pubkey_b64u"],
    "epoch": 42,
    "sequence": 102,
    "issued_at": None,    # filled per vector; position is canonical (§9)
    "expires_at": None,   # filled per vector; position is canonical (§9)
    "is_delta": False,
    "base_sequence": None,
    "base_hash": None,
    "entries": {
        V08["keys"]["minter_peer"]["pubkey_b64u"]: {
            "display_name": "anchor",
            "federation_visible": True,
            "added_at": "2026-09-27T05:00:00Z",
        }
    },
    "tombstones": {},
}

NEW = [
    ("directory/expired", "negative:directory_expired",
     "2026-09-27T06:00:00Z", "2026-09-27T05:59:59Z"),
    ("directory/ttl-cap-exceeded", "negative:directory_ttl_cap",
     "2026-09-27T06:00:00Z", "2026-10-05T06:00:00Z"),
    ("directory/future-issued", "negative:directory_issued_in_future",
     "2036-01-01T00:00:00Z", "2036-01-02T00:00:00Z"),
]

new_vectors = []
EXPECTED_ORDER = ["v", "issuer_relay_key", "audience_relay_key", "epoch",
                  "sequence", "issued_at", "expires_at", "is_delta",
                  "base_sequence", "base_hash", "entries", "tombstones"]
for name, role, issued_at, expires_at in NEW:
    obj = dict(BASE_DIR)  # issued_at/expires_at already in canonical position
    obj["issued_at"] = issued_at
    obj["expires_at"] = expires_at
    assert list(obj.keys()) == EXPECTED_ORDER, "noncanonical field order: %s" % name
    canon = canonical(obj)
    pre = domain("directory") + canon
    sig = ed25519.sign(seed, pre)
    assert ed25519.verify(pub, sig, pre), name
    new_vectors.append({
        "name": name,
        "role": role,
        "domain": "clack:directory/v1:",
        "signer": "relay_x",
        "signer_pubkey_b64u": b64u(pub),
        "canonical_json": canon.decode("utf-8"),
        "canonical_hex": canon.hex(),
        "preimage_hex": pre.hex(),
        "object_sha256_b64u": b64u(hashlib.sha256(canon).digest()),
        "signature_b64u": b64u(sig),
    })

# --- Assemble the v0.9 corpus ----------------------------------------------
out = dict(V08)
out["corpus"] = "clack-federation-v09-test-corpus"
out["version"] = 2
out["source_spec"] = "docs/federation-trust-model.md v0.9"
out["generated_by"] = "reviews/gen-v09-corpus.py"
out["vectors"] = list(V08["vectors"]) + new_vectors

# Final self-check: every signature in the assembled corpus verifies.
for v in out["vectors"]:
    pub2 = b64u_decode(v["signer_pubkey_b64u"])
    sig2 = b64u_decode(v["signature_b64u"])
    pre2 = bytes.fromhex(v["preimage_hex"])
    assert ed25519.verify(pub2, sig2, pre2), "final check failed: %s" % v["name"]

dest = os.path.join(HERE, "federation-v09-test-corpus.json")
with open(dest, "w") as f:
    json.dump(out, f, indent=2, ensure_ascii=False)
    f.write("\n")
print("wrote %s: %d vectors (%d v0.8 byte-identical + %d new), all signatures verified"
      % (dest, len(out["vectors"]), len(V08["vectors"]), len(new_vectors)))
