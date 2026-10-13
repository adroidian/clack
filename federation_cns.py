#!/usr/bin/env python3
"""Signed-static CNS route snapshot loader (candidate-679-py-federation-v1).

Implements ``blobs/route-snapshot-contract-v1.json``
(CONTROLLER_APPROVED_FOR_PRIVATE_IMPLEMENTATION, 2026-10-08T04:01:09Z) and
the KNS/CNS seam rules from ``blobs/kns-cns-seam-contract-v1.json``.

Posture:
- Source: operator-curated complete snapshot, uid-owned mode-0600 regular
  file, no symlink components. Authority public key: separately pinned,
  uid-owned mode-0600 32-byte raw file. No TOFU, no auto-pin, no key
  generation, no key download.
- Live KNS is OFF (``live_kns_activation=false``). ``kns_source_merge`` and
  ``kns_server_or_plugin_activation`` are FORBIDDEN. This module contains no
  socket code at all: an optional KNS *hint* may be supplied by the caller
  as an already-parsed dict and is compared against CNS authority bytes
  only; it can never create authority.
- Fail-closed codes are the seam contract's codes. A rejected snapshot or
  resolution causes zero partial route, key, grant, or endpoint mutation.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sqlite3
import stat
import time
import unicodedata
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parent

import ed25519  # vendored pure-stdlib Ed25519 (see ed25519.py)

SCHEMA = "clack-cns-route-snapshot/v1"
SNAPSHOT_VERSION = 1
SIGNING_DOMAIN = b"clack-cns-route-snapshot/v1\n"

_TOP_FIELDS = (
    "schema", "version", "snapshot_id", "issuer", "issuer_key_id",
    "sequence", "issued_at", "expires_at", "routes", "signature",
)
_ROUTE_FIELDS = (
    "peer", "identity", "owner", "prime_relay", "home", "relay_endpoint",
    "relay_identity_key_id", "generation", "signing_key_id", "encryption_key_id",
)
_SIG_FIELDS = ("alg", "key_id", "value")

_PEER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_KEY_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_INT = 9223372036854775807

_HINT_FIELDS = ("agent", "primeRelay", "relayEndpoint", "status", "source")

# Fail-closed codes (kns-cns-seam-contract-v1.json).
CNS_SNAPSHOT_UNAVAILABLE = "cns_snapshot_unavailable"
CNS_SNAPSHOT_INVALID = "cns_snapshot_invalid"
CNS_ROUTE_UNKNOWN = "cns_route_unknown"
KNS_HINT_INVALID = "kns_hint_invalid"
KNS_CNS_MISMATCH = "kns_cns_mismatch"
RELAY_PIN_MISMATCH = "relay_pin_mismatch"
HANDSHAKE_INACTIVE = "handshake_inactive"
GRANT_INACTIVE = "grant_inactive"
E2EE_V2_CONTEXT_UNTRUSTED = "e2ee_v2_context_untrusted"


class CNSResolutionError(ValueError):
    """Fail-closed CNS resolution failure. ``code`` is a seam-contract code."""

    def __init__(self, code, detail=""):
        super().__init__("%s: %s" % (code, detail) if detail else code)
        self.code = code


# ---------------------------------------------------------------------------
# Private file reads (same posture as federation_adapter.private_read)

def _canonical(path):
    if not isinstance(path, str) or not os.path.isabs(path) or os.path.normpath(path) != path:
        raise CNSResolutionError(CNS_SNAPSHOT_UNAVAILABLE, "path must be canonical and absolute")
    p = Path(path)
    if str(p.resolve()) != path or any(x.is_symlink() for x in (p, *p.parents)):
        raise CNSResolutionError(CNS_SNAPSHOT_UNAVAILABLE, "symlink paths are forbidden")
    return p


def _private_read(path, limit=1048576):
    _canonical(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise CNSResolutionError(CNS_SNAPSHOT_UNAVAILABLE, str(exc)) from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o600:
            raise CNSResolutionError(CNS_SNAPSHOT_UNAVAILABLE, "reference must be an owned mode-0600 regular file")
        with os.fdopen(fd, "rb", closefd=False) as f:
            data = f.read(limit + 1)
        if len(data) > limit:
            raise CNSResolutionError(CNS_SNAPSHOT_INVALID, "reference exceeds size limit")
        return data
    finally:
        os.close(fd)


def _strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def constant(_):
        raise ValueError("non-finite JSON number")

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise CNSResolutionError(CNS_SNAPSHOT_INVALID, "snapshot is not strict UTF-8") from None
    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    except ValueError as exc:
        raise CNSResolutionError(CNS_SNAPSHOT_INVALID, "snapshot JSON rejected: %s" % exc) from None


def _nfc_clean(value):
    return (
        type(value) is str
        and unicodedata.normalize("NFC", value) == value
        and not any(ord(c) < 32 or ord(c) == 127 for c in value)
    )


def _exact_int(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def _b64u_decode_canonical(value):
    """Canonical unpadded base64url decode; rejects non-canonical forms."""
    if type(value) is not str or not value:
        raise ValueError("base64url value must be a nonempty string")
    try:
        raw = base64.b64decode(
            (value + "=" * (-len(value) % 4)).encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except Exception:
        raise ValueError("base64url decode failed") from None
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
        raise ValueError("base64url value is not canonical")
    return raw


# ---------------------------------------------------------------------------
# Snapshot shape validation (route-snapshot-contract-v1.json)

def _route_error(route, index):
    prefix = "routes[%d]" % index
    if type(route) is not dict:
        return prefix + ": route must be an object"
    if any(type(k) is not str for k in route):
        return prefix + ": bad route field set"
    if set(route) != set(_ROUTE_FIELDS):
        return prefix + ": route has missing or unknown fields"
    if not _nfc_clean(route["peer"]) or _PEER_RE.match(route["peer"]) is None:
        return prefix + ": bad peer"
    ident = route["identity"]
    if (not _nfc_clean(ident) or not ident.startswith("agent://")
            or not 1 <= len(ident.encode("utf-8")) - len("agent://") <= 512):
        return prefix + ": bad identity"
    for field, limit in (("owner", 512), ("prime_relay", 256), ("home", 2048)):
        value = route[field]
        if (not _nfc_clean(value) or not value
                or len(value.encode("utf-8")) > limit):
            return prefix + ": bad %s" % field
    endpoint = route["relay_endpoint"]
    if not _nfc_clean(endpoint):
        return prefix + ": bad relay_endpoint"
    parts = endpoint.split("://", 1)
    if len(parts) != 2 or parts[0] not in ("http", "https"):
        return prefix + ": bad relay_endpoint scheme"
    rest = parts[1]
    if "@" in rest or "?" in rest or "#" in rest:
        return prefix + ": relay_endpoint must be secret-free"
    host_port, _, path = rest.partition("/")
    if path not in ("",):
        return prefix + ": relay_endpoint must have no non-root path"
    host = host_port.rsplit(":", 1)[0].strip("[]")
    if not host:
        return prefix + ": bad relay_endpoint host"
    if parts[0] == "http":
        # http allowed only for numeric loopback or approved Tailnet addresses.
        import ipaddress

        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            return prefix + ": http relay_endpoint requires numeric host"
        tailnet = addr in ipaddress.ip_network("100.64.0.0/10") or addr in ipaddress.ip_network("fd7a:115c:a1e0::/48")
        if not (addr.is_loopback or tailnet):
            return prefix + ": http relay_endpoint outside approved scope"
    if not _nfc_clean(route["relay_identity_key_id"]) or _KEY_ID_RE.match(route["relay_identity_key_id"]) is None:
        return prefix + ": bad relay_identity_key_id"
    if not _exact_int(route["generation"], 0, _MAX_INT):
        return prefix + ": bad generation"
    for field in ("signing_key_id", "encryption_key_id"):
        value = route[field]
        if type(value) is not str:
            return prefix + ": bad %s" % field
        try:
            if len(_b64u_decode_canonical(value)) != 8:
                return prefix + ": bad %s length" % field
        except ValueError:
            return prefix + ": bad %s encoding" % field
    return None


def validate_snapshot_shape(snap):
    """Return an error string for a malformed snapshot, otherwise None."""
    if type(snap) is not dict:
        return "snapshot must be an object"
    if any(type(k) is not str for k in snap):
        return "bad snapshot field set"
    if set(snap) != set(_TOP_FIELDS):
        return "snapshot has missing or unknown fields"
    if snap["schema"] != SCHEMA:
        return "bad snapshot schema"
    if not _exact_int(snap["version"], 1, 1):
        return "bad snapshot version"
    if (not _nfc_clean(snap["snapshot_id"])
            or _UUID_RE.match(snap["snapshot_id"]) is None
            or str(uuid.UUID(snap["snapshot_id"])) != snap["snapshot_id"]):
        return "bad snapshot_id"
    if (not _nfc_clean(snap["issuer"]) or not snap["issuer"]
            or len(snap["issuer"].encode("utf-8")) > 512):
        return "bad issuer"
    if not _nfc_clean(snap["issuer_key_id"]) or _KEY_ID_RE.match(snap["issuer_key_id"]) is None:
        return "bad issuer_key_id"
    if not _exact_int(snap["sequence"], 1, _MAX_INT):
        return "bad sequence"
    if not _exact_int(snap["issued_at"], 0, _MAX_INT):
        return "bad issued_at"
    if not _exact_int(snap["expires_at"], 0, _MAX_INT):
        return "bad expires_at"
    routes = snap["routes"]
    if type(routes) is not list or len(routes) < 1:
        return "routes must be a non-empty array"
    seen = set()
    prev_key = None
    for i, route in enumerate(routes):
        err = _route_error(route, i)
        if err:
            return err
        key = (route["identity"].encode("utf-8"), route["peer"].encode("utf-8"))
        if key in seen:
            return "duplicate peer or identity"
        seen.add(key)
        # Strictly ascending by the UTF-8 byte tuple (identity, peer).
        if prev_key is not None and not prev_key < key:
            return "routes not strictly ordered by (identity, peer)"
        prev_key = key
    sig = snap["signature"]
    if type(sig) is not dict:
        return "bad signature object"
    if any(type(k) is not str for k in sig):
        return "bad signature field set"
    if set(sig) != set(_SIG_FIELDS):
        return "signature has missing or unknown fields"
    if sig["alg"] != "Ed25519":
        return "bad signature alg"
    if sig["key_id"] != snap["issuer_key_id"]:
        return "signature key_id must equal issuer_key_id"
    try:
        if len(_b64u_decode_canonical(sig["value"])) != 64:
            return "bad signature length"
    except ValueError:
        return "bad signature encoding"
    return None


def canonical_signed_bytes(snap):
    """Canonical bytes of the signed object (snapshot minus signature)."""
    unsigned = {k: v for k, v in snap.items() if k != "signature"}
    raw = json.dumps(
        unsigned, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    )
    if raw.endswith("\n"):
        raise ValueError("canonical form must not end with newline")
    return raw.encode("utf-8")


def snapshot_digest(snap):
    return hashlib.sha256(canonical_signed_bytes(snap)).hexdigest()


def verify_snapshot(snap, authority_pub32):
    """Shape, canonicalization, issuer pin, and Ed25519 verification.

    Returns (True, None) or raises CNSResolutionError(cns_snapshot_invalid).
    """
    err = validate_snapshot_shape(snap)
    if err:
        raise CNSResolutionError(CNS_SNAPSHOT_INVALID, err)
    if type(authority_pub32) is not bytes or len(authority_pub32) != 32:
        raise CNSResolutionError(CNS_SNAPSHOT_INVALID, "authority key must be 32 bytes")
    pinned = "sha256:" + hashlib.sha256(authority_pub32).hexdigest()
    if snap["issuer_key_id"] != pinned:
        raise CNSResolutionError(CNS_SNAPSHOT_INVALID, "issuer_key_id does not match pinned authority key")
    preimage = SIGNING_DOMAIN + canonical_signed_bytes(snap)
    signature = _b64u_decode_canonical(snap["signature"]["value"])
    try:
        if not ed25519.verify(authority_pub32, signature, preimage):
            raise CNSResolutionError(CNS_SNAPSHOT_INVALID, "Ed25519 signature verification failed")
    except CNSResolutionError:
        raise
    except Exception as exc:
        raise CNSResolutionError(CNS_SNAPSHOT_INVALID, "signature verification error: %s" % exc) from None
    return True


def check_freshness(snap, now=None):
    """Freshness per contract; raises cns_snapshot_invalid on violation."""
    now = time.time() if now is None else now
    if type(now) not in (int, float):
        raise CNSResolutionError(CNS_SNAPSHOT_INVALID, "clock must be numeric")
    issued, expires = snap["issued_at"], snap["expires_at"]
    if issued > now + 300:
        raise CNSResolutionError(CNS_SNAPSHOT_INVALID, "issued_at is in the future")
    if expires <= issued:
        raise CNSResolutionError(CNS_SNAPSHOT_INVALID, "expires_at <= issued_at")
    if expires - issued > 604800:
        raise CNSResolutionError(CNS_SNAPSHOT_INVALID, "snapshot lifetime exceeds 604800s")
    if expires <= now - 300:
        raise CNSResolutionError(CNS_SNAPSHOT_INVALID, "snapshot is stale")
    return True


# ---------------------------------------------------------------------------
# Monotonic high-water state (sqlite; atomic projection)

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS cns_meta(
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    sequence INTEGER NOT NULL,
    digest TEXT NOT NULL,
    signature TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cns_routes(
    identity TEXT PRIMARY KEY,
    peer TEXT NOT NULL,
    owner TEXT NOT NULL,
    prime_relay TEXT NOT NULL,
    home TEXT NOT NULL,
    relay_endpoint TEXT NOT NULL,
    relay_identity_key_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    signing_key_id TEXT NOT NULL,
    encryption_key_id TEXT NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0
);
"""

_MUTABLE_BY_GENERATION = (
    "peer", "home", "relay_endpoint", "relay_identity_key_id",
    "signing_key_id", "encryption_key_id",
)


def _open_state(state_path):
    _canonical(state_path)
    parent = str(Path(state_path).parent)
    _canonical(parent)
    if not os.path.isdir(parent):
        raise CNSResolutionError(CNS_SNAPSHOT_UNAVAILABLE, "state parent is not a directory")
    conn = sqlite3.connect(state_path, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA_SQL)
    return conn


def _project(conn, snap):
    """Validate monotonicity and atomically project the accepted routes.

    Raises CNSResolutionError on any violation; on success the meta row and
    all route rows are committed as one fail-closed transition.
    """
    digest = snapshot_digest(snap)
    signature = snap["signature"]["value"]
    sequence = snap["sequence"]
    cur = conn.execute("SELECT sequence, digest, signature FROM cns_meta WHERE singleton=1").fetchone()
    if cur is not None:
        old_seq, old_digest, old_sig = cur
        if sequence < old_seq:
            raise CNSResolutionError(CNS_SNAPSHOT_INVALID, "sequence rollback")
        if sequence == old_seq:
            if digest != old_digest or signature != old_sig:
                raise CNSResolutionError(CNS_SNAPSHOT_INVALID, "same sequence with different bytes")
            return {"sequence": sequence, "replayed": True}
    rows = {
        r["identity"]: dict(r)
        for r in (
            dict(zip(
                ("identity", "peer", "owner", "prime_relay", "home",
                 "relay_endpoint", "relay_identity_key_id", "generation",
                 "signing_key_id", "encryption_key_id", "disabled"),
                row,
            ))
            for row in conn.execute(
                "SELECT identity, peer, owner, prime_relay, home,"
                " relay_endpoint, relay_identity_key_id, generation,"
                " signing_key_id, encryption_key_id, disabled FROM cns_routes"
            ).fetchall()
        )
    }
    seen_identities = set()
    for route in snap["routes"]:
        ident = route["identity"]
        seen_identities.add(ident)
        old = rows.get(ident)
        if old is None:
            continue
        if route["generation"] < old["generation"]:
            raise CNSResolutionError(CNS_SNAPSHOT_INVALID, "generation rollback for %s" % ident)
        if route["generation"] == old["generation"]:
            for field in _ROUTE_FIELDS:
                if field == "generation":
                    continue
                if route[field] != old[field]:
                    raise CNSResolutionError(
                        CNS_SNAPSHOT_INVALID,
                        "same-generation rewrite of %s for %s" % (field, ident),
                    )
        else:
            # Higher generation may rotate peer/home/endpoint/relay pin/keys,
            # but may not change the stable identity or the owner anchor.
            if route["owner"] != old["owner"]:
                raise CNSResolutionError(CNS_SNAPSHOT_INVALID, "owner change requires identity-migration contract")
    # Atomic projection: one transaction for meta + all route rows.
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute(
            "INSERT OR REPLACE INTO cns_meta(singleton, sequence, digest, signature) VALUES (1,?,?,?)",
            (sequence, digest, signature),
        )
        for route in snap["routes"]:
            conn.execute(
                "INSERT OR REPLACE INTO cns_routes(identity, peer, owner, prime_relay, home,"
                " relay_endpoint, relay_identity_key_id, generation,"
                " signing_key_id, encryption_key_id, disabled)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,0)",
                (route["identity"], route["peer"], route["owner"], route["prime_relay"],
                 route["home"], route["relay_endpoint"], route["relay_identity_key_id"],
                 route["generation"], route["signing_key_id"], route["encryption_key_id"]),
            )
        # Omission from a higher-sequence complete snapshot disables the
        # route for new work; the high-water row is retained for rollback
        # detection and exact accepted-message reconciliation.
        for ident in rows:
            if ident not in seen_identities:
                conn.execute("UPDATE cns_routes SET disabled=1 WHERE identity=?", (ident,))
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return {"sequence": sequence, "replayed": False}


def load_snapshot(snapshot_path, authority_key_path, state_path, now=None):
    """Full ingest pipeline: parse, verify, freshness, monotonicity, project.

    Returns {"sequence": int, "routes": {peer: route-row}, "replayed": bool}.
    Raises CNSResolutionError with a seam-contract fail-closed code.
    """
    raw = _private_read(snapshot_path)
    snap = _strict_json(raw)
    key = _private_read(authority_key_path, 32)
    if len(key) != 32:
        raise CNSResolutionError(CNS_SNAPSHOT_INVALID, "authority key must be exactly 32 bytes")
    # Verification order per contract: shape/types -> canonicalize ->
    # issuer pin -> signature -> freshness -> monotonicity -> projection.
    verify_snapshot(snap, key)
    check_freshness(snap, now)
    conn = _open_state(state_path)
    try:
        result = _project(conn, snap)
    finally:
        conn.close()
    result["routes"] = active_routes(state_path)
    return result


def active_routes(state_path):
    """Return {peer: route-row} for routes not disabled by omission."""
    conn = _open_state(state_path)
    try:
        out = {}
        for row in conn.execute(
            "SELECT peer, identity, owner, prime_relay, home, relay_endpoint,"
            " relay_identity_key_id, generation, signing_key_id, encryption_key_id"
            " FROM cns_routes WHERE disabled=0"
        ).fetchall():
            out[row[0]] = {
                "peer": row[0], "identity": row[1], "owner": row[2],
                "prime_relay": row[3], "home": row[4], "relay_endpoint": row[5],
                "relay_identity_key_id": row[6], "generation": row[7],
                "signing_key_id": row[8], "encryption_key_id": row[9],
            }
        return out
    finally:
        conn.close()


def route_context(route):
    """The relay_e2ee_v2_contexts projection value for one route."""
    return {
        "identity": route["identity"],
        "home": route["home"],
        "generation": route["generation"],
        "signing_key_id": route["signing_key_id"],
        "encryption_key_id": route["encryption_key_id"],
    }


# ---------------------------------------------------------------------------
# Resolution (CNS authority only; KNS stays OFF)

def _check_kns_hint(hint, short_name, route):
    """Compare an optional already-parsed KNS hint against CNS authority.

    Pure function: no network, no sockets. A matching hint never alters the
    selected authority bytes. Any disagreement is kns_cns_mismatch.
    """
    if hint is None:
        return
    if type(hint) is not dict:
        raise CNSResolutionError(KNS_HINT_INVALID, "hint must be an object")
    if any(type(k) is not str for k in hint):
        raise CNSResolutionError(KNS_HINT_INVALID, "bad hint field set")
    # Only the five accepted hint fields; extra fields fail closed. Absent
    # fields are simply absent hints (the algorithm says "a present hint.X").
    if not set(hint) <= set(_HINT_FIELDS):
        raise CNSResolutionError(KNS_HINT_INVALID, "hint has unknown fields")
    for field in hint:
        if type(hint[field]) is not str:
            raise CNSResolutionError(KNS_HINT_INVALID, "hint field %s must be a string" % field)
    if hint.get("agent") != short_name:
        raise CNSResolutionError(KNS_CNS_MISMATCH, "hint agent != short_name")
    if "primeRelay" in hint and hint["primeRelay"] != route["prime_relay"]:
        raise CNSResolutionError(KNS_CNS_MISMATCH, "hint primeRelay disagrees with CNS")
    if "relayEndpoint" in hint:
        claimed = hint["relayEndpoint"].rstrip("/")
        if claimed != route["relay_endpoint"].rstrip("/"):
            raise CNSResolutionError(KNS_CNS_MISMATCH, "hint relayEndpoint disagrees with CNS")
    # status/source are observability/provenance only: never authority.


def resolve_route(state_path, short_name, kns_hint=None):
    """Resolve short_name to exactly one active CNS route.

    Returns the route row dict. Raises CNSResolutionError with a
    seam-contract fail-closed code. KNS is OFF: the hint path is a pure
    comparison that can never create authority, derive keys, or egress.
    """
    if type(short_name) is not str or _PEER_RE.match(short_name) is None:
        raise CNSResolutionError(CNS_ROUTE_UNKNOWN, "short_name failed peer-name validation")
    routes = active_routes(state_path)
    matches = [r for r in routes.values() if r["peer"] == short_name]
    if len(matches) != 1:
        raise CNSResolutionError(CNS_ROUTE_UNKNOWN, "short_name did not resolve to exactly one active CNS route")
    route = matches[0]
    _check_kns_hint(kns_hint, short_name, route)
    return route


def check_envelope_against_route(enc, route):
    """Bind a v2 envelope to its CNS route context.

    Returns None when the envelope's kid/skid/ctx match the accepted CNS
    route; otherwise raises CNSResolutionError(e2ee_v2_context_untrusted).
    Plain shape validation is the caller's job (clack_client.envelope).
    """
    if type(enc) is not dict or enc.get("v") != 2:
        raise CNSResolutionError(E2EE_V2_CONTEXT_UNTRUSTED, "not a v2 envelope")
    ctx = enc.get("ctx")
    if type(ctx) is not dict:
        raise CNSResolutionError(E2EE_V2_CONTEXT_UNTRUSTED, "v2 envelope lacks context")
    if enc.get("kid") != route["encryption_key_id"]:
        raise CNSResolutionError(E2EE_V2_CONTEXT_UNTRUSTED, "kid != CNS encryption_key_id")
    if enc.get("skid") != route["signing_key_id"]:
        raise CNSResolutionError(E2EE_V2_CONTEXT_UNTRUSTED, "skid != CNS signing_key_id")
    cns = route_context(route)
    if ctx.get("recipient_id") != cns["identity"]:
        raise CNSResolutionError(E2EE_V2_CONTEXT_UNTRUSTED, "ctx recipient_id != CNS identity")
    if ctx.get("recipient_home") != cns["home"]:
        raise CNSResolutionError(E2EE_V2_CONTEXT_UNTRUSTED, "ctx recipient_home != CNS home")
    if ctx.get("recipient_home_generation") != cns["generation"]:
        raise CNSResolutionError(E2EE_V2_CONTEXT_UNTRUSTED, "ctx generation != CNS generation")
    return None
