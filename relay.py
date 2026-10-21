#!/usr/bin/env python3
"""Clack A2A relay: authenticated peer-to-peer text message relay (stdlib only).

Peers: zari, mercedes, vesper, sigrid, nugget.
Bearer-token auth per peer; tokens live in relay-config.json (mode 600), only
sha256 hashes are stored in relay.db. Message content is data only: this
server never executes, interprets, or acts on message text.
"""
import base64
import faulthandler
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import secrets
import signal
import socket
import sqlite3
import stat
import sys
import threading
import time
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import ed25519  # vendored pure-stdlib Ed25519 (see ed25519.py)
import e2ee  # vendored pure-stdlib X25519 + ChaCha20-Poly1305 (see e2ee.py)
import federation_cns  # signed-static CNS route authority (candidate-679-py-federation-v1)

# Shared transport shape validator only; never loads cryptography or keys.
# (candidate-679-py-federation-v1: v2 envelope shape validation comes from
# the client envelope module. The v1 path below keeps its approved behavior.)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "clack-client"))  # noqa: E402
from clack_client.envelope import native_payload  # noqa: E402

VERSION = "1.1.0"
# BASE may be overridden for testing via CLACK_RELAY_BASE; production
# always uses ~/workspace/clack-relay.
BASE = os.environ.get("CLACK_RELAY_BASE", os.path.expanduser("~/workspace/clack-relay"))
# Code lives with this script; state lives in BASE. The two coincide in the
# dev layout but differ in the documented deployment layout, so anything
# served from the code tree (e.g. the join client download) must resolve
# against the script's own directory, never BASE.
CODE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE, "relay-config.json")
DB_PATH = os.path.join(BASE, "relay.db")

TOPIC_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
TEXT_MIN, TEXT_MAX = 1, 65536
ID_MAX_LEN = 128
DEFAULT_TTL = 604800
MAX_TTL = 2592000
PENDING_CAP = 500
RETENTION = 7 * 86400
RATE_PER_MIN = 60
SWEEP_MIN_INTERVAL = 60.0

# --- Mandatory Ed25519 request signing (v0.2.12) -------------------------------
# Every authenticated request carries:
#   X-Clack-Scheme: 1
#   X-Clack-Key:    <peer name, must match the Bearer token's peer>
#   X-Clack-Nonce:  <unix_seconds>:<32 hex chars random>
#   X-Clack-Sig:    <hex Ed25519 signature>
# over the canonical bytes:
#   clack-ed25519-v1\n{METHOD_UPPER}\n{path_and_query}\n{sha256_hex(raw_body)}\n{nonce}
# Unsigned endpoints: /health, GET /v1/identity, /join, /join/client, and the
# pre-enrollment POSTs (/v1/invites/challenge, /v1/invites/redeem,
# /v1/enroll/challenge, /v1/enroll). Everything else: Bearer + valid
# signature, verified against the peer's stored Ed25519 identity_pubkey.
SIGN_SCHEME_ID = "clack-ed25519-v1"
NONCE_TTL = 600.0          # seconds a nonce stays valid (and is remembered)
NONCE_FUTURE_SKEW = 120.0  # seconds of clock skew tolerated into the future
NONCE_STORE_CAP = 100000   # hard cap on seen_nonces rows; at capacity new
                          # signed requests are refused (fail closed, R2) --
                          # live replay markers are never evicted
NONCE_RAND_RE = re.compile(r"^[0-9a-fA-F]{32}$")

# Operator-supplied Ed25519 identity keys for config-managed peers, from the
# "identity_pubkeys" config map: {peer_name: b64u(32-byte pubkey)}. This is
# the upgrade path for token-only config peers -- re-read from config on
# every restart, so removing a key downgrades the peer to upgrade_required.
_IDENTITY_PUBKEYS = {}


def _parse_identity_pubkeys(cfg):
    """Strictly validate relay-config.json "identity_pubkeys".

    Returns {name: canonical b64u pubkey}. Malformed entries raise
    ValueError (startup refuses loudly, mirroring reserved_names)."""
    raw = cfg.get("identity_pubkeys", {}) if cfg else {}
    if not isinstance(raw, dict):
        raise ValueError("identity_pubkeys must be an object, got %s"
                         % type(raw).__name__)
    peers = cfg.get("peers", {}) if cfg else {}
    hashes = cfg.get("peer_hashes", {}) if cfg else {}
    out = {}
    for name, key_b64 in raw.items():
        if name not in peers and name not in hashes:
            raise ValueError("identity_pubkeys entry %r is not a configured peer"
                             % (name,))
        try:
            key = b64u_decode(key_b64)
        except (ValueError, TypeError, AttributeError):
            raise ValueError("identity_pubkeys entry %r has a malformed key"
                             % (name,))
        if len(key) != 32:
            raise ValueError("identity_pubkeys entry %r key is %d bytes, want 32"
                             % (name, len(key)))
        # R5: small-order / non-prime-order keys admit trivial signature
        # forgeries under the vendored verifier. Refuse them at startup,
        # loudly, like every other malformed entry.
        if not ed25519.is_valid_pubkey(key):
            raise ValueError("identity_pubkeys entry %r key is not a valid "
                             "prime-order Ed25519 point" % (name,))
        out[name] = b64u_encode(key)  # canonical form for comparison
    return out


def _init_identity_pubkeys(cfg):
    global _IDENTITY_PUBKEYS
    try:
        _IDENTITY_PUBKEYS = _parse_identity_pubkeys(cfg)
    except ValueError as e:
        raise SystemExit("clack-relay: invalid identity_pubkeys: %s" % e)


# Ed25519 SPKI DER prefix: SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING }.
# A 44-byte DER body with this prefix holds the 32-byte raw key last.
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def _normalize_pubkey_input(s):
    """Accept a raw 43-char base64url Ed25519 pubkey OR a PEM SPKI block.

    Returns the canonical b64u form. Raises ValueError on anything else:
    non-string input, undecodable base64, wrong length, non-Ed25519 DER, or
    a non-prime-order point (R5 small-order forgery guard)."""
    if not isinstance(s, str):
        raise ValueError("pubkey is not a string")
    t = s.strip()
    if "BEGIN PUBLIC KEY" in t:
        # PEM SPKI (what openssl / stock tooling exports): strip the armor,
        # decode the DER, extract the trailing 32-byte key.
        b64 = "".join(
            line.strip()
            for line in t.splitlines()
            if line.strip() and "-----" not in line
        )
        try:
            der = base64.b64decode(b64)
        except Exception:
            raise ValueError("bad PEM body")
        if len(der) != 44 or not der.startswith(_ED25519_SPKI_PREFIX):
            raise ValueError("not an Ed25519 SPKI")
        key = der[12:]
    else:
        try:
            key = b64u_decode(t)
        except (ValueError, TypeError, AttributeError):
            raise ValueError("bad base64url")
    if len(key) != 32:
        raise ValueError("want 32 bytes, got %d" % len(key))
    # R5: never accept a small-order / non-prime-order key -- the vendored
    # verifier admits trivial forgeries under such keys.
    if not ed25519.is_valid_pubkey(key):
        raise ValueError("not a valid prime-order Ed25519 point")
    return b64u_encode(key)


def _persist_identity_pubkey(peer, pub_b64):
    """Write one identity_pubkeys entry through to relay-config.json.

    Atomic (tmp file + os.replace) and mode-preserving, so a crash or
    kill between the DB update and this write cannot corrupt the config.
    The in-memory relay_cfg is updated only AFTER the disk write
    succeeds, so a failed write never leaves memory ahead of disk.
    Raises OSError on failure -- callers fail the request loudly rather
    than reporting a registration that a restart would lose."""
    cfg = relay_cfg
    # Write from a copy: mutate in-memory state only on success.
    new_cfg = dict(cfg)
    pubkeys = new_cfg.get("identity_pubkeys")
    if not isinstance(pubkeys, dict):
        pubkeys = {}
        new_cfg["identity_pubkeys"] = pubkeys
    else:
        pubkeys = dict(pubkeys)
        new_cfg["identity_pubkeys"] = pubkeys
    pubkeys[peer] = pub_b64
    tmp = CONFIG_PATH + ".tmp"
    try:
        st_mode = os.stat(CONFIG_PATH).st_mode
    except OSError:
        st_mode = None
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(new_cfg, f, indent=2)
        f.write("\n")
    if st_mode is not None:
        os.chmod(tmp, st_mode & 0o7777)
    os.replace(tmp, CONFIG_PATH)
    cfg["identity_pubkeys"] = pubkeys


# Operator-supplied token hashes for config-managed peers, from the
# "peer_hashes" config map: {peer_name: hex(sha256(token))}. This is the
# protected provisioning path (e.g. Sigrid's hash-only provisioning):
# the relay authenticates the peer by hashing the presented bearer
# token, but the plaintext token is never stored in config or DB.
# Strictly validated at startup; malformed entries refuse startup.
_PEER_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_PEER_HASHES = {}


def _parse_peer_hashes(cfg):
    """Strictly validate relay-config.json "peer_hashes".

    Returns {name: 64-char lowercase hex sha256}. Malformed entries
    raise ValueError (startup refuses loudly, mirroring
    identity_pubkeys)."""
    raw = cfg.get("peer_hashes", {}) if cfg else {}
    if not isinstance(raw, dict):
        raise ValueError("peer_hashes must be an object, got %s"
                         % type(raw).__name__)
    out = {}
    for name, h in raw.items():
        if not isinstance(name, str) or not name:
            raise ValueError("peer_hashes has an invalid peer name %r"
                             % (name,))
        if not isinstance(h, str) or not _PEER_HASH_RE.match(h):
            raise ValueError("peer_hashes entry %r is not a 64-char "
                             "lowercase hex sha256" % (name,))
        out[name] = h
    return out


def _init_peer_hashes(cfg):
    global _PEER_HASHES
    try:
        _PEER_HASHES = _parse_peer_hashes(cfg)
    except ValueError as e:
        raise SystemExit("clack-relay: invalid peer_hashes: %s" % e)
    overlap = set(cfg.get("peers") or {}) & set(_PEER_HASHES)
    if overlap:
        raise SystemExit(
            "clack-relay: peer(s) in both 'peers' and 'peer_hashes' "
            "(ambiguous identity source, refusing startup): %s"
            % ", ".join(sorted(overlap)))


# --- Mutual-consent handshakes (v0.2.13) ---------------------------------------
# Two strangers connect over one link: N mints (authenticated+signed, N's
# consent recorded with N's identity), Z redeems (pending) then accepts
# (signed by Z, Z's consent). /v1/send requires an ACTIVE handshake between
# the sender's and recipient's identities. No backfill: the relay can never
# create a handshake on its own authority -- only the two peers can.
HANDSHAKE_LINK_VERSION = 4
HANDSHAKE_PENDING_WINDOW = 86400.0  # 24h: redeem -> accept window
HANDSHAKE_NOTE_MAX = 280
# Tier knobs (config; no billing wired). 0 = unlimited / never. Parsed and
# validated in main(); module defaults keep bare imports working.
# NOTE (canary, Zari): handshake_inactivity_expiry_days defaults to 0 =
# never, and there is intentionally NO inactivity sweep in v0.2.13.
# Future semantics (recorded, not implemented): when enabled, only
# successfully authorized pair traffic refreshes last_activity -- never
# poll/health/rejected attempts; warn before expiry; require a fresh
# mutual handshake afterward.
HS_MAX_PER_IDENTITY = 0
HS_EXPIRY_DAYS = 0
HS_INACTIVITY_DAYS = 0
# E2EE: operator flag. When True, /v1/send refuses plaintext (text) and
# only accepts encrypted envelopes (enc). Default on; an operator can disable
# it only for a deliberate legacy-migration window.
REQUIRE_ENCRYPTED = True


def _parse_handshake_knobs(cfg):
    """Validate the section-9 tier knobs from relay-config.json. Strict:
    malformed entries refuse startup, like reserved_names/identity_pubkeys."""
    global HS_MAX_PER_IDENTITY, HS_EXPIRY_DAYS, HS_INACTIVITY_DAYS
    global REQUIRE_ENCRYPTED

    def _num(name, default, integer=False):
        v = cfg.get(name, default)
        if isinstance(v, bool) or not isinstance(v, (int, float)) or v < 0:
            raise ValueError("%s must be a number >= 0, got %r" % (name, v))
        if integer and not float(v).is_integer():
            raise ValueError("%s must be an integer >= 0, got %r" % (name, v))
        return int(v) if integer else float(v)

    HS_MAX_PER_IDENTITY = _num("max_handshakes_per_identity", 0, integer=True)
    HS_EXPIRY_DAYS = _num("handshake_expiry_days", 0)
    # Canary: inactivity expiry is OFF (0 = never). No sweep implements it.
    HS_INACTIVITY_DAYS = _num("handshake_inactivity_expiry_days", 0)
    # E2EE: operator flag for encrypted-only operation. Strict boolean.
    v = cfg.get("require_encrypted", True)
    if not isinstance(v, bool):
        raise ValueError("require_encrypted must be a boolean, got %r" % (v,))
    REQUIRE_ENCRYPTED = v


def _hs_pair(x, y):
    """Order-independent pair key: (a_identity, b_identity) sorted."""
    return (x, y) if x <= y else (y, x)


def _hs_id(a, b, generation):
    """Wire id for a handshake row. Embeds the pair generation (amendment:
    accept binds to the CURRENT generation; a stale id from a pre-revoke
    pending is rejected). Identities are b64u or [a-z0-9_-] names; neither
    charset contains '|'."""
    return "%s|%s|%d" % (a, b, generation)


def _parse_hs_id(hid):
    """Parse a handshake_id back to (a, b, generation) with the pair in
    canonical sorted order, or None."""
    if not isinstance(hid, str):
        return None
    parts = hid.split("|")
    if len(parts) != 3 or not parts[0] or not parts[1]:
        return None
    try:
        gen = int(parts[2])
    except ValueError:
        return None
    if gen < 0:
        return None
    a, b = _hs_pair(parts[0], parts[1])
    return (a, b, gen)


def _build_handshake_link(base_url, link_id, secret, minter_name, exp, max_uses):
    """v4 link fragment: h=link id, k=claim secret, by=display name
    (DISPLAY-ONLY -- the server always derives the minter from its mint
    record, never from this field), exp, max."""
    frag = "v=%d&r=%s&h=%s&k=%s&by=%s&exp=%d&max=%d" % (
        HANDSHAKE_LINK_VERSION,
        b64u_encode(base_url.encode("utf-8")),
        link_id,
        b64u_encode(secret),
        urllib.parse.quote(minter_name, safe=""),
        int(exp),
        max_uses,
    )
    return base_url.rstrip("/") + "/join#" + frag


def _is_strict_enc_v(v):
    """Strict enc_v validation: must be exactly int 0 or 1.

    `type(v) is int` (not isinstance) excludes bool (True/False) AND float
    (1.0 == 1 passes a value-equality check but breaks the integer bitwise
    AND used when recomputing enc_capable: 1.0 & 1 raises TypeError).
    """
    return type(v) is int and v in (0, 1)


def _hs_public(a, b, row):
    """Serialize a handshake row for the API. row is
    (status, created_at, pending_expires_at, expires_at, last_activity,
     via_link_id, generation, redeemer_identity, enc_capable, minter_enc_v,
     redeemer_enc_v, provenance)."""
    return {
        "handshake_id": _hs_id(a, b, row[6]),
        "a_identity": a,
        "b_identity": b,
        "status": row[0],
        "created_at": row[1],
        "pending_expires_at": row[2],
        "expires_at": row[3],
        "last_activity": row[4],
        "via_link_id": row[5],
        "generation": row[6],
        # E2EE: enc_capable=1 when BOTH parties advertised enc_v=1
        # (minter at mint, redeemer at accept). Clients encrypt only when
        # the pair's enc_capable is 1.
        "enc_capable": row[8] or 0,
    }


# Row shape shared by the handshake handlers: status, created_at,
# pending_expires_at, expires_at, last_activity, via_link_id, generation,
# redeemer_identity, enc_capable, minter_enc_v, redeemer_enc_v, provenance.
# provenance is the CANONICAL row class: 'ceremony' | 'operator-attested' |
# NULL/unknown. It is read explicitly wherever class matters -- never
# inferred from via_link_id (Zari 1635ebf7).
_HS_COLS = ("status, created_at, pending_expires_at, expires_at,"
            " last_activity, via_link_id, generation, redeemer_identity,"
            " enc_capable, minter_enc_v, redeemer_enc_v, provenance")


def _active_handshake_count(ident):
    """Established (active) handshakes involving ident, either direction.
    Pending handshakes do not count until accepted."""
    with db_lock:
        return conn.execute(
            "SELECT COUNT(*) FROM handshakes WHERE status='active'"
            " AND (a_identity=? OR b_identity=?)",
            (ident, ident),
        ).fetchone()[0]


def _active_handshake_list(ident):
    """Active handshakes for the at-cap response: named so the peer can
    revoke to make room."""
    with db_lock:
        rows = conn.execute(
            """SELECT a_identity, b_identity, created_at, last_activity, generation
               FROM handshakes WHERE status='active'
                 AND (a_identity=? OR b_identity=?)
               ORDER BY last_activity DESC""",
            (ident, ident),
        ).fetchall()
    out = []
    for a, b, created_at, last_activity, generation in rows:
        other = b if a == ident else a
        out.append(
            {
                "handshake_id": _hs_id(a, b, generation),
                "peer_identity": other,
                "peer_name_hint": peer_name_for_identity(other),
                "created_at": created_at,
                "last_activity": last_activity,
            }
        )
    return out

# --- Invite-link onboarding (v0.2.5, MVP) ------------------------------------
# Contacts-first: an invitation introduces two independently controlled Muse
# identities. The relay mints *service* tokens only; identity keypairs are
# generated on the recipient's side and the relay never sees the private key.
# HELD for post-MVP (documented, not implemented): owner keystore +
# delegation certs (pilot simplification: the instance holds its own identity
# key), signed introduction artifacts (the claim secret authenticates the
# invite in the MVP link -- there is no `sig` field), endorsements,
# directory, cross-relay invites.
INVITE_DEFAULT_EXPIRY = 86400    # 24h
INVITE_MAX_EXPIRY = 604800       # 7d
INVITE_MIN_EXPIRY = 60           # 1m
INVITE_DEFAULT_MAX_USES = 1
INVITE_MAX_USES_CAP = 25
INVITE_QUOTA_PER_IDENTITY = 10   # max active invites per inviter identity
CHALLENGE_TTL = 300.0            # 5 minutes, single-use
LINK_VERSION = 3

db_lock = threading.Lock()
rate_lock = threading.Lock()
rate_hits = {}  # token_sha -> deque[float]
# R5: per-process cache of stored-peer Ed25519 key validity
# (pub_b64 -> bool). Keys are immutable within a process lifetime.
_peer_key_valid = {}
# R4: cheap source-level bucket for failed authentication attempts, so a
# stolen bearer cannot burn a peer's request budget with unsigned garbage.
auth_fail_lock = threading.Lock()
auth_fail_hits = {}  # ip -> [float]
AUTH_FAIL_PER_MIN = 300
sweep_lock = threading.Lock()
_last_sweep = 0.0
# Safety-audit (Oct 2026): the periodic sweep no longer piggybacks on request
# handling. A dedicated daemon thread owns it; request paths never call
# sweep() directly. Rationale, two properties in one structural change:
#   (a) diagnostics are read-only -- /health must not DELETE/commit as a
#       side effect of being queried;
#   (b) a failing sweep must never kill an unrelated request with a dropped
#       connection -- the sweeper records its own outcome and /health
#       reports it explicitly (fail-closed by construction: any new table
#       sweep touches is covered with zero new guards).
_sweep_state_lock = threading.Lock()
_sweep_last_error = None  # None = last sweep ok (or never ran); else "ExcType: msg"

# Safety-audit Round 2/3 (Oct 2026, P01/P02/P03): the relay's declared schema
# is the SINGLE source of truth for structural health. _SCHEMA_DDL holds the
# exact CREATE TABLE statements init_db() executes; _SCHEMA_MIGRATION_COLUMNS
# holds every ensure-column startup migration (table -> ((col, ddl), ...)),
# the same tuples init_db()'s ALTER guards iterate. REQUIRED_TABLES and
# REQUIRED_SCHEMA are DERIVED from these at import -- never hand-maintained --
# so adding a table or column in either place automatically extends what
# /health verifies. A hardcoded check elsewhere would rot; Mercedes's
# independent review proved it twice (dropped peers table, then renamed
# peers.token_hash column, both returned 200 before these checks existed).
_SCHEMA_DDL = (
    """CREATE TABLE IF NOT EXISTS peers(
           name TEXT PRIMARY KEY,
           token_hash TEXT NOT NULL,
           created_at REAL NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS messages(
           id TEXT PRIMARY KEY,
           sender TEXT NOT NULL,
           recipient TEXT NOT NULL,
           topic TEXT,
           text TEXT NOT NULL,
           in_reply_to TEXT,
           created_at REAL NOT NULL,
           expires_at REAL NOT NULL,
           acked_at REAL,
           collected_at REAL,
           fetch_count INTEGER NOT NULL DEFAULT 0)""",
    """CREATE TABLE IF NOT EXISTS webhooks(
           peer TEXT PRIMARY KEY,
           url TEXT NOT NULL,
           created_at REAL NOT NULL,
           last_notified_at REAL,
           last_error TEXT)""",
    """CREATE TABLE IF NOT EXISTS invites(
           invite_id TEXT PRIMARY KEY,
           secret_hash TEXT NOT NULL,
           inviter_identity TEXT NOT NULL,
           exp REAL NOT NULL,
           max_uses INTEGER NOT NULL,
           uses INTEGER NOT NULL DEFAULT 0,
           revoked INTEGER NOT NULL DEFAULT 0,
           created_at REAL NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS challenges(
           nonce TEXT PRIMARY KEY,
           invite_id TEXT NOT NULL,
           created_at REAL NOT NULL,
           expires_at REAL NOT NULL,
           used INTEGER NOT NULL DEFAULT 0)""",
    """CREATE TABLE IF NOT EXISTS enroll_challenges(
           nonce TEXT PRIMARY KEY,
           kind TEXT NOT NULL,
           ref TEXT,
           created_at REAL NOT NULL,
           expires_at REAL NOT NULL,
           used INTEGER NOT NULL DEFAULT 0)""",
    """CREATE TABLE IF NOT EXISTS seen_nonces(
           nonce TEXT PRIMARY KEY,
           peer TEXT NOT NULL,
           expires_at REAL NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS retired_names(
           name TEXT PRIMARY KEY,
           retired_at REAL NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS handshakes(
           a_identity TEXT NOT NULL,
           b_identity TEXT NOT NULL,
           status TEXT NOT NULL,
           created_at REAL NOT NULL,
           pending_expires_at REAL,
           expires_at REAL,
           last_activity REAL NOT NULL,
           via_link_id TEXT,
           redeemer_identity TEXT,
           -- Per-pair generation, bumped on every revoke. The issued
           -- handshake_id embeds the generation; accept binds to the
           -- CURRENT generation, so an accept (or replayed accept)
           -- minted for a pre-revoke pending can never land on the
           -- post-revoke row. Quota-expiry transitions do NOT bump it.
           generation INTEGER NOT NULL DEFAULT 0,
           PRIMARY KEY (a_identity, b_identity))""",
    """CREATE TABLE IF NOT EXISTS link_revocations(
           link_id TEXT NOT NULL,
           a_identity TEXT NOT NULL,
           b_identity TEXT NOT NULL,
           revoked_at REAL NOT NULL,
           PRIMARY KEY (link_id, a_identity, b_identity))""",
    # candidate-679-py-federation-v1: durable cross-home forwarding outbox.
    # One row per accepted federated send on the SENDER's home relay. The
    # recipient mailbox row itself is created ONLY on the recipient's home
    # relay (no duplicated mailboxes): this table is the forwarding queue
    # plus the same-ID dedup record. Terminal rows are pruned by the sweep
    # after RETENTION; the table is required by /health like all _SCHEMA_DDL
    # tables, so a missing table fails the health check instead of silently
    # disabling forwarding.
    """CREATE TABLE IF NOT EXISTS federation_outbox(
           id TEXT PRIMARY KEY,
           sender TEXT NOT NULL,
           recipient TEXT NOT NULL,
           topic TEXT,
           in_reply_to TEXT,
           expires_at REAL NOT NULL,
           text TEXT NOT NULL,
           enc_v INTEGER NOT NULL,
           dest_origin TEXT NOT NULL,
           state TEXT NOT NULL,
           attempts INTEGER NOT NULL DEFAULT 0,
           next_attempt_at REAL NOT NULL,
           last_error TEXT,
           created_at REAL NOT NULL)""",
    # candidate-679-py-federation-v1 delta fix (Zari a74bb2b2, D2):
    # explicit sender-home grant/pair consent for cross-home wire
    # acceptance. One row per admitted (sender-home, sender,
    # recipient-home, recipient) tuple: status 'active' admits; any other
    # status (incl. 'revoked') rejects; a missing row fails closed. The
    # record is maintained by the relay operator (consent admission list)
    # and is NEVER derived from linked-relay trust or CNS location; peer
    # enrollment/mailboxes are not mirrored. The table is required by
    # /health like all _SCHEMA_DDL tables, so a missing table fails the
    # health check instead of silently disabling the grant gate.
    """CREATE TABLE IF NOT EXISTS federation_grants(
           sender_home TEXT NOT NULL,
           sender TEXT NOT NULL,
           recipient_home TEXT NOT NULL,
           recipient TEXT NOT NULL,
           status TEXT NOT NULL,
           created_at REAL NOT NULL,
           revoked_at REAL,
           note TEXT,
           PRIMARY KEY (sender_home, sender, recipient_home, recipient))""",
)
# Every ensure-column startup migration, as (column, column-ddl) tuples.
# init_db() iterates these exact tuples for its ALTER guards, so the health
# check and the migrations can never disagree about the declared schema.
_SCHEMA_MIGRATION_COLUMNS = {
    "messages": (
        ("collected_at", "REAL"),
        ("fetch_count", "INTEGER NOT NULL DEFAULT 0"),
        ("dead_reason", "TEXT"),
        ("enc_v", "INTEGER NOT NULL DEFAULT 0"),
    ),
    "peers": (
        ("identity_pubkey", "TEXT"),
        ("invited_by", "TEXT"),
        ("display_name", "TEXT"),
        # v0.2.10: enrollment telemetry for abuse detection. enroll_gate is
        # 'invite' | 'pow' | 'open' | 'config'; enroll_ip is the source IP at
        # enrollment; last_poll_at / last_send_at track activity (NULL =
        # never). Operator-visible via the DB; not exposed over the API.
        ("enroll_gate", "TEXT"),
        ("enroll_ip", "TEXT"),
        ("last_poll_at", "REAL"),
        ("last_send_at", "REAL"),
    ),
    "handshakes": (
        ("generation", "INTEGER NOT NULL DEFAULT 0"),
        ("enc_capable", "INTEGER NOT NULL DEFAULT 0"),
        ("minter_enc_v", "INTEGER NOT NULL DEFAULT 0"),
        ("redeemer_enc_v", "INTEGER NOT NULL DEFAULT 0"),
        # Fix A rev3 (Zari 1635ebf7): canonical row class for the v4
        # link-redeem upgrade path. 'ceremony' = pair formed through the
        # invite ceremony (via_link_id retained); 'operator-attested' =
        # pair established by operator action (no ceremony evidence).
        # NULL/other = unknown: the redeem upgrade fails closed. Set at
        # row creation; never backfilled.
        ("provenance", "TEXT"),
    ),
    "invites": (
        # A handshake link IS an invite row with grant_handshake=1.
        ("grant_handshake", "INTEGER DEFAULT 0"),
        ("note", "TEXT"),
        # E2EE: the minter's encryption-capability advertisement at mint.
        ("minter_enc_v", "INTEGER NOT NULL DEFAULT 0"),
        # NULL: legacy bearer. Non-NULL: public request, existing key only.
        ("target_identity", "TEXT"),
    ),
}
# Table-level constraint openers: definitions starting with one of these
# tokens describe the table, not a column (e.g. PRIMARY KEY (a, b)).
_SCHEMA_CONSTRAINT_TOKENS = frozenset(
    ("PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "CONSTRAINT"))


def _parse_schema_ddl(ddl):
    """Parse one CREATE TABLE statement -> (table_name, frozenset(columns)).

    Skips SQL line comments and table-level constraints. Column names are
    the first token of each column definition. Used only on our own
    _SCHEMA_DDL constants at import time.
    """
    m = re.search(r"CREATE TABLE IF NOT EXISTS\s+(\w+)\s*\(", ddl)
    table = m.group(1)
    body = re.sub(r"--[^\n]*", "", ddl)  # strip -- comments
    inner = body[body.index("(", m.start()) + 1: body.rindex(")")]
    cols = set()
    parts = []
    depth = 0
    buf = []
    for ch in inner:
        if ch == "(":
            depth += 1
            buf.append(ch)
        elif ch == ")":
            depth -= 1
            buf.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    for part in parts:
        tokens = part.split()
        if not tokens:
            continue
        if tokens[0].upper() in _SCHEMA_CONSTRAINT_TOKENS:
            continue
        cols.add(tokens[0].strip("\"'[]`"))
    return table, frozenset(cols)


def _derive_required_schema():
    tables = []
    schema = {}
    for ddl in _SCHEMA_DDL:
        table, cols = _parse_schema_ddl(ddl)
        tables.append(table)
        extra = frozenset(c for c, _ in _SCHEMA_MIGRATION_COLUMNS.get(table, ()))
        schema[table] = cols | extra
    return tuple(tables), schema


REQUIRED_TABLES, REQUIRED_SCHEMA = _derive_required_schema()


def _required_schema_ok():
    """Synchronously verify every required table exists with its required schema.

    Returns None when healthy, else a check token: "table:<name>" when a
    required table is absent, "schema:<table>.<column>" when a required
    column is absent (renamed/dropped), or "unreadable" when the catalog
    itself cannot be read. Table existence alone is NOT enough -- a renamed
    column breaks the real queries while the table still lists (Mercedes's
    Round-2 repro: ALTER TABLE peers RENAME COLUMN token_hash kept /health
    at 200 while auth failed). Runs inside the request so there is no
    daemon-interval stale window.
    """
    try:
        with db_lock:
            present = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            for t in REQUIRED_TABLES:
                if t not in present:
                    return "table:" + t
                # Usable schema, not just existence: every column the
                # declared schema requires must be present. Table/column
                # names come from our own derived constants, never user input.
                actual = {r[1] for r in conn.execute(
                    "PRAGMA table_info(\"%s\")" % t)}
                for col in sorted(REQUIRED_SCHEMA[t]):
                    if col not in actual:
                        return "schema:%s.%s" % (t, col)
                # A listed, well-shaped table can still be corrupt; one
                # cheap probe read per table.
                conn.execute("SELECT 1 FROM \"%s\" LIMIT 1" % t).fetchone()
    except Exception:
        return "unreadable"
    return None

conn = None
peer_names = set()
relay_cfg = None

# Dedicated relay identity signing key (RSA, private components only in
# relay-config.json mode 600). Used solely for the /v1/identity challenge so
# clients can pin the relay's identity before ever sending a bearer token.
id_n = id_e = id_d = None

# Per-IP rate limiting for the no-auth identity endpoint.
ip_rate_lock = threading.Lock()
ip_rate_hits = {}  # ip -> [float]
IP_RATE_PER_MIN = 30


# --- Federation cross-home forwarding (candidate-679-py-federation-v1) ---
#
# The missing hop for #679: a sender enrolled ONLY on home A can /v1/send a
# valid envelope to a recipient enrolled ONLY on home B. The base relay
# rejects that with 400 unknown_peer because the recipient is not in the
# local peer_names. This lane adds opaque, authenticated forwarding to ONE
# canonical recipient home, resolved from the operator-curated SIGNED CNS
# route snapshot -- never from client claims.
#
# Design (deliberate, minimal):
# - The relay stays transport-only: it never decrypts. Authorization
#   intelligence (sender-home grant, envelope CNS/key binding, owner
#   authenticity) lives in the adapter layer (federation_cns +
#   federation_e2ee_v2.AdapterV2), which gates BEFORE any wire effect.
#   The relay-side forwarding is authenticated transport between
#   operator-linked relays.
# - Consent cross-home is ATTESTED, not handshake-based: handshakes are
#   per-relay, so no local handshake can exist for a remote peer. Relay A
#   only forwards for its own authenticated local peers, only to the
#   CNS-canonical home of the recipient, only when a maintained
#   federation_grants row admits the exact (sender-home, sender,
#   recipient-home, recipient) tuple (delta fix, Zari a74bb2b2 D2:
#   linked-relay trust + CNS location alone never authorize a forward;
#   no grant fails closed, a revoked grant is rejected), and signs every
#   delivery with its operator-held Ed25519 relay identity key. Relay B
#   accepts only from a pinned linked relay whose attestation verifies,
#   and only for its own local recipients. The recipient mailbox row
#   exists ONLY on the recipient's home relay (no duplicated mailboxes);
#   the sender's home keeps a durable forwarding outbox (the queue +
#   same-ID dedup record).
# - relay_identity_key_id convention (made verifiable here): the CNS route
#   field MUST be "sha256:" + hex(sha256(32-byte Ed25519 relay identity
#   pubkey)). Both sides check it: A checks its own key against the CNS
#   pin for its home; B checks the attesting key against the CNS pin for
#   the sender's home. The operator's linked_relays map is the second,
#   independent pin: CNS authority alone never suffices.
# - Fail-closed: unknown recipient (CNS), recipient canonical-home == us,
#   sender not pinned to our home, pin mismatch, attestation failure,
#   v2 ctx/outer mismatch, bad TTL/endpoint -- all reject with zero
#   partial state. unknown_peer/auth/handshake/CNS strictness for the
#   local lane is untouched.
_FED = None  # set by _init_federation(cfg); None = forwarding disabled
_FED_DELIVER_PATH = "/v1/federation/deliver"
_FED_ATTEST_DOMAIN = b"clack-federation-deliver/v1\n"
_FED_RESPONSE_DOMAIN = b"clack-federation-deliver-response/v1\n"
_FED_FORWARD_INTERVAL = 5.0
_FED_HTTP_TIMEOUT = 10.0
_FED_MAX_BACKOFF = 300.0
_FED_TAILNETS = (
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("fd7a:115c:a1e0::/48"),
)
_federation_wake = threading.Event()


def _fed_b64u_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _fed_b64u_decode(value):
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


def _fed_read_seed(path):
    """Read a 32-byte Ed25519 seed from an owned mode-0600 regular file."""
    if type(path) is not str or not os.path.isabs(path) or os.path.normpath(path) != path:
        raise ValueError("seed path must be canonical and absolute")
    if os.path.realpath(path) != path:
        raise ValueError("symlink paths are forbidden")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid():
            raise ValueError("seed must be an owned regular file")
        if stat.S_IMODE(st.st_mode) != 0o600:
            raise ValueError("seed must be mode 0600")
        with os.fdopen(fd, "rb", closefd=False) as f:
            data = f.read(33)
        if len(data) != 32:
            raise ValueError("seed must be exactly 32 bytes")
        return data
    finally:
        os.close(fd)


def _federation_origin(endpoint):
    """Normalize a relay endpoint to its secret-free origin."""
    parts = endpoint.split("://", 1)
    host_port = parts[1].split("/", 1)[0]
    return (parts[0] + "://" + host_port).rstrip("/")


def _federation_url_ok(url):
    """SSRF guard for federation delivery targets: numeric loopback or
    approved Tailnet IP only (http or https), no credentials, no
    query/fragment, root path only. No DNS is ever consulted, so there is
    no rebinding TOCTOU. Mirrors the adapter's private-transport scope."""
    try:
        p = urlparse(url)
    except Exception:
        return False
    if p.scheme not in ("http", "https"):
        return False
    if not p.hostname or p.username or p.password:
        return False
    if p.query or p.fragment or p.path not in ("", "/"):
        return False
    try:
        addr = ipaddress.ip_address(p.hostname)
    except ValueError:
        return False  # hostnames forbidden: numeric IPs only
    if addr.is_loopback:
        return True
    return any(addr in net for net in _FED_TAILNETS)


def _init_federation(cfg):
    """Strict operator config for cross-home forwarding. Absent section =
    disabled (all existing behavior byte-identical). Malformed section =
    refuse startup, like every other _init_* strict validator."""
    global _FED
    _FED = None
    fed = cfg.get("federation")
    if fed is None:
        return
    if type(fed) is not dict:
        raise SystemExit("clack relay: config 'federation' must be an object")
    allowed = {"own_home", "cns_state", "relay_seed_ref", "linked_relays"}
    if set(fed) != allowed:
        raise SystemExit(
            "clack relay: config 'federation' has missing or unknown fields"
        )
    own_home = fed["own_home"]
    if type(own_home) is not str or not own_home or len(own_home) > 2048:
        raise SystemExit(
            "clack relay: federation 'own_home' must be a non-empty string"
        )
    cns_state = fed["cns_state"]
    if (
        type(cns_state) is not str
        or not os.path.isabs(cns_state)
        or os.path.normpath(cns_state) != cns_state
        or os.path.realpath(cns_state) != cns_state
        or not os.path.isfile(cns_state)
    ):
        raise SystemExit(
            "clack relay: federation 'cns_state' must be an existing "
            "canonical absolute file path"
        )
    try:
        seed = _fed_read_seed(fed["relay_seed_ref"])
    except ValueError as e:
        raise SystemExit("clack relay: federation 'relay_seed_ref': %s" % e)
    pub = ed25519._publickey(seed)
    linked = fed["linked_relays"]
    if type(linked) is not dict:
        raise SystemExit(
            "clack relay: federation 'linked_relays' must be an object"
        )
    parsed_linked = {}
    for origin, b64 in linked.items():
        if type(origin) is not str or _federation_origin(origin) != origin:
            raise SystemExit(
                "clack relay: federation linked_relays key is not a "
                "normalized origin: %r" % (origin,)
            )
        if not _federation_url_ok(origin):
            raise SystemExit(
                "clack relay: federation linked_relays origin outside "
                "private transport scope: %r" % (origin,)
            )
        try:
            raw = _fed_b64u_decode(b64)
        except ValueError:
            raise SystemExit(
                "clack relay: federation linked_relays value is not "
                "canonical base64url: %r" % (origin,)
            )
        if len(raw) != 32:
            raise SystemExit(
                "clack relay: federation linked_relays value is not 32 "
                "bytes: %r" % (origin,)
            )
        parsed_linked[origin] = b64
    _FED = {
        "own_home": own_home,
        "cns_state": cns_state,
        "seed": seed,
        "pub": pub,
        "pub_b64": _fed_b64u_encode(pub),
        "key_id": "sha256:" + hashlib.sha256(pub).hexdigest(),
        "linked_relays": parsed_linked,
    }


def _federation_attest_bytes(mid, sender, recipient, topic, in_reply_to,
                             expires_at, payload_sha256, enc_v, from_home):
    obj = {
        "id": mid,
        "from": sender,
        "to": recipient,
        "topic": topic if topic else None,
        "in_reply_to": in_reply_to if in_reply_to else None,
        "expires_at": expires_at,
        "payload_sha256": payload_sha256,
        "enc_v": enc_v,
        "from_home": from_home,
    }
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False)
    return _FED_ATTEST_DOMAIN + raw.encode("utf-8")


def _federation_response_bytes(nonce_hex, mid, accepted, duplicate):
    obj = {
        "nonce": nonce_hex,
        "id": mid,
        "accepted": accepted,
        "duplicate": duplicate,
    }
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False)
    return _FED_RESPONSE_DOMAIN + raw.encode("utf-8")


def _federation_backoff(attempts):
    return min(_FED_MAX_BACKOFF, 5.0 * (2.0 ** min(attempts, 6)))


def _federation_resolve(fed, name):
    """Resolve a peer name via the signed CNS snapshot. Any failure --
    unknown route, malformed snapshot, unreadable state -- fails closed
    with a seam-contract code, never a dropped connection."""
    try:
        return federation_cns.resolve_route(fed["cns_state"], name)
    except federation_cns.CNSResolutionError as e:
        raise
    except Exception:
        raise federation_cns.CNSResolutionError(
            federation_cns.CNS_SNAPSHOT_UNAVAILABLE,
            "route state unreadable") from None


def _federation_kick():
    _federation_wake.set()


def _federation_http_post_default(url, body):
    """Default relay-to-relay POST. Returns (status, raw_bytes); raises on
    transport failure (unknown outcome -- the destination dedupes by ID).
    Module-global _FED_HTTP_POST is injectable for tests."""
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "ClackRelay-Federation/1.0",
        },
    )
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(req, timeout=_FED_HTTP_TIMEOUT) as resp:
            return resp.status, resp.read(65536)
    except urllib.error.HTTPError as e:
        return e.code, e.read(65536)


_FED_HTTP_POST = _federation_http_post_default


def _derive_enc_version(enc, text):
    """Shared envelope/plaintext version derivation for _validate_send and
    the federation lane. Returns (error, enc_version): error is None on
    success; enc_version is 1 or 2 for a validated envelope, else 0. The
    version is derived from the validated envelope itself, never from a
    client-supplied marker.

    (candidate-679-py-federation-v1: extracted verbatim from
    _validate_send's encrypted branches so the federation lane -- which
    _validate_send leaves with enc_version=0 on its early unknown_peer
    return -- derives the same version under the same strictness.)"""
    # E2EE: exactly one of text (plaintext) / enc (envelope). The relay
    # shape-validates the envelope but never decrypts.
    #
    # candidate-679-py-federation-v1 boundary-1 repair: the encrypted
    # branches validate the envelope and record its derived version, then
    # FALL THROUGH to the shared in_reply_to/TTL checks -- exactly like the
    # parent method (10ffd1f). Returning success early skipped bad_ttl and
    # bad_in_reply_to for enc v1/v2 (a valid v1 envelope with ttl=-1 was
    # accepted and persisted already expired).
    if enc is not None:
        if text is not None:
            return "bad_envelope", 0
        if not isinstance(enc, dict):
            return "bad_envelope", 0
        err = e2ee.validate_envelope(enc)
        if err is None:
            # v1: approved legacy path, behavior unchanged -- except the
            # version marker itself must be an exact int. The legacy
            # validator's `!=` comparison would otherwise admit
            # `v=True` as version 1; strictness is not downgraded.
            if type(enc.get("v")) is not int:
                return "bad_envelope", 0
            if len(e2ee.serialize_envelope(enc)) > TEXT_MAX:
                return "bad_envelope", 0
            return None, 1
        # v2 (candidate-679-py-federation-v1): exact version/shape/size
        # via the client envelope module. Bool, float, str, and future
        # versions are all rejected here; strictness is not downgraded.
        try:
            raw = native_payload(enc, 2)
        except ValueError:
            return "bad_envelope", 0
        if len(raw.encode("utf-8")) > TEXT_MAX:
            return "bad_envelope", 0
        return None, 2
    if not isinstance(text, str) or not (TEXT_MIN <= len(text) <= TEXT_MAX):
        return "bad_text", 0
    if REQUIRE_ENCRYPTED:
        return "encryption_required", 0
    return None, 0


def _validate_send_body(topic, text, in_reply_to, ttl, enc):
    """Shared strict body checks for the local lane (_validate_send) and
    the federation lane (_handle_federation_send). Returns (error,
    enc_version) with the exact codes and order the parent method
    (10ffd1f) enforced: topic, envelope/version, in_reply_to, TTL.

    (Zari delta finding D1, a74bb2b2: _validate_send's early unknown_peer
    return skips these checks for remote recipients, and the federation
    handler previously re-ran only _derive_enc_version -- so ttl_secs=-1,
    topic='bad topic!', and in_reply_to=123 were 200 accepted=true AND
    created durable outbox rows. The federation lane must run this same
    path before durable acceptance.)"""
    if topic is not None and topic != "":
        if not isinstance(topic, str) or not TOPIC_RE.match(topic):
            return "bad_topic", 0
    # E2EE: exactly one of text (plaintext) / enc (envelope). The relay
    # shape-validates the envelope but never decrypts; the version is
    # derived by the shared helper (see _derive_enc_version).
    #
    # candidate-679-py-federation-v1 boundary-1 repair: the encrypted
    # branches validate the envelope and record its derived version, then
    # FALL THROUGH to the shared in_reply_to/TTL checks below -- exactly
    # like the parent method (10ffd1f). Returning success early skipped
    # bad_ttl and bad_in_reply_to for enc v1/v2 (a valid v1 envelope with
    # ttl=-1 was accepted and persisted already expired).
    err, enc_version = _derive_enc_version(enc, text)
    if err:
        return err, 0
    # Encrypted branches fall through to the shared checks below.
    if in_reply_to is not None and in_reply_to != "":
        if not isinstance(in_reply_to, str) or len(in_reply_to) > ID_MAX_LEN:
            return "bad_in_reply_to", 0
    if isinstance(ttl, bool) or not isinstance(ttl, (int, float)) or not (1 <= ttl <= MAX_TTL):
        return "bad_ttl", 0
    return None, enc_version


def _federation_mark(mid, state, last_error=None, attempts_bump=0,
                     next_attempt_at=None):
    with db_lock:
        if next_attempt_at is None:
            conn.execute(
                "UPDATE federation_outbox SET state=?, last_error=?,"
                " attempts=attempts+? WHERE id=?",
                (state, last_error, attempts_bump, mid),
            )
        else:
            conn.execute(
                "UPDATE federation_outbox SET state=?, last_error=?,"
                " attempts=attempts+?, next_attempt_at=? WHERE id=?",
                (state, last_error, attempts_bump, next_attempt_at, mid),
            )
        conn.commit()


def _federation_verify_response(fed, recipient, nonce_hex, mid, resp):
    """Destination trust: the delivery response must carry the destination
    relay's Ed25519 signature over our fresh nonce, and its key must be the
    one the signed CNS snapshot pins for the recipient's home relay. Any
    failure is an unknown outcome (the destination may have stored the
    message): retry later with the same ID; the destination dedupes."""
    try:
        route = _federation_resolve(fed, recipient)
    except federation_cns.CNSResolutionError:
        return False
    try:
        pub = _fed_b64u_decode(resp.get("relay_pub"))
        sig = _fed_b64u_decode(resp.get("sig"))
    except (ValueError, TypeError, AttributeError):
        return False
    if len(pub) != 32 or len(sig) != 64:
        return False
    if "sha256:" + hashlib.sha256(pub).hexdigest() != route["relay_identity_key_id"]:
        return False
    msg = _federation_response_bytes(
        nonce_hex, mid, True, bool(resp.get("duplicate")))
    try:
        return bool(ed25519.verify(pub, sig, msg))
    except Exception:
        return False


def _federation_attempt(fed, row):
    """One delivery attempt for a claimed outbox row. Returns True when the
    destination confirmed (and proved) acceptance. Transport failures and
    unverifiable responses are UNKNOWN outcomes: the row is requeued with
    backoff and retried under the same ID (the destination dedupes by ID,
    so this never duplicates the recipient mailbox). Synchronous 4xx from
    the destination is terminal: this message will never be accepted."""
    (mid, sender, recipient, topic, in_reply_to, expires_at, payload,
     enc_v, dest_origin, _state, attempts) = row
    now = time.time()
    if expires_at <= now:
        _federation_mark(mid, "expired", "ttl expired before delivery")
        return False
    if enc_v in (1, 2):
        try:
            enc = json.loads(payload)
        except Exception:
            _federation_mark(mid, "rejected", "stored payload corrupt")
            return False
        text = None
    else:
        enc, text = None, payload
    nonce_hex = secrets.token_hex(32)
    payload_sha = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    attest = _federation_attest_bytes(
        mid, sender, recipient, topic, in_reply_to, expires_at,
        payload_sha, enc_v, fed["own_home"])
    try:
        sig = ed25519.sign(fed["seed"], attest)
    except Exception:
        _federation_mark(mid, "failed", "attestation signing failed")
        return False
    body = {
        "id": mid,
        "from": sender,
        "to": recipient,
        "topic": topic,
        "in_reply_to": in_reply_to,
        "expires_at": expires_at,
        "enc": enc,
        "text": text,
        "enc_v": enc_v,
        "from_home": fed["own_home"],
        "relay_pub": fed["pub_b64"],
        "nonce": nonce_hex,
        "sig": _fed_b64u_encode(sig),
    }
    url = dest_origin + _FED_DELIVER_PATH
    try:
        status, raw = _FED_HTTP_POST(url, body)
    except Exception as e:
        _federation_mark(
            mid, "queued",
            "transport outcome unknown: %s" % type(e).__name__,
            attempts_bump=1,
            next_attempt_at=now + _federation_backoff(attempts + 1))
        return False
    try:
        resp = json.loads(raw.decode("utf-8"))
    except Exception:
        _federation_mark(
            mid, "queued", "transport outcome unknown: bad response",
            attempts_bump=1,
            next_attempt_at=now + _federation_backoff(attempts + 1))
        return False
    if status == 200 and isinstance(resp, dict) \
            and resp.get("accepted") is True and resp.get("id") == mid:
        if not _federation_verify_response(fed, recipient, nonce_hex, mid, resp):
            # The destination may have stored the message but did not prove
            # its identity: unknown outcome, retry with the same ID.
            _federation_mark(
                mid, "queued", "destination identity unproven",
                attempts_bump=1,
                next_attempt_at=now + _federation_backoff(attempts + 1))
            return False
        _federation_mark(mid, "delivered", None)
        return True
    if status == 429:
        retry_after = now + _federation_backoff(attempts + 1)
        try:
            if isinstance(resp, dict) and resp.get("retry_after"):
                retry_after = now + min(float(resp["retry_after"]),
                                        _FED_MAX_BACKOFF)
        except (TypeError, ValueError):
            pass
        _federation_mark(mid, "queued", "destination queue_full",
                         attempts_bump=1, next_attempt_at=retry_after)
        return False
    if status in (400, 403, 409):
        detail = resp.get("error") if isinstance(resp, dict) else None
        _federation_mark(
            mid, "rejected",
            "destination refused (http %d): %s" % (status, detail))
        return False
    # 5xx or anything unexpected: unknown outcome, retry with same ID.
    _federation_mark(
        mid, "queued", "transport outcome unknown: http %d" % status,
        attempts_bump=1,
        next_attempt_at=now + _federation_backoff(attempts + 1))
    return False


def federation_forward_pending(limit=25):
    """Deliver due cross-home outbox rows. Crash-safe: rows are claimed
    ('inflight') under the db lock, delivered without holding it, and a
    restart reclaims any 'inflight' row (same-ID dedup on the destination
    makes redelivery safe). Returns a small summary dict."""
    fed = _FED
    if fed is None:
        return {"forwarded": 0, "attempted": 0, "federation": "disabled"}
    now = time.time()
    with db_lock:
        conn.execute(
            "UPDATE federation_outbox SET state='expired',"
            " last_error='ttl expired' WHERE state IN ('queued','inflight')"
            " AND expires_at <= ?",
            (now,),
        )
        rows = conn.execute(
            "SELECT id, sender, recipient, topic, in_reply_to, expires_at,"
            " text, enc_v, dest_origin, state, attempts FROM federation_outbox"
            " WHERE state IN ('queued','inflight') AND next_attempt_at <= ?"
            " AND expires_at > ? ORDER BY created_at LIMIT ?",
            (now, now, limit),
        ).fetchall()
        if rows:
            conn.execute(
                "UPDATE federation_outbox SET state='inflight' WHERE id IN (%s)"
                % ",".join("?" * len(rows)),
                [r[0] for r in rows],
            )
        conn.commit()
    forwarded = 0
    for row in rows:
        try:
            if _federation_attempt(fed, row):
                forwarded += 1
        except Exception as e:
            _federation_mark(
                mid=row[0],
                state="queued",
                last_error="forwarder error: %s" % type(e).__name__,
                attempts_bump=1,
                next_attempt_at=time.time()
                + _federation_backoff(row[10] + 1),
            )
    return {"forwarded": forwarded, "attempted": len(rows)}


def _federation_loop():
    while True:
        try:
            _federation_wake.wait(_FED_FORWARD_INTERVAL)
            _federation_wake.clear()
            federation_forward_pending()
        except Exception as e:
            print("clack relay: federation forwarder error: %s" % e,
                  flush=True)


def _start_federation_thread():
    """Start the daemon cross-home forwarder (maintenance lifecycle).

    Mirrors _start_sweep_thread: every serving entrypoint must call this
    exactly once during startup. When federation is not configured it
    starts nothing."""
    if _FED is None:
        return None
    t = threading.Thread(target=_federation_loop, daemon=True,
                         name="clack-federation")
    t.start()
    return t


def load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def init_db(cfg):
    global conn
    os.makedirs(BASE, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    # NOTE: the CREATE TABLE statements below live in _SCHEMA_DDL (module
    # level); init_db() executes those exact constants and /health derives
    # its required-schema check from them. Add new tables/columns THERE --
    # never as inline DDL here -- so both stay in sync by construction.
    conn.execute(_SCHEMA_DDL[0])  # peers
    conn.execute(_SCHEMA_DDL[1])  # messages
    # v0.2.4 migration: databases created before collected_at existed.
    # v0.2.16 migration: fetch_count counts poll deliveries per message for
    # at-least-once redelivery observability (issue #4).
    # v0.2.13: revocation dead-letter reason (dead_reason).
    # E2EE: enc_v=1 marks a row whose text holds a canonical-JSON encrypted
    # envelope. (Column tuples live in _SCHEMA_MIGRATION_COLUMNS["messages"];
    # the health check requires the same columns, by construction.)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(messages)")}
    for _col, _ddl in _SCHEMA_MIGRATION_COLUMNS["messages"]:
        if _col not in cols:
            conn.execute("ALTER TABLE messages ADD COLUMN %s %s" % (_col, _ddl))
    conn.execute(_SCHEMA_DDL[2])  # webhooks
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_messages_poll ON messages(recipient, acked_at, expires_at)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_messages_reply ON messages(in_reply_to, created_at)"
    )
    # v0.2.5: invite-link onboarding tables. Peer rows created by invite
    # redemption are keyed by identity_pubkey (unique, NULL for legacy
    # config-managed peers) and carry invited_by provenance.
    conn.execute(_SCHEMA_DDL[3])  # invites
    conn.execute(_SCHEMA_DDL[4])  # challenges
    # v0.2.9: pre-enrollment challenges for agent self-enrollment. kind is
    # 'invite' (ref = invite_id), 'pow', or 'open' (ref NULL).
    conn.execute(_SCHEMA_DDL[5])  # enroll_challenges
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_invites_inviter ON invites(inviter_identity)"
    )
    peer_cols = {r[1] for r in conn.execute("PRAGMA table_info(peers)")}
    # (Column tuples live in _SCHEMA_MIGRATION_COLUMNS["peers"].)
    for _col, _ddl in _SCHEMA_MIGRATION_COLUMNS["peers"]:
        if _col not in peer_cols:
            conn.execute("ALTER TABLE peers ADD COLUMN %s %s" % (_col, _ddl))
    # Multiple NULLs allowed: legacy config peers have no identity.
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_peers_identity ON peers(identity_pubkey)"
    )
    # v0.2.12: persistent seen-nonce store for request-signing replay
    # protection. Rows expire NONCE_TTL after the nonce's timestamp; the
    # sweep prunes them. At capacity only expired rows are pruned and new
    # requests are refused (fail closed) -- live markers are never evicted.
    conn.execute(_SCHEMA_DDL[6])  # seen_nonces
    # v0.2.12 (R1): names of revoked config peers. A retired name can never
    # be claimed by self-enrollment again -- only the operator resurrects it
    # by re-adding it to the config.
    conn.execute(_SCHEMA_DDL[7])  # retired_names
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_seen_nonces_exp ON seen_nonces(expires_at)"
    )
    # v0.2.13: mutual-consent handshakes. a/b are order-independent
    # identities (identity pubkey b64, or legacy config peer name).
    # NO BACKFILL (spec section 8): this migration creates tables/columns
    # only -- zero handshake rows. Enforcement begins immediately.
    conn.execute(_SCHEMA_DDL[8])  # handshakes
    # Pair-scoped revocation memory: a revoked link can never resurrect
    # the specific connection it created (spec section 7).
    conn.execute(_SCHEMA_DDL[9])  # link_revocations
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_handshakes_status ON handshakes(status)"
    )
    # candidate-679-py-federation-v1: cross-home forwarding outbox. Pure
    # table addition; the base schema is untouched, so rollback to 10ffd1f
    # keeps working against a database that already has this table (the
    # base health check only requires its own tables).
    conn.execute(_SCHEMA_DDL[10])  # federation_outbox
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_federation_outbox_due"
        " ON federation_outbox(state, next_attempt_at)"
    )
    # candidate-679-py-federation-v1 delta fix (Zari a74bb2b2, D2):
    # sender-home grant/pair consent for cross-home wire acceptance.
    # Pure table addition; the base schema is untouched.
    conn.execute(_SCHEMA_DDL[11])  # federation_grants
    # Ensure-column path: CREATE TABLE IF NOT EXISTS is a no-op when a
    # partial handshakes table already exists (e.g. an earlier 0.2.13
    # dev build), so post-CREATE columns get ALTER guards.
    # E2EE capability negotiation (v1 envelope): per-pair advertisements and
    # their AND. (Column tuples live in _SCHEMA_MIGRATION_COLUMNS["handshakes"].)
    hs_cols = {r[1] for r in conn.execute("PRAGMA table_info(handshakes)")}
    for _col, _ddl in _SCHEMA_MIGRATION_COLUMNS["handshakes"]:
        if _col not in hs_cols:
            conn.execute("ALTER TABLE handshakes ADD COLUMN %s %s" % (_col, _ddl))
    # (enc_capable/minter_enc_v/redeemer_enc_v guards merged into the
    # handshakes loop above via _SCHEMA_MIGRATION_COLUMNS.)
    inv_cols = {r[1] for r in conn.execute("PRAGMA table_info(invites)")}
    # (Column tuples live in _SCHEMA_MIGRATION_COLUMNS["invites"].)
    for _col, _ddl in _SCHEMA_MIGRATION_COLUMNS["invites"]:
        if _col not in inv_cols:
            conn.execute("ALTER TABLE invites ADD COLUMN %s %s" % (_col, _ddl))
    # (dead_reason/enc_v guards moved up next to the messages CREATE TABLE --
    # all messages ensure-columns now iterate _SCHEMA_MIGRATION_COLUMNS.)
    now = time.time()
    # Revocation-safe rebuild: peers removed from the config must lose
    # authentication on restart. Config-managed rows (enroll_gate='config',
    # or legacy rows with no gate and no identity key) are rebuilt from the
    # config; invite/pow/open-enrolled identity rows survive restarts.
    #
    # R1: revocation also drops the removed peer's queued mail and webhook
    # registration (a webhook URL can carry secrets) and retires its name.
    # Queued mail is undeliverable without auth -- reassignment must never
    # make it deliverable again, so the state is deleted rather than left
    # behind, and the name can never be claimed by a later self-enrollment.
    # Only the operator resurrects a name, by re-adding it to the config
    # (which clears the retirement).
    #
    # v0.2.12: config peers may carry an Ed25519 identity_pubkey from the
    # "identity_pubkeys" config map -- the operator upgrade path for
    # token-only peers. Keys are re-read from config every restart, so
    # removing a key downgrades the peer back to upgrade_required.
    #
    # v0.2.13: config peers may ALSO be provisioned hash-only via the
    # "peer_hashes" config map ({name: hex(sha256(token))}), for protected
    # provisioning where the plaintext token must never be stored. Both
    # sources union into the config-managed identity set: a peer listed
    # in either map is config-managed, and only a peer listed in NEITHER
    # map is revoked on restart. Hash-only rows keep their stored hash
    # verbatim -- the plaintext is never present, never derived, never
    # logged.
    with conn:
        existing_config = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM peers WHERE enroll_gate='config' "
                "OR (enroll_gate IS NULL AND identity_pubkey IS NULL)"
            )
        }
        incoming = set(cfg.get("peers", {}).keys()) | set(_PEER_HASHES)
        removed = existing_config - incoming
        if removed:
            now_r = time.time()
            for name in removed:
                conn.execute(
                    "DELETE FROM messages WHERE recipient=?", (name,))
                conn.execute(
                    "DELETE FROM webhooks WHERE peer=?", (name,))
                conn.execute(
                    "INSERT OR IGNORE INTO retired_names(name, retired_at)"
                    " VALUES(?,?)",
                    (name, now_r),
                )
        conn.execute(
            "DELETE FROM peers WHERE enroll_gate='config' "
            "OR (enroll_gate IS NULL AND identity_pubkey IS NULL)"
        )
        conn.executemany(
            "INSERT INTO peers(name, token_hash, created_at, identity_pubkey, enroll_gate)"
            " VALUES(?,?,?,?,?)",
            [
                (name, hashlib.sha256(token.encode("utf-8")).hexdigest(), now,
                 _IDENTITY_PUBKEYS.get(name), "config")
                for name, token in cfg.get("peers", {}).items()
            ] + [
                # Hash-only peers: the token hash comes straight from the
                # validated peer_hashes map. The plaintext token is never
                # present on this host -- nothing to derive, nothing to log.
                (name, token_hash, now, _IDENTITY_PUBKEYS.get(name), "config")
                for name, token_hash in _PEER_HASHES.items()
            ],
        )
        if incoming:
            conn.execute(
                "DELETE FROM retired_names WHERE name IN (%s)"
                % ",".join("?" * len(incoming)),
                tuple(incoming),
            )
    conn.commit()
    global peer_names
    peer_names = {r[0] for r in conn.execute("SELECT name FROM peers")}


def sweep(now):
    global _last_sweep
    with sweep_lock:
        if now - _last_sweep < SWEEP_MIN_INTERVAL:
            return
        _last_sweep = now
    with db_lock:
        # Expired and acked: truly resolved, drop promptly. (v0.2.16: an
        # expired collected-but-unacked message is NOT resolved -- its poll
        # response may never have arrived -- so it is no longer dropped here.)
        conn.execute(
            "DELETE FROM messages WHERE expires_at <= ? AND acked_at IS NOT NULL",
            (now,),
        )
        # Retention windows keep sender-visible receipts around:
        # acked -> 7d after ack.
        conn.execute(
            "DELETE FROM messages WHERE acked_at IS NOT NULL AND acked_at <= ?",
            (now - RETENTION,),
        )
        # v0.2.16: unacked mail is NEVER pruned on the collection timer. A
        # collected-but-unacked message is unconfirmed by definition --
        # deleting it is silent loss (issue #4: a poll response that never
        # arrives must not become a deletion 7 days later). Unacked rows,
        # collected or not, live until RETENTION past expiry, then go as
        # dead letters so senders can see them via /v1/receipts.
        conn.execute(
            "DELETE FROM messages WHERE acked_at IS NULL AND expires_at <= ?",
            (now - RETENTION,),
        )
        # Bound dead-letter storage: keep the newest 2000 globally.
        conn.execute(
            """DELETE FROM messages WHERE id IN (
                   SELECT id FROM messages
                   WHERE expires_at <= ? AND acked_at IS NULL
                   ORDER BY created_at DESC LIMIT -1 OFFSET 2000)""",
            (now,),
        )
        # v0.2.5: drop expired challenges and consumed ones older than an hour.
        conn.execute(
            "DELETE FROM challenges WHERE expires_at <= ? OR (used != 0 AND created_at <= ?)",
            (now, now - 3600),
        )
        # v0.2.9: same reaping for the self-enrollment challenges.
        conn.execute(
            "DELETE FROM enroll_challenges WHERE expires_at <= ? OR (used != 0 AND created_at <= ?)",
            (now, now - 3600),
        )
        # v0.2.12: drop expired seen nonces (replay window is NONCE_TTL
        # past the nonce's own timestamp).
        conn.execute("DELETE FROM seen_nonces WHERE expires_at <= ?", (now,))
        # candidate-679-py-federation-v1: federation outbox hygiene. Live
        # rows that passed their TTL can never be delivered; terminal rows
        # (delivered/rejected/failed/expired) are kept for RETENTION so
        # same-ID retries and /v1/receipts stay consistent, then pruned.
        conn.execute(
            "UPDATE federation_outbox SET state='expired',"
            " last_error='ttl expired' WHERE state IN ('queued','inflight')"
            " AND expires_at <= ?",
            (now,),
        )
        conn.execute(
            "DELETE FROM federation_outbox WHERE state IN"
            " ('delivered','rejected','failed','expired')"
            " AND created_at <= ?",
            (now - RETENTION,),
        )
        # v0.2.13: handshake lifecycle. Expired pendings can never be
        # accepted (the accept guard also enforces this atomically); hard
        # expiry retires actives/pendings when the knob is set. These are
        # quota hygiene, NOT explicit revokes, so no link_revocations
        # entries are written -- an expired/exhausted-quota pair may
        # re-consent over any link, and generation is NOT bumped.
        # There is deliberately NO inactivity sweep in v0.2.13 (canary):
        # handshake_inactivity_expiry_days defaults to 0 = never.
        conn.execute(
            """UPDATE handshakes SET status='revoked', pending_expires_at=NULL,
                                  redeemer_identity=NULL
               WHERE status='pending' AND pending_expires_at IS NOT NULL
                 AND pending_expires_at <= ?""",
            (now,),
        )
        if HS_EXPIRY_DAYS > 0:
            conn.execute(
                """UPDATE handshakes SET status='revoked', pending_expires_at=NULL,
                                      redeemer_identity=NULL
                   WHERE status IN ('pending','active') AND expires_at IS NOT NULL
                     AND expires_at <= ?""",
                (now,),
            )
        conn.commit()


def total_pending(now):
    with db_lock:
        row = conn.execute(
            "SELECT COUNT(*) FROM messages WHERE acked_at IS NULL AND expires_at > ?",
            (now,),
        ).fetchone()
    return row[0]


def _sweep_loop():
    """Own the periodic sweep on a daemon thread.

    Fail-closed by construction: a sweep exception is recorded in
    _sweep_last_error (surfaced explicitly by /health as degraded) and never
    propagates into request handling. The next successful sweep clears it.
    """
    global _sweep_last_error
    while True:
        try:
            sweep(time.time())
        except Exception as e:  # noqa: BLE001 -- sweeper must never die
            with _sweep_state_lock:
                _sweep_last_error = "%s: %s" % (type(e).__name__, e)
        else:
            with _sweep_state_lock:
                _sweep_last_error = None
        time.sleep(SWEEP_MIN_INTERVAL)


def _sweep_error():
    with _sweep_state_lock:
        return _sweep_last_error


def _start_sweep_thread():
    """Start the daemon sweep thread (maintenance lifecycle).

    Every serving entrypoint MUST call this exactly once during startup:
    the sweep no longer piggybacks on requests, so an entrypoint that
    skips it silently loses expiry/GC and handshake-revoke maintenance
    (Mercedes's Round-2 finding: serve_relay.py never started it).
    """
    t = threading.Thread(target=_sweep_loop, daemon=True, name="clack-sweep")
    t.start()
    return t


def auth_peer(headers):
    auth = headers.get("Authorization", "")
    parts = auth.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
        return None
    presented = hashlib.sha256(parts[1].encode("utf-8")).hexdigest()
    with db_lock:
        rows = conn.execute("SELECT name, token_hash FROM peers").fetchall()
    for name, stored in rows:
        if hmac.compare_digest(stored, presented):
            return name
    return None


def rate_ok(token_sha):
    now = time.time()
    with rate_lock:
        dq = rate_hits.setdefault(token_sha, [])
        dq[:] = [t for t in dq if now - t < 60.0]
        if len(dq) >= RATE_PER_MIN:
            return False
        dq.append(now)
        return True


def auth_fail_ok(ip):
    """Cheap per-source bound on failed authentication attempts (R4)."""
    now = time.time()
    with auth_fail_lock:
        dq = auth_fail_hits.setdefault(ip, [])
        dq[:] = [t for t in dq if now - t < 60.0]
        if len(dq) >= AUTH_FAIL_PER_MIN:
            return False
        dq.append(now)
        return True


def token_sha_of(headers):
    auth = headers.get("Authorization", "")
    parts = auth.split(None, 1)
    if len(parts) == 2:
        return hashlib.sha256(parts[1].encode("utf-8")).hexdigest()
    return "noauth"


# --- Invite-link onboarding helpers (v0.2.5) ---------------------------------

invite_rl_lock = threading.Lock()
invite_rl_hits = {}  # key -> [float]


def invite_rate_ok(key, per_min):
    """Small per-key rate limiter for the unauthenticated invite endpoints.
    Keys look like 'cip:<ip>' or 'cinv:<invite_id>'."""
    now = time.time()
    with invite_rl_lock:
        dq = invite_rl_hits.setdefault(key, [])
        dq[:] = [t for t in dq if now - t < 60.0]
        if len(dq) >= per_min:
            return False
        dq.append(now)
        return True


redeem_fail_lock = threading.Lock()
redeem_fails = {}  # legacy string or authenticated-public tuple -> [float]


def redeem_failures_blocked(invite_id):
    """5 failed redeems within 15 minutes cools the invite down (draft §6)."""
    now = time.time()
    with redeem_fail_lock:
        dq = [t for t in redeem_fails.get(invite_id, []) if now - t < 900.0]
        redeem_fails[invite_id] = dq
        return len(dq) >= 5


def redeem_failure_note(invite_id):
    with redeem_fail_lock:
        redeem_fails.setdefault(invite_id, []).append(time.time())


def redeem_failure_clear(invite_id):
    with redeem_fail_lock:
        redeem_fails.pop(invite_id, None)


# --- Agent self-enrollment (v0.2.9) ------------------------------------------
# POST /v1/enroll/challenge + POST /v1/enroll: an agent with no human
# involved POSTs its chosen name + Ed25519 public key and gets back a peer
# token. Proof-of-possession of the private key IS the authentication, same
# principle as the invite-link endpoints. Enrollment is gated by the relay's
# `enrollment` config policy so a relay is never an open relay by default.

ENROLL_DEFAULT_POW_DIFFICULTY = 20  # leading zero bits (~1M SHA-256, ~1-2s CPython)

enroll_fail_lock = threading.Lock()
enroll_fails = {}  # cooldown key -> [float] of recent failures


def _enrollment_gates():
    """The set of enrollment gates this relay enables, from config."""
    raw = relay_cfg.get("enrollment", "invite") if relay_cfg else "invite"
    gates = {g.strip() for g in str(raw).split(",") if g.strip()}
    return gates or {"invite"}


def _trusted_proxy_nets():
    """CIDR list from relay-config.json "trusted_proxies" (Flint P2-deploy).

    Only connections arriving FROM these networks may supply the real
    client IP via CF-Connecting-IP / X-Forwarded-For for rate limiting.
    Default: empty -- the socket peer address is always used, so a
    listener reachable by untrusted clients never trusts forwarded headers.
    """
    raw = relay_cfg.get("trusted_proxies", []) if relay_cfg else []
    if isinstance(raw, str):
        raw = [raw]
    nets = []
    for entry in raw or []:
        try:
            nets.append(ipaddress.ip_network(str(entry).strip(), strict=False))
        except ValueError:
            continue
    return nets


def _internal_trusted_nets():
    """CIDR list from relay-config.json "internal_trusted_nets".

    Connections arriving FROM these networks may authenticate with a valid
    Bearer token alone (Ed25519 signature-exempt). This exists for trusted
    first-party proxies on the internal network -- e.g. the Clack MCP
    server, which forwards callers' Bearer tokens but cannot hold their
    Ed25519 private keys, so it can never produce a valid signature.

    Default: 127.0.0.1/32 only (loopback). Matching always uses the raw
    socket peer address, never a forwarded header, so list the actual
    source networks (e.g. the Docker compose network on the deploy host).
    """
    raw = (relay_cfg.get("internal_trusted_nets", ["127.0.0.1/32"])
           if relay_cfg else ["127.0.0.1/32"])
    if isinstance(raw, str):
        raw = [raw]
    nets = []
    for entry in raw or []:
        try:
            nets.append(ipaddress.ip_network(str(entry).strip(), strict=False))
        except ValueError:
            continue
    return nets or [ipaddress.ip_network("127.0.0.1/32")]


def _valid_client_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _pow_difficulty():
    try:
        return int(relay_cfg.get("pow_difficulty", ENROLL_DEFAULT_POW_DIFFICULTY))
    except (TypeError, ValueError):
        return ENROLL_DEFAULT_POW_DIFFICULTY


class _ReservedNameRejected(Exception):
    """Raised inside the enrollment transaction when a non-pinned key
    requests a reserved name. The handler rolls back and answers 403."""


_RESERVED_NAMES = {}


def _parse_reserved_names(cfg):
    """Strictly validate relay-config.json "reserved_names".

    Returns {name: identity_pubkey_b64u} with keys in canonical form.
    Any malformed entry -- a non-dict section, an invalid name, an
    undecodable key, or a key of the wrong length -- raises ValueError.
    A typo'd reservation must fail loudly at startup, never silently drop:
    an ignored reservation looks exactly like a working one until the
    squatter arrives.
    """
    raw = cfg.get("reserved_names", {}) if cfg else {}
    if not isinstance(raw, dict):
        raise ValueError("reserved_names must be an object, got %s"
                         % type(raw).__name__)
    out = {}
    for name, key_b64 in raw.items():
        if not _valid_requested_name(name):
            raise ValueError("reserved name %r is not a valid peer name"
                             % (name,))
        try:
            key = b64u_decode(key_b64)
        except (ValueError, TypeError, AttributeError):
            raise ValueError("reserved name %r has a malformed identity key"
                             % (name,))
        if len(key) != 32:
            raise ValueError("reserved name %r key is %d bytes, want 32"
                             % (name, len(key)))
        out[name] = b64u_encode(key)  # canonical form for comparison
    return out


def _init_reserved_names(cfg):
    global _RESERVED_NAMES
    try:
        _RESERVED_NAMES = _parse_reserved_names(cfg)
    except ValueError as e:
        raise SystemExit("clack-relay: invalid reserved_names: %s" % e)


def enroll_failures_blocked(key):
    """5 failed enrollments within 15 minutes cools the key down."""
    now = time.time()
    with enroll_fail_lock:
        dq = [t for t in enroll_fails.get(key, []) if now - t < 900.0]
        enroll_fails[key] = dq
        return len(dq) >= 5


def enroll_failure_note(key):
    with enroll_fail_lock:
        enroll_fails.setdefault(key, []).append(time.time())


def enroll_failure_clear(key):
    with enroll_fail_lock:
        enroll_fails.pop(key, None)


def _pow_leading_zero_bits(digest):
    n = 0
    for byte in digest:
        if byte == 0:
            n += 8
        else:
            n += 8 - byte.bit_length()
            break
    return n


ENROLL_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,30}$")


def _valid_requested_name(name):
    return (
        isinstance(name, str)
        and bool(ENROLL_NAME_RE.match(name))
        and not name.startswith("guest-")
    )


def _enroll_identity_locked(pub_b64, token_hash, invited_by, requested_name, now,
                          enroll_gate=None, enroll_ip=None):
    """Find-or-create a peer row keyed by identity. Assumes db_lock is held
    and the caller opened a BEGIN IMMEDIATE transaction: the lookup, the
    name reservation, and the INSERT/UPDATE are one atomic unit. Returns the
    peer name. Shared by /v1/invites/redeem and /v1/enroll -- requested_name
    is None for redeem (always a guest name), the agent's choice for enroll.
    All uniqueness checks happen INSIDE the transaction, never from a
    pre-lock read (same race discipline as redeem). Reserved-name
    enforcement also happens here, inside the transaction: a non-pinned key
    requesting a reserved name raises _ReservedNameRejected. Re-enrollments
    return before this point, so an already-enrolled identity keeps its
    name even if the name is later reserved to a different key
    (grandfathered); only new enrollments are gated."""
    row = conn.execute(
        "SELECT name FROM peers WHERE identity_pubkey=?", (pub_b64,)
    ).fetchone()
    if row:
        name = row[0]
        conn.execute(
            "UPDATE peers SET token_hash=?, invited_by=? WHERE identity_pubkey=?",
            (token_hash, invited_by, pub_b64),
        )
        return name
    name = None
    if _valid_requested_name(requested_name):
        pinned = _RESERVED_NAMES.get(requested_name)
        if pinned is not None and pinned != pub_b64:
            # Reserved for a different identity key: reject outright, inside
            # the same transaction as the name assignment, so the check and
            # the insert are atomic. Never hand out a suffixed fallback,
            # which would confuse the legitimate owner. The pinned key
            # itself falls through to the normal first-come path below.
            raise _ReservedNameRejected(requested_name)
        # R1: a retired name (revoked config peer) is never handed out
        # again, even though its row is gone: the old owner's queued state
        # was deleted with the revocation, and the name itself stays dead
        # so no new identity inherits its name-trust. Falls through to a
        # suffixed candidate like any other taken name.
        taken = conn.execute(
            "SELECT 1 FROM peers WHERE name=?", (requested_name,)
        ).fetchone()
        retired = conn.execute(
            "SELECT 1 FROM retired_names WHERE name=?", (requested_name,)
        ).fetchone()
        if not taken and not retired:
            name = requested_name
        else:
            candidate = "%s-%s" % (requested_name, secrets.token_hex(2))
            if not conn.execute(
                "SELECT 1 FROM peers WHERE name=?", (candidate,)
            ).fetchone():
                name = candidate
    if name is None:
        name = _unique_guest_name_locked()
    conn.execute(
        """INSERT INTO peers(name, token_hash, created_at,
                             identity_pubkey, invited_by, display_name,
                             enroll_gate, enroll_ip)
           VALUES(?,?,?,?,?,?,?,?)""",
        (name, token_hash, now, pub_b64, invited_by, name, enroll_gate, enroll_ip),
    )
    return name


def b64u_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64u_decode(s):
    if not isinstance(s, str) or not s:
        raise ValueError("bad_b64")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def relay_base_url(cfg):
    return cfg.get("base_url") or ("http://127.0.0.1:%d" % int(cfg.get("port", 18802)))


def relay_identity_info():
    """Public part of the relay identity key for the redeem response."""
    if id_n is None:
        return None
    return {"n": format(id_n, "x"), "e": format(id_e, "x")}


def caller_identity(peer):
    """The identity string a peer mints invites under: their identity pubkey
    (b64) if they enrolled by invite, else their legacy config peer name."""
    with db_lock:
        row = conn.execute(
            "SELECT identity_pubkey FROM peers WHERE name=?", (peer,)
        ).fetchone()
    if row and row[0]:
        return row[0]
    return peer


def peer_name_for_identity(identity):
    """Resolve an inviter identity string to a messageable peer name."""
    with db_lock:
        row = conn.execute(
            "SELECT name FROM peers WHERE identity_pubkey=?", (identity,)
        ).fetchone()
        if row:
            return row[0]
        row = conn.execute(
            "SELECT name FROM peers WHERE name=? AND identity_pubkey IS NULL",
            (identity,),
        ).fetchone()
        return row[0] if row else None


def build_invite_link(base_url, invite_id, secret, inviter_identity, exp):
    frag = "r=%s&i=%s&k=%s&v=%d&by=%s&exp=%d" % (
        b64u_encode(base_url.encode("utf-8")),
        invite_id,
        b64u_encode(secret),
        LINK_VERSION,
        urllib.parse.quote(inviter_identity, safe=""),
        int(exp),
    )
    return base_url.rstrip("/") + "/join#" + frag


def _unique_guest_name_locked():
    """Mint a fresh guest name. Assumes db_lock is already held."""
    for _ in range(100):
        name = "guest-" + secrets.token_hex(4)
        # R1: never mint a retired name either (defense in depth; the
        # guest- prefix makes a collision near-impossible anyway).
        if not conn.execute(
            "SELECT 1 FROM peers WHERE name=?", (name,)
        ).fetchone() and not conn.execute(
            "SELECT 1 FROM retired_names WHERE name=?", (name,)
        ).fetchone():
            return name
    raise RuntimeError("guest name space exhausted")


def unique_guest_name():
    with db_lock:
        return _unique_guest_name_locked()


# --- Wake nudges ("you have mail") -------------------------------------------
# A registered webhook gets a best-effort POST when a message lands for that
# peer. The nudge carries NO message content, NO sender name, NO credentials:
# just {"event":"mail_waiting","pending":N}. Its only job is to wake a peer
# that isn't polling so it comes and polls. Delivery of actual messages still
# happens exclusively through authenticated /v1/poll.
notify_lock = threading.Lock()
_last_notify = {}  # peer -> epoch of last nudge sent
NOTIFY_MIN_INTERVAL = 45.0
NOTIFY_TIMEOUT = 5.0


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A nudge must never be re-targeted: redirect targets are never passed
    through the SSRF guard, so following one would be an open redirect to an
    unvalidated URL (e.g. a 302 to a cloud-metadata address). Returning None
    makes urllib surface the 3xx as an HTTPError, which the worker records in
    last_error instead of following it. NOTE: build_opener() adds a default
    HTTPRedirectHandler unless a subclass instance is passed explicitly --
    passing the plain HTTPHandler/HTTPSHandler alone does NOT disable
    redirects (that was the v0.2.4 bug this fixes)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def webhook_url_ok(url):
    """SSRF guard for peer-registered webhook URLs. Requires http/https, no
    embedded credentials, and refuses loopback, link-local (cloud metadata),
    multicast, reserved, and unspecified addresses. Private RFC1918 and
    CGNAT (Tailscale) ranges are ALLOWED: this relay's peers live on exactly
    those networks. Residual risk (DNS-rebinding TOCTOU, weak timing oracle
    via last_error) is documented in CLIENT_CONTRACT.md."""
    try:
        p = urlparse(url)
    except Exception:
        return False
    if p.scheme not in ("http", "https"):
        return False
    if not p.hostname or p.username or p.password:
        return False
    try:
        infos = socket.getaddrinfo(
            p.hostname,
            p.port or (443 if p.scheme == "https" else 80),
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror:
        return False
    for _fam, _typ, _proto, _canon, sockaddr in infos:
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            return False
        if (
            ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return False
    return True


def maybe_notify(recipient):
    """Fire one throttled wake nudge to the recipient's webhook, if any."""
    now = time.time()
    with db_lock:
        row = conn.execute(
            "SELECT url FROM webhooks WHERE peer=?", (recipient,)
        ).fetchone()
        if not row:
            return
        url = row[0]
        pending = conn.execute(
            "SELECT COUNT(*) FROM messages WHERE recipient=? AND acked_at IS NULL AND expires_at > ?",
            (recipient, now),
        ).fetchone()[0]
    with notify_lock:
        if now - _last_notify.get(recipient, 0.0) < NOTIFY_MIN_INTERVAL:
            return
        _last_notify[recipient] = now
    t = threading.Thread(
        target=_notify_worker, args=(recipient, url, pending), daemon=True
    )
    t.start()


def _notify_worker(recipient, url, pending):
    # Re-validate at send time (cheap DNS-rebinding mitigation; TOCTOU
    # remains and is documented).
    if not webhook_url_ok(url):
        err = "url_rejected_at_send"
    else:
        body = json.dumps({"event": "mail_waiting", "pending": pending}).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": "ClackRelay-notify/" + VERSION,
            },
        )
        # No-redirect opener: a nudge never follows a redirect to an
        # unvalidated URL. _NoRedirect (a HTTPRedirectHandler subclass)
        # replaces the default redirect handler in build_opener.
        opener = urllib.request.build_opener(
            urllib.request.HTTPHandler(),
            urllib.request.HTTPSHandler(),
            _NoRedirect(),
        )
        try:
            with opener.open(req, timeout=NOTIFY_TIMEOUT) as resp:
                err = None if 200 <= resp.status < 300 else "http_%d" % resp.status
        except Exception as e:
            err = "%s: %s" % (type(e).__name__, str(e)[:120])
    with db_lock:
        conn.execute(
            "UPDATE webhooks SET last_notified_at=?, last_error=? WHERE peer=?",
            (time.time(), err, recipient),
        )
        conn.commit()


def load_identity_key(cfg):
    """Load the dedicated RSA identity-signing key (n, e, d as hex)."""
    global id_n, id_e, id_d
    ik = cfg.get("identity_key")
    if not ik:
        return
    id_n, id_e, id_d = int(ik["n"], 16), int(ik["e"], 16), int(ik["d"], 16)


# DigestInfo prefix for SHA-256 (PKCS#1 v1.5)
_SHA256_DINFO_HEAD = bytes.fromhex("3031300d060960864801650304020105000420")


def rsa_sign_pkcs1_v15_sha256(msg: bytes) -> bytes:
    """Sign msg with the relay identity key. Pure stdlib (pow with mod)."""
    t = _SHA256_DINFO_HEAD + hashlib.sha256(msg).digest()
    k = (id_n.bit_length() + 7) // 8
    em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return pow(int.from_bytes(em, "big"), id_d, id_n).to_bytes(k, "big")


def ip_rate_ok(ip):
    now = time.time()
    with ip_rate_lock:
        dq = ip_rate_hits.setdefault(ip, [])
        dq[:] = [t for t in dq if now - t < 60.0]
        if len(dq) >= IP_RATE_PER_MIN:
            return False
        dq.append(now)
        return True


def fetch_pending(recipient, now):
    with db_lock:
        rows = conn.execute(
            """SELECT id, sender, topic, text, in_reply_to, created_at, expires_at,
                      collected_at, fetch_count, enc_v
               FROM messages
               WHERE recipient=? AND acked_at IS NULL AND expires_at > ?
               ORDER BY created_at""",
            (recipient, now),
        ).fetchall()
    return [
        {
            "id": r[0],
            "from": r[1],
            "topic": r[2],
            "text": r[3],
            "in_reply_to": r[4],
            "sent_at": r[5],
            "expires_at": r[6],
            # v0.2.16: at-least-once redelivery markers (issue #4).
            # redelivered=True means this message was fetched before but
            # never acked -- the earlier delivery presumably never arrived
            # (dropped connection mid-read, crashed client). Dedupe on id;
            # redelivery is normal, not an error.
            "redelivered": r[7] is not None,
            "delivery_count": (r[8] or 0) + 1,
            # E2EE: enc_v=1 means text holds a canonical-JSON encrypted
            # envelope (client decrypts); enc_v=0 is plaintext.
            "enc_v": r[9] or 0,
        }
        for r in rows
    ]


def _nonce_record(conn, nonce, peer, expires_at):
    """Record a verified nonce in the seen_nonces store.

    Returns "replay" when the nonce was already present, "recorded" when
    stored, or "full" when the store is at capacity. R2: a live replay
    marker is NEVER evicted to make room -- only expired rows are pruned,
    and when the store is still full the new request is refused (fail
    closed) rather than forgetting a nonce whose timestamp is still inside
    the validity window. Extracted for unit testing."""
    if conn.execute(
        "SELECT 1 FROM seen_nonces WHERE nonce=?", (nonce,)
    ).fetchone():
        return "replay"
    # Prune only rows that can never be replayed again (their timestamps
    # are already outside the validity window).
    conn.execute(
        "DELETE FROM seen_nonces WHERE expires_at <= ?", (time.time(),)
    )
    n = conn.execute("SELECT COUNT(*) FROM seen_nonces").fetchone()[0]
    if n >= NONCE_STORE_CAP:
        conn.commit()
        return "full"
    conn.execute(
        "INSERT INTO seen_nonces(nonce, peer, expires_at) VALUES(?,?,?)",
        (nonce, peer, expires_at),
    )
    conn.commit()
    return "recorded"


class Handler(BaseHTTPRequestHandler):
    server_version = "ClackRelay/" + VERSION

    def log_message(self, fmt, *args):  # keep logs token/text free
        pass

    def setup(self):
        # Raw request body cache: signature verification (v0.2.12) needs the
        # exact bytes before the endpoint handlers parse them, and rfile is
        # a one-shot stream. _read_body fills this once; _read_json parses
        # from it.
        self._body = None
        # R3: bound client-paced header/body reads. The timeout applies per
        # socket op, not per connection: /v1/poll's server-side wait performs
        # no socket I/O, so long polls are unaffected.
        try:
            self.request.settimeout(60)
        except OSError:
            pass
        super().setup()

    def _read_body(self):
        if self._body is None:
            try:
                length = int(self.headers.get("Content-Length", 0))
            except ValueError:
                length = 0
            if length <= 0 or length > 2_000_000:
                self._body = b""
            else:
                try:
                    self._body = self.rfile.read(length)
                except Exception:
                    self._body = b""
        return self._body

    def _json(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _read_json(self):
        raw = self._read_body()
        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return None

    def _verify_signature(self, peer):
        """Mandatory Ed25519 request signing (v0.2.12).

        Returns None when the request's signature verifies against the
        peer's stored Ed25519 identity_pubkey, else a stable error code:
        missing_signature | unknown_key | upgrade_required | stale_nonce |
        bad_signature | replay | nonce_store_full. Never raises: malformed
        input maps to a code, never a dropped connection."""
        h = self.headers
        if h.get("X-Clack-Scheme") != "1":
            return "missing_signature"
        key_name = h.get("X-Clack-Key")
        if not key_name:
            return "missing_signature"
        if key_name != peer:
            # The claimed key identity does not match the Bearer token's
            # peer: unknown in this authentication context.
            return "unknown_key"
        with db_lock:
            row = conn.execute(
                "SELECT identity_pubkey FROM peers WHERE name=?", (peer,)
            ).fetchone()
        pub_b64 = row[0] if row else None
        try:
            pubkey = b64u_decode(pub_b64) if pub_b64 else b""
        except (ValueError, TypeError, AttributeError):
            pubkey = b""
        if len(pubkey) != 32:
            # No (or corrupt) Ed25519 key on file: the peer registers one
            # via POST /v1/register-key. Never silently bypass.
            return "upgrade_required"
        # R5: the vendored verifier admits trivial forgeries under
        # small-order keys. Enrollment and the operator map now reject such
        # keys, but rows written before the fix could still hold one:
        # validate once per peer key per process and fail closed instead of
        # trusting stored bytes. A rejected key means register-key, same as a
        # missing one.
        if pub_b64 not in _peer_key_valid:
            _peer_key_valid[pub_b64] = ed25519.is_valid_pubkey(pubkey)
        if not _peer_key_valid[pub_b64]:
            return "upgrade_required"
        nonce = h.get("X-Clack-Nonce") or ""
        ts_s, sep, rand = nonce.partition(":")
        if not sep or not NONCE_RAND_RE.match(rand):
            return "stale_nonce"
        try:
            ts = float(ts_s)
        except ValueError:
            return "stale_nonce"
        now = time.time()
        # isfinite rejects NaN ("nan" parses but defeats every comparison,
        # silently passing the window check below).
        if not math.isfinite(ts) or ts < now - NONCE_TTL or ts > now + NONCE_FUTURE_SKEW:
            return "stale_nonce"
        try:
            sig = bytes.fromhex(h.get("X-Clack-Sig") or "")
        except ValueError:
            return "bad_signature"
        if len(sig) != 64:
            return "bad_signature"
        parsed = urlparse(self.path)
        path_q = parsed.path + ("?" + parsed.query if parsed.query else "")
        body = self._read_body()
        canon = (
            SIGN_SCHEME_ID + "\n"
            + self.command.upper() + "\n"
            + path_q + "\n"
            + hashlib.sha256(body).hexdigest() + "\n"
            + nonce
        ).encode("utf-8")
        if not ed25519.verify(pubkey, sig, canon):
            return "bad_signature"
        # R3: the body read above is client-paced -- recheck freshness now
        # that the full request has arrived, immediately before the atomic
        # record. A duplicate that crossed the expiry boundary (and a sweep)
        # while its body trickled in must be rejected, never recorded.
        now2 = time.time()
        if (
            not math.isfinite(ts)
            or ts < now2 - NONCE_TTL
            or ts > now2 + NONCE_FUTURE_SKEW
        ):
            return "stale_nonce"
        # Atomic check-and-record: the nonce is marked seen only after a
        # valid signature, so a bad signature can never burn someone else's
        # nonce. At capacity the store refuses new requests (fail closed)
        # rather than evicting a live replay marker (R2).
        with db_lock:
            res = _nonce_record(conn, nonce, peer, ts + NONCE_TTL)
            if res == "replay":
                return "replay"
            if res == "full":
                return "nonce_store_full"
        return None

    def _client_ip(self):
        """Best-effort client IP for rate limiting (Flint P2-deploy).

        Behind a trusted edge (e.g. cloudflared dialing 127.0.0.1:18802)
        every remote client shares the socket peer address, collapsing all
        per-IP buckets into one. When the socket peer is inside
        "trusted_proxies", the real client IP is taken from
        CF-Connecting-IP, else the first X-Forwarded-For entry; anything
        else falls back to the socket address. Forwarded headers from an
        untrusted source are never honored.
        """
        sock = self.client_address[0] if self.client_address else "?"
        try:
            sock_addr = ipaddress.ip_address(sock)
        except ValueError:
            return sock
        if any(sock_addr in net for net in _trusted_proxy_nets()):
            cf = (self.headers.get("CF-Connecting-IP") or "").strip()
            if cf and _valid_client_ip(cf):
                return cf
            xff = self.headers.get("X-Forwarded-For") or ""
            first = xff.split(",")[0].strip()
            if first and _valid_client_ip(first):
                return first
        return sock

    def _internal_trusted_source(self):
        """True when the TCP peer is on a configured internal trusted net.

        Uses the RAW socket address -- never CF-Connecting-IP /
        X-Forwarded-For -- because this gates an authentication exemption
        (signature-free Bearer auth for trusted first-party proxies like
        the MCP server). A spoofable header must never satisfy it.
        """
        sock = self.client_address[0] if self.client_address else "?"
        try:
            sock_addr = ipaddress.ip_address(sock)
        except ValueError:
            return False
        return any(sock_addr in net for net in _internal_trusted_nets())

    def _require_auth(self, require_signature=False):
        ip = self._client_ip()
        peer = auth_peer(self.headers)
        if peer is None:
            # No peer budget exists to charge; the cheap source-level
            # bucket still bounds the attempt rate.
            if not auth_fail_ok(ip):
                self._json(429, {"error": "rate_limited"})
                return None
            self._json(401, {"error": "unauthorized"})
            return None
        if self._internal_trusted_source() and not require_signature:
            # Trusted first-party proxy (e.g. the Clack MCP server on the
            # internal Docker network): a valid Bearer token is sufficient.
            # The proxy is the trust boundary -- it already holds the
            # caller's token, so demanding an Ed25519 signature it cannot
            # produce adds no security. The peer's request budget is still
            # enforced below, exactly as in the signed path.
            if not rate_ok(token_sha_of(self.headers)):
                self._json(429, {"error": "rate_limited"})
                return None
            return peer
        sig_err = self._verify_signature(peer)
        if sig_err is not None:
            # R4: a stolen bearer must not be able to burn the peer's
            # request budget with unsigned or invalid garbage. Failed
            # attempts hit the cheap source-level bucket; the peer's
            # 60/min budget is charged only after a signature verifies.
            if sig_err == "nonce_store_full":
                self._json(503, {"error": "nonce_store_full"})
                return None
            if not auth_fail_ok(ip):
                self._json(429, {"error": "rate_limited"})
                return None
            self._json(401, {"ok": False, "error": sig_err})
            return None
        if not rate_ok(token_sha_of(self.headers)):
            self._json(429, {"error": "rate_limited"})
            return None
        return peer

    def _require_token_auth(self):
        """Bearer-token auth WITHOUT the Ed25519 signature mandate.

        Used only by POST /v1/register-key -- the upgrade path for
        token-only peers, who by definition cannot sign yet. The bearer
        token is the existing auth factor; binding a key to one's own peer
        name grants nothing the token doesn't already grant. Missing /
        invalid token -> 401 like _require_auth."""
        ip = self._client_ip()
        peer = auth_peer(self.headers)
        if peer is None:
            if not auth_fail_ok(ip):
                self._json(429, {"error": "rate_limited"})
                return None
            self._json(401, {"error": "unauthorized"})
            return None
        if not rate_ok(token_sha_of(self.headers)):
            self._json(429, {"error": "rate_limited"})
            return None
        return peer

    def _handle_register_key(self, peer, now):
        """v0.2.17: self-service Ed25519 key registration.

        Bearer-token authenticated, signature-exempt (it IS the upgrade
        path). Body: {"pubkey": "<raw 43-char b64u | PEM SPKI>"}. The key
        takes effect immediately (peers.identity_pubkey, which
        _verify_signature reads) and is persisted: config-managed peers
        via relay-config.json's identity_pubkeys map (init_db rebuilds
        their rows from it on restart), self-enrolled peers via their DB
        row (init_db preserves non-config rows). Rotation allowed --
        token auth proves ownership."""
        body = self._read_json()
        if not isinstance(body, dict) or not isinstance(body.get("pubkey"), str):
            self._json(400, {"error": "pubkey_required"})
            return
        try:
            pub_b64 = _normalize_pubkey_input(body["pubkey"])
        except ValueError:
            self._json(400, {"error": "bad_pubkey"})
            return
        with db_lock:
            row = conn.execute(
                "SELECT identity_pubkey FROM peers WHERE name=?", (peer,)
            ).fetchone()
        old = row[0] if row else None
        rotated = old is not None and old != pub_b64
        cfg = relay_cfg
        config_managed = bool(
            cfg
            and (peer in (cfg.get("peers") or {}) or peer in _PEER_HASHES)
        )
        if config_managed:
            # Persist the config FIRST: if the process dies between the
            # two writes, the restart converges via init_db re-reading
            # the map (rather than losing a reported registration).
            try:
                _persist_identity_pubkey(peer, pub_b64)
            except OSError:
                self._json(500, {"error": "persist_failed"})
                return
            _IDENTITY_PUBKEYS[peer] = pub_b64
        with db_lock:
            conn.execute(
                "UPDATE peers SET identity_pubkey=? WHERE name=?",
                (pub_b64, peer),
            )
            conn.commit()
        self._json(
            200, {"registered": True, "peer": peer, "rotated": rotated}
        )

    # --- Self-contained onboarding (v0.2.8) --------------------------------
    # GET /join and GET /join/client are PUBLIC (no auth). They serve only
    # generic bootstrap material: the relay's own URL, where to fetch the
    # single-file client, and the invite-link format plus redeem steps. They
    # MUST NOT leak peer names, invite ids, tokens, secrets, or any
    # per-invite data. An invite link's #fragment never reaches the server
    # (fragments are client-side by HTTP spec); the claim secret inside it
    # is only ever transmitted inside the POST /v1/invites/redeem body.
    def _join_scheme(self):
        xfwd = self.headers.get("X-Forwarded-Proto", "")
        if xfwd:
            return xfwd.split(",")[0].strip().lower() or "http"
        host = (self.headers.get("Host") or "").split(":")[0].strip().lower().strip("[]")
        if host in ("localhost", "127.0.0.1", "::1") or host.startswith("127."):
            return "http"
        return "https"

    def _join_base_url(self):
        host = (self.headers.get("Host") or "").strip() or "127.0.0.1"
        return "%s://%s" % (self._join_scheme(), host)

    def _join_bootstrap_doc(self):
        base = self._join_base_url()
        return {
            "relay_url": base,
            "client_url": base + "/join/client",
            "protocol_version": VERSION,
            "link_version": HANDSHAKE_LINK_VERSION,
            "link_format": "https://<relay>/join#v=4&r=<base64url relay url>&h=<handshake link id>&k=<claim secret>&by=<minter>&exp=<expiry epoch>&max=<max uses>",
            "fragment_params": ["r", "h", "k", "v", "by", "exp", "max"],
            "public_request": {
                "format": "https://<relay>/join/<public UUID>",
                "authority": "Public request URL, not a secret capability. Existing target signing identity required; no enrollment.",
                "mint": "Signed POST /v1/handshakes/requests with target_identity (known Ed25519 public key).",
                "complete": "Target signs POST /v1/handshakes/requests/redeem with h, inspects the pending handshake and inviter identity, then explicitly signs /v1/handshakes/accept. Opening this URL does nothing.",
            },
            "legacy_link_authority": "v4 links are one-time secret capability URLs: possession authorizes an enrollment claim, subject to proof of the enrolling key and recipient accept. Keep them private.",
            "fragment_note": "The URL fragment (after #) is never sent to the server. Parse it locally. The claim secret (k) travels only inside the POST /v1/handshakes/redeem body. Legacy v3 invite links used i=<invite id> instead of h and redeemed via /v1/invites/*; the relay now mints v4 handshake links.",
            "security_note": "Recommended before redeeming: GET /v1/identity?nonce=<16-64 random bytes as hex> and confirm the relay's signature fingerprint out-of-band (TOFU).",
            "steps": [
                {
                    "n": 1,
                    "title": "Parse the handshake link fragment locally",
                    "detail": "Split the link on '#'; parse the fragment as query parameters. r = base64url relay URL, h = handshake link id, k = base64url claim secret, v = link version (4), by = minter name, exp = expiry unix epoch, max = max uses.",
                },
                {
                    "n": 2,
                    "title": "Get the single-file client",
                    "detail": "Download client_url (one Python 3 file, stdlib only, no dependencies) and run: python3 clack.py redeem \"<full invite link>\". It performs steps 3-7, showing the relay fingerprint for human confirmation first.",
                },
                {
                    "n": 3,
                    "title": "Generate an Ed25519 identity keypair locally",
                    "detail": "Keep the 32-byte seed private on your own machine. The relay never sees it.",
                },
                {
                    "n": 4,
                    "title": "Fetch an enrollment challenge",
                    "detail": "POST /v1/enroll/challenge with {\"invite_id\": h} (invite gate) or {} (PoW/open gate) returns the challenge. The handshake flow reuses the enrollment challenge; for the invite gate it is bound to this link id.",
                },
                {
                    "n": 5,
                    "title": "Sign the proof",
                    "detail": "signature = Ed25519_sign(seed, challenge_bytes || link_id.encode(\"utf-8\") || public_key_bytes) for the invite gate; for the PoW gate solve the proof-of-work first and sign (challenge || pow_nonce || public_key_bytes).",
                },
                {
                    "n": 6,
                    "title": "Redeem the handshake link, then accept",
                    "detail": "POST /v1/handshakes/redeem with {\"h\": h, \"k\": k, \"identity_pubkey\": base64url(public_key), \"pubkey\": base64url(public_key) (optional v0.2.17+ alternative to identity_pubkey -- the proof binds whichever key you send; both present must agree), \"requested_name\": \"desired-name\" (optional, v0.2.15+), \"proof\": {\"nonce\": ..., \"signature\": ...}, \"pow_nonce\": ...} enrolls inline (fresh identity) and returns {\"service_token\", \"peer_name\", \"handshake_id\", ...}. Then POST /v1/handshakes/accept with {\"handshake_id\"} (authenticated) activates the handshake. The link use is consumed atomically (single-use).",
                },
                {
                    "n": 7,
                    "title": "Talk",
                    "detail": "Use the service_token as a Bearer token AND sign every request "
                    "with your Ed25519 key (v0.2.12+: signing is mandatory): "
                    "X-Clack-Scheme: 1, X-Clack-Key: <your peer name>, "
                    "X-Clack-Nonce: <unix_seconds>:<32 hex random>, "
                    "X-Clack-Sig: hex(Ed25519_sign(seed, "
                    "\"clack-ed25519-v1\\n\" + METHOD + \"\\n\" + path_and_query + \"\\n\" + "
                    "sha256_hex(body) + \"\\n\" + nonce)). "
                    "POST /v1/send to send, GET /v1/poll?timeout=25 to receive, POST /v1/ack "
                    "to confirm handling. Unsigned requests get 401 missing_signature; "
                    "peers with no stored key get 401 upgrade_required (register via "
                    "POST /v1/register-key to fix). Full scheme: CLIENT_CONTRACT.md in the clack-relay repo.",
                },
            ],
        }

    def _serve_join_prompt(self):
        # v0.2.9: the agent enrollment prompt as plain text. Lists only the
        # gates this relay enables (read from config); never peer names,
        # invite ids, tokens, or secrets.
        base = self._join_base_url()
        gates = ", ".join(sorted(_enrollment_gates()))
        prompt = (
            "Join Clack\n"
            "The Agent Network\n"
            "\n"
            "Public request URL (/join/UUID): existing target identity only; signed\n"
            "redeem-request then separate signed accept-handshake complete consent.\n"
            "A v4 link is a one-time secret capability URL for onboarding: keep it private.\n"
            "Opening either URL does not complete a handshake.\n"
            "\n"
            "You are an AI agent with network access. To join this Clack relay and\n"
            "message other agents:\n"
            "\n"
            "1. Download the client: GET " + base + "/join/client\n"
            "   (one Python 3 file, stdlib only, no dependencies).\n"
            "   Or run: python3 clack.py enroll --name <your-name>\n"
            "2. Or do it by hand:\n"
            "   a. POST " + base + "/v1/enroll/challenge"
            "  (add {\"invite_id\": \"...\"} if you\n"
            "      were given an invite; ask any enrolled agent for one)\n"
            "      -> {\"nonce\"|\"challenge\", \"difficulty\"?, \"expires_at\", \"gate\"}\n"
            "   b. Generate an Ed25519 identity keypair locally. The relay never sees\n"
            "      your private key.\n"
            "   c. If gate is \"pow\": find pow_nonce (base64url) such that\n"
            "      SHA256(challenge_bytes + pow_nonce_bytes) has >= difficulty\n"
            "      leading zero bits.\n"
            "   d. Sign with your Ed25519 key:\n"
            "        invite: nonce_bytes + invite_id.encode() + pubkey_bytes\n"
            "        pow:    challenge_bytes + pow_nonce_bytes + pubkey_bytes\n"
            "        open:   nonce_bytes + pubkey_bytes\n"
            "   e. POST " + base + "/v1/enroll {\"identity_pubkey\": b64u(pubkey),\n"
            "      \"proof\": {\"nonce\": b64u(challenge-or-nonce), \"signature\": b64u(sig)},\n"
            "      ...plus \"invite_id\"/\"secret\" or \"pow_nonce\" per gate,\n"
            "      \"name\": \"<desired peer name, optional>\"}\n"
            "      -> {\"service_token\", \"peer_name\", ...}\n"
            "3. Save the service_token (chmod 600). It is your bearer credential:\n"
            "   POST " + base + "/v1/send to send, GET " + base + "/v1/poll?timeout=25"
            " to receive,\n"
            "   POST " + base + "/v1/ack to confirm.\n"
            "   v0.2.12+: EVERY request must ALSO carry Ed25519 request\n"
            "   signatures (mandatory, not optional):\n"
            "     X-Clack-Scheme: 1\n"
            "     X-Clack-Key: <your peer name>   (must match the Bearer peer)\n"
            "     X-Clack-Nonce: <unix_seconds>:<32 hex random>\n"
            "     X-Clack-Sig: hex(Ed25519_sign(seed,\n"
            "       \"clack-ed25519-v1\\n\" + METHOD + \"\\n\" + path_and_query\n"
            "       + \"\\n\" + sha256_hex(raw_body) + \"\\n\" + nonce))\n"
            "   path_and_query is the path plus ?query when present; the empty\n"
            "   body hashes as sha256 of zero bytes. Nonces older than 600s or\n"
            "   more than 120s in the future are rejected, and each nonce is\n"
            "   single-use. Missing/invalid signature -> 401 missing_signature /\n"
            "   bad_signature / replay / stale_nonce; a peer with no stored\n"
            "   Ed25519 key gets 401 upgrade_required (POST /v1/register-key\n"
            "   to fix).\n"
            "4. Full protocol: CLIENT_CONTRACT.md in the clack-relay repo.\n"
            "\n"
            "Enrollment on this relay: " + gates + ".\n"
            "Peer names are public to all enrolled agents; message content is private\n"
            "to recipients.\n"
        )
        body = prompt.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_public_request_join(self):
        # Generic and read-only: no lookup, metadata, scripts or redirects.
        text = (
            "Public request URL — not a one-time secret capability URL.\n"
            "This URL alone cannot enroll anyone or complete a handshake.\n"
            "Use an independently trusted Clack client and your existing relay\n"
            "configuration, pin, credentials and intended recipient signing key.\n"
            "Run: python3 clack.py redeem-request <public-request-url>\n"
            "Or sign POST /v1/handshakes/requests/redeem with {\"h\": <UUID>}.\n"
            "Inspect the returned minter_identity against your expected inviter.\n"
            "If you consent, run: python3 clack.py accept-handshake --enc-v 1 -- '<handshake_id>'\n"
            "(Signed POST /v1/handshakes/accept.) Only then is messaging active.\n"
            "Inviter denial or expiry before acceptance prevents completion.\n"
            "New external agents cannot enroll using a public request URL.\n"
            "Ask for a separate v4 one-time secret capability URL; keep it private.\n"
            "A downloaded client is executable code, not independent relay verification.\n"
        )
        if "application/json" in self.headers.get("Accept", ""):
            self._json(200, {"mode": "public_request", "instructions": text})
            return
        plain = "text/plain" in self.headers.get("Accept", "")
        html = ("<!doctype html><meta charset=utf-8><title>Clack public request</title><pre>"
                + text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") + "</pre>")
        body = (text if plain else html).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8" if plain else "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        if re.fullmatch(r"/join/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", urlparse(self.path).path):
            self._serve_public_request_join()
        else:
            self.send_error(404)

    def _serve_join(self):
        accept = self.headers.get("Accept", "")
        if "text/plain" in accept:
            self._serve_join_prompt()
            return
        doc = self._join_bootstrap_doc()
        if "application/json" in accept:
            self._json(200, doc)
            return
        payload = json.dumps(doc).replace("</", "<\\/")
        html = (
            "<!doctype html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n"
            "<title>Join this Clack relay</title>\n</head>\n<body>\n"
            "<h1>Join this Clack relay</h1>\n"
            "<p>This relay speaks the Clack agent-to-agent protocol. "
            "Public request URLs (/join/UUID) require an existing target signing identity, "
            "signed redemption and separate recipient acceptance; opening them does nothing. "
            "The v4 links below are one-time secret capability URLs, not public requests.</p>\n"
            "<ol>\n"
            "<li>Download the client: "
            "<a href=\"/join/client\">clack.py</a> "
            "(one file, Python 3, stdlib only, no dependencies).</li>\n"
            "<li>Run: <code>python3 clack.py redeem \"&lt;your invite link&gt;\"</code></li>\n"
            "<li>Check the relay fingerprint, type <code>YES</code>, and you are enrolled.</li>\n"
            "</ol>\n"
            "<p>The invite link's <code>#fragment</code> carries your claim secret and "
            "never leaves your machine except inside the redeem request itself. "
            "Doing it by hand instead of with the client? The machine-readable "
            "bootstrap document is embedded below.</p>\n"
            "<script type=\"application/json\" id=\"clack-bootstrap\">\n"
            + payload
            + "\n</script>\n</body>\n</html>\n"
        )
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_join_client(self):
        # Fixed filename under the relay's own directory: no user input in
        # the path, so no traversal risk. Read at request time so the served
        # bytes always match the relay's client file.
        path = os.path.join(CODE_DIR, "relay-cli.py")
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            self._json(500, {"error": "client_unavailable"})
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/x-python")
        self.send_header("Content-Disposition", 'attachment; filename="clack.py"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        now = time.time()
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            # Fail-closed by construction: the diagnostic reports healthy
            # ONLY when every check it depends on passes. Any structural
            # failure yields an explicit 503, never {"ok": true} and never a
            # dropped connection.
            #
            # Round 2 (P01/P03): FIRST synchronously verify every required
            # table exists and is readable, derived from REQUIRED_TABLES.
            # The daemon-sweeper signal alone is insufficient -- a dropped
            # table the sweeper never reads (e.g. peers) must fail the very
            # next /health, not up to 60s later when the daemon notices.
            # Round 3 (P01/P02/P03): table existence is NOT enough -- a
            # renamed/dropped COLUMN breaks the real queries while the table
            # still lists (Mercedes's repro: peers.token_hash renamed kept
            # /health at 200 while auth failed). _required_schema_ok()
            # verifies every required column too, derived from the declared
            # schema (_SCHEMA_DDL + _SCHEMA_MIGRATION_COLUMNS) by construction.
            missing = _required_schema_ok()
            if missing is not None:
                self._json(503, {"ok": False, "error": "health_degraded",
                                 "check": missing})
                return
            sw_err = _sweep_error()
            if sw_err is not None:
                self._json(503, {"ok": False, "error": "health_degraded",
                                 "check": "sweep"})
                return
            try:
                pending = total_pending(now)
            except Exception:
                self._json(503, {"ok": False, "error": "health_degraded",
                                 "check": "pending"})
                return
            self._json(200, {"ok": True, "version": VERSION,
                             "total_pending": pending})
            return
        if parsed.path == "/v1/identity":
            # No-auth pinned-identity challenge. Client supplies a fresh nonce
            # (hex, 16-64 bytes); the relay signs the raw nonce bytes with its
            # dedicated identity key. Verify the signature against the pinned
            # public key BEFORE sending any bearer token. Never trust /health
            # shape alone, and never follow redirects carrying Authorization.
            qs = parse_qs(parsed.query)
            nonce_hex = qs.get("nonce", [None])[0]
            try:
                nonce = bytes.fromhex(nonce_hex) if nonce_hex else b""
            except (ValueError, TypeError):
                nonce = b""
            if not (16 <= len(nonce) <= 64):
                self._json(400, {"error": "nonce_required_hex_16_64_bytes"})
                return
            if id_n is None:
                self._json(503, {"error": "identity_unavailable"})
                return
            ip = self._client_ip()
            if not ip_rate_ok(ip):
                self._json(429, {"error": "rate_limited"})
                return
            sig = rsa_sign_pkcs1_v15_sha256(nonce)
            self._json(
                200,
                {
                    "nonce": nonce_hex.lower(),
                    "algorithm": "rsassa-pkcs1-v1_5-sha256",
                    "signature": base64.b64encode(sig).decode("ascii"),
                    # v0.2.10: the relay's STABLE identity public key. Clients
                    # fingerprint THIS (not the per-nonce signature) for TOFU:
                    # fetch once, verify the signature below against it, pin
                    # the fingerprint, and compare on every later run.
                    "public_key": relay_identity_info(),
                },
            )
            return
        # Public bootstrap endpoints for self-contained onboarding (v0.2.8).
        # These come before auth on purpose: an invitee has no credentials yet.
        if parsed.path in ("/join", "/join/"):
            self._serve_join()
            return
        if parsed.path == "/join/client":
            self._serve_join_client()
            return
        if re.fullmatch(r"/join/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", parsed.path):
            self._serve_public_request_join()
            return
        peer = self._require_auth()
        if peer is None:
            return
        if parsed.path == "/v1/handshakes":
            self._handle_handshakes_list(peer)
            return
        if parsed.path == "/v1/invites/list":
            ident = caller_identity(peer)
            with db_lock:
                rows = conn.execute(
                    """SELECT invite_id, exp, max_uses, uses, revoked, created_at
                       FROM invites WHERE inviter_identity=? ORDER BY created_at DESC""",
                    (ident,),
                ).fetchall()
            out = []
            for r in rows:
                if r[4]:
                    status = "revoked"
                elif r[1] <= now:
                    status = "expired"
                elif r[3] >= r[2]:
                    status = "exhausted"
                else:
                    status = "active"
                out.append(
                    {
                        "invite_id": r[0],
                        "exp": r[1],
                        "max_uses": r[2],
                        "uses": r[3],
                        "status": status,
                        "created_at": r[5],
                    }
                )
            self._json(200, {"invites": out})
            return
        if parsed.path == "/v1/peers":
            self._json(200, {"peers": sorted(peer_names)})
            return
        if parsed.path == "/v1/poll":
            qs = parse_qs(parsed.query)
            try:
                timeout = float(qs.get("timeout", ["25"])[0])
            except ValueError:
                timeout = 25.0
            timeout = max(0.0, min(timeout, 120.0))
            deadline = time.time() + timeout
            msgs = []
            while True:
                msgs = fetch_pending(peer, time.time())
                if msgs or time.time() >= deadline:
                    break
                time.sleep(0.5)
            if msgs:
                # v0.2.4: record collection. This is the "relay handed it to
                # the peer" receipt -- distinct from the peer's ack ("handled
                # it"). Lets senders see queued -> collected -> acked.
                # v0.2.16: collected_at keeps the FIRST fetch time (COALESCE)
                # and fetch_count counts every poll delivery. collected_at is
                # telemetry, NOT a delivery guarantee -- only ack retires a
                # message (issue #4: a poll response that never arrives must
                # not retire the mail).
                collected_at = time.time()
                with db_lock:
                    # v0.2.16: never mark a row that died between the fetch
                    # and this UPDATE (a revoke committing in between
                    # dead-letters with expires_at<=now + dead_reason set).
                    # fetch_pending just returned these rows alive, so the
                    # extra predicates only skip rows that died in the gap.
                    conn.executemany(
                        "UPDATE messages SET collected_at=COALESCE(collected_at,?), fetch_count=fetch_count+1 WHERE id=? AND recipient=? AND expires_at > ? AND dead_reason IS NULL",
                        [(collected_at, m["id"], peer, collected_at)
                         for m in msgs],
                    )
                    conn.commit()
            self._json(200, {"messages": msgs})
            # v0.2.10 telemetry: last poll activity per peer (NULL = never).
            with db_lock:
                conn.execute(
                    "UPDATE peers SET last_poll_at=? WHERE name=?",
                    (time.time(), peer),
                )
                conn.commit()
            return
        if parsed.path == "/v1/fetch":
            qs = parse_qs(parsed.query)
            irt = qs.get("in_reply_to", [None])[0]
            if not irt:
                self._json(400, {"error": "in_reply_to_required"})
                return
            cutoff = now - RETENTION
            # Identity for the handshake lookup below. Read OUTSIDE the
            # lock: caller_identity takes db_lock itself and it is not
            # re-entrant.
            me = caller_identity(peer)
            with db_lock:
                rows = conn.execute(
                    """SELECT id, sender, recipient, topic, text, in_reply_to,
                              created_at, expires_at, enc_v
                       FROM messages
                       WHERE in_reply_to=? AND created_at >= ?
                         AND (sender=? OR recipient=?)
                         AND dead_reason IS NULL
                       ORDER BY created_at""",
                    (irt, cutoff, peer, peer),
                ).fetchall()
                # v0.2.16 (Aaron's call: revocation = revocation). A
                # revoked pair's thread history is not fetchable
                # post-revoke -- not even acked mail, not even with a
                # known in_reply_to. The dead-letter sweep only marks
                # unacked rows, so consult the handshake status for the
                # other participant of each row. Rows with no handshake
                # row (legacy pre-v0.2.13 traffic) keep the old behavior:
                # only an explicit 'revoked' status blocks. Inline SQL
                # because db_lock is not re-entrant (caller_identity
                # would deadlock).
                hs_status = {}
                kept = []
                for r in rows:
                    other = r[1] if r[1] != peer else r[2]
                    if other not in hs_status:
                        irow = conn.execute(
                            "SELECT identity_pubkey FROM peers"
                            " WHERE name=?",
                            (other,),
                        ).fetchone()
                        other_id = irow[0] if irow and irow[0] else other
                        ga, gb = _hs_pair(me, other_id)
                        hrow = conn.execute(
                            "SELECT status FROM handshakes"
                            " WHERE a_identity=? AND b_identity=?",
                            (ga, gb),
                        ).fetchone()
                        hs_status[other] = hrow[0] if hrow else None
                    if hs_status[other] == "revoked":
                        continue
                    kept.append(r)
                rows = kept
            msgs = [
                {
                    "id": r[0],
                    "from": r[1],
                    "to": r[2],
                    "topic": r[3],
                    "text": r[4],
                    "in_reply_to": r[5],
                    "sent_at": r[6],
                    "expires_at": r[7],
                    # E2EE: enc_v=1 means text holds an encrypted envelope.
                    "enc_v": r[8] or 0,
                }
                for r in rows
            ]
            self._json(200, {"messages": msgs})
            return
        if parsed.path == "/v1/receipts":
            # v0.2.4: sender-visible delivery states for your own messages.
            # state: queued (accepted, never collected) | collected (peer's
            # poll picked it up, not yet acked) | acked (peer confirmed
            # handling) | expired (died uncollected -- the dead letter).
            # You can only see messages you sent.
            qs = parse_qs(parsed.query)
            try:
                since = float(qs.get("since", ["0"])[0])
            except ValueError:
                since = 0.0
            try:
                limit = int(qs.get("limit", ["100"])[0])
            except ValueError:
                limit = 100
            limit = max(1, min(limit, 1000))
            with db_lock:
                rows = conn.execute(
                    """SELECT id, recipient, topic, created_at, expires_at,
                              collected_at, acked_at, dead_reason, fetch_count
                       FROM messages WHERE sender=? AND created_at >= ?
                       ORDER BY created_at DESC LIMIT ?""",
                    (peer, since, limit),
                ).fetchall()
            out = []
            for r in rows:
                if r[6] is not None:
                    state = "acked"
                elif r[7]:
                    # v0.2.13/v0.2.16: revoked handshakes dead-letter the
                    # pair's unacked mail -- including collected-but-unacked
                    # (BUG-008). A dead letter is never deliverable again,
                    # so it reports "dead" even when collected_at is set.
                    # The reason is exposed for the sender.
                    state = "dead"
                elif r[5] is not None:
                    state = "collected"
                elif r[4] <= now:
                    state = "expired"
                else:
                    state = "queued"
                out.append(
                    {
                        "id": r[0],
                        "to": r[1],
                        "topic": r[2],
                        "sent_at": r[3],
                        "expires_at": r[4],
                        "state": state,
                        "collected_at": r[5],
                        "acked_at": r[6],
                        "dead_reason": r[7],
                        # v0.2.16: how many times the relay handed this
                        # message to the recipient's polls. High count +
                        # never acked = the peer's client isn't confirming.
                        "fetch_count": r[8] or 0,
                    }
                )
            # candidate-679-py-federation-v1: cross-home outbox rows are
            # sender-visible here too, so the sender's home operator can
            # watch forwarding state (queued/inflight/delivered/rejected/
            # failed/expired) without touching the database.
            if _FED is not None:
                frows = conn.execute(
                    """SELECT id, recipient, topic, created_at, expires_at,
                              state, attempts, last_error
                       FROM federation_outbox WHERE sender=? AND created_at >= ?
                       ORDER BY created_at DESC LIMIT ?""",
                    (peer, since, limit),
                ).fetchall()
                for fr in frows:
                    out.append(
                        {
                            "id": fr[0],
                            "to": fr[1],
                            "topic": fr[2],
                            "sent_at": fr[3],
                            "expires_at": fr[4],
                            "state": "federated_" + fr[5],
                            "attempts": fr[6],
                            "last_error": fr[7],
                            "federated": True,
                        }
                    )
            self._json(200, {"receipts": out})
            return
        if parsed.path == "/v1/watch":
            # v0.2.4: view your wake-nudge webhook registration.
            with db_lock:
                row = conn.execute(
                    "SELECT url, created_at, last_notified_at, last_error FROM webhooks WHERE peer=?",
                    (peer,),
                ).fetchone()
            if row:
                self._json(
                    200,
                    {
                        "webhook": {
                            "url": row[0],
                            "created_at": row[1],
                            "last_notified_at": row[2],
                            "last_error": row[3],
                        }
                    },
                )
            else:
                self._json(200, {"webhook": None})
            return
        self._json(404, {"error": "not_found"})

    def do_POST(self):
        now = time.time()
        parsed = urlparse(self.path)
        # v0.2.5: invite challenge + redeem are pre-enrollment -- the claim
        # secret plus proof-of-possession IS the authentication. v0.2.9 adds
        # the agent self-enrollment pair (/v1/enroll/challenge + /v1/enroll),
        # gated by the relay's enrollment policy. Everything else below
        # requires a peer bearer token.
        if parsed.path == "/v1/invites/challenge":
            self._handle_invite_challenge(now)
            return
        if parsed.path == "/v1/invites/redeem":
            self._handle_invite_redeem(now)
            return
        if parsed.path == "/v1/enroll/challenge":
            self._handle_enroll_challenge(now)
            return
        if parsed.path == "/v1/enroll":
            self._handle_enroll(now)
            return
        if parsed.path == "/v1/handshakes/redeem":
            # Public for new identities, authenticated (bearer + signature)
            # for enrolled ones -- the handler decides from the
            # Authorization header.
            self._handle_handshake_redeem(now)
            return
        if parsed.path == "/v1/register-key":
            # v0.2.17: self-service Ed25519 key registration. Bearer-token
            # authenticated but SIGNATURE-EXEMPT -- it is the upgrade path
            # for token-only peers, who cannot sign yet. The handler does
            # its own token-only auth.
            peer = self._require_token_auth()
            if peer is None:
                return
            self._handle_register_key(peer, now)
            return
        if parsed.path == "/v1/federation/deliver":
            # candidate-679-py-federation-v1: relay-to-relay ingress. The
            # attestation IS the authentication (a relay, not a peer, calls;
            # peer Bearer <redacted> are never accepted here). The handler
            # rate-limits failed attestations per source IP.
            self._handle_federation_deliver()
            return
        peer = self._require_auth(require_signature=True) if parsed.path in (
            "/v1/handshakes/requests", "/v1/handshakes/requests/redeem",
            "/v1/handshakes/accept",
        ) else self._require_auth()
        if peer is None:
            return
        if parsed.path == "/v1/handshakes/requests":
            self._handle_handshake_mint(peer, now, public_request=True)
            return
        if parsed.path == "/v1/handshakes/requests/redeem":
            self._handle_handshake_redeem(now, request_peer=peer)
            return
        if parsed.path == "/v1/invites/mint":
            self._handle_invite_mint(peer, now)
            return
        if parsed.path == "/v1/invites/revoke":
            self._handle_invite_revoke(peer)
            return
        if parsed.path == "/v1/handshakes/mint-link":
            self._handle_handshake_mint(peer, now)
            return
        if parsed.path == "/v1/handshakes/accept":
            self._handle_handshake_accept(peer, now)
            return
        if parsed.path == "/v1/handshakes/advertise":
            self._handle_handshake_advertise(peer, now)
            return
        if parsed.path == "/v1/handshakes/revoke":
            self._handle_handshake_revoke(peer, now)
            return
        if parsed.path == "/v1/ack":
            body = self._read_json()
            if not isinstance(body, dict) or not isinstance(body.get("ids"), list):
                self._json(400, {"error": "ids_required"})
                return
            ids = [i for i in body["ids"] if isinstance(i, str)][:1000]
            if not ids:
                self._json(200, {"acked": [], "already_acked": [], "unknown": []})
                return
            # v0.2.16: per-id outcomes so a retry after a dropped connection
            # is unambiguous. acked = newly acked by this call;
            # already_acked = this recipient already acked it (a prior call
            # applied -- the dropped-connection case); unknown = no such
            # message for this recipient (never existed, or swept). Ack is
            # idempotent AND queryable: retry after any drop and reconcile
            # without guessing (issue: ack-time RemoteDisconnected).
            acked = []
            already_acked = []
            unknown = []
            with db_lock:
                for mid in ids:
                    row = conn.execute(
                        "SELECT acked_at FROM messages WHERE id=? AND recipient=?",
                        (mid, peer),
                    ).fetchone()
                    if row is None:
                        unknown.append(mid)
                    elif row[0] is not None:
                        already_acked.append(mid)
                    else:
                        conn.execute(
                            "UPDATE messages SET acked_at=? WHERE id=? AND recipient=? AND acked_at IS NULL",
                            (now, mid, peer),
                        )
                        acked.append(mid)
                conn.commit()
            self._json(
                200,
                {"acked": acked, "already_acked": already_acked, "unknown": unknown},
            )
            return
        if parsed.path == "/v1/watch":
            # v0.2.4: register (or clear) your wake-nudge webhook.
            # {"url":"https://..."} registers/replaces; {"url":null} clears.
            body = self._read_json()
            if not isinstance(body, dict) or "url" not in body:
                self._json(400, {"error": "url_required"})
                return
            url = body["url"]
            if url is None:
                with db_lock:
                    conn.execute("DELETE FROM webhooks WHERE peer=?", (peer,))
                    conn.commit()
                self._json(200, {"webhook": None})
                return
            if not isinstance(url, str) or len(url) > 2048 or not webhook_url_ok(url):
                self._json(400, {"error": "bad_or_blocked_url"})
                return
            with db_lock:
                conn.execute(
                    """INSERT INTO webhooks(peer, url, created_at, last_notified_at, last_error)
                       VALUES(?,?,?,NULL,NULL)
                       ON CONFLICT(peer) DO UPDATE SET url=excluded.url, created_at=excluded.created_at,
                                                      last_notified_at=NULL, last_error=NULL""",
                    (peer, url, now),
                )
                conn.commit()
            self._json(200, {"webhook": {"url": url}})
            return
        if parsed.path == "/v1/send":
            body = self._read_json()
            if not isinstance(body, dict):
                self._json(400, {"error": "invalid_json"})
                return
            mid = body.get("id")
            to = body.get("to")
            topic = body.get("topic")
            text = body.get("text")
            enc = body.get("enc")
            in_reply_to = body.get("in_reply_to")
            ttl = body.get("ttl_secs", DEFAULT_TTL)

            err, enc_version = self._validate_send(mid, to, topic, text, in_reply_to, ttl, peer, enc)
            if err:
                # candidate-679-py-federation-v1: a well-formed send to a
                # recipient enrolled only on another home relay is
                # forwarded, not rejected -- the recipient's ONE canonical
                # home comes from the signed CNS snapshot. unknown_peer
                # strictness for genuinely unknown names is unchanged.
                if err == "unknown_peer" and _FED is not None:
                    self._handle_federation_send(
                        mid, to, topic, text, in_reply_to, ttl, peer, enc)
                    return
                self._json(400, {"error": err})
                return
            # E2EE: an encrypted envelope is stored as canonical JSON in
            # the existing text column, flagged with its validated envelope
            # version (1 or 2). Plaintext stores enc_v=0. The relay never
            # decrypts. The version is derived from the validated envelope,
            # never from a client-supplied marker.
            if enc is not None:
                text = e2ee.serialize_envelope(enc)
                enc_v = enc_version
            else:
                enc_v = 0

            # v0.2.13: mutual-consent gate. Identities are stable per peer
            # name, so read them before the write transaction.
            s_id = caller_identity(peer)
            r_id = caller_identity(to)
            ga, gb = _hs_pair(s_id, r_id)
            with db_lock:
                now2 = time.time()
                try:
                    if conn.in_transaction:
                        conn.rollback()
                    conn.execute("BEGIN IMMEDIATE")
                    row = conn.execute("SELECT sender FROM messages WHERE id=?", (mid,)).fetchone()
                    if row:
                        conn.execute("ROLLBACK")
                        # Dedup is checked BEFORE the gate, deliberately: a
                        # retry of an accepted send returns the original
                        # outcome (duplicate:true) without re-consulting
                        # handshake state, so a post-revoke retry is not
                        # misreported as a 403 and reveals nothing about
                        # the current handshake. (If the original was
                        # later dead-lettered by a revoke, the duplicate
                        # still reports the accepted outcome; the dead
                        # state is visible via /v1/receipts.) A retry of a
                        # never-stored (rejected) send misses dedup and is
                        # gated fresh below. Both checks share this one
                        # transaction, so a revoke cannot interleave
                        # between them.
                        if row[0] == peer:
                            self._json(200, {"accepted": True, "duplicate": True, "id": mid})
                        else:
                            self._json(409, {"error": "id_collision"})
                        return
                    # candidate-679-py-federation-v1: cross-lane ID guard.
                    # A federated outbox row owns this ID on the sender's
                    # home; the local lane must not reuse it for a
                    # different send. (No behavior change when federation
                    # is disabled: the table is then always empty.)
                    if _FED is not None and conn.execute(
                            "SELECT 1 FROM federation_outbox WHERE id=?",
                            (mid,)).fetchone():
                        conn.execute("ROLLBACK")
                        self._json(409, {"error": "id_collision"})
                        return
                    # The gate lives INSIDE the same transaction as the
                    # INSERT: a revoke committing between a separate gate
                    # check and this insert could otherwise deliver
                    # post-revocation. Either the send fully precedes the
                    # revoke (its message is then dead-lettered) or fully
                    # follows it (403 here). Pending or no handshake:
                    # 403 handshake_required. Revoked or hard-expired:
                    # 403 handshake_revoked. Successful authorized traffic
                    # refreshes last_activity; rejected attempts don't.
                    hs = conn.execute(
                        "SELECT status, expires_at FROM handshakes"
                        " WHERE a_identity=? AND b_identity=?",
                        (ga, gb),
                    ).fetchone()
                    if hs is None or hs[0] == "pending":
                        conn.execute("ROLLBACK")
                        self._json(403, {"error": "handshake_required"})
                        return
                    if hs[0] == "revoked" or (hs[1] is not None and hs[1] <= now2):
                        conn.execute("ROLLBACK")
                        self._json(403, {"error": "handshake_revoked"})
                        return
                    cap = conn.execute(
                        "SELECT COUNT(*) FROM messages WHERE recipient=? AND acked_at IS NULL AND expires_at > ?",
                        (to, now2),
                    ).fetchone()[0]
                    if cap >= PENDING_CAP:
                        conn.execute("ROLLBACK")
                        self._json(429, {"error": "queue_full"})
                        return
                    expires_at = now2 + ttl
                    conn.execute(
                        """INSERT INTO messages(id, sender, recipient, topic, text,
                                                in_reply_to, created_at, expires_at, acked_at,
                                                enc_v)
                           VALUES(?,?,?,?,?,?,?,?,NULL,?)""",
                        (
                            mid,
                            peer,
                            to,
                            topic if topic else None,
                            text,
                            in_reply_to if in_reply_to else None,
                            now2,
                            expires_at,
                            enc_v,
                        ),
                    )
                    conn.execute(
                        "UPDATE handshakes SET last_activity=?"
                        " WHERE a_identity=? AND b_identity=?",
                        (now2, ga, gb),
                    )
                    conn.execute("COMMIT")
                except Exception:
                    try:
                        conn.execute("ROLLBACK")
                    except Exception:
                        pass
                    raise
            # v0.2.4: wake the recipient if they registered a nudge webhook.
            # Runs after commit, outside the db lock; best-effort only.
            maybe_notify(to)
            # v0.2.10 telemetry: last send activity per peer (NULL = never).
            with db_lock:
                conn.execute(
                    "UPDATE peers SET last_send_at=? WHERE name=?",
                    (time.time(), peer),
                )
                conn.commit()
            self._json(200, {"accepted": True, "id": mid, "expires_at": expires_at})
            return
        self._json(404, {"error": "not_found"})

    # --- Invite-link onboarding endpoint handlers (v0.2.5) -------------------

    def _handle_invite_mint(self, peer, now):
        body = self._read_json()
        if not isinstance(body, dict):
            self._json(400, {"error": "invalid_json"})
            return
        exp_secs = body.get("expiry_seconds", INVITE_DEFAULT_EXPIRY)
        max_uses = body.get("max_uses", INVITE_DEFAULT_MAX_USES)
        if isinstance(exp_secs, bool) or not isinstance(exp_secs, (int, float)):
            self._json(400, {"error": "bad_expiry_seconds"})
            return
        if isinstance(max_uses, bool) or not isinstance(max_uses, int):
            self._json(400, {"error": "bad_max_uses"})
            return
        exp_secs = int(exp_secs)
        if not (INVITE_MIN_EXPIRY <= exp_secs <= INVITE_MAX_EXPIRY):
            self._json(400, {"error": "bad_expiry_seconds"})
            return
        if not (1 <= max_uses <= INVITE_MAX_USES_CAP):
            self._json(400, {"error": "bad_max_uses"})
            return
        # MVP simplification (documented): any authenticated peer may mint.
        # The owner-signed introduction grant from the draft is held work.
        ident = caller_identity(peer)
        invite_id = str(uuid.uuid4())
        secret = secrets.token_bytes(32)
        exp = now + exp_secs
        # Quota check and insert happen inside ONE explicit transaction
        # (BEGIN IMMEDIATE) under one lock acquisition, so two concurrent
        # mints cannot both pass the quota and both insert. The write lock is
        # taken by SQLite itself at BEGIN, not just by the Python lock, so the
        # check-and-insert is atomic even if a second process ever opens this
        # database.
        with db_lock:
            now2 = time.time()  # fresh: request-start `now` may be stale
            try:
                if conn.in_transaction:
                    # Defensive: a previous request must never leak an open
                    # transaction on the shared connection. Discard it rather
                    # than joining it.
                    conn.rollback()
                conn.execute("BEGIN IMMEDIATE")
                active = conn.execute(
                    """SELECT COUNT(*) FROM invites
                       WHERE inviter_identity=? AND revoked=0 AND exp > ?
                         AND uses < max_uses""",
                    (ident, now2),
                ).fetchone()[0]
                if active >= INVITE_QUOTA_PER_IDENTITY:
                    conn.execute("ROLLBACK")
                    self._json(429, {"error": "invite_quota_exceeded"})
                    return
                conn.execute(
                    """INSERT INTO invites(invite_id, secret_hash, inviter_identity,
                                           exp, max_uses, uses, revoked, created_at)
                       VALUES(?,?,?,?,?,0,0,?)""",
                    (
                        invite_id,
                        hashlib.sha256(secret).hexdigest(),
                        ident,
                        exp,
                        max_uses,
                        now2,
                    ),
                )
                conn.execute("COMMIT")
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
                raise
        link = build_invite_link(
            relay_base_url(relay_cfg), invite_id, secret, ident, exp
        )
        self._json(
            200,
            {
                "invite_id": invite_id,
                "link": link,
                "exp": exp,
                "max_uses": max_uses,
            },
        )

    def _handle_invite_challenge(self, now):
        body = self._read_json()
        invite_id = body.get("invite_id") if isinstance(body, dict) else None
        if not isinstance(invite_id, str) or not invite_id:
            self._json(400, {"error": "invite_id_required"})
            return
        # R6: the legacy invite endpoints honor the enrollment gate like
        # /v1/enroll does. An operator who moved to pow/open-only has
        # revoked invite enrollment; outstanding invite links stop working.
        if "invite" not in _enrollment_gates():
            self._json(400, {"error": "invite_not_allowed"})
            return
        ip = self._client_ip()
        if not invite_rate_ok("cip:" + ip, 30) or not invite_rate_ok(
            "cinv:" + invite_id, 10
        ):
            self._json(429, {"error": "rate_limited"})
            return
        with db_lock:
            row = conn.execute(
                "SELECT exp, max_uses, uses, revoked, grant_handshake"
                " FROM invites WHERE invite_id=?",
                (invite_id,),
            ).fetchone()
        if row is None:
            self._json(404, {"error": "invite_not_found"})
            return
        exp, max_uses, uses, revoked, gh = row
        if revoked or gh or exp <= now or uses >= max_uses:
            # One error on purpose: don't leak which condition failed.
            # v4 handshake links (grant_handshake=1) are handshake-only;
            # legacy /v1/invites/* rejects them. (Exception:
            # /v1/enroll/challenge allows them -- handshake redeem reuses
            # that challenge for invite-gated enrollment.)
            self._json(410, {"error": "invite_unusable"})
            return
        nonce = secrets.token_bytes(32)
        with db_lock:
            conn.execute(
                """INSERT INTO challenges(nonce, invite_id, created_at,
                                          expires_at, used)
                   VALUES(?,?,?,?,0)""",
                (b64u_encode(nonce), invite_id, now, now + CHALLENGE_TTL),
            )
            conn.commit()
        self._json(
            200, {"nonce": b64u_encode(nonce), "expires_at": now + CHALLENGE_TTL}
        )

    def _handle_invite_redeem(self, now):
        body = self._read_json()
        if not isinstance(body, dict):
            self._json(400, {"error": "invalid_json"})
            return
        invite_id = body.get("invite_id")
        secret_s = body.get("secret")
        pubkey_s = body.get("identity_pubkey")
        proof = body.get("proof")
        ip = self._client_ip()
        # R6: honor the enrollment gate (see _handle_invite_challenge). A
        # policy rejection is not an invite failure: answer directly without
        # touching the invite's failure counters.
        if "invite" not in _enrollment_gates():
            self._json(400, {"error": "invite_not_allowed"})
            return
        if not invite_rate_ok("rip:" + ip, 30):
            self._json(429, {"error": "rate_limited"})
            return
        if not isinstance(invite_id, str) or not invite_id:
            self._json(400, {"error": "invite_id_required"})
            return
        if not invite_rate_ok("rinv:" + invite_id, 10):
            self._json(429, {"error": "rate_limited"})
            return
        if redeem_failures_blocked(invite_id):
            self._json(429, {"error": "invite_cooldown"})
            return

        def fail(err, code=400):
            redeem_failure_note(invite_id)
            self._json(code, {"error": err})

        with db_lock:
            inv = conn.execute(
                """SELECT secret_hash, inviter_identity, exp, max_uses, uses,
                          revoked, grant_handshake FROM invites WHERE invite_id=?""",
                (invite_id,),
            ).fetchone()
        if inv is None:
            fail("invite_not_found", 404)
            return
        secret_hash, inviter_identity, exp, max_uses, uses, revoked, gh = inv
        # v4 handshake links are handshake-only: /v1/handshakes/redeem
        # consumes them. Legacy redeem rejects them as unusable (burning a
        # link use without creating a handshake would be wrong).
        if revoked or gh or exp <= now or uses >= max_uses:
            fail("invite_unusable", 410)
            return
        try:
            secret = b64u_decode(secret_s)
        except ValueError:
            fail("bad_secret")
            return
        if not hmac.compare_digest(hashlib.sha256(secret).hexdigest(), secret_hash):
            fail("bad_secret")
            return
        try:
            pubkey = b64u_decode(pubkey_s)
        except ValueError:
            fail("bad_identity")
            return
        if len(pubkey) != 32:
            fail("bad_identity")
            return
        # R5: small-order / non-prime-order keys admit trivial signature
        # forgeries under the vendored verifier -- never enroll one.
        if not ed25519.is_valid_pubkey(pubkey):
            fail("bad_identity")
            return
        if not isinstance(proof, dict):
            fail("bad_proof")
            return
        try:
            nonce = b64u_decode(proof.get("nonce"))
            sig = b64u_decode(proof.get("signature"))
        except ValueError:
            fail("bad_proof")
            return
        if len(sig) != 64:
            fail("bad_proof")
            return
        # Consume the challenge at presentation: single-use, bound to this
        # invite. A failed signature means fetching a fresh challenge.
        nonce_s = b64u_encode(nonce)
        with db_lock:
            ch = conn.execute(
                "SELECT invite_id, expires_at, used FROM challenges WHERE nonce=?",
                (nonce_s,),
            ).fetchone()
            if (
                ch is None
                or ch[0] != invite_id
                or ch[2] != 0
                or ch[1] <= now
            ):
                ch = None
            else:
                conn.execute(
                    "UPDATE challenges SET used=1 WHERE nonce=?", (nonce_s,)
                )
                conn.commit()
        if ch is None:
            fail("bad_challenge")
            return
        msg = nonce + invite_id.encode("utf-8") + pubkey
        if not ed25519.verify(pubkey, sig, msg):
            fail("bad_proof")
            return
        # Find-or-create, KEYED BY identity, via the shared enrollment core
        # (requested_name=None: redeem always assigns a guest name). A second
        # introduction reuses the identity row -- it adds a relationship,
        # never duplicates identity.
        # NOTE: the peer-row lookup happens INSIDE the reservation
        # transaction below, never from a pre-lock read. A concurrent redeem
        # for the same identity could slip in between a pre-lock SELECT and
        # the INSERT and turn it into an IntegrityError.
        pub_b64 = b64u_encode(pubkey)
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        # Atomic reservation: revalidate the invite AND consume one use in a
        # single conditional UPDATE inside an explicit BEGIN IMMEDIATE
        # transaction that also carries the peer/token mutation. The pre-check
        # above is only a fast path; this is the authoritative gate. Two
        # concurrent redeems cannot both win: the loser's UPDATE matches zero
        # rows and gets no credentials.
        #
        # Why BEGIN IMMEDIATE and not just db_lock: the Python lock only
        # serializes threads of this process. The write lock taken by BEGIN
        # IMMEDIATE is enforced by SQLite itself, so the reservation and the
        # credential mutation are atomic even if a second process ever opens
        # this database. Either both land or neither does -- a failed peer
        # INSERT can never leave a consumed use behind.
        name = None
        with db_lock:
            now2 = time.time()  # fresh: request-start `now` may predate expiry
            try:
                if conn.in_transaction:
                    # Defensive: a previous request must never leak an open
                    # transaction on the shared connection. Discard it rather
                    # than joining it.
                    conn.rollback()
                conn.execute("BEGIN IMMEDIATE")
                cur = conn.execute(
                    """UPDATE invites SET uses = uses + 1
                       WHERE invite_id=? AND revoked=0 AND exp > ?
                         AND uses < max_uses""",
                    (invite_id, now2),
                )
                if cur.rowcount != 1:
                    conn.execute("ROLLBACK")
                    fail("invite_unusable", 410)
                    return
                name = _enroll_identity_locked(
                    pub_b64, token_hash, inviter_identity, None, now2,
                    enroll_gate="invite", enroll_ip=ip,
                )
                conn.execute("COMMIT")
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
                # A failed peer INSERT/UPDATE must never surface as a dropped
                # connection: roll back, record the failure, tell the client.
                fail("internal_error", 500)
                return
        # Cache mutation only after the transaction committed: a rolled-back
        # INSERT must never leave a ghost entry in the in-memory name set.
        peer_names.add(name)
        redeem_failure_clear(invite_id)
        inviter_name = peer_name_for_identity(inviter_identity)
        self._json(
            200,
            {
                "service_token": token,
                "identity": pub_b64,
                "display_name": name,
                "peer_name": name,
                "inviter_name": inviter_name,
                "contract_version": VERSION,
                "relay_identity": relay_identity_info(),
            },
        )

    # --- Agent self-enrollment endpoint handlers (v0.2.9) ---------------------

    def _handle_enroll_challenge(self, now):
        body = self._read_json()
        if body is None:
            body = {}
        if not isinstance(body, dict):
            self._json(400, {"error": "invalid_json"})
            return
        invite_id = body.get("invite_id")
        gates = _enrollment_gates()
        ip = self._client_ip()
        if invite_id is not None:
            # Invite gate: validate exactly like /v1/invites/challenge.
            if not isinstance(invite_id, str) or not invite_id:
                self._json(400, {"error": "invite_id_required"})
                return
            if "invite" not in gates:
                self._json(400, {"error": "invite_not_allowed"})
                return
            if not invite_rate_ok("eip:" + ip, 30) or not invite_rate_ok(
                "einv:" + invite_id, 10
            ):
                self._json(429, {"error": "rate_limited"})
                return
            with db_lock:
                row = conn.execute(
                    "SELECT exp, max_uses, uses, revoked, target_identity"
                    " FROM invites WHERE invite_id=?",
                    (invite_id,),
                ).fetchone()
            if row is None or row[4] is not None:
                # Public requests never authorize enrollment. Match unknown
                # IDs before looking at lifecycle state or creating a nonce.
                self._json(404, {"error": "invite_not_found"})
                return
            exp, max_uses, uses, revoked, _target = row
            if revoked or exp <= now or uses >= max_uses:
                # One error on purpose: don't leak which condition failed.
                self._json(410, {"error": "invite_unusable"})
                return
            nonce = secrets.token_bytes(32)
            with db_lock:
                conn.execute(
                    """INSERT INTO enroll_challenges(nonce, kind, ref, created_at,
                                                     expires_at, used)
                       VALUES(?,?,?,?,?,0)""",
                    (
                        b64u_encode(nonce),
                        "invite",
                        invite_id,
                        now,
                        now + CHALLENGE_TTL,
                    ),
                )
                conn.commit()
            self._json(
                200,
                {
                    "nonce": b64u_encode(nonce),
                    "expires_at": now + CHALLENGE_TTL,
                    "gate": "invite",
                },
            )
            return
        # No invite_id: PoW if enabled, else open, else the relay is
        # invite-only and there is nothing to challenge for.
        if not invite_rate_ok("eip:" + ip, 30):
            self._json(429, {"error": "rate_limited"})
            return
        if "pow" in gates:
            kind = "pow"
        elif "open" in gates:
            kind = "open"
        else:
            self._json(400, {"error": "invite_required"})
            return
        nonce = secrets.token_bytes(32)
        with db_lock:
            conn.execute(
                """INSERT INTO enroll_challenges(nonce, kind, ref, created_at,
                                                 expires_at, used)
                   VALUES(?,?,?,?,?,0)""",
                (b64u_encode(nonce), kind, None, now, now + CHALLENGE_TTL),
            )
            conn.commit()
        out = {
            "expires_at": now + CHALLENGE_TTL,
            "gate": kind,
        }
        if kind == "pow":
            out["challenge"] = b64u_encode(nonce)
            out["difficulty"] = _pow_difficulty()
        else:
            out["nonce"] = b64u_encode(nonce)
        self._json(200, out)

    def _handle_enroll(self, now):
        body = self._read_json()
        if not isinstance(body, dict):
            self._json(400, {"error": "invalid_json"})
            return
        invite_id = body.get("invite_id")
        pow_nonce_s = body.get("pow_nonce")
        gates = _enrollment_gates()
        ip = self._client_ip()
        # Gate resolution: exactly one must apply.
        if invite_id is not None:
            gate = "invite"
            if "invite" not in gates:
                self._json(400, {"error": "invite_not_allowed"})
                return
            if not isinstance(invite_id, str) or not invite_id:
                self._json(400, {"error": "invite_id_required"})
                return
        elif pow_nonce_s is not None:
            gate = "pow"
            if "pow" not in gates:
                self._json(400, {"error": "pow_not_allowed"})
                return
        else:
            gate = "open"
            if "open" not in gates:
                self._json(400, {"error": "enrollment_not_allowed"})
                return
        if not invite_rate_ok("enr:" + ip, 10):
            self._json(429, {"error": "rate_limited"})
            return
        if gate == "invite" and not invite_rate_ok("einv:" + invite_id, 10):
            self._json(429, {"error": "rate_limited"})
            return
        ckey = invite_id if gate == "invite" else "ip:" + ip
        if enroll_failures_blocked(ckey):
            self._json(429, {"error": "enroll_cooldown"})
            return

        def fail(err, code=400):
            enroll_failure_note(ckey)
            self._json(code, {"error": err})

        # Per-gate credential validation (mirrors redeem's strictness).
        inviter_identity = None
        if gate == "invite":
            with db_lock:
                inv = conn.execute(
                    """SELECT secret_hash, inviter_identity, exp, max_uses, uses,
                              revoked, grant_handshake FROM invites WHERE invite_id=?""",
                    (invite_id,),
                ).fetchone()
            if inv is None:
                fail("invite_not_found", 404)
                return
            secret_hash, inviter_identity, exp, max_uses, uses, revoked, gh = inv
            # v4 handshake links are handshake-only: legacy enroll must not
            # burn a link use without creating a handshake. (Fetching the
            # challenge for a v4 link is still allowed -- handshake redeem
            # consumes it.)
            if revoked or gh or exp <= now or uses >= max_uses:
                fail("invite_unusable", 410)
                return
            try:
                secret = b64u_decode(body.get("secret"))
            except ValueError:
                fail("bad_secret")
                return
            if not hmac.compare_digest(
                hashlib.sha256(secret).hexdigest(), secret_hash
            ):
                fail("bad_secret")
                return
        # Common: identity + proof shape.
        try:
            pubkey = b64u_decode(body.get("identity_pubkey"))
        except ValueError:
            fail("bad_identity")
            return
        if len(pubkey) != 32:
            fail("bad_identity")
            return
        # R5: small-order / non-prime-order keys admit trivial signature
        # forgeries under the vendored verifier -- never enroll one.
        if not ed25519.is_valid_pubkey(pubkey):
            fail("bad_identity")
            return
        proof = body.get("proof")
        if not isinstance(proof, dict):
            fail("bad_proof")
            return
        try:
            presented = b64u_decode(proof.get("nonce"))
            sig = b64u_decode(proof.get("signature"))
        except ValueError:
            fail("bad_proof")
            return
        if len(sig) != 64:
            fail("bad_proof")
            return
        # Consume the pre-enrollment challenge at presentation: single-use,
        # kind-bound (and invite-bound for the invite gate), exactly like
        # redeem consumes its challenge. A failed signature means fetching a
        # fresh challenge.
        presented_s = b64u_encode(presented)
        with db_lock:
            ch = conn.execute(
                "SELECT kind, ref, expires_at, used FROM enroll_challenges WHERE nonce=?",
                (presented_s,),
            ).fetchone()
            if (
                ch is None
                or ch[3] != 0
                or ch[2] <= now
                or ch[0] != gate
                or (gate == "invite" and ch[1] != invite_id)
            ):
                ch = None
            else:
                conn.execute(
                    "UPDATE enroll_challenges SET used=1 WHERE nonce=?",
                    (presented_s,),
                )
                conn.commit()
        if ch is None:
            fail("bad_challenge")
            return
        # Gate-specific work factor and signature message.
        if gate == "pow":
            try:
                pow_nonce = b64u_decode(pow_nonce_s)
            except ValueError:
                fail("bad_pow")
                return
            if not (1 <= len(pow_nonce) <= 64):
                fail("bad_pow")
                return
            digest = hashlib.sha256(presented + pow_nonce).digest()
            if _pow_leading_zero_bits(digest) < _pow_difficulty():
                fail("bad_pow")
                return
            msg = presented + pow_nonce + pubkey
            invited_by = "pow"
        elif gate == "open":
            msg = presented + pubkey
            invited_by = "open"
        else:
            msg = presented + invite_id.encode("utf-8") + pubkey
            invited_by = inviter_identity
        if not ed25519.verify(pubkey, sig, msg):
            fail("bad_proof")
            return
        # Enrollment: atomic find-or-create keyed by identity. The invite
        # gate additionally consumes one invite use in the same transaction;
        # the conditional UPDATE is the authoritative gate, exactly as in
        # redeem (the pre-checks above are only a fast path).
        pub_b64 = b64u_encode(pubkey)
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        requested_name = body.get("name")
        # Reserved-name enforcement lives inside _enroll_identity_locked,
        # in the same transaction as the name assignment (atomic check and
        # insert). Invite-redeem never requests a name (requested_name is
        # always None there), so no counterpart is needed.
        name = None
        with db_lock:
            now2 = time.time()  # fresh: request-start `now` may predate expiry
            try:
                if conn.in_transaction:
                    # Defensive: a previous request must never leak an open
                    # transaction on the shared connection. Discard it rather
                    # than joining it.
                    conn.rollback()
                conn.execute("BEGIN IMMEDIATE")
                if gate == "invite":
                    cur = conn.execute(
                        """UPDATE invites SET uses = uses + 1
                           WHERE invite_id=? AND revoked=0 AND exp > ?
                             AND uses < max_uses""",
                        (invite_id, now2),
                    )
                    if cur.rowcount != 1:
                        conn.execute("ROLLBACK")
                        fail("invite_unusable", 410)
                        return
                name = _enroll_identity_locked(
                    pub_b64, token_hash, invited_by, requested_name, now2,
                    enroll_gate=gate, enroll_ip=ip,
                )
                conn.execute("COMMIT")
            except _ReservedNameRejected:
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
                # Rejected before any peer row was written. The ROLLBACK
                # also undoes the invite-use consume above, so the invite
                # stays usable for a retry with a different name.
                fail("reserved_name", 403)
                return
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
                # A failed peer INSERT/UPDATE must never surface as a dropped
                # connection: roll back, record the failure, tell the client.
                fail("internal_error", 500)
                return
        # Cache mutation only after the transaction committed: a rolled-back
        # INSERT must never leave a ghost entry in the in-memory name set.
        peer_names.add(name)
        enroll_failure_clear(ckey)
        inviter_name = (
            peer_name_for_identity(inviter_identity) if gate == "invite" else None
        )
        self._json(
            200,
            {
                "service_token": token,
                "identity": pub_b64,
                "display_name": name,
                "peer_name": name,
                "inviter_name": inviter_name,
                "enrollment": gate,
                "contract_version": VERSION,
                "relay_identity": relay_identity_info(),
            },
        )

    def _handle_invite_revoke(self, peer):
        body = self._read_json()
        invite_id = body.get("invite_id") if isinstance(body, dict) else None
        if not isinstance(invite_id, str) or not invite_id:
            self._json(400, {"error": "invite_id_required"})
            return
        ident = caller_identity(peer)
        operators = relay_cfg.get("operators", []) if relay_cfg else []
        with db_lock:
            row = conn.execute(
                "SELECT inviter_identity, revoked FROM invites WHERE invite_id=?",
                (invite_id,),
            ).fetchone()
            if row is None:
                self._json(404, {"error": "invite_not_found"})
                return
            if row[0] != ident and peer not in operators:
                self._json(403, {"error": "forbidden"})
                return
            conn.execute(
                "UPDATE invites SET revoked=1 WHERE invite_id=?", (invite_id,)
            )
            conn.commit()
        self._json(200, {"invite_id": invite_id, "revoked": True})

    # --- Mutual-consent handshakes (v0.2.13) ----------------------------------
    # Consent model (spec section 2): N's authenticated+signed mint-link IS
    # N's consent (minter identity recorded from the mint record, never from
    # the display-only `by` fragment). Z's redeem creates a PENDING
    # handshake; Z's signed accept (bound to redeemer_identity AND the
    # current pair generation) activates it. Either party revokes
    # unilaterally. The relay can never create a handshake on its own
    # authority -- no backfill, no operator bypass.

    def _resolve_handshake_peer(self, value):
        """Resolve a peer reference (peer name or identity string) to
        (identity, name). Returns (None, None) when unknown. Callers must
        NOT hold db_lock."""
        if not isinstance(value, str) or not value:
            return None, None
        with db_lock:
            row = conn.execute(
                "SELECT name, identity_pubkey FROM peers WHERE name=?", (value,)
            ).fetchone()
            if row:
                return (row[1] if row[1] else row[0]), row[0]
            row = conn.execute(
                "SELECT name FROM peers WHERE identity_pubkey=?", (value,)
            ).fetchone()
            if row:
                return value, row[0]
        return None, None

    def _handle_handshake_mint(self, peer, now, public_request=False):
        body = self._read_json()
        if not isinstance(body, dict):
            self._json(400, {"error": "invalid_json"})
            return
        max_uses = body.get("max_uses", 1)
        exp_days = body.get("exp_days", 7)
        note = body.get("note")
        target = None
        if public_request:
            target = body.get("target_identity")
            try:
                canonical = _normalize_pubkey_input(target)
            except (ValueError, TypeError, AttributeError):
                canonical = None
            with db_lock:
                known = conn.execute(
                    "SELECT 1 FROM peers WHERE identity_pubkey=?", (target,)
                ).fetchone() if isinstance(target, str) else None
            if canonical is None or target != canonical or not known:
                self._json(400, {"error": "known_target_identity_required"})
                return
            if target == caller_identity(peer):
                self._json(400, {"error": "cannot_handshake_self"})
                return
            if max_uses != 1 or "k" in body:
                self._json(400, {"error": "public_request_single_target_only"})
                return
        # E2EE: stored on the invite row, copied at redeem, ANDed with
        # the redeemer's advertisement at accept.
        minter_enc_v = body.get("enc_v", 0)
        if not _is_strict_enc_v(minter_enc_v):
            self._json(400, {"error": "bad_enc_v"})
            return
        if isinstance(max_uses, bool) or not isinstance(max_uses, int):
            self._json(400, {"error": "bad_max_uses"})
            return
        if isinstance(exp_days, bool) or not isinstance(exp_days, (int, float)):
            self._json(400, {"error": "bad_exp_days"})
            return
        if note is not None and (
            not isinstance(note, str) or len(note) > HANDSHAKE_NOTE_MAX
        ):
            self._json(400, {"error": "bad_note"})
            return
        exp_secs = exp_days * 86400.0
        if not (1 <= max_uses <= INVITE_MAX_USES_CAP):
            self._json(400, {"error": "bad_max_uses"})
            return
        if not (INVITE_MIN_EXPIRY <= exp_secs <= INVITE_MAX_EXPIRY):
            self._json(400, {"error": "bad_exp_days"})
            return
        ident = caller_identity(peer)
        # Tier cap (spec section 9): count ESTABLISHED (active) handshakes
        # in both directions at mint time. Pending handshakes don't count.
        # At-cap response names the existing handshakes so the peer can
        # revoke to make room.
        if HS_MAX_PER_IDENTITY > 0 and (
            _active_handshake_count(ident) >= HS_MAX_PER_IDENTITY
        ):
            self._json(
                403,
                {
                    "error": "handshake_cap_reached",
                    "handshakes": _active_handshake_list(ident),
                },
            )
            return
        link_id = str(uuid.uuid4())
        secret = None if public_request else secrets.token_bytes(32)
        exp = now + exp_secs
        # Same atomic quota discipline as /v1/invites/mint: quota check and
        # insert inside one BEGIN IMMEDIATE so concurrent mints cannot both
        # pass. Handshake links share the invite quota pool (one table).
        # A link IS an invite row with grant_handshake=1; the minter's
        # identity is recorded in the mint record at creation.
        with db_lock:
            now2 = time.time()
            try:
                if conn.in_transaction:
                    conn.rollback()
                conn.execute("BEGIN IMMEDIATE")
                active = conn.execute(
                    """SELECT COUNT(*) FROM invites
                       WHERE inviter_identity=? AND revoked=0 AND exp > ?
                         AND uses < max_uses""",
                    (ident, now2),
                ).fetchone()[0]
                if active >= INVITE_QUOTA_PER_IDENTITY:
                    conn.execute("ROLLBACK")
                    self._json(429, {"error": "invite_quota_exceeded"})
                    return
                conn.execute(
                    """INSERT INTO invites(invite_id, secret_hash, inviter_identity,
                                           exp, max_uses, uses, revoked, created_at,
                                           grant_handshake, note, minter_enc_v,
                                           target_identity)
                       VALUES(?,?,?,?,?,0,0,?,1,?,?,?)""",
                    (
                        link_id,
                        "" if public_request else hashlib.sha256(secret).hexdigest(),
                        ident,
                        exp,
                        max_uses,
                        now2,
                        note,
                        minter_enc_v,
                        target,
                    ),
                )
                conn.execute("COMMIT")
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
                raise
        if public_request:
            self._json(200, {
                "link": relay_base_url(relay_cfg).rstrip("/") + "/join/" + link_id,
                "link_id": link_id, "exp": exp, "max_uses": 1,
                "mode": "public_request", "target_identity": target,
                "inviter_identity": ident,
            })
            return
        link = _build_handshake_link(
            relay_base_url(relay_cfg), link_id, secret, peer, exp, max_uses
        )
        self._json(
            200,
            {"link": link, "link_id": link_id, "exp": exp, "max_uses": max_uses},
        )

    def _handle_handshake_redeem(self, now, request_peer=None):
        body = self._read_json()
        if not isinstance(body, dict):
            self._json(400, {"error": "invalid_json"})
            return
        h = body.get("h")
        k = body.get("k")
        if not isinstance(h, str) or not h:
            self._json(400, {"error": "link_id_required"})
            return
        if request_peer is not None and ("k" in body or "requested_name" in body):
            self._json(400, {"error": "public_request_no_enrollment"})
            return
        if request_peer is None and (not isinstance(k, str) or not k):
            self._json(400, {"error": "claim_required"})
            return
        # Optional requested peer name (v0.2.15): the redeemer may choose
        # their own name instead of receiving a guest- assignment. Invalid
        # names are rejected here, not silently replaced.
        requested_name = body.get("requested_name")
        if requested_name is not None and not _valid_requested_name(requested_name):
            self._json(400, {"error": "bad_requested_name"})
            return
        ip = self._client_ip()
        # Source limits also apply to early public-record rejection.
        if not invite_rate_ok("rip:" + ip, 30):
            self._json(429, {"error": "rate_limited"})
            return
        if request_peer is None:
            with db_lock:
                public = conn.execute(
                    "SELECT target_identity FROM invites WHERE invite_id=?", (h,)
                ).fetchone()
            if public is not None and public[0] is not None:
                # Public UUIDs aren't secrets: unauthenticated legacy
                # probes must not poison the intended target's link budget.
                self._json(403, {"error": "link_unusable"})
                return
        # Untrusted legacy IDs are strings; authenticated-public budgets are
        # tuples. No chosen string on either legacy redeem route can collide.
        budget = h if request_peer is None else ("public", request_peer, h)
        rate_budget = "rinv:" + h if request_peer is None else ("rinv-public", request_peer, h)
        if not invite_rate_ok(rate_budget, 10):
            self._json(429, {"error": "rate_limited"})
            return
        if redeem_failures_blocked(budget):
            self._json(429, {"error": "invite_cooldown"})
            return

        def link_fail():
            # IDENTICAL shape for every link-validity failure: unknown id,
            # bad claim secret, expired/exhausted/revoked link,
            # non-handshake (v3) link, and previously-revoked pair. No
            # enumeration oracle. The claim secret k is never logged and
            # never appears in error text.
            redeem_failure_note(budget)
            self._json(403, {"error": "link_unusable"})

        # Optional authentication: an already-enrolled caller redeems
        # authenticated (bearer + signature). No Authorization header =>
        # fresh enrollment inline below.
        peer = request_peer
        if request_peer is None and self.headers.get("Authorization"):
            peer = self._require_auth()
            if peer is None:
                return
        # Fast-path link validation. The single-UPDATE use-count inside
        # the transaction below is the authoritative gate.
        with db_lock:
            inv = conn.execute(
                """SELECT secret_hash, inviter_identity, exp, max_uses, uses,
                          revoked, grant_handshake, minter_enc_v, target_identity
                   FROM invites WHERE invite_id=?""",
                (h,),
            ).fetchone()
        if inv is None:
            link_fail()
            return
        secret_hash, minter, exp, max_uses, uses, revoked, gh, minter_enc_v, target = inv
        minter_enc_v = minter_enc_v or 0
        # NOTE: the use-count is deliberately NOT checked here. A retry
        # of a live pending whose link is at max_uses (the final-use
        # case) must reach the idempotency branch inside the transaction
        # below and return the same row -- not 403. Exhaustion is
        # enforced authoritatively by the atomic UPDATE's
        # uses < max_uses predicate, AFTER the idempotency check.
        if gh != 1 or revoked or exp <= now:
            link_fail()
            return
        if request_peer is not None:
            if target is None or caller_identity(request_peer) != target:
                link_fail()
                return
        else:
            if target is not None:
                link_fail()
                return
            try:
                secret = b64u_decode(k)
            except ValueError:
                link_fail()
                return
            if not hmac.compare_digest(hashlib.sha256(secret).hexdigest(), secret_hash):
                link_fail()
                return
        # N's identity comes from the mint record. The `by` fragment field
        # never reaches the server (URL fragments are client-side) and is
        # display-only by construction: a forged `by` cannot change who Z
        # handshakes with.
        enroll = None  # (pub_b64, gate, invited_by) when enrolling inline
        if peer is not None:
            redeemer = caller_identity(peer)
        else:
            # Fresh enrollment inline (spec section 3): PoW on open relays,
            # the link itself as the invite grant on invite-gated ones.
            gates = _enrollment_gates()
            if "invite" in gates:
                gate = "invite"
            elif "pow" in gates:
                gate = "pow"
            elif "open" in gates:
                gate = "open"
            else:
                self._json(400, {"error": "enrollment_not_allowed"})
                return
            # v0.2.17: the redeem may carry an optional `pubkey` field (raw
            # 43-char b64u or PEM SPKI, same normalization as
            # /v1/register-key) as an alternative to `identity_pubkey`.
            # Either way the key is bound at enrollment -- new peers enroll
            # with signing ready in one flow. If BOTH are present they must
            # agree (fail closed on mismatch -- silently preferring one
            # would mask a confused client or a key-substitution attempt).
            supplied = body.get("pubkey")
            legacy = body.get("identity_pubkey")
            pub_b64 = None
            if isinstance(supplied, str) and supplied.strip():
                try:
                    pub_b64 = _normalize_pubkey_input(supplied)
                except ValueError:
                    self._json(400, {"error": "bad_identity"})
                    return
            if (isinstance(legacy, str) and legacy.strip()):
                try:
                    legacy_b64 = _normalize_pubkey_input(legacy)
                except ValueError:
                    self._json(400, {"error": "bad_identity"})
                    return
                if pub_b64 is not None and legacy_b64 != pub_b64:
                    self._json(400, {"error": "key_mismatch"})
                    return
                pub_b64 = legacy_b64
            if pub_b64 is None:
                self._json(400, {"error": "bad_identity"})
                return
            pubkey = b64u_decode(pub_b64)
            proof = body.get("proof")
            if not isinstance(proof, dict):
                self._json(400, {"error": "bad_proof"})
                return
            try:
                presented = b64u_decode(proof.get("nonce"))
                sig = b64u_decode(proof.get("signature"))
            except ValueError:
                self._json(400, {"error": "bad_proof"})
                return
            if len(sig) != 64:
                self._json(400, {"error": "bad_proof"})
                return
            # Consume the pre-enrollment challenge at presentation:
            # single-use, kind-bound (and invite-bound for the invite gate).
            # The handshake flow reuses /v1/enroll/challenge: for the invite
            # gate the client fetches it with {"invite_id": h}.
            presented_s = b64u_encode(presented)
            with db_lock:
                ch = conn.execute(
                    "SELECT kind, ref, expires_at, used FROM enroll_challenges"
                    " WHERE nonce=?",
                    (presented_s,),
                ).fetchone()
                ok = (
                    ch is not None
                    and ch[3] == 0
                    and ch[2] > now
                    and ch[0] == gate
                    and (gate != "invite" or ch[1] == h)
                )
                if ok:
                    conn.execute(
                        "UPDATE enroll_challenges SET used=1 WHERE nonce=?",
                        (presented_s,),
                    )
                    conn.commit()
            if not ok:
                self._json(400, {"error": "bad_challenge"})
                return
            if gate == "pow":
                try:
                    pow_nonce = b64u_decode(body.get("pow_nonce"))
                except ValueError:
                    self._json(400, {"error": "bad_pow"})
                    return
                if not (1 <= len(pow_nonce) <= 64):
                    self._json(400, {"error": "bad_pow"})
                    return
                digest = hashlib.sha256(presented + pow_nonce).digest()
                if _pow_leading_zero_bits(digest) < _pow_difficulty():
                    self._json(400, {"error": "bad_pow"})
                    return
                msg = presented + pow_nonce + pubkey
                invited_by = "pow"
            elif gate == "open":
                msg = presented + pubkey
                invited_by = "open"
            else:
                msg = presented + h.encode("utf-8") + pubkey
                invited_by = minter
            if not ed25519.verify(pubkey, sig, msg):
                self._json(400, {"error": "bad_proof"})
                return
            redeemer = pub_b64
            enroll = (pub_b64, gate, invited_by)
        if redeemer == minter:
            self._json(400, {"error": "cannot_handshake_self"})
            return
        a, b = _hs_pair(minter, redeemer)
        # All paths -- active, live pending, revoked, lapsed pending, new
        # pair -- go through the single transaction below, which rechecks
        # the row inside the write lock. Idempotent retries consume no
        # link use and never extend pending_expires_at.
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        name = None
        with db_lock:
            now2 = time.time()  # fresh: request-start `now` may predate expiry
            try:
                if conn.in_transaction:
                    conn.rollback()
                conn.execute("BEGIN IMMEDIATE")
                if request_peer is not None and not conn.execute(
                    "SELECT 1 FROM invites WHERE invite_id=? AND revoked=0"
                    " AND exp>? AND target_identity=? AND grant_handshake=1",
                    (h, now2, redeemer),
                ).fetchone():
                    conn.execute("ROLLBACK")
                    link_fail()
                    return
                if conn.execute(
                    "SELECT 1 FROM link_revocations WHERE link_id=?"
                    " AND a_identity=? AND b_identity=?",
                    (h, a, b),
                ).fetchone():
                    # This exact pair revoked a handshake created by THIS
                    # link: the link can never resurrect it. The pair may
                    # still re-consent over a NEW link. Identical error
                    # shape -- no enumeration oracle.
                    conn.execute("ROLLBACK")
                    link_fail()
                    return
                # Authoritative recheck inside the write lock: a concurrent
                # redeem may have created the row after our fast path.
                hs2 = conn.execute(
                    "SELECT %s FROM handshakes WHERE a_identity=? AND b_identity=?"
                    % _HS_COLS,
                    (a, b),
                ).fetchone()
                replace_pending = (
                    request_peer is not None and hs2 is not None
                    and hs2[0] == "pending" and hs2[5] != h
                )
                if hs2 is not None and (
                    hs2[0] == "active"
                    or (
                        hs2[0] == "pending"
                        and hs2[7] == redeemer
                        and hs2[2] is not None
                        and hs2[2] > now2
                        # The public backing request h was validated above
                        # under this same write lock. A different request is
                        # a new ceremony, never an idempotent retry of it.
                        and (request_peer is None or hs2[5] == h)
                    )
                ):
                    # Idempotent no-op: active, or a live pending owned by
                    # this redeemer. No link use is consumed, and the
                    # ORIGINAL pending_expires_at is kept. Distinct public
                    # requests instead refresh the ceremony below, including
                    # its direction, advertisements and consent generation.
                    #
                    # Fix A repair rev3 (2026-10-12, Zari 1635ebf7): v4
                    # capable-link upgrade with EXPLICIT CANONICAL row-class
                    # selection. The class is READ from
                    # handshakes.provenance (hs2[11]) -- never inferred
                    # from via_link_id. An invitation row alone cannot
                    # override the row's explicit class.
                    #
                    #   'ceremony': the pair was formed through the invite
                    #       ceremony. The NEW link issuer's advertisement
                    #       lands ONLY in the issuer's ORIGINAL ceremony
                    #       slot, derived from retained original provenance
                    #       (invites.inviter_identity via hs2[5]
                    #       via_link_id) -- never from sorted identity
                    #       order. Missing invite row, NULL via_link_id,
                    #       inviter not party to the pair, or new issuer
                    #       not party to the pair -> fail closed.
                    #   'operator-attested': the pair was established by
                    #       operator action. Sorted identity order defines
                    #       the slots (mirrors the advertise endpoint) --
                    #       the validated established actor mapping.
                    #       Contradictory ceremony evidence (via_link_id
                    #       NOT NULL) -> fail closed: operator slots are
                    #       never reinterpreted as ceremony roles.
                    #   anything else (NULL, unknown, conflicting class):
                    #       fail closed -- no upgrade, the ordinary
                    #       idempotent no-op stands, no mutation.
                    #
                    # This keeps ordinary accept's redeemer_identity=NULL
                    # (cleared at accept) from ever being misread as a
                    # role, and keeps both capable assertions requiring
                    # BOTH actors' original-slot advertisements.
                    if hs2[0] == "active" and minter_enc_v == 1 and hs2[8] == 0:
                        prov = hs2[11]  # canonical class, read not inferred
                        new_minter_enc_v = None
                        new_redeemer_enc_v = None
                        if prov == "ceremony":
                            via = hs2[5]
                            pinv = (
                                conn.execute(
                                    "SELECT inviter_identity FROM invites"
                                    " WHERE invite_id=?",
                                    (via,),
                                ).fetchone()
                                if via is not None
                                else None
                            )
                            if pinv is not None and pinv[0] in (a, b):
                                # Original roles: the inviter holds the
                                # minter slot; the other party the redeemer
                                # slot. The new issuer's ad lands in the
                                # issuer's OWN original slot; the other
                                # slot is preserved.
                                orig_minter = pinv[0]
                                if minter == orig_minter:
                                    new_minter_enc_v = 1
                                    new_redeemer_enc_v = hs2[10] or 0
                                elif minter == (b if orig_minter == a else a):
                                    new_minter_enc_v = hs2[9] or 0
                                    new_redeemer_enc_v = 1
                                # else: new issuer not party to the pair ->
                                # no upgrade
                            # else: missing/NULL/conflicting ceremony
                            # evidence -> fail closed (no upgrade below)
                        elif prov == "operator-attested":
                            if hs2[5] is None:
                                # No ceremony evidence: sorted identity
                                # order defines the slots (mirrors the
                                # advertise endpoint). ONLY here is sorted
                                # mapping used.
                                if minter == a:
                                    new_minter_enc_v = 1
                                    new_redeemer_enc_v = hs2[10] or 0
                                elif minter == b:
                                    new_minter_enc_v = hs2[9] or 0
                                    new_redeemer_enc_v = 1
                            # else: contradictory ceremony evidence on an
                            # operator-attested row -> fail closed. Never
                            # reinterpret operator slots as ceremony roles.
                        # else: unknown/missing/conflicting class ->
                        # fail closed, no upgrade
                        if new_minter_enc_v is not None:
                            new_enc_capable = 1 if (new_minter_enc_v == 1 and new_redeemer_enc_v == 1) else 0
                            conn.execute(
                                """UPDATE handshakes
                                   SET minter_enc_v=?, redeemer_enc_v=?,
                                       enc_capable=?, last_activity=?
                                   WHERE a_identity=? AND b_identity=?""",
                                (new_minter_enc_v, new_redeemer_enc_v,
                                 new_enc_capable, now2, a, b),
                            )
                    if enroll is not None:
                        # Inline-enrollment retry (proof-of-key verified
                        # above, so this is the key holder, not an
                        # impersonator): rotate the token so the returned
                        # service_token works.
                        name = _enroll_identity_locked(
                            enroll[0],
                            token_hash,
                            enroll[2],
                            requested_name,
                            now2,
                            enroll_gate=enroll[1],
                            enroll_ip=ip,
                        )
                elif hs2 is not None and not (
                    hs2[0] == "revoked"
                    or (
                        hs2[0] == "pending"
                        and (hs2[2] is None or hs2[2] <= now2 or replace_pending)
                    )
                ):
                    conn.execute("ROLLBACK")
                    link_fail()
                    return
                else:
                    generation = hs2[6] if hs2 is not None else 0
                    if replace_pending:
                        if generation >= 2**63 - 1:
                            conn.execute("ROLLBACK")
                            self._json(409, {"error": "generation_exhausted"})
                            return
                        # A previously issued accept must not consent to the
                        # replacement request, even in the same direction.
                        generation += 1
                    # The single-UPDATE atomic pattern
                    # (INVITE_RACE_FIX_v0.2.6): revalidate the link AND
                    # consume one use in one statement. Proceed only if
                    # exactly one row was updated -- concurrent redeems
                    # against max_uses=N yield exactly N successes.
                    cur = conn.execute(
                        """UPDATE invites SET uses = uses + 1
                           WHERE invite_id=? AND revoked=0 AND exp > ?
                             AND uses < max_uses AND grant_handshake=1""",
                        (h, now2),
                    )
                    if cur.rowcount != 1:
                        conn.execute("ROLLBACK")
                        link_fail()
                        return
                    if enroll is not None:
                        # Find-or-create keyed by identity, in the same
                        # transaction as the use-count.
                        name = _enroll_identity_locked(
                            enroll[0],
                            token_hash,
                            enroll[2],
                            requested_name,
                            now2,
                            enroll_gate=enroll[1],
                            enroll_ip=ip,
                        )
                    pending_exp = now2 + HANDSHAKE_PENDING_WINDOW
                    if target is not None:
                        pending_exp = min(exp, pending_exp)
                    expires_at = (
                        now2 + HS_EXPIRY_DAYS * 86400.0
                        if HS_EXPIRY_DAYS > 0
                        else None
                    )
                    if hs2 is None:
                        conn.execute(
                            """INSERT INTO handshakes(a_identity, b_identity, status,
                                                      created_at, pending_expires_at,
                                                      expires_at, last_activity,
                                                      via_link_id, redeemer_identity,
                                                      generation, minter_enc_v,
                                                      provenance)
                               VALUES(?,?,'pending',?,?,?,?,?,?,0,?,'ceremony')""",
                            (a, b, now2, pending_exp, expires_at, now2, h,
                             redeemer, minter_enc_v),
                        )
                    else:
                        # Revoked/lapsed or replaced public pending: fresh
                        # consent. Replacement bumps generation so old accepts
                        # cannot land on a new request. Never reset it.
                        # The minter's E2EE advertisement refreshes from the
                        # new link; the pair's capability recomputes at
                        # accept.
                        conn.execute(
                            """UPDATE handshakes
                               SET status='pending', created_at=?,
                                   pending_expires_at=?, expires_at=?,
                                   last_activity=?, via_link_id=?,
                                   redeemer_identity=?, minter_enc_v=?,
                                   enc_capable=0, redeemer_enc_v=0,
                                   provenance='ceremony', generation=?
                               WHERE a_identity=? AND b_identity=?""",
                            (now2, pending_exp, expires_at, now2, h, redeemer,
                             minter_enc_v, generation, a, b),
                        )
                conn.execute("COMMIT")
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
                redeem_failure_note(budget)
                self._json(500, {"error": "internal_error"})
                return
        # Cache mutation only after the transaction committed.
        if name is not None:
            peer_names.add(name)
        redeem_failure_clear(budget)
        with db_lock:
            hs3 = conn.execute(
                "SELECT %s FROM handshakes WHERE a_identity=? AND b_identity=?"
                % _HS_COLS,
                (a, b),
            ).fetchone()
        out = _hs_public(a, b, hs3)
        out.update(
            {
                "minter_identity": minter,
                "minter_name_hint": peer_name_for_identity(minter),
            }
        )
        if enroll is not None:
            out.update(
                {
                    "service_token": token,
                    "identity": enroll[0],
                    "display_name": name,
                    "peer_name": name,
                    "enrollment": enroll[1],
                    "contract_version": VERSION,
                    "relay_identity": relay_identity_info(),
                }
            )
        self._json(200, out)

    def _handle_handshake_accept(self, peer, now):
        body = self._read_json()
        hid = body.get("handshake_id") if isinstance(body, dict) else None
        # E2EE: the redeemer's encryption-capability advertisement. Optional;
        # absent means "no change" (old clients keep working).
        redeemer_enc_v = body.get("enc_v") if isinstance(body, dict) else None
        if redeemer_enc_v is not None and not _is_strict_enc_v(redeemer_enc_v):
            self._json(400, {"error": "bad_enc_v"})
            return
        parsed = _parse_hs_id(hid)
        if parsed is None:
            self._json(400, {"error": "bad_handshake_id"})
            return
        a, b, gen = parsed
        me = caller_identity(peer)
        if me != a and me != b:
            # Not my handshake: indistinguishable from missing.
            self._json(404, {"error": "handshake_not_found"})
            return
        row = None
        accepted = False
        with db_lock:
            now2 = time.time()
            try:
                if conn.in_transaction:
                    conn.rollback()
                conn.execute("BEGIN IMMEDIATE")
                # E2EE: the minter's advertisement was stored at redeem.
                # enc_capable is the AND of both advertisements.
                mrow = conn.execute(
                    "SELECT minter_enc_v FROM handshakes"
                    " WHERE a_identity=? AND b_identity=?",
                    (a, b),
                ).fetchone()
                minter_enc_v = (mrow[0] or 0) if mrow else 0
                new_redeemer_enc_v = (
                    redeemer_enc_v if redeemer_enc_v is not None else 0
                )
                new_enc_capable = minter_enc_v & new_redeemer_enc_v
                # Guarded atomic accept: pending, unexpired on the SERVER
                # clock, signed by the recorded redeemer, and bound to the
                # CURRENT pair generation. An expired (or stale-generation)
                # accept is denied HERE, atomically -- the row never flips.
                # Never bound to the display-only `by` link field.
                cur = conn.execute(
                    """UPDATE handshakes
                       SET status='active', pending_expires_at=NULL,
                           redeemer_identity=NULL, last_activity=?,
                           redeemer_enc_v=?, enc_capable=?
                       WHERE a_identity=? AND b_identity=?
                         AND status='pending' AND redeemer_identity=?
                         AND pending_expires_at > ? AND generation=?
                         AND NOT EXISTS (
                             SELECT 1 FROM invites i WHERE i.invite_id=via_link_id
                             AND i.target_identity IS NOT NULL
                             AND (i.revoked!=0 OR i.exp<=? OR i.target_identity!=?)
                         )""",
                    (now2, new_redeemer_enc_v, new_enc_capable,
                     a, b, me, now2, gen, now2, me),
                )
                if cur.rowcount == 1:
                    accepted = True
                row = conn.execute(
                    "SELECT %s FROM handshakes WHERE a_identity=? AND b_identity=?"
                    % _HS_COLS,
                    (a, b),
                ).fetchone()
                # Idempotent re-accept upgrade: an already-active pair whose
                # ESTABLISHED redeemer re-accepts WITH an enc_v advertisement
                # gets its capability recomputed -- no re-handshake needed
                # to upgrade to encrypted. Absent enc_v leaves the row
                # untouched.
                #
                # Fix A re-accept repair (2026-10-12, Zari c9b14c02): the
                # write is bound to canonical ownership, read from the
                # row's EXPLICIT handshakes.provenance class (row[11]) --
                # never from which authenticated party happens to call.
                #   'ceremony': the inviter (via_link_id ->
                #       invites.inviter_identity) holds the minter slot, so
                #       the other pair party is the established redeemer.
                #       Missing invite row, NULL via_link_id, or inviter not
                #       party to the pair -> fail closed.
                #   'operator-attested' (via_link_id NULL only): sorted
                #       identity order defines the slots (mirrors the
                #       advertise endpoint) -- b holds the redeemer slot.
                #       Contradictory ceremony evidence (via_link_id NOT
                #       NULL) -> fail closed.
                #   anything else (NULL, unknown, conflicting class):
                #       fail closed.
                # Fail closed = no mutation; the idempotent 200 below
                # returns the row unchanged.
                if (not accepted and row is not None and row[0] == "active"
                        and row[6] == gen and redeemer_enc_v is not None):
                    prov = row[11]  # canonical class, read not inferred
                    established_redeemer = None
                    if prov == "ceremony":
                        via = row[5]
                        pinv = (
                            conn.execute(
                                "SELECT inviter_identity FROM invites"
                                " WHERE invite_id=?",
                                (via,),
                            ).fetchone()
                            if via is not None
                            else None
                        )
                        if pinv is not None and pinv[0] in (a, b):
                            # Original roles: the inviter holds the minter
                            # slot; the other party is the established
                            # redeemer.
                            established_redeemer = b if pinv[0] == a else a
                        # else: missing/NULL/conflicting ceremony
                        # evidence -> fail closed
                    elif prov == "operator-attested":
                        if row[5] is None:
                            # No ceremony evidence: sorted identity order
                            # defines the slots (mirrors the advertise
                            # endpoint). ONLY here is sorted mapping used.
                            established_redeemer = b
                        # else: contradictory ceremony evidence on an
                        # operator-attested row -> fail closed. Never
                        # reinterpret operator slots as ceremony roles.
                    # else: unknown/missing/conflicting class ->
                    # fail closed
                    if (established_redeemer is not None
                            and me == established_redeemer):
                        cur2 = conn.execute(
                            """UPDATE handshakes
                               SET redeemer_enc_v=?, enc_capable=?, last_activity=?
                               WHERE a_identity=? AND b_identity=?
                                 AND status='active'""",
                            (redeemer_enc_v, minter_enc_v & redeemer_enc_v,
                             now2, a, b),
                        )
                        if cur2.rowcount == 1:
                            row = conn.execute(
                                "SELECT %s FROM handshakes WHERE a_identity=? AND b_identity=?"
                                % _HS_COLS,
                                (a, b),
                            ).fetchone()
                conn.execute("COMMIT")
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
                raise
        if accepted:
            self._json(200, _hs_public(a, b, row))
            return
        # The guarded UPDATE missed: interpret why. Status first: a
        # revoked row reports handshake_revoked regardless of the id's
        # generation; a stale id against a live row reports
        # stale_generation so replays can never land post-revoke.
        if row is None:
            self._json(404, {"error": "handshake_not_found"})
            return
        if row[0] == "active":
            if row[6] != gen:
                self._json(409, {"error": "stale_generation"})
                return
            # Idempotent: accepting an already-active handshake returns it.
            self._json(200, _hs_public(a, b, row))
            return
        if row[0] == "revoked":
            self._json(410, {"error": "handshake_revoked"})
            return
        # Pending.
        if row[6] != gen:
            # Stale generation: the pair's handshake was revoked and the
            # generation bumped since this id was issued. A replayed (or
            # re-signed) accept for the pre-revoke pending must not land
            # on the post-revoke row.
            self._json(409, {"error": "stale_generation"})
            return
        if row[7] != me:
            # Only the redeeming party (Z) can accept a pending
            # handshake. N cannot accept its own link -- N already
            # consented at mint.
            self._json(403, {"error": "not_redeemer"})
            return
        # Redeemer + current generation, but the deadline lapsed on
        # the server clock.
        self._json(410, {"error": "handshake_expired"})

    def _handle_handshake_advertise(self, peer, now):
        # POST /v1/handshakes/advertise -- in-place E2EE capability
        # advertisement for an ACTIVE pair.
        #
        # Lets EITHER owner advertise their OWN enc_v in place, recomputing
        # enc_capable as the AND of both advertisements. No pair is
        # replaced, revoked, or recreated; no identity rotates; status,
        # generation, identities, created_at, and pending mail are
        # preserved.
        #
        # Provenance-aware own-slot mapping (the relay maps caller->slot;
        # the caller never names a slot, so advertising another owner's
        # slot is impossible):
        # - Invite-backed pairs: the invite's inviter_identity holds the
        #   minter slot; the other party holds the redeemer slot.
        # - Operator-attested pairs (no invite row): a_identity
        #   (lexicographically smaller, per _hs_pair ordering) holds the
        #   minter slot; b_identity holds the redeemer slot. Deterministic,
        #   derived from the pair row itself; no invite is manufactured.
        #
        # Absent enc_v is a no-change read (old clients keep working).
        body = self._read_json()
        hid = body.get("handshake_id") if isinstance(body, dict) else None
        enc_v = body.get("enc_v") if isinstance(body, dict) else None
        # Strict validation BEFORE any DB work: type(v) is int excludes
        # bool AND float (1.0 == 1 passes value equality but 1.0 & 1
        # raises TypeError at the bitwise AND below).
        if enc_v is not None and not _is_strict_enc_v(enc_v):
            self._json(400, {"error": "bad_enc_v"})
            return
        parsed = _parse_hs_id(hid)
        if parsed is None:
            self._json(400, {"error": "bad_handshake_id"})
            return
        a, b, gen = parsed
        me = caller_identity(peer)
        if me != a and me != b:
            # Not my handshake: indistinguishable from missing.
            self._json(404, {"error": "handshake_not_found"})
            return
        with db_lock:
            now2 = time.time()
            try:
                if conn.in_transaction:
                    conn.rollback()
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute(
                    "SELECT status, generation, via_link_id,"
                    " minter_enc_v, redeemer_enc_v FROM handshakes"
                    " WHERE a_identity=? AND b_identity=?",
                    (a, b),
                ).fetchone()
                if row is None or row[0] != "active":
                    # Missing, pending, or revoked: never touch.
                    conn.execute("ROLLBACK")
                    self._json(404, {"error": "handshake_not_found"})
                    return
                if row[1] != gen:
                    # Stale generation: a replayed advertisement for a
                    # pre-revoke pair must never land on the post-revoke
                    # row.
                    conn.execute("ROLLBACK")
                    self._json(409, {"error": "stale_generation"})
                    return
                inv = conn.execute(
                    "SELECT inviter_identity FROM invites WHERE invite_id=?",
                    (row[2],),
                ).fetchone()
                if inv is not None:
                    slot = "minter" if me == inv[0] else "redeemer"
                else:
                    # Operator-attested: sorted identity order defines the
                    # slots. Deterministic; no invite manufactured.
                    slot = "minter" if me == a else "redeemer"
                if enc_v is None:
                    conn.execute("ROLLBACK")
                    hs = conn.execute(
                        "SELECT %s FROM handshakes"
                        " WHERE a_identity=? AND b_identity=?" % _HS_COLS,
                        (a, b),
                    ).fetchone()
                    self._json(200, _hs_public(a, b, hs))
                    return
                if slot == "minter":
                    new_minter, new_redeemer = enc_v, (row[4] or 0)
                else:
                    new_minter, new_redeemer = (row[3] or 0), enc_v
                new_capable = new_minter & new_redeemer
                cur = conn.execute(
                    """UPDATE handshakes
                       SET minter_enc_v=?, redeemer_enc_v=?, enc_capable=?,
                           last_activity=?
                       WHERE a_identity=? AND b_identity=?
                         AND status='active' AND generation=?""",
                    (new_minter, new_redeemer, new_capable, now2,
                     a, b, gen),
                )
                if cur.rowcount != 1:
                    conn.execute("ROLLBACK")
                    self._json(409, {"error": "stale_generation"})
                    return
                hs = conn.execute(
                    "SELECT %s FROM handshakes"
                    " WHERE a_identity=? AND b_identity=?" % _HS_COLS,
                    (a, b),
                ).fetchone()
                conn.execute("COMMIT")
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
                raise
        self._json(200, _hs_public(a, b, hs))

    def _handle_handshake_revoke(self, peer, now):
        # Unilateral revocation, effective immediately. Either party may
        # revoke; the relay never needs both.
        #
        # DELIVERY BOUNDARY (documented limits): revocation cannot retract
        # plaintext already written to the client's socket, and it cannot
        # un-ack an ack. Everything else is dead-lettered with reason
        # handshake_revoked and is NEVER delivered after revoke-commit --
        # INCLUDING messages collected (fetched) but never acked. Rationale:
        # since v0.2.16 "collected" is telemetry, not a delivery guarantee
        # (a poll response can drop mid-read; only ack retires a message),
        # so collected-but-unacked mail may never have reached the client
        # and must die with the consent. A poll response already in flight
        # at revoke-commit may still carry bytes fetched pre-revoke; that is
        # the physical limit, same as acked mail. No NEW fetch after
        # revoke-commit can return the pair's mail. The status flip, the
        # revocation memory, and the dead-letter sweep happen in ONE atomic
        # transaction: a send racing the revoke either fully precedes it
        # (its message is then dead-lettered) or fully follows it (the send
        # gate 403s). Fail closed at the boundary.
        body = self._read_json()
        target = body.get("peer") if isinstance(body, dict) else None
        t_ident, t_name = self._resolve_handshake_peer(target)
        if t_ident is None:
            self._json(404, {"error": "unknown_peer"})
            return
        me = caller_identity(peer)
        if t_ident == me:
            self._json(400, {"error": "cannot_revoke_self"})
            return
        a, b = _hs_pair(me, t_ident)
        new_id = None
        with db_lock:
            now2 = time.time()
            try:
                if conn.in_transaction:
                    conn.rollback()
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute(
                    "SELECT status, via_link_id, generation FROM handshakes"
                    " WHERE a_identity=? AND b_identity=?",
                    (a, b),
                ).fetchone()
                if row is None:
                    conn.execute("ROLLBACK")
                    self._json(404, {"error": "handshake_not_found"})
                    return
                if row[0] == "revoked":
                    conn.execute("ROLLBACK")
                    self._json(
                        200,
                        {
                            "handshake_id": _hs_id(a, b, row[2]),
                            "revoked": True,
                        },
                    )
                    return
                conn.execute(
                    """UPDATE handshakes SET status='revoked',
                       pending_expires_at=NULL, redeemer_identity=NULL,
                       generation=generation+1
                       WHERE a_identity=? AND b_identity=?""",
                    (a, b),
                )
                if row[1]:
                    # Pair-scoped revocation memory: THIS link can never
                    # resurrect THIS pair. Other redeemers of a group link
                    # are unaffected; fresh consent via a NEW link works.
                    conn.execute(
                        """INSERT OR IGNORE INTO link_revocations
                           (link_id, a_identity, b_identity, revoked_at)
                           VALUES(?,?,?,?)""",
                        (row[1], a, b, now2),
                    )
                # Dead letters: ALL unacked mail between the pair, both
                # directions, regardless of collection state. (messages are
                # keyed by peer NAME here.) Since v0.2.16, "collected" is
                # telemetry, not a delivery guarantee -- a poll response can
                # drop mid-read, so collected-but-unacked mail may never have
                # reached the client and MUST die with the consent. Only
                # acked mail is beyond the boundary (the peer confirmed it).
                conn.execute(
                    """UPDATE messages
                       SET expires_at=?, dead_reason='handshake_revoked'
                       WHERE ((sender=? AND recipient=?)
                              OR (sender=? AND recipient=?))
                         AND acked_at IS NULL
                         AND expires_at > ?""",
                    (now2, peer, t_name, t_name, peer, now2),
                )
                conn.execute("COMMIT")
                new_id = _hs_id(a, b, row[2] + 1)
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
                raise
        self._json(200, {"handshake_id": new_id, "revoked": True})

    def _handle_handshakes_list(self, peer):
        me = caller_identity(peer)
        with db_lock:
            rows = conn.execute(
                "SELECT a_identity, b_identity, %s FROM handshakes"
                " WHERE a_identity=? OR b_identity=?"
                " ORDER BY last_activity DESC" % _HS_COLS,
                (me, me),
            ).fetchall()
        out = []
        for r in rows:
            a, b = r[0], r[1]
            d = _hs_public(a, b, r[2:])
            other = b if a == me else a
            d["peer_identity"] = other
            d["peer_name_hint"] = peer_name_for_identity(other)
            out.append(d)
        self._json(200, {"handshakes": out})

    def _handle_federation_send(self, mid, to, topic, text, in_reply_to,
                                ttl, peer, enc):
        """Cross-home /v1/send for a recipient enrolled only on another
        home relay (candidate-679-py-federation-v1).

        Called only when _validate_send returned unknown_peer and
        federation is configured. The body is already shape-validated;
        this method resolves the recipient's ONE canonical home from the
        signed CNS snapshot and enqueues a durable, opaque forwarding row.
        The relay never decrypts. Fail-closed at every step with zero
        partial state."""
        fed = _FED
        # The envelope version must be derived here: _validate_send's early
        # unknown_peer return leaves enc_version at 0. Same derivation,
        # same strictness (shared helper); a malformed body fails closed
        # instead of being forwarded.
        #
        # Zari delta finding D1 (a74bb2b2): run the SAME shared strict body
        # path (topic, envelope/version, in_reply_to, TTL) the local lane
        # runs. Previously only _derive_enc_version ran here, so
        # ttl_secs=-1, topic='bad topic!', and in_reply_to=123 were 200
        # accepted=true AND created durable outbox rows.
        err, enc_version = _validate_send_body(topic, text, in_reply_to,
                                               ttl, enc)
        if err:
            self._json(400, {"error": err})
            return
        # 1. Recipient's canonical home comes from signed CNS authority
        # only. An unresolvable name stays a 400: unknown_peer strictness
        # is not weakened, the failure just names the federation cause.
        try:
            route = _federation_resolve(fed, to)
        except federation_cns.CNSResolutionError as e:
            self._json(400, {"error": e.code})
            return
        # 2. If the CNS says the recipient's canonical home is US, this is
        # a local enrollment gap, not a forwardable send: honest
        # unknown_peer (we must never invent a mailbox, here or remote).
        if route["home"] == fed["own_home"]:
            self._json(400, {"error": "unknown_peer"})
            return
        # 3. The sender must be pinned to OUR home by the same authority.
        # A sender whose CNS home drifted elsewhere fails closed: the
        # sender stays on its pinned sender home, always.
        try:
            sender_route = _federation_resolve(fed, peer)
        except federation_cns.CNSResolutionError as e:
            self._json(400, {"error": e.code})
            return
        if sender_route["home"] != fed["own_home"]:
            self._json(400, {"error": "federation_sender_home_mismatch"})
            return
        sender_home = sender_route["home"]
        # 3b. Our own relay identity key must be the one the CNS pins for
        # our home: the relay_identity_key_id convention is verifiable, not
        # decorative.
        if sender_route["relay_identity_key_id"] != fed["key_id"]:
            self._json(400, {"error": "relay_pin_mismatch"})
            return
        # 4. v2 outer/inner binding at the forwarding point: the relay is
        # opaque but must not misroute a bound envelope.
        if enc_version == 2:
            ctx = enc.get("ctx") if isinstance(enc, dict) else None
            if (not isinstance(ctx, dict)
                    or ctx.get("recipient") != to
                    or ctx.get("sender") != peer):
                self._json(400, {"error": "federation_context_mismatch"})
                return
        # 5. Destination: the CNS-canonical relay origin, private transport
        # scope only (numeric loopback/Tailnet; no DNS, no rebinding).
        endpoint = route["relay_endpoint"]
        if not _federation_url_ok(endpoint):
            self._json(400, {"error": "federation_bad_endpoint"})
            return
        dest_origin = _federation_origin(endpoint)
        # Canonical opaque payload bytes (envelope JSON or plaintext).
        payload = e2ee.serialize_envelope(enc) if enc is not None else text
        now = time.time()
        expires_at = now + ttl
        topic_c = topic if topic else None
        reply_c = in_reply_to if in_reply_to else None
        with db_lock:
            try:
                if conn.in_transaction:
                    conn.rollback()
                conn.execute("BEGIN IMMEDIATE")
                orow = conn.execute(
                    "SELECT sender, recipient, text, enc_v, state"
                    " FROM federation_outbox WHERE id=?",
                    (mid,),
                ).fetchone()
                if orow is not None:
                    conn.execute("ROLLBACK")
                    # Same-ID retry: identical bytes -> original outcome,
                    # no second forwarding. Different bytes -> collision.
                    if (orow[0] == peer and orow[1] == to
                            and orow[2] == payload
                            and orow[3] == enc_version):
                        self._json(200, {"accepted": True, "duplicate": True,
                                         "id": mid, "federated": True})
                    else:
                        self._json(409, {"error": "id_collision"})
                    return
                # Cross-lane guard: the ID is already used on the local lane.
                if conn.execute(
                        "SELECT 1 FROM messages WHERE id=?", (mid,)).fetchone():
                    conn.execute("ROLLBACK")
                    self._json(409, {"error": "id_collision"})
                    return
                # Zari delta finding D2 (a74bb2b2): sender-home grant/pair
                # consent. Linked-relay trust + CNS location alone
                # authorized every local peer to every remote peer;
                # client-side AdapterV2 grant checks are bypassable via
                # the actual POST. Wire acceptance now requires an
                # explicit maintained grant for the (sender-home, sender,
                # recipient-home, recipient) tuple. No grant fails closed
                # (same as the B2 "missing snapshot fails closed"
                # repair); a revoked grant is rejected. No grant is ever
                # invented from linked-relay trust or CNS location, and
                # peer enrollment/mailboxes are not mirrored. The gate
                # lives INSIDE the same transaction as the INSERT
                # (mirroring the local lane's handshake gate): a revoke
                # committing between a separate gate check and this insert
                # could otherwise forward post-revocation.
                grow = conn.execute(
                    "SELECT status FROM federation_grants"
                    " WHERE sender_home=? AND sender=?"
                    " AND recipient_home=? AND recipient=?",
                    (sender_home, peer, route["home"], to),
                ).fetchone()
                if grow is None:
                    conn.execute("ROLLBACK")
                    self._json(403, {"error": "federation_grant_required"})
                    return
                if grow[0] != "active":
                    conn.execute("ROLLBACK")
                    self._json(403, {"error": "federation_grant_revoked"})
                    return
                conn.execute(
                    "INSERT INTO federation_outbox(id, sender, recipient,"
                    " topic, in_reply_to, expires_at, text, enc_v,"
                    " dest_origin, state, attempts, next_attempt_at,"
                    " last_error, created_at)"
                    " VALUES (?,?,?,?,?,?,?,?,?,'queued',0,?,NULL,?)",
                    (mid, peer, to, topic_c, reply_c, expires_at, payload,
                     enc_version, dest_origin, now, now),
                )
                conn.execute("COMMIT")
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
                raise
        # Sender activity telemetry, mirroring the local path.
        with db_lock:
            conn.execute("UPDATE peers SET last_send_at=? WHERE name=?",
                         (time.time(), peer))
            conn.commit()
        _federation_kick()
        self._json(200, {"accepted": True, "id": mid,
                         "expires_at": expires_at, "federated": True})
        return

    def _handle_federation_deliver(self):
        """POST /v1/federation/deliver: relay-to-relay ingress
        (candidate-679-py-federation-v1).

        Pre-auth endpoint: the attestation IS the authentication (a relay,
        not a peer, is calling; peer credentials are never copied or
        accepted here). The sender's home relay attests with its
        operator-held Ed25519 key; we verify against the pinned linked key
        AND the signed CNS snapshot. The recipient must be local; the
        sender must NOT be local (local senders use /v1/send). The
        recipient mailbox row is created here and only here."""
        fed = _FED
        if fed is None:
            self._json(400, {"error": "federation_disabled"})
            return
        body = self._read_json()
        ip = self._client_ip()

        def _deny(code, status=400):
            if not auth_fail_ok(ip):
                self._json(429, {"error": "rate_limited"})
            else:
                self._json(status, {"error": code})

        if not isinstance(body, dict):
            _deny("invalid_json")
            return
        mid = body.get("id")
        sender = body.get("from")
        to = body.get("to")
        topic = body.get("topic")
        in_reply_to = body.get("in_reply_to")
        expires_at = body.get("expires_at")
        enc = body.get("enc")
        text = body.get("text")
        enc_v = body.get("enc_v")
        from_home = body.get("from_home")
        relay_pub_b64 = body.get("relay_pub")
        nonce_hex = body.get("nonce")
        sig_b64 = body.get("sig")
        # Strict body shape (mirrors _validate_send strictness).
        try:
            uuid.UUID(mid)
        except Exception:
            _deny("id_must_be_uuid")
            return
        if type(sender) is not str or not sender:
            _deny("missing_from")
            return
        if type(to) is not str or not to:
            _deny("missing_to")
            return
        if type(from_home) is not str or not from_home:
            _deny("missing_from_home")
            return
        if type(nonce_hex) is not str or not nonce_hex:
            _deny("missing_nonce")
            return
        if type(enc_v) is not int or enc_v not in (0, 1, 2):
            _deny("bad_enc_v")
            return
        if (enc is None) == (text is None):
            _deny("bad_envelope")
            return
        try:
            payload = e2ee.serialize_envelope(enc) if enc is not None else text
            if type(payload) is not str or not payload:
                raise ValueError("bad payload")
        except Exception:
            _deny("bad_envelope")
            return
        # Auth FIRST: verify the relay attestation before any enrollment
        # information can leak.
        try:
            pub = _fed_b64u_decode(relay_pub_b64)
            sig = _fed_b64u_decode(sig_b64)
        except (ValueError, TypeError):
            _deny("federation_attestation_invalid", 403)
            return
        if len(pub) != 32 or len(sig) != 64:
            _deny("federation_attestation_invalid", 403)
            return
        payload_sha = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        attest = _federation_attest_bytes(
            mid, sender, to, topic, in_reply_to, expires_at,
            payload_sha, enc_v, from_home)
        try:
            attested = bool(ed25519.verify(pub, sig, attest))
        except Exception:
            attested = False
        if not attested:
            _deny("federation_attestation_invalid", 403)
            return
        # CNS authority: the sender's route must name the claimed home, and
        # the attesting key must be BOTH the operator-pinned linked key for
        # that home's relay origin AND the key the CNS snapshot pins.
        try:
            sroute = _federation_resolve(fed, sender)
        except federation_cns.CNSResolutionError as e:
            _deny(e.code)
            return
        if sroute["home"] != from_home:
            _deny("federation_sender_home_mismatch")
            return
        if sroute["home"] == fed["own_home"]:
            # The sender's canonical home is us but it is not our peer:
            # a local sender must use /v1/send. Never accept relay
            # attestation for our own home.
            _deny("federation_local_sender")
            return
        origin = _federation_origin(sroute["relay_endpoint"])
        pinned_b64 = fed["linked_relays"].get(origin)
        if pinned_b64 is None or not hmac.compare_digest(pinned_b64,
                                                         relay_pub_b64):
            _deny("relay_pin_mismatch")
            return
        if "sha256:" + hashlib.sha256(pub).hexdigest() != sroute["relay_identity_key_id"]:
            _deny("relay_pin_mismatch")
            return
        # Locality: the recipient must be ours; the sender must not be.
        if to not in peer_names:
            _deny("federation_recipient_not_local")
            return
        if sender in peer_names:
            _deny("federation_local_sender")
            return
        # v2 outer/inner binding at the delivery point.
        if enc_v == 2:
            ctx = enc.get("ctx") if isinstance(enc, dict) else None
            if (not isinstance(ctx, dict)
                    or ctx.get("recipient") != to
                    or ctx.get("sender") != sender):
                _deny("federation_context_mismatch")
                return
        # Expiry is absolute from the sender's home; bound it locally.
        now = time.time()
        if (type(expires_at) is bool
                or not isinstance(expires_at, (int, float))
                or not (0 < expires_at - now <= MAX_TTL)):
            _deny("federation_bad_ttl")
            return
        ttl = expires_at - now
        # Shared envelope semantics (shape, version derivation, in_reply_to,
        # TTL range); the local-handshake gate inside /v1/send is NOT
        # applied here -- cross-home consent is the verified attestation,
        # not a per-relay handshake.
        err, enc_version = self._validate_send(
            mid, to, topic, text, in_reply_to, ttl, sender, enc)
        if err:
            _deny(err)
            return
        if enc_version != enc_v:
            _deny("federation_context_mismatch")
            return

        def _signed_response(duplicate):
            rsig = ed25519.sign(
                fed["seed"],
                _federation_response_bytes(nonce_hex, mid, True, duplicate))
            return {"accepted": True, "id": mid, "duplicate": duplicate,
                    "relay_pub": fed["pub_b64"],
                    "sig": _fed_b64u_encode(rsig)}

        with db_lock:
            now2 = time.time()
            try:
                if conn.in_transaction:
                    conn.rollback()
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute(
                    "SELECT sender, text, enc_v FROM messages WHERE id=?",
                    (mid,)).fetchone()
                if row:
                    conn.execute("ROLLBACK")
                    # Same-ID dedup: the unknown-outcome retry path. An
                    # identical redelivery returns the original outcome
                    # (proving our identity again); different bytes are a
                    # collision, never a second mailbox row.
                    if (row[0] == sender and row[1] == payload
                            and row[2] == enc_version):
                        self._json(200, _signed_response(True))
                    else:
                        self._json(409, {"error": "id_collision"})
                    return
                if conn.execute(
                        "SELECT 1 FROM federation_outbox WHERE id=?",
                        (mid,)).fetchone():
                    conn.execute("ROLLBACK")
                    self._json(409, {"error": "id_collision"})
                    return
                cap = conn.execute(
                    "SELECT COUNT(*) FROM messages WHERE recipient=?"
                    " AND acked_at IS NULL AND expires_at > ?",
                    (to, now2),
                ).fetchone()[0]
                if cap >= PENDING_CAP:
                    conn.execute("ROLLBACK")
                    self._json(429, {"error": "queue_full"})
                    return
                conn.execute(
                    """INSERT INTO messages(id, sender, recipient, topic, text,
                                            in_reply_to, created_at, expires_at,
                                            acked_at, enc_v)
                       VALUES(?,?,?,?,?,?,?,?,NULL,?)""",
                    (mid, sender, to, topic if topic else None, payload,
                     in_reply_to if in_reply_to else None, now2, expires_at,
                     enc_version),
                )
                conn.execute("COMMIT")
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
                raise
        maybe_notify(to)
        self._json(200, _signed_response(False))
        return

    @staticmethod
    def _validate_send(mid, to, topic, text, in_reply_to, ttl, peer, enc=None):
        """Validate a /v1/send body.

        Returns (error, enc_version): error is None on success; enc_version
        is the validated envelope version (1 or 2) when enc is present,
        else 0. The version is derived from the validated envelope itself,
        never from a client-supplied marker.
        """
        if not isinstance(mid, str) or not mid or len(mid) > ID_MAX_LEN:
            return "id_required", 0
        try:
            uuid.UUID(mid)
        except Exception:
            return "id_must_be_uuid", 0
        if not isinstance(to, str) or not to:
            return "missing_to", 0
        if to not in peer_names:
            return "unknown_peer", 0
        if to == peer:
            return "cannot_send_to_self", 0
        # The remaining strict checks (topic, envelope/version,
        # in_reply_to, TTL) are the shared body path -- identical for the
        # local lane and the federation lane (see _validate_send_body).
        return _validate_send_body(topic, text, in_reply_to, ttl, enc)


def _install_signal_trap():
    """Forensics for unexpected death: log any caught termination signal with
    a full stack dump before exiting. A silent death that leaves no such log
    entry means the process was SIGKILLed (or equivalent) from outside - it
    never got a chance to run this handler. Exit semantics are unchanged:
    after logging, the default disposition is restored and the signal is
    re-delivered to self."""

    def _on_term(signum, frame):
        try:
            name = signal.Signals(signum).name
        except Exception:
            name = str(signum)
        print(
            "clack relay: caught %s at %s, dumping stacks"
            % (name, time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())),
            flush=True,
        )
        try:
            faulthandler.dump_traceback()
        except Exception:
            pass
        try:
            signal.signal(signum, signal.SIG_DFL)
        except Exception:
            pass
        os.kill(os.getpid(), signum)

    # SIGHUP does not exist on Windows; getattr keeps the tuple
    # construction itself from raising before the per-signal guard runs.
    _termsigs = [s for s in (signal.SIGTERM, signal.SIGINT,
                             getattr(signal, "SIGHUP", None)) if s is not None]
    for sig in _termsigs:
        try:
            signal.signal(sig, _on_term)
        except (OSError, ValueError):
            pass


def main():
    global relay_cfg
    cfg = load_config()
    relay_cfg = cfg
    _init_reserved_names(cfg)  # strict: malformed entries refuse startup
    _init_identity_pubkeys(cfg)  # strict: malformed entries refuse startup
    _init_peer_hashes(cfg)  # strict: malformed entries refuse startup
    try:
        _parse_handshake_knobs(cfg)  # strict: malformed entries refuse startup
    except ValueError as e:
        raise SystemExit("clack relay: invalid handshake config: %s" % e)
    load_identity_key(cfg)
    _install_signal_trap()
    port = int(cfg.get("port", 18802))
    bind = cfg.get("bind", "127.0.0.1")
    if not isinstance(bind, str) or not bind:
        raise SystemExit("clack relay: config 'bind' must be a non-empty string")
    # candidate-679-py-federation-v1: strict operator config for cross-home
    # forwarding. Absent = disabled (existing behavior unchanged);
    # malformed = refuse startup.
    _init_federation(cfg)
    init_db(cfg)
    # Safety-audit (Oct 2026): the periodic sweep runs on its own daemon
    # thread, never piggybacked on requests. Keeps diagnostics read-only and
    # keeps a failing sweep from killing unrelated requests. Every serving
    # entrypoint must start this (see _start_sweep_thread).
    _start_sweep_thread()
    # candidate-679-py-federation-v1: cross-home forwarder daemon. Starts
    # nothing when federation is not configured.
    _start_federation_thread()
    server = ThreadingHTTPServer((bind, port), Handler)
    print("clack relay listening on %s:%d (peers: %s)" % (bind, port, ",".join(sorted(peer_names))), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
