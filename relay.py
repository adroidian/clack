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
import threading
import time
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import ed25519  # vendored pure-stdlib Ed25519 (see ed25519.py)

VERSION = "0.2.16"
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


def _parse_handshake_knobs(cfg):
    """Validate the section-9 tier knobs from relay-config.json. Strict:
    malformed entries refuse startup, like reserved_names/identity_pubkeys."""
    global HS_MAX_PER_IDENTITY, HS_EXPIRY_DAYS, HS_INACTIVITY_DAYS

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


def _hs_public(a, b, row):
    """Serialize a handshake row for the API. row is
    (status, created_at, pending_expires_at, expires_at, last_activity,
     via_link_id, generation)."""
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
    }


# Row shape shared by the handshake handlers: status, created_at,
# pending_expires_at, expires_at, last_activity, via_link_id, generation,
# redeemer_identity.
_HS_COLS = ("status, created_at, pending_expires_at, expires_at,"
            " last_activity, via_link_id, generation, redeemer_identity")


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


def load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def init_db(cfg):
    global conn
    os.makedirs(BASE, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS peers(
               name TEXT PRIMARY KEY,
               token_hash TEXT NOT NULL,
               created_at REAL NOT NULL)"""
    )
    conn.execute(
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
               fetch_count INTEGER NOT NULL DEFAULT 0)"""
    )
    # v0.2.4 migration: databases created before collected_at existed.
    cols = {r[1] for r in conn.execute("PRAGMA table_info(messages)")}
    if "collected_at" not in cols:
        conn.execute("ALTER TABLE messages ADD COLUMN collected_at REAL")
    # v0.2.16 migration: fetch_count counts poll deliveries per message for
    # at-least-once redelivery observability (issue #4).
    if "fetch_count" not in cols:
        conn.execute("ALTER TABLE messages ADD COLUMN fetch_count INTEGER NOT NULL DEFAULT 0")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS webhooks(
               peer TEXT PRIMARY KEY,
               url TEXT NOT NULL,
               created_at REAL NOT NULL,
               last_notified_at REAL,
               last_error TEXT)"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_messages_poll ON messages(recipient, acked_at, expires_at)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_messages_reply ON messages(in_reply_to, created_at)"
    )
    # v0.2.5: invite-link onboarding tables. Peer rows created by invite
    # redemption are keyed by identity_pubkey (unique, NULL for legacy
    # config-managed peers) and carry invited_by provenance.
    conn.execute(
        """CREATE TABLE IF NOT EXISTS invites(
               invite_id TEXT PRIMARY KEY,
               secret_hash TEXT NOT NULL,
               inviter_identity TEXT NOT NULL,
               exp REAL NOT NULL,
               max_uses INTEGER NOT NULL,
               uses INTEGER NOT NULL DEFAULT 0,
               revoked INTEGER NOT NULL DEFAULT 0,
               created_at REAL NOT NULL)"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS challenges(
               nonce TEXT PRIMARY KEY,
               invite_id TEXT NOT NULL,
               created_at REAL NOT NULL,
               expires_at REAL NOT NULL,
               used INTEGER NOT NULL DEFAULT 0)"""
    )
    # v0.2.9: pre-enrollment challenges for agent self-enrollment. kind is
    # 'invite' (ref = invite_id), 'pow', or 'open' (ref NULL).
    conn.execute(
        """CREATE TABLE IF NOT EXISTS enroll_challenges(
               nonce TEXT PRIMARY KEY,
               kind TEXT NOT NULL,
               ref TEXT,
               created_at REAL NOT NULL,
               expires_at REAL NOT NULL,
               used INTEGER NOT NULL DEFAULT 0)"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_invites_inviter ON invites(inviter_identity)"
    )
    peer_cols = {r[1] for r in conn.execute("PRAGMA table_info(peers)")}
    for _col, _ddl in (
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
    ):
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
    conn.execute(
        """CREATE TABLE IF NOT EXISTS seen_nonces(
               nonce TEXT PRIMARY KEY,
               peer TEXT NOT NULL,
               expires_at REAL NOT NULL)"""
    )
    # v0.2.12 (R1): names of revoked config peers. A retired name can never
    # be claimed by self-enrollment again -- only the operator resurrects it
    # by re-adding it to the config.
    conn.execute(
        """CREATE TABLE IF NOT EXISTS retired_names(
               name TEXT PRIMARY KEY,
               retired_at REAL NOT NULL)"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_seen_nonces_exp ON seen_nonces(expires_at)"
    )
    # v0.2.13: mutual-consent handshakes. a/b are order-independent
    # identities (identity pubkey b64, or legacy config peer name).
    # NO BACKFILL (spec section 8): this migration creates tables/columns
    # only -- zero handshake rows. Enforcement begins immediately.
    conn.execute(
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
               PRIMARY KEY (a_identity, b_identity))"""
    )
    # Pair-scoped revocation memory: a revoked link can never resurrect
    # the specific connection it created (spec section 7).
    conn.execute(
        """CREATE TABLE IF NOT EXISTS link_revocations(
               link_id TEXT NOT NULL,
               a_identity TEXT NOT NULL,
               b_identity TEXT NOT NULL,
               revoked_at REAL NOT NULL,
               PRIMARY KEY (link_id, a_identity, b_identity))"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_handshakes_status ON handshakes(status)"
    )
    # Ensure-column path: CREATE TABLE IF NOT EXISTS is a no-op when a
    # partial handshakes table already exists (e.g. an earlier 0.2.13
    # dev build), so the generation column gets its own ALTER guard.
    hs_cols = {r[1] for r in conn.execute("PRAGMA table_info(handshakes)")}
    if "generation" not in hs_cols:
        conn.execute(
            "ALTER TABLE handshakes ADD COLUMN"
            " generation INTEGER NOT NULL DEFAULT 0"
        )
    inv_cols = {r[1] for r in conn.execute("PRAGMA table_info(invites)")}
    for _col, _ddl in (
        # A handshake link IS an invite row with grant_handshake=1.
        ("grant_handshake", "INTEGER DEFAULT 0"),
        ("note", "TEXT"),
    ):
        if _col not in inv_cols:
            conn.execute("ALTER TABLE invites ADD COLUMN %s %s" % (_col, _ddl))
    # v0.2.13: revocation dead-letter reason. Queued-but-unpolled messages
    # killed by a handshake revoke carry dead_reason='handshake_revoked';
    # they surface via /v1/receipts as expired-with-reason and are never
    # delivered after revocation.
    msg_cols = {r[1] for r in conn.execute("PRAGMA table_info(messages)")}
    if "dead_reason" not in msg_cols:
        conn.execute("ALTER TABLE messages ADD COLUMN dead_reason TEXT")
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
redeem_fails = {}  # invite_id -> [float] of recent failures


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
                      collected_at, fetch_count
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
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
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
            # No (or corrupt) Ed25519 key on file: the peer must re-enroll
            # via /join to get one. Never silently bypass.
            return "upgrade_required"
        # R5: the vendored verifier admits trivial forgeries under
        # small-order keys. Enrollment and the operator map now reject such
        # keys, but rows written before the fix could still hold one:
        # validate once per peer key per process and fail closed instead of
        # trusting stored bytes. A rejected key means re-enroll, same as a
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

    def _require_auth(self):
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
                    "detail": "POST /v1/handshakes/redeem with {\"h\": h, \"k\": k, \"identity_pubkey\": base64url(public_key), \"requested_name\": \"desired-name\" (optional, v0.2.15+), \"proof\": {\"nonce\": ..., \"signature\": ...}, \"pow_nonce\": ...} enrolls inline (fresh identity) and returns {\"service_token\", \"peer_name\", \"handshake_id\", ...}. Then POST /v1/handshakes/accept with {\"handshake_id\"} (authenticated) activates the handshake. The link use is consumed atomically (single-use).",
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
                    "peers with no stored key get 401 upgrade_required (re-enroll via /join "
                    "to fix). Full scheme: CLIENT_CONTRACT.md in the clack-relay repo.",
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
            "   Ed25519 key gets 401 upgrade_required (re-enroll to fix).\n"
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
            "All you need is an invite link.</p>\n"
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
        sweep(now)
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._json(200, {"ok": True, "version": VERSION, "total_pending": total_pending(now)})
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
                              created_at, expires_at
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
        sweep(now)
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
        peer = self._require_auth()
        if peer is None:
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
            in_reply_to = body.get("in_reply_to")
            ttl = body.get("ttl_secs", DEFAULT_TTL)

            err = self._validate_send(mid, to, topic, text, in_reply_to, ttl, peer)
            if err:
                self._json(400, {"error": err})
                return

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
                                                in_reply_to, created_at, expires_at, acked_at)
                           VALUES(?,?,?,?,?,?,?,?,NULL)""",
                        (
                            mid,
                            peer,
                            to,
                            topic if topic else None,
                            text,
                            in_reply_to if in_reply_to else None,
                            now2,
                            expires_at,
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
                    "SELECT exp, max_uses, uses, revoked FROM invites WHERE invite_id=?",
                    (invite_id,),
                ).fetchone()
            if row is None:
                self._json(404, {"error": "invite_not_found"})
                return
            exp, max_uses, uses, revoked = row
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

    def _handle_handshake_mint(self, peer, now):
        body = self._read_json()
        if not isinstance(body, dict):
            self._json(400, {"error": "invalid_json"})
            return
        max_uses = body.get("max_uses", 1)
        exp_days = body.get("exp_days", 7)
        note = body.get("note")
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
        secret = secrets.token_bytes(32)
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
                                           grant_handshake, note)
                       VALUES(?,?,?,?,?,0,0,?,1,?)""",
                    (
                        link_id,
                        hashlib.sha256(secret).hexdigest(),
                        ident,
                        exp,
                        max_uses,
                        now2,
                        note,
                    ),
                )
                conn.execute("COMMIT")
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
                raise
        link = _build_handshake_link(
            relay_base_url(relay_cfg), link_id, secret, peer, exp, max_uses
        )
        self._json(
            200,
            {"link": link, "link_id": link_id, "exp": exp, "max_uses": max_uses},
        )

    def _handle_handshake_redeem(self, now):
        body = self._read_json()
        if not isinstance(body, dict):
            self._json(400, {"error": "invalid_json"})
            return
        h = body.get("h")
        k = body.get("k")
        if not isinstance(h, str) or not h:
            self._json(400, {"error": "link_id_required"})
            return
        if not isinstance(k, str) or not k:
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
        # Redeem is rate-limited per IP and per link: the invite limiters.
        if not invite_rate_ok("rip:" + ip, 30):
            self._json(429, {"error": "rate_limited"})
            return
        if not invite_rate_ok("rinv:" + h, 10):
            self._json(429, {"error": "rate_limited"})
            return
        if redeem_failures_blocked(h):
            self._json(429, {"error": "invite_cooldown"})
            return

        def link_fail():
            # IDENTICAL shape for every link-validity failure: unknown id,
            # bad claim secret, expired/exhausted/revoked link,
            # non-handshake (v3) link, and previously-revoked pair. No
            # enumeration oracle. The claim secret k is never logged and
            # never appears in error text.
            redeem_failure_note(h)
            self._json(403, {"error": "link_unusable"})

        # Optional authentication: an already-enrolled caller redeems
        # authenticated (bearer + signature). No Authorization header =>
        # fresh enrollment inline below.
        peer = None
        if self.headers.get("Authorization"):
            peer = self._require_auth()
            if peer is None:
                return
        # Fast-path link validation. The single-UPDATE use-count inside
        # the transaction below is the authoritative gate.
        with db_lock:
            inv = conn.execute(
                """SELECT secret_hash, inviter_identity, exp, max_uses, uses,
                          revoked, grant_handshake
                   FROM invites WHERE invite_id=?""",
                (h,),
            ).fetchone()
        if inv is None:
            link_fail()
            return
        secret_hash, minter, exp, max_uses, uses, revoked, gh = inv
        # NOTE: the use-count is deliberately NOT checked here. A retry
        # of a live pending whose link is at max_uses (the final-use
        # case) must reach the idempotency branch inside the transaction
        # below and return the same row -- not 403. Exhaustion is
        # enforced authoritatively by the atomic UPDATE's
        # uses < max_uses predicate, AFTER the idempotency check.
        if gh != 1 or revoked or exp <= now:
            link_fail()
            return
        try:
            secret = b64u_decode(k)
        except ValueError:
            link_fail()
            return
        if not hmac.compare_digest(
            hashlib.sha256(secret).hexdigest(), secret_hash
        ):
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
            try:
                pubkey = b64u_decode(body.get("identity_pubkey"))
            except ValueError:
                self._json(400, {"error": "bad_identity"})
                return
            if len(pubkey) != 32 or not ed25519.is_valid_pubkey(pubkey):
                # R5: never enroll a small-order key.
                self._json(400, {"error": "bad_identity"})
                return
            pub_b64 = b64u_encode(pubkey)
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
                if hs2 is not None and (
                    hs2[0] == "active"
                    or (
                        hs2[0] == "pending"
                        and hs2[7] == redeemer
                        and hs2[2] is not None
                        and hs2[2] > now2
                    )
                ):
                    # Idempotent no-op: active, or a live pending owned by
                    # this redeemer. No link use is consumed, and the
                    # ORIGINAL pending_expires_at is kept -- redeem NEVER
                    # extends the deadline. (A live pending with a
                    # different redeemer is impossible -- the pair
                    # determines the redeemer -- and fails closed below.)
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
                        and (hs2[2] is None or hs2[2] <= now2)
                    )
                ):
                    conn.execute("ROLLBACK")
                    link_fail()
                    return
                else:
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
                                                      generation)
                               VALUES(?,?,'pending',?,?,?,?,?,?,0)""",
                            (a, b, now2, pending_exp, expires_at, now2, h,
                             redeemer),
                        )
                    else:
                        # Revoked or lapsed-pending row: a fresh consent
                        # round. Generation is NOT reset (only revoke bumps
                        # it); the deadline is fresh because the old one
                        # lapsed -- this is a new pending, not an extension.
                        conn.execute(
                            """UPDATE handshakes
                               SET status='pending', created_at=?,
                                   pending_expires_at=?, expires_at=?,
                                   last_activity=?, via_link_id=?,
                                   redeemer_identity=?
                               WHERE a_identity=? AND b_identity=?""",
                            (now2, pending_exp, expires_at, now2, h, redeemer,
                             a, b),
                        )
                conn.execute("COMMIT")
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
                redeem_failure_note(h)
                self._json(500, {"error": "internal_error"})
                return
        # Cache mutation only after the transaction committed.
        if name is not None:
            peer_names.add(name)
        redeem_failure_clear(h)
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
                # Guarded atomic accept: pending, unexpired on the SERVER
                # clock, signed by the recorded redeemer, and bound to the
                # CURRENT pair generation. An expired (or stale-generation)
                # accept is denied HERE, atomically -- the row never flips.
                # Never bound to the display-only `by` link field.
                cur = conn.execute(
                    """UPDATE handshakes
                       SET status='active', pending_expires_at=NULL,
                           redeemer_identity=NULL, last_activity=?
                       WHERE a_identity=? AND b_identity=?
                         AND status='pending' AND redeemer_identity=?
                         AND pending_expires_at > ? AND generation=?""",
                    (now2, a, b, me, now2, gen),
                )
                if cur.rowcount == 1:
                    accepted = True
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

    @staticmethod
    def _validate_send(mid, to, topic, text, in_reply_to, ttl, peer):
        if not isinstance(mid, str) or not mid or len(mid) > ID_MAX_LEN:
            return "id_required"
        try:
            uuid.UUID(mid)
        except Exception:
            return "id_must_be_uuid"
        if not isinstance(to, str) or to not in peer_names:
            return "unknown_peer"
        if to == peer:
            return "cannot_send_to_self"
        if topic is not None and topic != "":
            if not isinstance(topic, str) or not TOPIC_RE.match(topic):
                return "bad_topic"
        if not isinstance(text, str) or not (TEXT_MIN <= len(text) <= TEXT_MAX):
            return "bad_text"
        if in_reply_to is not None and in_reply_to != "":
            if not isinstance(in_reply_to, str) or len(in_reply_to) > ID_MAX_LEN:
                return "bad_in_reply_to"
        if isinstance(ttl, bool) or not isinstance(ttl, (int, float)) or not (1 <= ttl <= MAX_TTL):
            return "bad_ttl"
        return None


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
    init_db(cfg)
    server = ThreadingHTTPServer((bind, port), Handler)
    print("clack relay listening on %s:%d (peers: %s)" % (bind, port, ",".join(sorted(peer_names))), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
