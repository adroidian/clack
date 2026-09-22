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

VERSION = "0.2.8"
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
               collected_at REAL)"""
    )
    # v0.2.4 migration: databases created before collected_at existed.
    cols = {r[1] for r in conn.execute("PRAGMA table_info(messages)")}
    if "collected_at" not in cols:
        conn.execute("ALTER TABLE messages ADD COLUMN collected_at REAL")
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
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_invites_inviter ON invites(inviter_identity)"
    )
    peer_cols = {r[1] for r in conn.execute("PRAGMA table_info(peers)")}
    for _col, _ddl in (
        ("identity_pubkey", "TEXT"),
        ("invited_by", "TEXT"),
        ("display_name", "TEXT"),
    ):
        if _col not in peer_cols:
            conn.execute("ALTER TABLE peers ADD COLUMN %s %s" % (_col, _ddl))
    # Multiple NULLs allowed: legacy config peers have no identity.
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_peers_identity ON peers(identity_pubkey)"
    )
    now = time.time()
    # Revocation-safe rebuild: peers removed from the config must lose
    # authentication on restart. Only config-managed rows (identity_pubkey
    # IS NULL) are rebuilt; invite-enrolled identity rows survive restarts.
    # Queued messages are left alone; they expire via TTL and are
    # undeliverable without auth.
    with conn:
        conn.execute("DELETE FROM peers WHERE identity_pubkey IS NULL")
        conn.executemany(
            "INSERT OR IGNORE INTO peers(name, token_hash, created_at) VALUES(?,?,?)",
            [
                (name, hashlib.sha256(token.encode("utf-8")).hexdigest(), now)
                for name, token in cfg.get("peers", {}).items()
            ],
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
        # Expired and already resolved (acked or collected): drop promptly.
        conn.execute(
            "DELETE FROM messages WHERE expires_at <= ? AND (acked_at IS NOT NULL OR collected_at IS NOT NULL)",
            (now,),
        )
        # Retention windows keep sender-visible receipts around:
        # acked -> 7d after ack; collected-but-unacked -> 7d after collection.
        conn.execute(
            "DELETE FROM messages WHERE acked_at IS NOT NULL AND acked_at <= ?",
            (now - RETENTION,),
        )
        conn.execute(
            "DELETE FROM messages WHERE collected_at IS NOT NULL AND acked_at IS NULL AND collected_at <= ?",
            (now - RETENTION,),
        )
        # Dead letters: expired, never collected. Kept RETENTION past expiry
        # so senders can see them via /v1/receipts instead of wondering.
        conn.execute(
            "DELETE FROM messages WHERE expires_at <= ? AND collected_at IS NULL AND acked_at IS NULL AND expires_at <= ?",
            (now, now - RETENTION),
        )
        # Bound dead-letter storage: keep the newest 2000 globally.
        conn.execute(
            """DELETE FROM messages WHERE id IN (
                   SELECT id FROM messages
                   WHERE expires_at <= ? AND collected_at IS NULL AND acked_at IS NULL
                   ORDER BY created_at DESC LIMIT -1 OFFSET 2000)""",
            (now,),
        )
        # v0.2.5: drop expired challenges and consumed ones older than an hour.
        conn.execute(
            "DELETE FROM challenges WHERE expires_at <= ? OR (used != 0 AND created_at <= ?)",
            (now, now - 3600),
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
        if not conn.execute(
            "SELECT 1 FROM peers WHERE name=?", (name,)
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
            """SELECT id, sender, topic, text, in_reply_to, created_at, expires_at
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
        }
        for r in rows
    ]


class Handler(BaseHTTPRequestHandler):
    server_version = "ClackRelay/" + VERSION

    def log_message(self, fmt, *args):  # keep logs token/text free
        pass

    def _json(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return None
        if length <= 0 or length > 2_000_000:
            return None
        try:
            raw = self.rfile.read(length)
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return None

    def _require_auth(self):
        peer = auth_peer(self.headers)
        if peer is None:
            self._json(401, {"error": "unauthorized"})
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
            "link_version": LINK_VERSION,
            "link_format": "https://<relay>/join#v=3&r=<base64url relay url>&i=<invite id>&k=<claim secret>&by=<inviter>&exp=<expiry epoch>",
            "fragment_params": ["r", "i", "k", "v", "by", "exp"],
            "fragment_note": "The URL fragment (after #) is never sent to the server. Parse it locally. The claim secret (k) travels only inside the POST /v1/invites/redeem body.",
            "security_note": "Recommended before redeeming: GET /v1/identity?nonce=<16-64 random bytes as hex> and confirm the relay's signature fingerprint out-of-band (TOFU).",
            "steps": [
                {
                    "n": 1,
                    "title": "Parse the invite link fragment locally",
                    "detail": "Split the link on '#'; parse the fragment as query parameters. r = base64url relay URL, i = invite id, k = base64url claim secret, v = link version, by = inviter name, exp = expiry unix epoch.",
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
                    "title": "Fetch a challenge nonce",
                    "detail": "POST /v1/invites/challenge with {\"invite_id\": i} returns {\"nonce\"} (base64url, single-use, 5-minute expiry, bound to the invite).",
                },
                {
                    "n": 5,
                    "title": "Sign the proof",
                    "detail": "signature = Ed25519_sign(seed, nonce_bytes || invite_id.encode(\"utf-8\") || public_key_bytes).",
                },
                {
                    "n": 6,
                    "title": "Redeem the invite",
                    "detail": "POST /v1/invites/redeem with {\"invite_id\": i, \"secret\": k, \"identity_pubkey\": base64url(public_key), \"proof\": {\"nonce\": nonce, \"signature\": base64url(signature)}} returns {\"service_token\", \"peer_name\", ...}. The invite is consumed atomically (single-use).",
                },
                {
                    "n": 7,
                    "title": "Talk",
                    "detail": "Use the service_token as a Bearer token: POST /v1/send to send, GET /v1/poll?timeout=25 to receive, POST /v1/ack to confirm handling.",
                },
            ],
        }

    def _serve_join(self):
        doc = self._join_bootstrap_doc()
        accept = self.headers.get("Accept", "")
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
            ip = self.client_address[0] if self.client_address else "?"
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
                collected_at = time.time()
                with db_lock:
                    conn.executemany(
                        "UPDATE messages SET collected_at=? WHERE id=? AND recipient=? AND collected_at IS NULL",
                        [(collected_at, m["id"], peer) for m in msgs],
                    )
                    conn.commit()
            self._json(200, {"messages": msgs})
            return
        if parsed.path == "/v1/fetch":
            qs = parse_qs(parsed.query)
            irt = qs.get("in_reply_to", [None])[0]
            if not irt:
                self._json(400, {"error": "in_reply_to_required"})
                return
            cutoff = now - RETENTION
            with db_lock:
                rows = conn.execute(
                    """SELECT id, sender, recipient, topic, text, in_reply_to,
                              created_at, expires_at
                       FROM messages
                       WHERE in_reply_to=? AND created_at >= ?
                         AND (sender=? OR recipient=?)
                       ORDER BY created_at""",
                    (irt, cutoff, peer, peer),
                ).fetchall()
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
                              collected_at, acked_at
                       FROM messages WHERE sender=? AND created_at >= ?
                       ORDER BY created_at DESC LIMIT ?""",
                    (peer, since, limit),
                ).fetchall()
            out = []
            for r in rows:
                if r[6] is not None:
                    state = "acked"
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
        # secret plus proof-of-possession IS the authentication. Everything
        # else below requires a peer bearer token.
        if parsed.path == "/v1/invites/challenge":
            self._handle_invite_challenge(now)
            return
        if parsed.path == "/v1/invites/redeem":
            self._handle_invite_redeem(now)
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
        if parsed.path == "/v1/ack":
            body = self._read_json()
            if not isinstance(body, dict) or not isinstance(body.get("ids"), list):
                self._json(400, {"error": "ids_required"})
                return
            ids = [i for i in body["ids"] if isinstance(i, str)][:1000]
            if not ids:
                self._json(200, {"acked": []})
                return
            acked = []
            with db_lock:
                for mid in ids:
                    cur = conn.execute(
                        "UPDATE messages SET acked_at=? WHERE id=? AND recipient=? AND acked_at IS NULL",
                        (now, mid, peer),
                    )
                    if cur.rowcount:
                        acked.append(mid)
                conn.commit()
            self._json(200, {"acked": acked})
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

            with db_lock:
                row = conn.execute("SELECT sender FROM messages WHERE id=?", (mid,)).fetchone()
                if row:
                    if row[0] == peer:
                        self._json(200, {"accepted": True, "duplicate": True, "id": mid})
                    else:
                        self._json(409, {"error": "id_collision"})
                    return
                cap = conn.execute(
                    "SELECT COUNT(*) FROM messages WHERE recipient=? AND acked_at IS NULL AND expires_at > ?",
                    (to, now),
                ).fetchone()[0]
                if cap >= PENDING_CAP:
                    self._json(429, {"error": "queue_full"})
                    return
                expires_at = now + ttl
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
                        now,
                        expires_at,
                    ),
                )
                conn.commit()
            # v0.2.4: wake the recipient if they registered a nudge webhook.
            # Runs after commit, outside the db lock; best-effort only.
            maybe_notify(to)
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
        ip = self.client_address[0] if self.client_address else "?"
        if not invite_rate_ok("cip:" + ip, 30) or not invite_rate_ok(
            "cinv:" + invite_id, 10
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
        ip = self.client_address[0] if self.client_address else "?"
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
                          revoked FROM invites WHERE invite_id=?""",
                (invite_id,),
            ).fetchone()
        if inv is None:
            fail("invite_not_found", 404)
            return
        secret_hash, inviter_identity, exp, max_uses, uses, revoked = inv
        if revoked or exp <= now or uses >= max_uses:
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
        # Find-or-create, KEYED BY identity. A second introduction reuses the
        # identity row -- it adds a relationship, never duplicates identity.
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
                peer_row = conn.execute(
                    "SELECT name FROM peers WHERE identity_pubkey=?", (pub_b64,)
                ).fetchone()
                if peer_row:
                    name = peer_row[0]
                    conn.execute(
                        "UPDATE peers SET token_hash=?, invited_by=? WHERE identity_pubkey=?",
                        (token_hash, inviter_identity, pub_b64),
                    )
                else:
                    name = _unique_guest_name_locked()
                    conn.execute(
                        """INSERT INTO peers(name, token_hash, created_at,
                                             identity_pubkey, invited_by, display_name)
                           VALUES(?,?,?,?,?,?)""",
                        (name, token_hash, now2, pub_b64, inviter_identity, name),
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

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        try:
            signal.signal(sig, _on_term)
        except (OSError, ValueError):
            pass


def main():
    global relay_cfg
    cfg = load_config()
    relay_cfg = cfg
    load_identity_key(cfg)
    _install_signal_trap()
    port = int(cfg.get("port", 18802))
    init_db(cfg)
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print("clack relay listening on 127.0.0.1:%d (peers: %s)" % (port, ",".join(sorted(peer_names))), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
