#!/usr/bin/env python3
"""CLI for the Clack A2A relay.

Two config flavors (auto-detected):

  legacy:   relay-config.json style {"peers": {"nugget": "<token>"}, ...}
            -- existing commands keep working exactly as before.
  identity: {"kind": "clack-identity-v1", "relay_url": ..., "identity_pubkey":
            ..., "identity_privkey": ..., "service_token": ..., "peer_name": ...}
            -- created by `keygen` / `redeem`, used by every command.

Invite-link onboarding (v0.2.5 MVP):
  keygen                     create an ed25519 identity (mode 600)
  mint-invite                mint a shareable join link (any authed peer)
  redeem <link>              full join flow: confirm -> keygen -> challenge ->
                             sign -> redeem -> save config -> send hello
  invite-list / invite-revoke  manage your outstanding invites

Agent self-enrollment (v0.2.9):
  enroll                     no link needed: confirm -> keygen -> challenge ->
                             (solve PoW) -> sign -> enroll -> save config.
                             Uses the relay's enabled enrollment gate
                             (invite/pow/open); --invite-id/--secret select
                             the invite gate explicitly.

Never print a token or private key.
"""
import argparse
import base64
import datetime
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid

# --- BEGIN vendored ed25519 (inlined from ed25519.py; that file remains
# --- the canonical, libsodium-verified copy) ---
"""Ed25519 sign/verify/keygen, pure stdlib.

This is the public-domain reference implementation by Daniel J. Bernstein,
Niels Duif, Tanja Lange, Peter Schwabe and Bo-Yin Yang
(http://ed25519.cr.yp.to/python/ed25519.py), trimmed to keygen/sign/verify
and wrapped in a small friendly API.

Vendored (not a new dependency) because the relay is stdlib-only by design
and neither `cryptography` nor PyNaCl is guaranteed on every machine that
runs it (verified absent 2026-09-21). Pure-Python signing costs ~50-200ms
per operation -- fine for invite flows, which are rare. Do NOT use this for
high-throughput signing; that is out of scope for the relay.
"""

import hashlib
import secrets as _secrets

b = 256
q = (1 << 255) - 19
l = (1 << 252) + 27742317777372353535851937790883648493


def _H(m):
    return hashlib.sha512(m).digest()


def _expmod(base, exp, mod):
    if exp == 0:
        return 1
    t = _expmod(base, exp // 2, mod) ** 2 % mod
    if exp & 1:
        t = (t * base) % mod
    return t


def _inv(x):
    return _expmod(x, q - 2, q)


_d = -121665 * _inv(121666)
_I = _expmod(2, (q - 1) // 4, q)


def _xrecover(y):
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = _expmod(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0:
        x = (x * _I) % q
    if x % 2 != 0:
        x = q - x
    return x


_By = 4 * _inv(5)
_Bx = _xrecover(_By)
_B = [_Bx % q, _By % q]


def _edwards(P, Q):
    # Twisted Edwards addition for a*x^2 + y^2 = 1 + d*x^2*y^2 with a = -1
    # (Ed25519). NOTE the y-numerator is (y1*y2 + x1*x2): the "- a*x1*x2"
    # term becomes "+" when a = -1. Getting this sign wrong produces a
    # self-consistent-but-wrong group law that fails the l*B == identity
    # check -- which is exactly how the bug was caught (2026-09-21).
    x1, y1 = P[0], P[1]
    x2, y2 = Q[0], Q[1]
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _d * x1 * x2 * y1 * y2)
    return [x3 % q, y3 % q]


def _scalarmult(P, e):
    if e == 0:
        return [0, 1]
    Q = _scalarmult(P, e // 2)
    Q = _edwards(Q, Q)
    if e & 1:
        Q = _edwards(Q, P)
    return Q


def _encodeint(y):
    bits = [(y >> i) & 1 for i in range(b)]
    return b"".join(
        bytes([sum(bits[i * 8 + j] << j for j in range(8))]) for i in range(b // 8)
    )


def _encodepoint(P):
    x, y = P[0], P[1]
    bits = [(y >> i) & 1 for i in range(b - 1)] + [x & 1]
    return b"".join(
        bytes([sum(bits[i * 8 + j] << j for j in range(8))]) for i in range(b // 8)
    )


def _bit(h, i):
    return (h[i // 8] >> (i % 8)) & 1


def _publickey(sk):
    h = _H(sk)
    a = 2 ** (b - 2) + sum(2**i * _bit(h, i) for i in range(3, b - 2))
    return _encodepoint(_scalarmult(_B, a))


def _Hint(m):
    h = _H(m)
    return sum(2**i * _bit(h, i) for i in range(2 * b))


def _signature(m, sk, pk):
    h = _H(sk)
    a = 2 ** (b - 2) + sum(2**i * _bit(h, i) for i in range(3, b - 2))
    r = _Hint(h[b // 8 : b // 4] + m)
    R = _scalarmult(_B, r)
    S = (r + _Hint(_encodepoint(R) + pk + m) * a) % l
    return _encodepoint(R) + _encodeint(S)


def _isoncurve(P):
    x, y = P[0], P[1]
    return (-x * x + y * y - 1 - _d * x * x * y * y) % q == 0


def _decodeint(s):
    return sum(2**i * _bit(s, i) for i in range(b))


def _decodepoint(s):
    y = sum(2**i * _bit(s, i) for i in range(b - 1))
    sign = _bit(s, b - 1)
    x = _xrecover(y)
    if x & 1 != sign:
        x = q - x
    P = [x, y]
    if not _isoncurve(P):
        raise ValueError("decoding point that is not on curve")
    return P


def _checkvalid(s, m, pk):
    if len(s) != b // 4:
        raise ValueError("signature length is wrong")
    if len(pk) != b // 8:
        raise ValueError("public-key length is wrong")
    R = _decodepoint(s[0 : b // 8])
    A = _decodepoint(pk)
    S = _decodeint(s[b // 8 : b // 4])
    h = _Hint(_encodepoint(R) + pk + m)
    v1 = _scalarmult(_B, S)
    v2 = _edwards(R, _scalarmult(A, h))
    return v1 == v2


# --- Friendly API -----------------------------------------------------------


def keygen():
    """Generate a fresh ed25519 keypair. Returns (seed_bytes, pubkey_bytes)."""
    seed = _secrets.token_bytes(32)
    return seed, _publickey(seed)


def sign(seed, msg):
    """Sign msg (bytes) with the 32-byte seed. Returns 64-byte signature."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    return _signature(bytes(msg), bytes(seed), _publickey(bytes(seed)))


def verify(pubkey, signature, msg):
    """Verify. Returns True/False, never raises on bad input."""
    try:
        return bool(_checkvalid(bytes(signature), bytes(msg), bytes(pubkey)))
    except Exception:
        return False
# --- END vendored ed25519 ---

BASE = os.path.expanduser("~/workspace/clack-relay")
DEFAULT_CONFIG = os.environ.get(
    "CLACK_RELAY_CONFIG", os.path.join(BASE, "relay-config.json")
)
IDENTITY_KIND = "clack-identity-v1"


def b64u_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64u_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def load_config(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def is_identity_cfg(cfg):
    return isinstance(cfg, dict) and cfg.get("kind") == IDENTITY_KIND


# Peer name selected via --peer for legacy (token) configs. None means
# "nugget" for backward compatibility, or the only peer if there is one.
_selected_peer = None


def auth_token(cfg):
    if is_identity_cfg(cfg):
        return cfg.get("service_token")
    peers = cfg.get("peers") or {}
    if _selected_peer:
        return peers.get(_selected_peer)
    if "nugget" in peers:
        return peers["nugget"]
    if len(peers) == 1:
        return next(iter(peers.values()))
    return None


def base_url(cfg):
    if is_identity_cfg(cfg):
        return cfg["relay_url"].rstrip("/")
    return (cfg.get("base_url") or "http://127.0.0.1:%d" % cfg.get("port", 18802)).rstrip("/")


def user_agent(cfg):
    return cfg.get("user_agent") or "ClackRelay-CLI/0.2.9"


def req(cfg, method, path, body=None, base=None):
    url = (base or base_url(cfg)) + path
    token = auth_token(cfg)
    data = json.dumps(body).encode("utf-8") if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    if token:
        r.add_header("Authorization", "Bearer " + token)
    r.add_header("User-Agent", user_agent(cfg))
    if data is not None:
        r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r, timeout=130) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read().decode("utf-8"))
        except Exception:
            payload = {"error": "http_%d" % e.code}
        return e.code, payload


# --- Relay identity (TOFU, v0.2.10) -------------------------------------------
# The relay exposes its STABLE identity public key at GET /v1/identity. The
# fingerprint is computed over that key -- never over the per-nonce
# signature, which varies every run and is unconfirmable theater. The
# construction is: sha256("clack-relay-identity-v1" || ":" || n_be || ":"
# || e_be), displayed as "sha256:<first 16 hex chars>", where n_be / e_be
# are the minimal big-endian encodings of the "n" / "e" hex fields.

_IDENTITY_FP_DOMAIN = b"clack-relay-identity-v1"


def relay_identity_fingerprint(pubkey):
    """Stable fingerprint of a relay identity public key {"n": hex, "e": hex}."""
    n = int(pubkey["n"], 16)
    e = int(pubkey["e"], 16)
    n_be = n.to_bytes((n.bit_length() + 7) // 8, "big")
    e_be = e.to_bytes((e.bit_length() + 7) // 8, "big")
    digest = hashlib.sha256(_IDENTITY_FP_DOMAIN + b":" + n_be + b":" + e_be).hexdigest()
    return "sha256:" + digest[:16]


_SHA256_DINFO_HEAD = bytes.fromhex("3031300d060960864801650304020105000420")


def relay_identity_verify(pubkey, nonce_hex, signature_b64):
    """Verify the relay's /v1/identity nonce signature. Pure stdlib RSA."""
    n = int(pubkey["n"], 16)
    e = int(pubkey["e"], 16)
    nonce = bytes.fromhex(nonce_hex)
    sig = base64.b64decode(signature_b64)
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    t = _SHA256_DINFO_HEAD + hashlib.sha256(nonce).digest()
    em = pow(int.from_bytes(sig, "big"), e, n).to_bytes(k, "big")
    expect = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return em == expect


def fetch_relay_identity(relay_url):
    """Fetch and verify the relay's identity.

    Returns (fingerprint, pubkey). Raises on transport/HTTP errors other
    than 503 (relay has no identity key), in which case returns (None, None)
    and the caller must warn loudly.
    """
    nonce = os.urandom(32).hex()
    try:
        with urllib.request.urlopen(
            relay_url + "/v1/identity?nonce=" + nonce, timeout=30
        ) as resp:
            ident = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 503:
            return None, None
        raise
    pubkey = ident.get("public_key")
    if not pubkey or "n" not in pubkey or "e" not in pubkey:
        raise ValueError("relay identity response has no public_key")
    if not relay_identity_verify(pubkey, ident["nonce"], ident["signature"]):
        raise ValueError("relay identity signature verification failed")
    return relay_identity_fingerprint(pubkey), pubkey


def check_relay_identity(relay_url, cfg):
    """TOFU for the identity-establishing flows (redeem, enroll).

    Fetches the relay's stable identity key, verifies the nonce signature
    against it, and enforces the pinned fingerprint when the config already
    has one. Returns the fingerprint (or None when the relay has no
    identity key). Aborts the process on pin mismatch -- a changed relay
    key is never silently accepted.
    """
    try:
        fingerprint, _pubkey = fetch_relay_identity(relay_url)
    except urllib.error.HTTPError as e:
        print("could not verify relay identity: HTTP Error %d" % e.code,
              file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print("could not verify relay identity: %s" % e, file=sys.stderr)
        sys.exit(1)
    if fingerprint is None:
        return None
    pinned = (cfg or {}).get("relay_identity_fingerprint")
    if pinned and pinned != fingerprint:
        print("RELAY IDENTITY CHANGED: pinned %s but relay now presents %s"
              % (pinned, fingerprint), file=sys.stderr)
        print("aborting: verify out-of-band before proceeding", file=sys.stderr)
        sys.exit(1)
    return fingerprint


def cmd_keygen(args):
    if os.path.exists(args.config) and not args.force:
        print("refusing to overwrite existing %s (use --force)" % args.config,
              file=sys.stderr)
        return 1
    seed, pub = keygen()
    cfg = {
        "kind": IDENTITY_KIND,
        "relay_url": args.relay_url,
        "identity_pubkey": b64u_encode(pub),
        "identity_privkey": b64u_encode(seed),
    }
    if args.user_agent:
        cfg["user_agent"] = args.user_agent
    os.makedirs(os.path.dirname(os.path.abspath(args.config)) or ".", exist_ok=True)
    fd = os.open(args.config, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
        f.write("\n")
    print("identity created: %s" % args.config)
    print("pubkey: %s" % cfg["identity_pubkey"])
    return 0


def parse_link(link):
    link = link.strip()
    if "#" not in link:
        raise ValueError("link has no fragment")
    frag = link.split("#", 1)[1]
    q = urllib.parse.parse_qs(frag, keep_blank_values=True)
    get = lambda k: (q.get(k) or [None])[0]
    fields = {k: get(k) for k in ("r", "i", "k", "v", "by", "exp")}
    if not fields["r"] or not fields["i"] or not fields["k"]:
        raise ValueError("link missing r/i/k fields")
    return fields


def cmd_mint_invite(args, cfg):
    body = {
        "expiry_seconds": int(args.expiry_hours * 3600),
        "max_uses": args.max_uses,
    }
    code, out = req(cfg, "POST", "/v1/invites/mint", body, base=args.base_url)
    if 200 <= code < 300:
        print(out["link"])
        print("invite_id: %s" % out["invite_id"])
        print("expires:   %s" % datetime.datetime.fromtimestamp(out["exp"]).strftime("%Y-%m-%d %H:%M:%S"))
        print("max_uses:  %d" % out["max_uses"])
    else:
        print(json.dumps(out, indent=2))
    return 0 if 200 <= code < 300 else 1


def cmd_redeem(args):
    try:
        f = parse_link(args.link)
    except ValueError as e:
        print("bad link: %s" % e, file=sys.stderr)
        return 1
    relay_url = b64u_decode(f["r"]).decode("utf-8")
    exp_human = datetime.datetime.fromtimestamp(int(f["exp"])).strftime("%Y-%m-%d %H:%M:%S")

    # Fetch the relay's stable identity key BEFORE sending the secret
    # anywhere (TOFU: the human sees the fingerprint at the confirmation
    # tap, and it is pinned in the saved config). If the relay has no
    # identity key, warn loudly and continue -- a fresh relay shouldn't
    # brick onboarding, but the human must know the relay is unauthenticated.
    existing_cfg = load_config(args.config) if os.path.exists(args.config) else None
    relay_fp = check_relay_identity(relay_url, existing_cfg)

    print("You are about to join a relay:")
    print("  relay:            %s" % relay_url)
    if relay_fp:
        print("  relay key (TOFU): %s  <- stable key; confirm once, pinned after" % relay_fp)
    else:
        print("  relay key (TOFU): UNAVAILABLE (relay has no identity key) --")
        print("                    continuing without relay authentication")
    print("  invited by:       %s" % f["by"])
    print("  link expires:     %s" % exp_human)
    print("  link version:     %s" % f["v"])
    print()
    print("This creates YOUR OWN identity keypair on this machine. The relay")
    print("never sees your private key.")
    ans = input("Type YES to redeem this invitation: ").strip()
    if ans != "YES":
        print("aborted.")
        return 1

    # Load or create the identity at --config (existing config = existing
    # user path: the same identity is reused, never duplicated).
    if os.path.exists(args.config):
        cfg = load_config(args.config)
        if not is_identity_cfg(cfg):
            print("%s exists but is not an identity config" % args.config,
                  file=sys.stderr)
            return 1
        if cfg.get("relay_url", "").rstrip("/") != relay_url:
            print("warning: config targets %s, link targets %s"
                  % (cfg.get("relay_url"), relay_url), file=sys.stderr)
    else:
        seed, pub = keygen()
        cfg = {
            "kind": IDENTITY_KIND,
            "relay_url": relay_url,
            "identity_pubkey": b64u_encode(pub),
            "identity_privkey": b64u_encode(seed),
            "user_agent": "ClackRelay-CLI/0.2.9",
        }
    seed = b64u_decode(cfg["identity_privkey"])
    pub = b64u_decode(cfg["identity_pubkey"])

    # Challenge -> sign(nonce || invite_id || pubkey) -> redeem.
    code, ch = req(cfg, "POST", "/v1/invites/challenge",
                   {"invite_id": f["i"]}, base=relay_url)
    if not (200 <= code < 300):
        print("challenge failed: %s" % json.dumps(ch), file=sys.stderr)
        return 1
    nonce_raw = b64u_decode(ch["nonce"])
    sig = sign(seed, nonce_raw + f["i"].encode("utf-8") + pub)
    code, out = req(cfg, "POST", "/v1/invites/redeem", {
        "invite_id": f["i"],
        "secret": f["k"],
        "identity_pubkey": b64u_encode(pub),
        "proof": {"nonce": ch["nonce"], "signature": b64u_encode(sig)},
    }, base=relay_url)
    if not (200 <= code < 300):
        print("redeem failed: %s" % json.dumps(out), file=sys.stderr)
        return 1

    cfg["service_token"] = out["service_token"]
    cfg["peer_name"] = out["peer_name"]
    cfg["display_name"] = out["display_name"]
    if relay_fp:
        cfg["relay_identity_fingerprint"] = relay_fp  # TOFU pin
    fd = os.open(args.config, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2)
        fh.write("\n")
    print("enrolled as %s (identity %s...)" % (out["peer_name"], out["identity"][:12]))

    # Greeting exchange: hello to the inviter. Onboarding succeeds when the
    # invitee receives AND acknowledges the inviter's reply (checked by the
    # inviter via /v1/receipts -> acked).
    inviter = out.get("inviter_name")
    if inviter:
        hello_id = str(uuid.uuid4())
        code, sent = req(cfg, "POST", "/v1/send", {
            "id": hello_id,
            "to": inviter,
            "topic": "introductions",
            "text": "hello %s -- joined via your invite link (Clack onboarding MVP)" % inviter,
        }, base=relay_url)
        if 200 <= code < 300:
            print("hello sent to %s (id %s)" % (inviter, hello_id))
        else:
            print("hello failed: %s" % json.dumps(sent), file=sys.stderr)
    else:
        print("note: inviter has no messageable peer name; skipping hello")
    print("config saved: %s" % args.config)
    return 0


def _pow_lead_zero(digest):
    """Count leading zero bits of a SHA-256 digest (PoW check)."""
    n = 0
    for byte in digest:
        if byte == 0:
            n += 8
        else:
            n += 8 - byte.bit_length()
            break
    return n


def cmd_enroll(args):
    # Resolve the relay URL: explicit --relay wins; otherwise reuse the
    # existing identity config's relay_url (same machine, new enrollment).
    relay_url = args.relay
    if not relay_url and os.path.exists(args.config):
        try:
            cfg0 = load_config(args.config)
            if is_identity_cfg(cfg0):
                relay_url = cfg0.get("relay_url")
        except Exception:
            pass
    if not relay_url:
        print("no relay URL: pass --relay <url> "
              "(or keep a relay_url in %s)" % args.config, file=sys.stderr)
        return 1
    relay_url = relay_url.rstrip("/")
    invite_id = args.invite_id
    if invite_id and not args.secret:
        print("--invite-id needs --secret", file=sys.stderr)
        return 1

    # Fetch the relay's stable identity key BEFORE enrolling (TOFU: the human
    # sees the fingerprint at the confirmation tap, and it is pinned in the
    # saved config), mirroring redeem.
    existing_cfg = load_config(args.config) if os.path.exists(args.config) else None
    relay_fp = check_relay_identity(relay_url, existing_cfg)

    print("You are about to enroll a new agent identity on a relay:")
    print("  relay:            %s" % relay_url)
    if relay_fp:
        print("  relay key (TOFU): %s  <- stable key; confirm once, pinned after" % relay_fp)
    else:
        print("  relay key (TOFU): UNAVAILABLE (relay has no identity key) --")
        print("                    continuing without relay authentication")
    if invite_id:
        print("  invite gate:      %s" % invite_id)
    if args.name:
        print("  desired name:     %s" % args.name)
    print()
    print("This creates YOUR OWN identity keypair on this machine. The relay")
    print("never sees your private key.")
    ans = None
    if args.yes:
        pass  # non-interactive agent use: the caller already decided
    elif not sys.stdin.isatty():
        print("not a terminal: re-run with --yes to enroll non-interactively",
              file=sys.stderr)
        return 1
    else:
        ans = input("Type YES to enroll: ").strip()
    if ans is not None and ans != "YES":
        print("aborted.")
        return 1

    # Load or create the identity at --config (existing config = existing
    # user path: the same identity is reused, never duplicated).
    if os.path.exists(args.config):
        cfg = load_config(args.config)
        if not is_identity_cfg(cfg):
            print("%s exists but is not an identity config" % args.config,
                  file=sys.stderr)
            return 1
        if cfg.get("relay_url", "").rstrip("/") != relay_url:
            print("warning: config targets %s, enrolling on %s"
                  % (cfg.get("relay_url"), relay_url), file=sys.stderr)
    else:
        seed, pub = keygen()
        cfg = {
            "kind": IDENTITY_KIND,
            "relay_url": relay_url,
            "identity_pubkey": b64u_encode(pub),
            "identity_privkey": b64u_encode(seed),
            "user_agent": "ClackRelay-CLI/0.2.9",
        }
    seed = b64u_decode(cfg["identity_privkey"])
    pub = b64u_decode(cfg["identity_pubkey"])

    # Challenge -> (solve PoW when the gate is pow) -> sign -> enroll.
    ch_body = {"invite_id": invite_id} if invite_id else {}
    code, ch = req(cfg, "POST", "/v1/enroll/challenge", ch_body, base=relay_url)
    if not (200 <= code < 300):
        print("challenge failed: %s" % json.dumps(ch), file=sys.stderr)
        return 1
    gate = ch.get("gate")
    chal_raw = b64u_decode(ch["challenge"] if gate == "pow" else ch["nonce"])
    body = {"identity_pubkey": b64u_encode(pub)}
    if args.name:
        body["name"] = args.name
    if gate == "pow":
        difficulty = int(ch.get("difficulty", 20))
        pow_nonce = None
        while pow_nonce is None:
            cand = os.urandom(16)
            if _pow_lead_zero(hashlib.sha256(chal_raw + cand).digest()) >= difficulty:
                pow_nonce = cand
        body["pow_nonce"] = b64u_encode(pow_nonce)
        sig = sign(seed, chal_raw + pow_nonce + pub)
    elif gate == "invite":
        body["invite_id"] = invite_id
        body["secret"] = args.secret
        sig = sign(seed, chal_raw + invite_id.encode("utf-8") + pub)
    elif gate == "open":
        sig = sign(seed, chal_raw + pub)
    else:
        print("unknown enrollment gate: %r" % gate, file=sys.stderr)
        return 1
    body["proof"] = {"nonce": b64u_encode(chal_raw),
                     "signature": b64u_encode(sig)}
    code, out = req(cfg, "POST", "/v1/enroll", body, base=relay_url)
    if not (200 <= code < 300):
        print("enroll failed: %s" % json.dumps(out), file=sys.stderr)
        return 1

    # Same config-save path as redeem: same file, same mode 600.
    cfg["relay_url"] = relay_url
    cfg["service_token"] = out["service_token"]
    cfg["peer_name"] = out["peer_name"]
    cfg["display_name"] = out["display_name"]
    if relay_fp:
        cfg["relay_identity_fingerprint"] = relay_fp  # TOFU pin
    fd = os.open(args.config, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2)
        fh.write("\n")
    print("enrolled as %s (identity %s..., via %s gate)"
          % (out["peer_name"], out["identity"][:12], out.get("enrollment")))

    # Greeting exchange, mirroring redeem: hello to the inviter when the
    # invite gate names one.
    inviter = out.get("inviter_name")
    if inviter:
        hello_id = str(uuid.uuid4())
        code, sent = req(cfg, "POST", "/v1/send", {
            "id": hello_id,
            "to": inviter,
            "topic": "introductions",
            "text": "hello %s -- self-enrolled on the relay (Clack agent onboarding)" % inviter,
        }, base=relay_url)
        if 200 <= code < 300:
            print("hello sent to %s (id %s)" % (inviter, hello_id))
        else:
            print("hello failed: %s" % json.dumps(sent), file=sys.stderr)
    print("config saved: %s" % args.config)
    return 0


def cmd_invite_list(args, cfg):
    code, out = req(cfg, "GET", "/v1/invites/list", base=args.base_url)
    print(json.dumps(out, indent=2))
    return 0 if 200 <= code < 300 else 1


def cmd_invite_revoke(args, cfg):
    code, out = req(cfg, "POST", "/v1/invites/revoke",
                    {"invite_id": args.invite_id}, base=args.base_url)
    print(json.dumps(out, indent=2))
    return 0 if 200 <= code < 300 else 1


def main():
    ap = argparse.ArgumentParser(description="Clack relay CLI")
    ap.add_argument("--config", default=DEFAULT_CONFIG,
                    help="config path (legacy relay-config.json or identity config)")
    ap.add_argument("--base-url", default=None, help="override relay base URL")
    ap.add_argument("--peer", default=None,
                    help="peer name for legacy token configs "
                         "(default: nugget, or the only peer if there is one)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    # --- existing commands (legacy-compatible) ---
    p = sub.add_parser("poll", help="long-poll for your messages")
    p.add_argument("--timeout", type=float, default=25.0)

    r = sub.add_parser("receipts", help="delivery states of messages you sent")
    r.add_argument("--since", type=float, default=0.0)
    r.add_argument("--limit", type=int, default=100)

    w = sub.add_parser("watch", help="wake-nudge webhook: show, set, or clear")
    w.add_argument("--url", default=None)
    w.add_argument("--clear", action="store_true")

    s = sub.add_parser("send", help="send a text message")
    s.add_argument("--to", required=True)
    s.add_argument("--text", required=True)
    s.add_argument("--topic", default=None)
    s.add_argument("--in-reply-to", default=None)
    s.add_argument("--id", default=None)

    a = sub.add_parser("ack", help="ack handled message ids")
    a.add_argument("--ids", required=True, help="comma-separated ids")

    sub.add_parser("peers", help="list peer names")

    # --- invite-link onboarding (v0.2.5 MVP) ---
    k = sub.add_parser("keygen", help="create an ed25519 identity config")
    k.add_argument("--relay-url", required=True, help="relay base URL, e.g. http://127.0.0.1:18998")
    k.add_argument("--force", action="store_true", help="overwrite existing config")
    k.add_argument("--user-agent", default=None)

    m = sub.add_parser("mint-invite", help="mint a shareable join link")
    m.add_argument("--max-uses", type=int, default=1)
    m.add_argument("--expiry-hours", type=float, default=24.0)

    rd = sub.add_parser("redeem", help="redeem an invite link (full join flow)")
    rd.add_argument("link", help="the invite link (or its #fragment payload)")

    e = sub.add_parser("enroll", help="self-enroll a new agent identity (v0.2.9)")
    e.add_argument("--name", default=None, help="desired peer name (optional)")
    e.add_argument("--invite-id", default=None, help="invite id (invite gate)")
    e.add_argument("--secret", default=None, help="invite claim secret (invite gate)")
    e.add_argument("--relay", default=None,
                   help="relay base URL, e.g. http://127.0.0.1:18998")
    e.add_argument("--yes", action="store_true",
                   help="skip the confirmation prompt (non-interactive/agent use)")

    sub.add_parser("invite-list", help="list your outstanding invites")
    rv = sub.add_parser("invite-revoke", help="revoke one of your invites")
    rv.add_argument("invite_id")

    args = ap.parse_args()
    global _selected_peer
    _selected_peer = args.peer

    if args.cmd in ("keygen", "redeem", "enroll"):
        # These manage the identity config file itself; no prior config needed.
        if args.cmd == "keygen":
            return cmd_keygen(args)
        if args.cmd == "redeem":
            return cmd_redeem(args)
        return cmd_enroll(args)

    cfg = load_config(args.config)
    token = auth_token(cfg)
    if not token and args.cmd in ("mint-invite", "invite-list", "invite-revoke",
                                  "poll", "receipts", "watch", "send", "ack"):
        print("no usable auth token in %s" % args.config, file=sys.stderr)
        return 1

    if args.cmd == "poll":
        t = float(args.timeout)
        t_str = str(int(t)) if t.is_integer() else str(t)
        code, out = req(cfg, "GET", "/v1/poll?timeout=%s" % t_str, base=args.base_url)
    elif args.cmd == "receipts":
        code, out = req(cfg, "GET",
                        "/v1/receipts?since=%s&limit=%d" % (args.since, args.limit),
                        base=args.base_url)
    elif args.cmd == "watch":
        if args.clear:
            code, out = req(cfg, "POST", "/v1/watch", {"url": None}, base=args.base_url)
        elif args.url:
            code, out = req(cfg, "POST", "/v1/watch", {"url": args.url}, base=args.base_url)
        else:
            code, out = req(cfg, "GET", "/v1/watch", base=args.base_url)
    elif args.cmd == "send":
        body = {"id": args.id or str(uuid.uuid4()), "to": args.to, "text": args.text}
        if args.topic:
            body["topic"] = args.topic
        if args.in_reply_to:
            body["in_reply_to"] = args.in_reply_to
        code, out = req(cfg, "POST", "/v1/send", body, base=args.base_url)
    elif args.cmd == "ack":
        ids = [i.strip() for i in args.ids.split(",") if i.strip()]
        code, out = req(cfg, "POST", "/v1/ack", {"ids": ids}, base=args.base_url)
    elif args.cmd == "peers":
        code, out = req(cfg, "GET", "/v1/peers", base=args.base_url)
    elif args.cmd == "mint-invite":
        return cmd_mint_invite(args, cfg)
    elif args.cmd == "invite-list":
        return cmd_invite_list(args, cfg)
    elif args.cmd == "invite-revoke":
        return cmd_invite_revoke(args, cfg)

    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0 if 200 <= code < 300 else 1


if __name__ == "__main__":
    sys.exit(main())
