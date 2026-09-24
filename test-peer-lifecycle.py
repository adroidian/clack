#!/usr/bin/env python3
"""R1 regression: peer-name reassignment must not expose the old owner's state.

Replicates Flint's relay-review proof (R1) against the fixed code:
  1. config peer "alice" exists; queue a message + webhook for her
  2. remove alice from the config and rebuild (the exact init_db() path)
  3. assert her queued mail + webhook are gone and her name is retired
  4. enroll a FRESH Ed25519 identity requesting "alice"
  5. assert the name is NOT handed out, and the new identity sees no old
     state via poll (/v1/poll path: fetch_pending) or watch
  6. operator re-adds "alice" via config -> retirement clears, peer works

DB-level only (no HTTP listener): uses the real init_db() rebuild and the
real _enroll_identity_locked() enrollment core. Scratch temp dir; never
touches the production relay.
"""
import hashlib
import importlib.util
import os
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TMPD = tempfile.mkdtemp(prefix="clack-lifecycle-")
os.environ["CLACK_RELAY_BASE"] = TMPD

_spec = importlib.util.spec_from_file_location("relay_mod", os.path.join(HERE, "relay.py"))
_rm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_rm)

_spec_e = importlib.util.spec_from_file_location("ed25519_t", os.path.join(HERE, "ed25519.py"))
_ed = importlib.util.module_from_spec(_spec_e)
_spec_e.loader.exec_module(_ed)

PASS = 0
FAIL = 0


def check(cond, name, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("ok   %s" % name)
    else:
        FAIL += 1
        print("FAIL %s %s" % (name, detail))


def enroll(pub_b64, requested_name):
    """The real enrollment core, with the same locking the handlers use."""
    token_hash = hashlib.sha256(b"tok").hexdigest()
    with _rm.db_lock:
        _rm.conn.execute("BEGIN IMMEDIATE")
        try:
            name = _rm._enroll_identity_locked(
                pub_b64, token_hash, None, requested_name, time.time(),
                enroll_gate="open", enroll_ip="127.0.0.1")
            _rm.conn.execute("COMMIT")
        except Exception:
            _rm.conn.execute("ROLLBACK")
            raise
    return name


def b64u(b):
    import base64
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


# --- 1. config peer alice exists; queue mail + webhook ---------------------
_rm.init_db({"peers": {"alice": "tok-alice", "bob": "tok-bob"}})
now = time.time()
with _rm.db_lock:
    _rm.conn.execute(
        "INSERT INTO messages(id, sender, recipient, topic, text, created_at,"
        " expires_at) VALUES(?,?,?,?,?,?,?)",
        ("m1", "bob", "alice", "t", "secret-for-alice", now, now + 86400))
    _rm.conn.execute(
        "INSERT INTO webhooks(peer, url, created_at) VALUES(?,?,?)",
        ("alice", "https://hooks.example.com/nudge?secret=s3cr3t", now))
    _rm.conn.commit()
check(_rm.fetch_pending("alice", now) != [], "setup: alice has queued mail")

# --- 2. operator removes alice; rebuild ------------------------------------
_rm.init_db({"peers": {"bob": "tok-bob"}})

# --- 3. old state is gone, name retired ------------------------------------
with _rm.db_lock:
    peer_row = _rm.conn.execute(
        "SELECT 1 FROM peers WHERE name='alice'").fetchone()
    msgs = _rm.conn.execute(
        "SELECT COUNT(*) FROM messages WHERE recipient='alice'").fetchone()[0]
    hook = _rm.conn.execute(
        "SELECT 1 FROM webhooks WHERE peer='alice'").fetchone()
    retired = _rm.conn.execute(
        "SELECT 1 FROM retired_names WHERE name='alice'").fetchone()
    bob_row = _rm.conn.execute(
        "SELECT 1 FROM peers WHERE name='bob'").fetchone()
check(peer_row is None, "R1 removed peer row is gone")
check(msgs == 0, "R1 removed peer's queued mail deleted", msgs)
check(hook is None, "R1 removed peer's webhook deleted")
check(retired is not None, "R1 removed peer's name retired")
check(bob_row is not None, "R1 surviving peer untouched")

# retirement survives a second rebuild (no resurrection by restart)
_rm.init_db({"peers": {"bob": "tok-bob"}})
with _rm.db_lock:
    retired2 = _rm.conn.execute(
        "SELECT 1 FROM retired_names WHERE name='alice'").fetchone()
check(retired2 is not None, "R1 retirement persists across restarts")

# --- 4/5. fresh identity requests "alice" -----------------------------------
_, fresh_pub = _ed.keygen()
fresh_b64 = b64u(fresh_pub)
check(_ed.is_valid_pubkey(fresh_pub), "setup: fresh key is prime-order")
assigned = enroll(fresh_b64, "alice")
check(assigned != "alice", "R1 retired name not handed out", assigned)
check(_rm.fetch_pending(assigned, time.time()) == [],
      "R1 new identity sees no old mail")
with _rm.db_lock:
    hook2 = _rm.conn.execute(
        "SELECT 1 FROM webhooks WHERE peer=?", (assigned,)).fetchone()
check(hook2 is None, "R1 new identity inherits no webhook")

# --- 6. operator re-adds alice via config -> resurrection -------------------
_rm.init_db({"peers": {"alice": "tok-alice2", "bob": "tok-bob"}})
with _rm.db_lock:
    alive = _rm.conn.execute(
        "SELECT 1 FROM peers WHERE name='alice'").fetchone()
    retired3 = _rm.conn.execute(
        "SELECT 1 FROM retired_names WHERE name='alice'").fetchone()
check(alive is not None, "R1 operator can resurrect the name via config")
check(retired3 is None, "R1 resurrection clears the retirement")

print("\npeer-lifecycle: %d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
