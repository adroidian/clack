#!/usr/bin/env python3
"""peer_hashes regression test (scratch only, never live).

Covers Zari's target-A compatibility defect: config peers provisioned
hash-only via the "peer_hashes" config map ({name: hex(sha256(token))})
must survive the init_db config rebuild -- they must NOT be revoked,
their queued messages/webhooks must NOT be deleted, and their names
must NOT be retired.

Also covers: strict validation of peer_hashes, fail-closed on a name
appearing in both peers and peer_hashes, identity_pubkeys for hash-only
peers, plaintext->hash migration without revocation, and that dropping
a hash-only peer from the config still revokes it (restart revocation
semantics preserved).
"""
import hashlib
import importlib.util
import os
import sqlite3
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
RELAY_PY = os.path.join(HERE, "relay.py")

PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("ok   %s" % name)
    else:
        FAIL += 1
        print("FAIL %s %s" % (name, detail))


def load_relay(tmpd):
    spec = importlib.util.spec_from_file_location("relay_under_test", RELAY_PY)
    relay = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(relay)
    relay.BASE = tmpd
    relay.DB_PATH = os.path.join(tmpd, "clack.db")
    relay._IDENTITY_PUBKEYS = {}
    relay._PEER_HASHES = {}
    return relay


HASH_ONLY_TOKEN = "synthetic-token-for-hash-only-peer"
HASH_ONLY_HEX = hashlib.sha256(HASH_ONLY_TOKEN.encode()).hexdigest()
LEGACY_TOKEN = "legacy-plaintext-token"


def base_cfg(**over):
    cfg = {"peers": {"scratch-legacy": LEGACY_TOKEN},
           "peer_hashes": {"scratch-hash-only": HASH_ONLY_HEX}}
    cfg.update(over)
    return cfg


def fresh_db_with_legacy_row(relay):
    """init schema, then plant a legacy 3-column peers row (no gate,
    no identity key) plus one queued message and one webhook for it --
    the pre-upgrade state on a hash-only-provisioned host."""
    relay._init_peer_hashes({"peers": {}, "peer_hashes": {}})
    relay.init_db({"peers": {}, "peer_hashes": {}})
    db = sqlite3.connect(relay.DB_PATH)
    now = time.time()
    db.execute("INSERT INTO peers(name, token_hash, created_at)"
               " VALUES(?,?,?)",
               ("scratch-hash-only", HASH_ONLY_HEX, now - 1000))
    db.execute("INSERT INTO messages(id, sender, recipient, topic, text,"
               " in_reply_to, created_at, expires_at, acked_at, collected_at)"
               " VALUES(?,?,?,?,?,?,?,?,?,?)",
               ("msg-1", "scratch-legacy", "scratch-hash-only", "t",
                "queued before upgrade", None, now, now + 3600, None, None))
    db.execute("INSERT INTO webhooks(peer, url, created_at)"
               " VALUES(?,?,?)",
               ("scratch-hash-only", "https://example.invalid/hook", now))
    db.commit()
    db.close()


def main():
    # --- Test 1: Zari's repro -- hash-only peer survives the rebuild ---
    tmpd = tempfile.mkdtemp(prefix="clack-peerhash-")
    relay = load_relay(tmpd)
    fresh_db_with_legacy_row(relay)
    cfg = base_cfg()
    relay._init_peer_hashes(cfg)
    relay.init_db(cfg)
    db = sqlite3.connect(relay.DB_PATH)
    row = db.execute("SELECT token_hash, enroll_gate FROM peers"
                     " WHERE name=?", ("scratch-hash-only",)).fetchone()
    check("hash-only peer survives rebuild", row is not None)
    check("hash-only token_hash verbatim (never re-derived)",
          row is not None and row[0] == HASH_ONLY_HEX, "got %r" % (row,))
    check("hash-only peer is config-gated",
          row is not None and row[1] == "config")
    check("legacy plaintext peer enrolled",
          db.execute("SELECT token_hash FROM peers WHERE name=?",
                     ("scratch-legacy",)).fetchone()[0]
          == hashlib.sha256(LEGACY_TOKEN.encode()).hexdigest())
    check("queued message retained",
          db.execute("SELECT 1 FROM messages WHERE id='msg-1'").fetchone()
          is not None)
    check("webhook retained",
          db.execute("SELECT 1 FROM webhooks WHERE peer='scratch-hash-only'")
          .fetchone() is not None)
    check("name not retired",
          db.execute("SELECT 1 FROM retired_names WHERE name="
                     "'scratch-hash-only'").fetchone() is None)
    db.close()

    # --- Test 2: dropping the hash-only peer from config still revokes ---
    relay._init_peer_hashes({"peers": {"scratch-legacy": LEGACY_TOKEN}})
    relay.init_db({"peers": {"scratch-legacy": LEGACY_TOKEN}})
    db = sqlite3.connect(relay.DB_PATH)
    check("removed hash-only peer row deleted",
          db.execute("SELECT 1 FROM peers WHERE name='scratch-hash-only'")
          .fetchone() is None)
    check("removed hash-only peer messages dead-lettered/deleted",
          db.execute("SELECT 1 FROM messages WHERE id='msg-1'").fetchone()
          is None)
    check("removed hash-only peer webhook deleted",
          db.execute("SELECT 1 FROM webhooks WHERE peer='scratch-hash-only'")
          .fetchone() is None)
    check("removed hash-only peer name retired",
          db.execute("SELECT 1 FROM retired_names WHERE name="
                     "'scratch-hash-only'").fetchone() is not None)
    check("surviving peer untouched",
          db.execute("SELECT 1 FROM peers WHERE name='scratch-legacy'")
          .fetchone() is not None)
    db.close()

    # --- Test 3: plaintext -> hash migration does not revoke ---
    tmpd = tempfile.mkdtemp(prefix="clack-peerhash-mig-")
    relay = load_relay(tmpd)
    cfg_a = {"peers": {"migrating": LEGACY_TOKEN}}
    relay._init_peer_hashes(cfg_a)
    relay.init_db(cfg_a)
    db = sqlite3.connect(relay.DB_PATH)
    now = time.time()
    db.execute("INSERT INTO messages(id, sender, recipient, topic, text,"
               " in_reply_to, created_at, expires_at, acked_at, collected_at)"
               " VALUES(?,?,?,?,?,?,?,?,?,?)",
               ("msg-m", "scratch-legacy", "migrating", "t", "hi",
                None, now, now + 3600, None, None))
    db.commit()
    db.close()
    mig_hex = hashlib.sha256(LEGACY_TOKEN.encode()).hexdigest()
    cfg_b = {"peer_hashes": {"migrating": mig_hex}}
    relay._init_peer_hashes(cfg_b)
    relay.init_db(cfg_b)
    db = sqlite3.connect(relay.DB_PATH)
    row = db.execute("SELECT token_hash FROM peers WHERE name=?",
                     ("migrating",)).fetchone()
    check("migrated peer survives", row is not None and row[0] == mig_hex)
    check("migrated peer messages retained",
          db.execute("SELECT 1 FROM messages WHERE id='msg-m'").fetchone()
          is not None)
    check("migrated peer name not retired",
          db.execute("SELECT 1 FROM retired_names WHERE name='migrating'")
          .fetchone() is None)
    db.close()

    # --- Test 4: strict validation ---
    tmpd = tempfile.mkdtemp(prefix="clack-peerhash-val-")
    relay = load_relay(tmpd)
    for bad, label in [
        ({"peer_hashes": {"x": "nothex"}}, "non-hex rejected"),
        ({"peer_hashes": {"x": "ab" * 31}}, "short hash rejected"),
        ({"peer_hashes": {"x": "AB" * 32}}, "uppercase hex rejected"),
        ({"peer_hashes": {"x": 123}}, "non-string rejected"),
        ({"peer_hashes": ["x"]}, "non-dict rejected"),
        ({"peer_hashes": {"": HASH_ONLY_HEX}}, "empty name rejected"),
    ]:
        try:
            relay._parse_peer_hashes(bad)
            check(label, False, "no error raised")
        except ValueError:
            check(label, True)
    # name in both maps: fail closed at startup
    try:
        relay._init_peer_hashes({"peers": {"dup": "tok"},
                                 "peer_hashes": {"dup": HASH_ONLY_HEX}})
        check("dual-source conflict fails closed", False, "no error raised")
    except SystemExit as e:
        check("dual-source conflict fails closed",
              "dup" in str(e), "msg=%r" % (e,))
    # identity_pubkeys may name a hash-only peer (membership check must
    # pass; the bad key must still be rejected for the right reason)
    try:
        relay._parse_identity_pubkeys(
            {"peer_hashes": {"scratch-hash-only": HASH_ONLY_HEX},
             "identity_pubkeys": {"scratch-hash-only": "not-a-key"}})
        check("identity_pubkeys accepts hash-only peer name", False,
              "bad key accepted")
    except ValueError as e:
        check("identity_pubkeys accepts hash-only peer name",
              "malformed key" in str(e), "msg=%r" % (e,))

    print("\n%d passed, %d failed" % (PASS, FAIL))
    print("pass=%d fail=%d" % (PASS, FAIL))
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
