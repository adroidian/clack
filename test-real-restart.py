#!/usr/bin/env python3
"""Real supervisor-style restart acceptance for the target-A hash-only defect.

Spawns ACTUAL relay.py processes (not init_db calls), SIGTERMs them the way a
supervisor/systemd would, restarts them, and verifies peer/message/webhook
state survived -- through the real HTTP API and the real DB files.

Queued messages and webhooks are seeded straight into the DB to simulate
pre-existing traffic waiting for the peer (the exact target-A shape); the
authenticated send path itself is proven by test-handshake.py's 103
real-process checks. Everything the restart does to that state is real.

Scenarios:
  S1  plaintext -> hash-only migration across a real SIGTERM restart
      (the exact target-A cutover shape): peer row, token hash, queued
      message and webhook all survive; the relay keeps serving API traffic.
  S2  hash-only peer from scratch across a real restart: everything retained.
  S3  removing the peer from both maps + real restart: row/messages/webhook
      gone, name retired (revocation still works).
  S4  name in both peers and peer_hashes: the real process refuses to start.
  S5  disposable restore: sqlite backup -> fresh dir -> start -> state intact.

Scratch ports/dirs only. Never touches production (18802) or the repo DB.
Usage: python3 test-real-restart.py
Env:   CLACK_RELAY_PY overrides the relay under test (default: ./relay.py).
"""
import hashlib
import json
import os
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
import urllib.request
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
RELAY_PY = os.environ.get("CLACK_RELAY_PY", os.path.join(HERE, "relay.py"))
# Expected version is whatever relay.py declares (not hardcoded here).
_m = re.search(r'^VERSION\s*=\s*"([^"]+)"', open(RELAY_PY).read(), re.M)
EXPECTED_VERSION = _m.group(1) if _m else "?"
ROOT = "/tmp/clack-real-restart"
PORTS = {"s1": 18980, "s2": 18981, "s4": 18982, "s5": 18983}

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


def write_config(basedir, cfg):
    os.makedirs(basedir, exist_ok=True)
    with open(os.path.join(basedir, "relay-config.json"), "w") as f:
        json.dump(cfg, f)


def start(basedir, port):
    env = dict(os.environ, CLACK_RELAY_BASE=basedir)
    proc = subprocess.Popen(
        [sys.executable, RELAY_PY],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return proc


def wait_health(port, timeout=20):
    url = "http://127.0.0.1:%d/health" % port
    end = time.time() + timeout
    while time.time() < end:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                return json.load(r)
        except Exception:
            time.sleep(0.2)
    return None


def stop(proc, timeout=15):
    if proc.poll() is not None:
        return proc.poll()
    proc.terminate()  # SIGTERM, like a supervisor would send
    try:
        return proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        return proc.wait()


def seed_message(basedir, sender, recipient, text):
    """Queue a message straight into the DB (simulates pre-existing queued
    traffic, exactly the target-A shape: messages already waiting for the
    hash-only peer when the restart happens). Returns the message id."""
    mid = str(uuid.uuid4())
    now = time.time()
    con = sqlite3.connect(os.path.join(basedir, "relay.db"))
    try:
        con.execute(
            "INSERT INTO messages(id,sender,recipient,topic,text,in_reply_to,"
            "created_at,expires_at,acked_at,collected_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?)",
            (mid, sender, recipient, None, text, None,
             now, now + 86400, None, None),
        )
        con.commit()
    finally:
        con.close()
    return mid


def api(port, path, token=None, data=None):
    url = "http://127.0.0.1:%d%s" % (port, path)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers,
                                 method="POST" if data is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.load(e)
        except Exception:
            return e.code, {}
    except Exception as e:
        return -1, {"error": str(e)}


def dbq(basedir, sql, args=()):
    con = sqlite3.connect(os.path.join(basedir, "relay.db"))
    try:
        return con.execute(sql, args).fetchall()
    finally:
        con.close()


def seed_webhook(basedir, peer, url="https://example.com/hook"):
    con = sqlite3.connect(os.path.join(basedir, "relay.db"))
    try:
        con.execute(
            "INSERT INTO webhooks(peer,url,created_at,last_notified_at,last_error)"
            " VALUES(?,?,?,NULL,NULL)",
            (peer, url, time.time()),
        )
        con.commit()
    finally:
        con.close()


# --- S1: plaintext -> hash-only migration across a real SIGTERM restart ------
d1 = os.path.join(ROOT, "s1")
shutil.rmtree(d1, ignore_errors=True)
SENDER_TOK = "tok_sender_9f8"
MIG_TOK = "tok_migrator_4d2"
MIG_HASH = hashlib.sha256(MIG_TOK.encode()).hexdigest()
write_config(d1, {"port": PORTS["s1"], "bind": "127.0.0.1",
                  "peers": {"sender": SENDER_TOK, "migrator": MIG_TOK},
                  "peer_hashes": {}})
p1 = start(d1, PORTS["s1"])
h = wait_health(PORTS["s1"])
check("s1 relay starts (real process)", h is not None, repr(h))
check("s1 version is %s" % EXPECTED_VERSION, (h or {}).get("version") == EXPECTED_VERSION, repr(h))
mid = seed_message(d1, "sender", "migrator", "hello migrator")
check("s1 pre-restart message queued", mid is not None)
seed_webhook(d1, "migrator")
pre_hash = dbq(d1, "SELECT token_hash FROM peers WHERE name='migrator'")
check("s1 pre-restart peer row present", len(pre_hash) == 1, repr(pre_hash))
stop(p1)
check("s1 SIGTERM stops process", p1.poll() is not None)
# migrate config: plaintext token -> hash-only entry (same sha256)
write_config(d1, {"port": PORTS["s1"], "bind": "127.0.0.1",
                  "peers": {"sender": SENDER_TOK},
                  "peer_hashes": {"migrator": MIG_HASH}})
p1 = start(d1, PORTS["s1"])
h = wait_health(PORTS["s1"])
check("s1 restarts after migration", h is not None)
row = dbq(d1, "SELECT token_hash FROM peers WHERE name='migrator'")
check("s1 migrated peer row survives real restart", len(row) == 1, repr(row))
check("s1 token hash verbatim after real restart",
      row and row[0][0] == MIG_HASH, repr(row))
msg = dbq(d1, "SELECT id FROM messages WHERE recipient='migrator'")
check("s1 queued message survives real restart",
      any(r[0] == mid for r in msg), repr(msg))
wh = dbq(d1, "SELECT url FROM webhooks WHERE peer='migrator'")
check("s1 webhook survives real restart",
      wh and wh[0][0] == "https://example.com/hook", repr(wh))
ret = dbq(d1, "SELECT 1 FROM retired_names WHERE name='migrator'")
check("s1 name not retired after migration", not ret, repr(ret))
names = {r[0] for r in dbq(d1, "SELECT name FROM peers")}
check("s1 both config peers present after migration restart",
      names == {"sender", "migrator"}, repr(names))
stop(p1)

# --- S2: hash-only from scratch across a real restart ------------------------
d2 = os.path.join(ROOT, "s2")
shutil.rmtree(d2, ignore_errors=True)
HP_HASH = "ab" * 32
write_config(d2, {"port": PORTS["s2"], "bind": "127.0.0.1",
                  "peers": {"sender": "tok_b"},
                  "peer_hashes": {"hashpeer": HP_HASH}})
p2 = start(d2, PORTS["s2"])
check("s2 relay starts", wait_health(PORTS["s2"]) is not None)
mid3 = seed_message(d2, "sender", "hashpeer", "for hashpeer")
check("s2 message queued for hash-only peer", mid3 is not None)
seed_webhook(d2, "hashpeer")
stop(p2)
p2 = start(d2, PORTS["s2"])  # same config: pure restart, no migration
check("s2 restarts", wait_health(PORTS["s2"]) is not None)
row = dbq(d2, "SELECT token_hash FROM peers WHERE name='hashpeer'")
check("s2 hash-only peer survives real restart",
      row and row[0][0] == HP_HASH, repr(row))
msg = dbq(d2, "SELECT id FROM messages WHERE recipient='hashpeer'")
check("s2 queued message survives real restart",
      any(r[0] == mid3 for r in msg), repr(msg))
wh = dbq(d2, "SELECT 1 FROM webhooks WHERE peer='hashpeer'")
check("s2 webhook survives real restart", len(wh) == 1, repr(wh))
ret = dbq(d2, "SELECT 1 FROM retired_names WHERE name='hashpeer'")
check("s2 name not retired", not ret, repr(ret))

# --- S3: removal from both maps + real restart still revokes ----------------
write_config(d2, {"port": PORTS["s2"], "bind": "127.0.0.1",
                  "peers": {"sender": "tok_b"}, "peer_hashes": {}})
stop(p2)
p2 = start(d2, PORTS["s2"])
check("s3 restarts after removal", wait_health(PORTS["s2"]) is not None)
row = dbq(d2, "SELECT 1 FROM peers WHERE name='hashpeer'")
check("s3 removed peer row deleted", not row, repr(row))
msg = dbq(d2, "SELECT 1 FROM messages WHERE recipient='hashpeer'")
check("s3 removed peer messages deleted", not msg, repr(msg))
wh = dbq(d2, "SELECT 1 FROM webhooks WHERE peer='hashpeer'")
check("s3 removed peer webhook deleted", not wh, repr(wh))
ret = dbq(d2, "SELECT 1 FROM retired_names WHERE name='hashpeer'")
check("s3 removed peer name retired", len(ret) == 1, repr(ret))
stop(p2)

# --- S4: dual-source conflict fails closed on a real process -----------------
d4 = os.path.join(ROOT, "s4")
shutil.rmtree(d4, ignore_errors=True)
write_config(d4, {"port": PORTS["s4"], "bind": "127.0.0.1",
                  "peers": {"bad": "tok_c"},
                  "peer_hashes": {"bad": "cd" * 32}})
p4 = start(d4, PORTS["s4"])
try:
    rc = p4.wait(timeout=8)
except subprocess.TimeoutExpired:
    rc = None
    p4.kill()
out = p4.stdout.read() if p4.stdout else ""
check("s4 conflict refuses startup (non-zero exit)", rc not in (None, 0),
      "rc=%r" % rc)
check("s4 conflict error names both maps", "both 'peers' and 'peer_hashes'" in out,
      out[-300:])

# --- S5: disposable restore (sqlite backup -> fresh dir -> start) ------------
d5 = os.path.join(ROOT, "s5")
shutil.rmtree(d5, ignore_errors=True)
os.makedirs(d5, exist_ok=True)
src = sqlite3.connect(os.path.join(d1, "relay.db"))
dst = sqlite3.connect(os.path.join(d5, "relay.db"))
try:
    src.backup(dst)
finally:
    dst.close()
    src.close()
shutil.copy(os.path.join(d1, "relay-config.json"),
            os.path.join(d5, "relay-config.json"))
cfg5 = json.load(open(os.path.join(d5, "relay-config.json")))
cfg5["port"] = PORTS["s5"]
write_config(d5, cfg5)
p5 = start(d5, PORTS["s5"])
check("s5 restored relay starts", wait_health(PORTS["s5"]) is not None)
row = dbq(d5, "SELECT token_hash FROM peers WHERE name='migrator'")
check("s5 restored peer row intact",
      row and row[0][0] == MIG_HASH, repr(row))
msg = dbq(d5, "SELECT COUNT(*) FROM messages WHERE recipient='migrator'")
check("s5 restored queued messages intact", msg and msg[0][0] >= 1, repr(msg))
wh = dbq(d5, "SELECT 1 FROM webhooks WHERE peer='migrator'")
check("s5 restored webhook intact", len(wh) == 1, repr(wh))
stop(p5)

print("\n%d passed, %d failed" % (PASS, FAIL))
print("pass=%d fail=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
