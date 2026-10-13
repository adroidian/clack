"""Benign lifecycle regression fixtures for the two remaining Flint 685 findings.

R1 P2: the configured finite partition cap must be evaluated with a fresh
trusted-clock sample inside the final serialized decision boundary (the
send/reconcile action fence and the receive acceptance transaction), not only
before it. These fixtures cross the configured expiry during ordinary
serialization delay and assert the fence caps and holds atomically.

R2 P2: the configured root device/inode pinning must be rechecked after the
blocking thread/flock acquisition, before any pathname-based DB open. These
fixtures replace the state root during ordinary lock contention (operator
maintenance simulation) and assert subsequent mutation is refused.

Fixture-only: synthetic throwaway state roots, keys and grants under /tmp,
stubbed transport clients (no relay, no network, no exploit material).
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from federation_adapter import Adapter, SCHEMA


def load(path):
    spec = importlib.util.spec_from_file_location("fixture_" + uuid.uuid4().hex, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("fixture source unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def private(path, obj):
    data = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
    fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


class FakeSendClient:
    """Loopback-substitute transport: records calls, accepts benignly."""

    def __init__(self):
        self.send_calls = []

    def send(self, peer, body, msg_id=None):
        self.send_calls.append((peer, body, msg_id))
        return (msg_id, True)


class FakePollClient:
    """Loopback-substitute transport: returns scripted messages, records acks."""

    def __init__(self, messages):
        self.messages = list(messages)
        self.ack_calls = []

    def poll(self, timeout=0):
        return list(self.messages)

    def ack(self, ids):
        self.ack_calls.append(list(ids))
        return {"acked": list(ids), "already_acked": []}


class LifecycleFixture(unittest.TestCase):
    """Owns one fresh disposable state root per adapter built; no relay rig."""

    def make_adapter(self, partition_cap_s):
        state = tempfile.TemporaryDirectory(prefix="clack-685-fixture-state-", dir="/tmp")
        self.addCleanup(state.cleanup)
        base = Path(state.name)
        private(base / ".clack-fed-v098-owned.json", {"owned": "disposable fixture only"})
        os.environ["FED_BASE"] = str(base)
        driver = load(REPO / "reviews/fed_driver.py")
        driver.install_grant("forward")
        ndr_key = base / "ndr.key"
        verifier_pub = base / "verifier.pub"
        private(ndr_key, os.urandom(32))
        private(verifier_pub, os.urandom(32))
        bootstrap = base / "bootstrap.json"
        private(bootstrap, {
            "schema": "clack-federation-bootstrap-reference-v1",
            "purpose": "fixture-proof",
            "approval_ref": "DISPOSABLE TEST ONLY",
            "state_dir": str(base),
        })
        endpoints = {}
        for name, port in (("send-ep", 19991), ("recv-ep", 19992)):
            token = base / (name + "-token.ref")
            key = base / (name + "-key.ref")
            pins = base / (name + "-pins.ref")
            url = "http://127.0.0.1:%d" % port
            private(token, b"disposable-fixture-token")
            private(key, os.urandom(32))
            private(pins, {url: "sha256:" + "00" * 32})
            endpoints[name] = {"url": url, "peer": "peer-x",
                               "token_ref": str(token), "key_ref": str(key),
                               "pin_ref": str(pins)}
        cfg = {
            "schema": SCHEMA,
            "proof_only": True,
            "state_dir": str(base),
            "bootstrap_ref": str(bootstrap),
            "ndr_key_ref": str(ndr_key),
            "verifier_pub_ref": str(verifier_pub),
            "verifier_id": "synthetic-recheck-verifier-v1",
            "timeout": 3,
            "partition_cap_s": partition_cap_s,
            "endpoints": endpoints,
            "routes": {"forward": {"send_endpoint": "send-ep", "to": "peer-y",
                                   "receive_endpoint": "recv-ep", "from": "peer-x"}},
        }
        config = base / "runtime.json"
        private(config, cfg)
        adapter = Adapter(str(config))
        self.addCleanup(adapter.clients.clear)
        return adapter, base

    def set_watermark(self, authority, grant, value):
        with authority.authority_lock():
            c = authority._connect()
            try:
                c.execute("UPDATE grants SET last_recheck_verified_at=? WHERE grant_id=?",
                          (value, grant))
            finally:
                c.close()

    def replace_root(self, base):
        moved = base.with_name(base.name + "-maintenance")
        base.rename(moved)
        base.mkdir(mode=0o700)
        return moved

    def restore_root(self, base, moved):
        for p in base.iterdir():
            if p.is_file() or p.is_symlink():
                p.unlink()
            else:
                raise RuntimeError("unexpected fixture content in replaced root")
        base.rmdir()
        moved.rename(base)


class InFencePartitionCapTests(LifecycleFixture):
    def test_send_fence_caps_grant_that_crossed_expiry_during_serialization(self):
        adapter, _ = self.make_adapter(partition_cap_s=0.5)
        a = adapter.authority
        self.set_watermark(a, "forward", time.time())
        fake = FakeSendClient()
        adapter.clients["send-ep"] = fake
        states = []
        original = adapter.enforce_cap

        def slowed(grant):
            original(grant)
            # Ordinary serialization delay between the eager check and the
            # authoritative fence; the configured expiry is crossed here.
            states.append(a.read_grant(grant))
            time.sleep(0.8)

        mid = str(uuid.uuid4())
        with mock.patch.object(adapter, "enforce_cap", side_effect=slowed):
            result = adapter.send("forward", mid, "fixture in-fence cap")
        self.assertEqual(states, ["OK"])  # the eager check alone was not sufficient
        self.assertEqual(result["outcome"], "held")
        self.assertEqual(a.read_grant("forward"), "CAPPED")
        self.assertEqual(fake.send_calls, [])  # no wire bytes for a capped grant
        record = a.read_grant_record("forward")
        self.assertEqual(record["generation"], 2)  # one atomic generation advance
        self.assertEqual(a.outbox_state(mid), "held")
        self.assertEqual(a.count_rows("ndrs"), 0)  # nothing queued/held at cap time
        # Replay of the stable id remains fenced; no authority laundering.
        self.assertEqual(adapter.send("forward", mid, "fixture in-fence cap")["outcome"], "held")
        self.assertEqual(fake.send_calls, [])

    def test_receive_fence_caps_and_refuses_after_expiry_crossing(self):
        adapter, _ = self.make_adapter(partition_cap_s=0.5)
        a = adapter.authority
        self.set_watermark(a, "forward", time.time())
        mid = str(uuid.uuid4())
        fake = FakePollClient([{"id": mid, "from": "peer-x", "text": "fixture receive fence"}])
        adapter.clients["recv-ep"] = fake
        states = []
        original = adapter.enforce_cap

        def slowed(grant):
            original(grant)
            states.append(a.read_grant(grant))
            time.sleep(0.8)

        with mock.patch.object(adapter, "enforce_cap", side_effect=slowed):
            result = adapter.receive("recv-ep")
        self.assertEqual(states, ["OK"])
        self.assertEqual(result["accepted_ids"], [])
        self.assertEqual(a.read_grant("forward"), "CAPPED")
        self.assertEqual(adapter.inbox_messages(), [])  # no durable acceptance
        self.assertEqual(fake.ack_calls, [])  # and no relay acknowledgement

    def test_apply_partition_cap_samples_trusted_clock_inside_lock(self):
        adapter, _ = self.make_adapter(partition_cap_s=3600)
        a = adapter.authority
        t0 = time.time()
        self.set_watermark(a, "forward", t0)
        # A None caller timestamp must sample the trusted clock inside the lock.
        self.assertEqual(a.apply_partition_cap("forward", None, 3600), ("not_due", []))
        with mock.patch("time.time", return_value=t0 + 7200):
            outcome, resolved = a.apply_partition_cap("forward", None, 3600)
        self.assertEqual((outcome, resolved), ("capped", []))
        self.assertEqual(a.read_grant("forward"), "CAPPED")
        self.assertEqual(a.apply_partition_cap("forward", None, 3600), ("capped", []))

    def test_not_due_grant_still_sends_and_receives(self):
        adapter, _ = self.make_adapter(partition_cap_s=3600)
        a = adapter.authority
        self.set_watermark(a, "forward", time.time())
        fake = FakeSendClient()
        adapter.clients["send-ep"] = fake
        mid = str(uuid.uuid4())
        self.assertEqual(adapter.send("forward", mid, "fixture control send")["outcome"], "sent")
        self.assertEqual(len(fake.send_calls), 1)
        incoming = str(uuid.uuid4())
        poller = FakePollClient([{"id": incoming, "from": "peer-x", "text": "fixture control receive"}])
        adapter.clients["recv-ep"] = poller
        self.assertEqual(adapter.receive("recv-ep")["accepted_ids"], [incoming])
        self.assertEqual(poller.ack_calls, [[incoming]])


class RootRecheckAfterLockWaitTests(LifecycleFixture):
    def test_root_replaced_during_thread_lock_wait_refuses_mutation(self):
        adapter, base = self.make_adapter(partition_cap_s=3600)
        a = adapter.authority
        entered = threading.Event()
        release = threading.Event()

        def holder():
            with a.authority_lock():
                entered.set()
                release.wait(5)

        thread = threading.Thread(target=holder)
        thread.start()
        self.assertTrue(entered.wait(5))
        outcome = []

        def waiter():
            try:
                a.set_grant("forward", "SUSPECT")
                outcome.append("mutated")
            except (RuntimeError, ValueError) as exc:
                outcome.append("%s: %s" % (type(exc).__name__, exc))

        work = threading.Thread(target=waiter)
        work.start()
        time.sleep(0.3)  # waiter is parked on the ordinary in-process lock
        moved = self.replace_root(base)
        try:
            release.set()
            thread.join(5)
            work.join(5)
            self.assertEqual(len(outcome), 1)
            self.assertIn("replaced", outcome[0])
            self.assertFalse((base / "federation-authority.db").exists(),
                             "no DB may be created in the maintenance root")
        finally:
            self.restore_root(base, moved)
        self.assertEqual(a.read_grant("forward"), "OK")  # original root unmutated

    def test_root_replaced_during_cross_process_flock_wait_refuses_mutation(self):
        adapter, base = self.make_adapter(partition_cap_s=3600)
        a = adapter.authority
        child_script = (
            "import importlib.util,sys,time\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "spec = importlib.util.spec_from_file_location('fed_auth_child', sys.argv[1] + '/federation_authority.py')\n"
            "m = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(m)\n"
            "m.configure(sys.argv[2], sys.argv[3], sys.argv[4], 'synthetic-recheck-verifier-v1')\n"
            "with m.authority_lock():\n"
            "    print('LOCKED', flush=True)\n"
            "    time.sleep(float(sys.argv[5]))\n"
        )
        cfg = adapter.cfg
        child = subprocess.Popen(
            [sys.executable, "-c", child_script, str(REPO), str(base),
             cfg["ndr_key_ref"], cfg["verifier_pub_ref"], "1.2"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(), "LOCKED")
            outcome = []

            def waiter():
                try:
                    a.set_grant("forward", "SUSPECT")
                    outcome.append("mutated")
                except (RuntimeError, ValueError) as exc:
                    outcome.append("%s: %s" % (type(exc).__name__, exc))

            work = threading.Thread(target=waiter)
            work.start()
            time.sleep(0.4)  # waiter is blocked in the cross-process flock wait
            moved = self.replace_root(base)
            try:
                work.join(10)
                self.assertEqual(len(outcome), 1)
                self.assertIn("replaced", outcome[0])
                self.assertFalse((base / "federation-authority.db").exists(),
                                 "no DB may be created in the maintenance root")
            finally:
                self.restore_root(base, moved)
        finally:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=10)
        self.assertEqual(a.read_grant("forward"), "OK")  # original root unmutated


if __name__ == "__main__":
    unittest.main(verbosity=2)
