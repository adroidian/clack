"""Bounded platform-boundary regressions; non-Linux is simulated, not native QA.

No live relay, credentials or messages. The original 243-check Linux registration
suite stays byte-for-byte unchanged and is run separately.
"""
import argparse
import base64
import contextlib
import copy
import ctypes
import datetime
import errno
import hashlib
import hmac
import http.client
import importlib.util
import io
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "relay-cli.py"
ERROR = (
    "private credential publication requires Linux with fcntl.flock, os.geteuid, "
    "abstract AF_UNIX sockets and renameat2; run enrollment/key setup in a "
    "supported Linux environment"
)
DOCS = ("README.md", "QUICKSTART.md", "JOIN.md", "CLIENT_CONTRACT.md", "CHANGELOG.md")
SEED = bytes(range(32))  # disposable test material, never a real identity


def load_cli():
    spec = importlib.util.spec_from_file_location("platform_probe_cli", CLI)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@contextlib.contextmanager
def absent_attr(obj, name):
    value = getattr(obj, name, None)
    existed = hasattr(obj, name)
    if existed:
        delattr(obj, name)
    try:
        yield
    finally:
        if existed:
            setattr(obj, name, value)


def snapshot(root):
    """Every descendant name, bytes, mode, inode and mtime (including directories)."""
    return {
        str(p.relative_to(root)): (
            stat.S_IMODE(p.stat().st_mode), p.stat().st_ino, p.stat().st_mtime_ns,
            p.read_bytes() if p.is_file() else None,
        )
        for p in sorted(root.rglob("*"))
    }


class PublicationPlatformTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="clack-platform-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / "identity.json"
        self.key = self.root / "identity.json.key"
        self.cli = load_cli()
        self.cfg = {
            "kind": self.cli.IDENTITY_KIND,
            "relay_url": "http://127.0.0.1:1",
            "peer_name": "scratch",
            "service_token": "scratch-only-not-a-live-token",
            "identity_privkey_path": str(self.key),
            "identity_pubkey": self.cli.b64u_encode(self.cli._publickey(SEED)),
            "relay_identity_fingerprint": "sha256:" + "0" * 16,
        }
        self.config.write_text(json.dumps(self.cfg))
        self.key.write_text(self.cli.b64u_encode(SEED) + "\n")
        # A late guard would chmod these; both bytes AND modes must survive.
        self.config.chmod(0o644)
        self.key.chmod(0o644)
        self.cli._config_path = str(self.config)
        self.args = argparse.Namespace(
            config=str(self.config), key_path=str(self.key), force=True,
            relay_url=self.cfg["relay_url"], relay=self.cfg["relay_url"],
            user_agent=None, peer="scratch", base_url=None, name="scratch",
            invite_id=None, secret=None, yes=True, link=self.capability_link(),
        )

    def capability_link(self):
        return "https://unused.invalid/#" + urllib.parse.urlencode({
            "r": base64.urlsafe_b64encode(b"http://127.0.0.1:1").rstrip(b"=").decode(),
            "i": "00000000-0000-4000-8000-000000000001", "k": "scratch-claim",
            "v": "3", "by": "scratch-inviter", "exp": "2000000000",
        })

    def assert_requirement(self, call):
        before = snapshot(self.root)
        with self.assertRaises(OSError) as raised:
            call()
        self.assertEqual(raised.exception.errno, errno.ENOSYS)
        self.assertEqual(raised.exception.strerror, ERROR)
        self.assertEqual(snapshot(self.root), before)

    @contextlib.contextmanager
    def no_enrollment_effects(self):
        with contextlib.ExitStack() as stack:
            traps = [stack.enter_context(mock.patch.object(
                self.cli, name, side_effect=AssertionError("unexpected effect: " + name)
            )) for name in ("keygen", "req", "check_relay_identity", "load_config")]
            traps.append(stack.enter_context(mock.patch.object(
                socket, "socket", side_effect=AssertionError("unexpected socket")
            )))
            yield
            for trap in traps:
                trap.assert_not_called()

    def command_argvs(self):
        return (
            ["keygen", "--relay-url", self.cfg["relay_url"], "--force"],
            ["attach-key"], ["register-key"], ["redeem", self.args.link],
            ["enroll", "--relay", self.cfg["relay_url"], "--yes"],
        )

    def check_command_rejections(self):
        with self.no_enrollment_effects():
            for argv in self.command_argvs():
                with self.subTest(command=argv[0]):
                    before = snapshot(self.root)
                    out, err = io.StringIO(), io.StringIO()
                    with mock.patch.object(sys, "argv", [str(CLI), "--config", str(self.config)] + argv), \
                            contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                        self.assertEqual(self.cli.main(), 1)
                    self.assertEqual(err.getvalue(), str(OSError(errno.ENOSYS, ERROR)) + "\n")
                    self.assertEqual(out.getvalue(), "")
                    self.assertEqual(snapshot(self.root), before)

    def test_windows_import_and_help_without_posix_facilities(self):
        with mock.patch.object(sys, "platform", "win32"), \
                mock.patch.dict(sys.modules, {"fcntl": None}), \
                absent_attr(os, "geteuid"), absent_attr(socket, "AF_UNIX"), \
                mock.patch.object(ctypes, "CDLL", side_effect=AssertionError("must not load libc")):
            before = snapshot(self.root)
            module = load_cli()
            self.assertIsNone(module.fcntl)
            self.assertIsNone(module._RENAMEAT2)
            for argv in (["--help"], ["enroll", "--help"], ["register-key", "--help"]):
                with mock.patch.object(sys, "argv", [str(CLI)] + argv), \
                        contextlib.redirect_stdout(io.StringIO()) as out:
                    with self.assertRaises(SystemExit) as raised:
                        module.main()
                    self.assertEqual(raised.exception.code, 0)
                    self.assertIn("usage:", out.getvalue())
            self.assertEqual(snapshot(self.root), before)

    def test_macos_import_does_not_load_linux_libc(self):
        with mock.patch.object(sys, "platform", "darwin"), \
                mock.patch.object(ctypes, "CDLL", side_effect=AssertionError("must not load libc")):
            module = load_cli()
            self.assertIsNone(module._LIBC)
            self.assertIsNone(module._RENAMEAT2)
            self.assert_requirement(module._require_private_publication_platform)

    def test_windows_commands_reject_before_effects(self):
        with mock.patch.object(sys, "platform", "win32"), \
                mock.patch.object(self.cli, "fcntl", None), \
                absent_attr(os, "geteuid"), absent_attr(socket, "AF_UNIX"):
            self.check_command_rejections()

    def test_macos_commands_reject_even_with_unix_primitives(self):
        with mock.patch.object(sys, "platform", "darwin"):
            self.check_command_rejections()

    def test_linux_missing_each_api_rejects_before_effects(self):
        contexts = (
            mock.patch.object(self.cli, "fcntl", None),
            mock.patch.object(self.cli, "fcntl", object()),
            absent_attr(os, "geteuid"), absent_attr(socket, "AF_UNIX"),
            mock.patch.object(self.cli, "_RENAMEAT2", None),
        )
        with mock.patch.object(sys, "platform", "linux"):
            for index, context in enumerate(contexts):
                with self.subTest(missing_api=index), context:
                    self.check_command_rejections()

    def test_direct_command_entrypoints_reject_before_effects(self):
        calls = (
            lambda: self.cli.cmd_keygen(self.args),
            lambda: self.cli.cmd_attach_key(self.args, self.cfg),
            lambda: self.cli.cmd_register_key(self.args, self.cfg),
            lambda: self.cli.cmd_redeem(self.args),
            lambda: self.cli.cmd_enroll(self.args),
        )
        with mock.patch.object(self.cli, "_RENAMEAT2", None), self.no_enrollment_effects():
            for index, call in enumerate(calls):
                with self.subTest(entrypoint=index):
                    self.assert_requirement(call)

    def test_publication_helpers_reject_without_chmod_or_parent_creation(self):
        calls = (
            lambda: self.cli._atomic_publish_private(str(self.config), b"replacement", "config"),
            lambda: self.cli._atomic_publish_private(str(self.root / "absent" / "key"), SEED, "key"),
            lambda: self.cli._save_identity_config(str(self.config), self.cfg, SEED),
            lambda: self.cli._write_key_file(str(self.key), SEED),
            lambda: self.cli._persist_tofu_pin(self.cfg, "sha256:" + "1" * 16),
            lambda: self.cli._RegisterKeyOperationLock(str(self.config)),
        )
        cfg_before = copy.deepcopy(self.cfg)
        for platform in ("win32", "darwin", "linux"):
            with self.subTest(platform=platform), mock.patch.object(sys, "platform", platform), \
                    mock.patch.object(self.cli, "_RENAMEAT2", None), self.no_enrollment_effects():
                for call in calls:
                    self.assert_requirement(call)
                    self.assertEqual(self.cfg, cfg_before)

    def test_missing_renameat2_low_level_still_enosys(self):
        with mock.patch.object(self.cli, "_RENAMEAT2", None):
            with self.assertRaises(OSError) as raised:
                self.cli._renameat2("unused-source", "unused-destination", 1)
            self.assertEqual(raised.exception.errno, errno.ENOSYS)
            self.assertEqual(raised.exception.strerror, "renameat2 is required for private publication")

    def test_unrelated_and_short_url_commands_still_dispatch(self):
        request_id = "00000000-0000-4000-8000-000000000001"
        commands = (
            (["peers"], "GET", "/v1/peers"),
            (["receipts"], "GET", "/v1/receipts?since=0.0&limit=100"),
            (["mint-request", "--enc-v", "1", "--", self.cfg["identity_pubkey"]],
             "POST", "/v1/handshakes/requests"),
            (["redeem-request", self.cfg["relay_url"] + "/join/" + request_id],
             "POST", "/v1/handshakes/requests/redeem"),
            (["accept-handshake", "--enc-v", "1", "--", request_id],
             "POST", "/v1/handshakes/accept"),
        )
        with mock.patch.object(sys, "platform", "win32"), mock.patch.object(self.cli, "fcntl", None), \
                mock.patch.object(self.cli, "_RENAMEAT2", None):
            for argv, method, path in commands:
                with self.subTest(command=argv[0]):
                    before = snapshot(self.root)
                    with mock.patch.object(sys, "argv", [str(CLI), "--config", str(self.config)] + argv), \
                            mock.patch.object(self.cli, "req", return_value=(200, {"ok": True})) as req, \
                            contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        self.assertEqual(self.cli.main(), 0)
                    self.assertEqual(req.call_count, 1)
                    self.assertEqual(req.call_args.args[1:3], (method, path))
                    self.assertEqual(snapshot(self.root), before)
            # Pinned trust verification does not attempt a TOFU publication.
            with mock.patch.object(self.cli, "fetch_relay_identity", return_value=(
                    self.cfg["relay_identity_fingerprint"], None)), \
                    mock.patch.object(self.cli, "_persist_tofu_pin", side_effect=AssertionError("pin write")):
                self.assertEqual(self.cli._ensure_origin_verified(self.cfg["relay_url"], self.cfg), "pinned")

    def test_linux_positive_control_publication_and_lock_are_real(self):
        # A supported Linux run must still mutate these same valid fixtures;
        # the negative snapshots above cannot pass merely because writes are no-ops.
        self.cli._require_private_publication_platform()
        with self.cli._RegisterKeyOperationLock(str(self.config)) as operation:
            operation.assert_held()
            self.cli._atomic_publish_private(str(self.config), b"changed", "config")
        self.assertEqual(self.config.read_bytes(), b"changed")
        self.assertEqual(stat.S_IMODE(self.config.stat().st_mode), 0o600)
        self.cli._save_identity_config(str(self.config), self.cfg, SEED)
        self.assertEqual(json.loads(self.config.read_text()), self.cfg)
        self.assertEqual(stat.S_IMODE(self.key.stat().st_mode), 0o600)

    def test_all_five_docs_state_boundary_and_linux_suite_scope(self):
        for name in DOCS:
            with self.subTest(document=name):
                text = " ".join((ROOT / name).read_text().split())
                for required in (ERROR.split(" with ")[0], "`fcntl.flock`", "`os.geteuid`",
                                 "`AF_UNIX`", "`renameat2`", "`ENOSYS`", "`RENAME_EXCHANGE`",
                                 "`RENAME_NOREPLACE`", "`fsync`", "243-check", "Linux-only",
                                 "already-provisioned, pinned", "`--help`"):
                    self.assertIn(required, text)

    def test_fresh_isolated_child_import_and_help_without_fcntl(self):
        # -I avoids ambient module paths; -B (not just PYTHONDONTWRITEBYTECODE)
        # suppresses child caches. Preload stdlib before simulating sys.platform.
        code = '''
import argparse, base64, ctypes, datetime, errno, hashlib, hmac, http.client
import importlib.util, json, os, secrets, socket, stat, struct, sys, time
import urllib.error, urllib.parse, urllib.request, uuid
sys.platform = "win32"
sys.modules["fcntl"] = None
for obj, name in ((os, "geteuid"), (socket, "AF_UNIX")):
    if hasattr(obj, name):
        delattr(obj, name)
def refuse_libc(*args, **kwargs):
    raise AssertionError("non-Linux import tried to load libc")
ctypes.CDLL = refuse_libc
spec = importlib.util.spec_from_file_location("fresh_cli", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
sys.argv = [sys.argv[1], "--help"]
module.main()
'''
        env = {"PATH": os.defpath, "HOME": str(self.root), "TMPDIR": str(self.root)}
        before = snapshot(self.root)
        child = subprocess.run([sys.executable, "-I", "-B", "-c", code, str(CLI)],
                               cwd=self.root, env=env, capture_output=True, text=True, timeout=15)
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertIn("Clack relay CLI", child.stdout)
        self.assertEqual(child.stderr, "")
        self.assertEqual(snapshot(self.root), before)


if __name__ == "__main__":
    unittest.main()
