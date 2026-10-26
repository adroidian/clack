"""Real native Windows credential onboarding tests; no WSL or POSIX fixtures."""
import argparse
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "relay-cli.py"


def load_cli(name="windows_native_cli"):
    spec = importlib.util.spec_from_file_location(name, CLI)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@unittest.skipUnless(sys.platform == "win32", "requires actual native Windows")
class WindowsNativeCredentials(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="clack-windows-native-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / "identity.json"
        self.cli = load_cli()

    def args(self, force=False):
        return argparse.Namespace(
            config=str(self.config), key_path=None, force=force,
            relay_url="https://relay.example", user_agent=None,
        )

    def security(self, path):
        kernel, _security, _DWORD, _FILE_INFO, _TOKEN_USER = self.cli._windows_config_api()
        handle = kernel.CreateFileW(str(path), 0x00020000, 7, None, 3, 0x00200000, None)
        self.assertNotIn(handle, (None, ctypes.c_void_p(-1).value))
        try:
            return self.cli._windows_security_sddl(handle)
        finally:
            kernel.CloseHandle(handle)

    def assert_private_security(self, path):
        sid = self.cli._windows_current_sid()
        self.assertIn(self.security(path), (
            "O:%sD:P(A;;FA;;;%s)" % (sid, sid),
            "O:%sD:PAI(A;;FA;;;%s)" % (sid, sid),
        ))

    def test_empty_keygen_and_restart_reuse_same_identity(self):
        self.assertEqual(self.cli.cmd_keygen(self.args()), 0)
        first = self.cli.load_config(str(self.config))
        first_seed = self.cli.signing_seed(first)
        self.assertEqual(len(first_seed), 32)
        self.assertEqual(self.cli.cmd_keygen(self.args()), 1)
        restarted = load_cli("windows_native_cli_restarted")
        second = restarted.load_config(str(self.config))
        self.assertEqual(second, first)
        self.assertEqual(restarted.signing_seed(second), first_seed)

    def test_identity_config_can_be_saved_twice_without_key_rotation(self):
        self.assertEqual(self.cli.cmd_keygen(self.args()), 0)
        first = self.cli.load_config(str(self.config))
        seed = self.cli.signing_seed(first)
        first["service_token"] = "replacement-token"
        self.cli._save_identity_config(str(self.config), first, seed)
        second = self.cli.load_config(str(self.config))
        self.assertEqual(second["service_token"], "replacement-token")
        self.assertEqual(self.cli.signing_seed(second), seed)
        self.assertEqual(second["identity_pubkey"], first["identity_pubkey"])

    def test_atomic_publish_preserves_operator_changes(self):
        path = self.root / "private.json"
        self.cli._atomic_publish_private(str(path), b"first", "config")
        expected = self.cli._snapshot_at_path(str(path))
        path.write_bytes(b"operator-edit")
        with self.assertRaisesRegex(ValueError, "changed"):
            self.cli._atomic_publish_private(
                str(path), b"candidate", "config", expected_snapshot=expected)
        self.assertEqual(path.read_bytes(), b"operator-edit")

    def test_atomic_publish_replaces_and_reads_back_exact_bytes(self):
        path = self.root / "private.json"
        self.cli._atomic_publish_private(str(path), b"first", "config")
        expected = self.cli._snapshot_at_path(str(path))
        self.cli._atomic_publish_private(
            str(path), b"second", "config", expected_snapshot=expected)
        self.assertEqual(path.read_bytes(), b"second")
        self.assertEqual(self.cli._read_windows_private_config(str(path)), b"second")
        restarted = load_cli("windows_native_cli_replacement")
        self.assertEqual(restarted._read_windows_private_config(str(path)), b"second")

    def test_hardlinked_private_key_is_not_used_for_signing(self):
        self.assertEqual(self.cli.cmd_keygen(self.args()), 0)
        cfg = self.cli.load_config(str(self.config))
        os.link(cfg["identity_privkey_path"], self.root / "key-alias")
        self.assertIsNone(self.cli.signing_seed(cfg))

    def test_private_files_use_non_inherited_owner_only_acl(self):
        self.assertEqual(self.cli.cmd_keygen(self.args()), 0)
        cfg = self.cli.load_config(str(self.config))
        for name in (self.config, Path(cfg["identity_privkey_path"])):
            result = subprocess.run(["icacls", str(name)], check=True,
                                    capture_output=True, text=True)
            self.assertNotIn("(I)", result.stdout)
            self.assertNotIn("BUILTIN\\Administrators", result.stdout)
            self.assertNotIn("NT AUTHORITY\\SYSTEM", result.stdout)
            self.assert_private_security(name)

    def test_hardlink_is_rejected_before_credentials_are_used(self):
        self.assertEqual(self.cli.cmd_keygen(self.args()), 0)
        os.link(self.config, self.root / "alias")
        with self.assertRaisesRegex(ValueError, "single-link"):
            self.cli.load_config(str(self.config))

    def test_broader_destination_acl_is_closed_before_secret_replacement(self):
        path = self.root / "broad.json"
        self.cli._atomic_publish_private(str(path), b"first", "config")
        result = subprocess.run(["icacls", str(path), "/grant", "*S-1-1-0:F"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("(A;;FA;;;WD)", self.security(path))
        self.cli._atomic_publish_private(str(path), b"second", "config")
        self.assertEqual(path.read_bytes(), b"second")
        self.assert_private_security(path)
        restarted = load_cli("windows_native_acl_restart")
        self.assertEqual(restarted._read_windows_private_config(str(path)), b"second")

    def test_security_drift_refuses_before_replacing_prior_bytes(self):
        path = self.root / "security-drift.json"
        self.cli._atomic_publish_private(str(path), b"first", "config")
        expected = self.cli._snapshot_at_path(str(path))
        result = subprocess.run(["icacls", str(path), "/grant", "*S-1-1-0:F"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        with self.assertRaisesRegex(ValueError, "changed"):
            self.cli._atomic_publish_private(
                str(path), b"must-not-appear", "config", expected_snapshot=expected)
        self.assertEqual(path.read_bytes(), b"first")
        self.assertIn("(A;;FA;;;WD)", self.security(path))

    def test_after_swap_operator_edit_and_backup_are_never_overwritten(self):
        path = self.root / "after-swap.json"
        self.cli._atomic_publish_private(str(path), b"first", "config")
        expected = self.cli._snapshot_at_path(str(path))
        original = self.cli._LOCAL_WINDOWS_REPLACE
        def replace_then_edit(destination, source, backup):
            original(destination, source, backup)
            Path(destination).write_bytes(b"operator-after-swap")
        with mock.patch.object(self.cli, "_LOCAL_WINDOWS_REPLACE", side_effect=replace_then_edit):
            with self.assertRaisesRegex(ValueError, "changed"):
                self.cli._atomic_publish_private(
                    str(path), b"candidate", "config", expected_snapshot=expected)
        self.assertEqual(path.read_bytes(), b"operator-after-swap")
        backups = list(self.root.glob(".*.prior"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), b"first")
        self.assert_private_security(backups[0])

    def test_curl_header_and_body_files_have_effective_private_acls_and_cleanup(self):
        seen = []
        secret_header = "Bearer synthetic-not-a-live-token"
        secret_body = b'{"claim":"synthetic-not-a-live-secret"}'
        def inspect_curl(cmd, capture_output, timeout):
            self.assertEqual(cmd[1], "-q")
            self.assertIn("--max-redirs", cmd)
            self.assertNotIn(secret_header, cmd)
            paths = [Path(arg[1:]) for arg in cmd if arg.startswith("@")]
            self.assertEqual(len(paths), 2)
            for path in paths:
                self.assertTrue(path.exists())
                self.assert_private_security(path)
            self.assertIn(b"X-Clack-Sig: synthetic-signature", paths[0].read_bytes())
            self.assertEqual(paths[1].read_bytes(), secret_body)
            seen.extend(paths)
            return argparse.Namespace(returncode=0, stdout=b"HTTP/1.1 200 OK\r\n\r\n{}", stderr=b"")
        with mock.patch.object(subprocess, "run", side_effect=inspect_curl):
            status, payload = self.cli._curl_req(
                {}, "POST", "https://relay.example/v1/test",
                {"Authorization": secret_header, "X-Clack-Sig": "synthetic-signature"},
                secret_body, 5)
        self.assertEqual((status, payload), (200, {}))
        self.assertEqual(len(seen), 2)
        for path in seen:
            self.assertFalse(path.exists())

    @staticmethod
    def lock_child(mode="exclude"):
        if mode == "die":
            body = "with other._RegisterKeyOperationLock(sys.argv[2]): os._exit(17)"
        elif mode == "acquire":
            body = "with other._RegisterKeyOperationLock(sys.argv[2]): pass"
        else:
            body = '''try:
    with other._RegisterKeyOperationLock(sys.argv[2]):
        pass
except ValueError as exc:
    if "already active" not in str(exc):
        raise
else:
    raise SystemExit("second process acquired the operation lock")'''
        return "import importlib.util, os, sys\n" + (
            'spec = importlib.util.spec_from_file_location("other", sys.argv[1])\n'
            "other = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(other)\n" + body)

    def run_lock_child(self, path, mode="exclude", expected=0):
        result = subprocess.run(
            [sys.executable, "-B", "-c", self.lock_child(mode), str(CLI), str(path)],
            capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, expected, result.stderr)
        return result

    def test_named_mutex_excludes_case_aliases_for_existing_and_absent_config(self):
        for existing in (False, True):
            with self.subTest(existing=existing):
                path = self.root / ("existing.json" if existing else "absent.json")
                if existing:
                    self.cli._atomic_publish_private(str(path), b"private", "config")
                upper_name = path.with_name(path.name.upper())
                upper_parent = Path(str(path.parent).upper()) / path.name
                self.assertTrue(os.path.samefile(path.parent, upper_parent.parent))
                with self.cli._RegisterKeyOperationLock(str(path)):
                    for alias in (path, upper_name, upper_parent):
                        self.run_lock_child(str(alias))
                # Independent positive control: exclusion is not a broken mutex.
                self.run_lock_child(str(upper_name), mode="acquire")

    def test_named_mutex_releases_after_exception_and_process_death(self):
        with self.assertRaisesRegex(RuntimeError, "release check"):
            with self.cli._RegisterKeyOperationLock(str(self.config)):
                raise RuntimeError("release check")
        self.run_lock_child(str(self.config), mode="acquire")
        self.run_lock_child(str(self.config), mode="die", expected=17)
        self.run_lock_child(str(self.config.with_name(self.config.name.upper())),
                          mode="acquire")


if __name__ == "__main__":
    unittest.main(verbosity=2)
