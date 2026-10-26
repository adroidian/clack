"""Real native Windows credential onboarding tests; no WSL or POSIX fixtures."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

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

    def test_hardlink_is_rejected_before_credentials_are_used(self):
        self.assertEqual(self.cli.cmd_keygen(self.args()), 0)
        os.link(self.config, self.root / "alias")
        with self.assertRaisesRegex(ValueError, "single-link"):
            self.cli.load_config(str(self.config))

    def test_named_mutex_excludes_another_process(self):
        code = r'''
import importlib.util, sys
spec = importlib.util.spec_from_file_location("other", sys.argv[1])
other = importlib.util.module_from_spec(spec)
spec.loader.exec_module(other)
try:
    with other._RegisterKeyOperationLock(sys.argv[2]):
        pass
except ValueError as exc:
    if "already active" not in str(exc):
        raise
else:
    raise SystemExit("second process acquired the operation lock")
'''
        with self.cli._RegisterKeyOperationLock(str(self.config)):
            result = subprocess.run(
                [sys.executable, "-B", "-c", code, str(CLI), str(self.config)],
                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
