"""Real native Windows credential onboarding tests; no WSL or POSIX fixtures."""
import argparse
import contextlib
import ctypes
import errno
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
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

    def broaden(self, path):
        result = subprocess.run(["icacls", str(path), "/grant", "*S-1-1-0:F"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("(A;;FA;;;WD)", self.security(path))

    def artifact_state(self, root):
        if not root.exists():
            return None
        return {
            str(path.relative_to(root)): (
                self.cli._snapshot_at_path(str(path)) if path.is_file() else None)
            for path in sorted(root.rglob("*"))
        }

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
        self.assertEqual(path.read_bytes(), b"first")
        self.assert_private_security(path)
        expected = self.cli._snapshot_at_path(str(path))
        self.cli._atomic_publish_private(
            str(path), b"second", "config", expected_snapshot=expected)
        self.assertEqual(path.read_bytes(), b"second")
        self.assert_private_security(path)
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

    def test_broader_destination_acl_refuses_before_any_mutation(self):
        for caller_snapshot in (False, True):
            with self.subTest(caller_snapshot=caller_snapshot):
                path = self.root / ("broad-snapshot.json" if caller_snapshot
                                    else "broad-no-snapshot.json")
                self.cli._atomic_publish_private(str(path), b"first", "config")
                self.broaden(path)
                before = self.cli._snapshot_at_path(str(path))
                expected = before if caller_snapshot else None
                with mock.patch.object(self.cli, "_windows_restrict_path_acl",
                                       side_effect=AssertionError("ACL mutation")) as restrict, \
                        mock.patch.object(self.cli, "_windows_open_private_stage",
                                          side_effect=AssertionError("stage mutation")) as stage:
                    with self.assertRaisesRegex(ValueError, "protected owner-only"):
                        self.cli._atomic_publish_private(
                            str(path), b"must-not-appear", "config",
                            expected_snapshot=expected)
                restrict.assert_not_called()
                stage.assert_not_called()
                after = self.cli._snapshot_at_path(str(path))
                self.assertTrue(self.cli._same_file_snapshot(before, after))
                self.assertEqual(path.read_bytes(), b"first")
                self.assertFalse(list(self.root.glob("." + path.name + ".*")))

    def test_tofu_broad_acl_refusal_preserves_file_and_memory_with_private_positive(self):
        path = self.root / "tofu-broad.json"
        cfg = {"kind": self.cli.IDENTITY_KIND, "relay_url": "https://relay.example",
               "peer_name": "disposable"}
        self.cli._atomic_publish_private(
            str(path), self.cli._private_json_bytes(cfg), "config")
        self.broaden(path)
        before = self.cli._snapshot_at_path(str(path))
        self.cli._config_path = str(path)
        with mock.patch.object(self.cli, "req",
                               side_effect=AssertionError("unexpected request")) as request, \
                mock.patch.object(self.cli, "_windows_open_private_stage",
                                  side_effect=AssertionError("stage mutation")):
            with self.assertRaisesRegex(ValueError, "protected owner-only"):
                self.cli._persist_tofu_pin(cfg, "sha256:" + "1" * 64)
        request.assert_not_called()
        self.assertNotIn("relay_identity_fingerprint", cfg)
        after = self.cli._snapshot_at_path(str(path))
        self.assertTrue(self.cli._same_file_snapshot(before, after))

        positive_path = self.root / "tofu-private.json"
        positive_cfg = dict(cfg)
        fingerprint = "sha256:" + "2" * 64
        self.cli._atomic_publish_private(
            str(positive_path), self.cli._private_json_bytes(positive_cfg), "config")
        self.cli._config_path = str(positive_path)
        with mock.patch.object(self.cli, "req",
                               side_effect=AssertionError("unexpected request")) as request:
            self.cli._persist_tofu_pin(positive_cfg, fingerprint)
        request.assert_not_called()
        self.assertEqual(positive_cfg["relay_identity_fingerprint"], fingerprint)
        self.assertEqual(json.loads(positive_path.read_text()), positive_cfg)
        self.assert_private_security(positive_path)

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

    def test_register_key_windows_refuses_main_and_direct_without_effects(self):
        for fixture in ("fresh", "existing-identity", "legacy-pending"):
            root = self.root / fixture
            config = root / "identity.json"
            key = root / "identity.json.key"
            pending = Path(self.cli._register_key_pending_path(str(config)))
            if fixture == "existing-identity":
                cfg = {"kind": self.cli.IDENTITY_KIND, "peer_name": "disposable",
                       "service_token": "retained-token"}
                self.cli._atomic_publish_private(
                    str(config), self.cli._private_json_bytes(cfg), "config")
                self.cli._atomic_publish_private(str(key), b"retained-key\n", "key")
            elif fixture == "legacy-pending":
                cfg = {"peers": {"disposable": "retained-token"}}
                self.cli._atomic_publish_private(
                    str(config), self.cli._private_json_bytes(cfg), "config")
                self.cli._atomic_publish_private(str(key), b"retained-key\n", "key")
                self.cli._atomic_publish_private(
                    str(pending), b"retained-pending-journal\n", "pending")
            args = argparse.Namespace(
                config=str(config), key_path=str(key) if key.exists() else None,
                peer="disposable", base_url=None)
            for entry in ("direct", "main"):
                with self.subTest(fixture=fixture, entry=entry):
                    before = self.artifact_state(root)
                    with contextlib.ExitStack() as stack:
                        effects = [stack.enter_context(mock.patch.object(
                            self.cli, name, side_effect=AssertionError(
                                "unexpected protected-state effect: " + name)))
                            for name in ("_require_private_publication_platform",
                                         "_RegisterKeyOperationLock", "keygen", "req",
                                         "check_relay_identity", "load_config",
                                         "_correct_private_mode", "_persist_tofu_pin")]
                        if entry == "direct":
                            with self.assertRaises(OSError) as raised:
                                self.cli.cmd_register_key(args)
                            self.assertEqual(raised.exception.errno, errno.ENOSYS)
                            self.assertIn("Linux-only", str(raised.exception))
                            self.assertIn("no recovery action was attempted",
                                          str(raised.exception))
                        else:
                            out, err = io.StringIO(), io.StringIO()
                            with mock.patch.object(sys, "argv", [
                                    str(CLI), "--config", str(config), "register-key"]), \
                                    contextlib.redirect_stdout(out), \
                                    contextlib.redirect_stderr(err):
                                self.assertEqual(self.cli.main(), 1)
                            self.assertEqual(out.getvalue(), "")
                            self.assertIn("Linux-only", err.getvalue())
                            self.assertIn("no recovery action was attempted",
                                          err.getvalue())
                    for effect in effects:
                        effect.assert_not_called()
                    self.assertEqual(self.artifact_state(root), before)

    def test_powershell_accept_instruction_executes_exact_argv_once(self):
        directory = self.root / "echo target's directory"
        directory.mkdir()
        script = directory / "echo argv.py"
        output = directory / "argv-output.jsonl"
        script.write_text(
            "import json, sys\n"
            "from pathlib import Path\n"
            "output = Path(%r)\n"
            "with output.open('a', encoding='utf-8') as stream:\n"
            "    stream.write(json.dumps(sys.argv) + '\\n')\n"
            % str(output), encoding="utf-8")
        config = directory / "config with spaces'and apostrophe.json"
        handshake = "pending|handshake's id"
        shell, command = self.cli._accept_handshake_command(
            sys.executable, str(script), str(config), handshake)
        self.assertEqual(shell, "PowerShell")
        self.assertTrue(command.startswith("& '"))
        powershell = shutil.which("powershell.exe") or shutil.which("powershell")
        self.assertIsNotNone(powershell, "native PowerShell is required for this acceptance test")
        result = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = output.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0]), [
            str(script), "--config", str(config), "accept-handshake",
            "--enc-v", "1", "--", handshake])

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
