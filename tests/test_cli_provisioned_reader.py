"""Windows API-contract simulation with real fixture-file reads, not native QA.

No fake UID or production fallback. The real native-reader code is exercised;
only Win32 kernel/security calls are translated to scratch POSIX file operations.
The original 243-label suite remains unchanged and runs separately on Linux.
"""
import argparse
import contextlib
import ctypes
import errno
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / 'relay-cli.py'


def load_cli():
    spec = importlib.util.spec_from_file_location('provisioned_reader_cli', CLI)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def value(obj):
    return obj.value if hasattr(obj, 'value') else obj


class Function:
    def __init__(self, call): self.call = call
    def __call__(self, *args): return self.call(*args)


class Win32Fixture:
    """Contract fake; records every native call, tracks resources and file data."""
    def __init__(self):
        # The fake translates Windows ownership checks to fixture-file uids.
        # Native Windows exposes a stable zero here; POSIX uses the real owner.
        self.current_uid = os.geteuid() if hasattr(os, "geteuid") else 0
        self.calls, self.files, self.tokens, self.descriptors = [], {}, set(), set()
        self.fail = None
        self.owner_matches = True
        self.file_type = 1
        self.attributes = 0x80
        self.info_calls = 0
        self.identity_drift = False
        self.path_drift = False
        self.token_size = ctypes.sizeof(ctypes.c_void_p) * 2
        self.kernel = types.SimpleNamespace()
        self.security = types.SimpleNamespace()
        for name in ('CreateFileW', 'GetFileType', 'GetFileInformationByHandle',
                     'ReadFile', 'CloseHandle', 'FlushFileBuffers', 'GetCurrentProcess', 'LocalFree'):
            setattr(self.kernel, name, Function(self.dispatch(name)))
        for name in ('GetSecurityInfo', 'OpenProcessToken', 'GetTokenInformation', 'EqualSid'):
            setattr(self.security, name, Function(self.dispatch(name)))

    def dispatch(self, name):
        def call(*args):
            self.calls.append(name)
            if self.fail == name:
                return ctypes.c_void_p(-1).value if name == 'CreateFileW' else 5 if name == 'GetSecurityInfo' else 0
            return getattr(self, name)(*args)
        return call

    def loader(self, name, **kwargs):
        if name == 'kernel32': return self.kernel
        if name == 'advapi32': return self.security
        raise AssertionError('unexpected DLL ' + name)

    def CreateFileW(self, path, access, share, security, disposition, flags, template):
        assert access == 0x80020000 and share == 1 and disposition == 3 and flags == 0x00200000
        assert security is None and template is None
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
                     | getattr(os, 'O_BINARY', 0))
        self.files[fd] = path
        return fd

    def GetFileType(self, handle): return self.file_type

    def GetFileInformationByHandle(self, handle, output):
        self.info_calls += 1
        st, info = os.fstat(value(handle)), output._obj
        info.attributes = self.attributes | (0x10 if stat.S_ISDIR(st.st_mode) else 0)
        info.volume = st.st_dev & 0xffffffff
        inode = st.st_ino + (1 if self.identity_drift and self.info_calls > 1 else 0)
        if self.path_drift and len(self.files) > 1: inode += 1
        info.index_high, info.index_low = inode >> 32, inode & 0xffffffff
        info.size_high, info.size_low = st.st_size >> 32, st.st_size & 0xffffffff
        info.links = st.st_nlink
        info.written.high, info.written.low = st.st_mtime_ns >> 32, st.st_mtime_ns & 0xffffffff
        info.created.high, info.created.low = st.st_ctime_ns >> 32, st.st_ctime_ns & 0xffffffff
        return 1

    def GetSecurityInfo(self, handle, object_type, mask, owner, group, dacl, sacl, descriptor):
        assert object_type == 1 and mask == 1
        actual_owner = os.fstat(value(handle)).st_uid
        owner._obj.value = 1001 if self.owner_matches and actual_owner == self.current_uid else 2002
        allocation = 50000 + len(self.calls)
        descriptor._obj.value = allocation
        self.descriptors.add(allocation)
        return 0

    def GetCurrentProcess(self): return ctypes.c_void_p(-1).value

    def OpenProcessToken(self, process, access, output):
        assert access == 8
        token = 1000000 + len(self.calls)
        output._obj.value = token
        self.tokens.add(token)
        return 1

    def GetTokenInformation(self, token, info_class, buffer, size, needed):
        assert info_class == 1 and value(token) in self.tokens
        needed._obj.value = self.token_size
        if buffer is None: return 0  # ordinary insufficient-buffer sizing call
        ctypes.c_void_p.from_buffer(buffer).value = 1001
        return 1

    def EqualSid(self, first, second): return int(value(first) == value(second))

    def ReadFile(self, handle, buffer, size, count, overlapped):
        data = os.read(value(handle), size)
        ctypes.memmove(buffer, data, len(data))
        count._obj.value = len(data)
        return 1

    def CloseHandle(self, handle):
        handle = value(handle)
        if handle in self.tokens: self.tokens.remove(handle)
        else:
            assert handle in self.files, ('double/unknown close', handle)
            os.close(handle)
            del self.files[handle]
        return 1

    def FlushFileBuffers(self, handle): return 1

    def LocalFree(self, pointer):
        self.descriptors.remove(value(pointer))
        return None

    def assert_closed(self, test):
        test.assertEqual(self.files, {})
        test.assertEqual(self.tokens, set())
        test.assertEqual(self.descriptors, set())


@contextlib.contextmanager
def windows_without_posix(fixture):
    with contextlib.ExitStack() as stack:
        stack.enter_context(mock.patch.object(sys, 'platform', 'win32'))
        stack.enter_context(mock.patch.object(ctypes, 'WinDLL', fixture.loader, create=True))
        stack.enter_context(mock.patch.object(ctypes, 'get_last_error', return_value=5, create=True))
        if hasattr(os, 'geteuid'):
            stack.enter_context(mock.patch.object(os, 'geteuid'))
            del os.geteuid
        if hasattr(os, 'getuid'):
            stack.enter_context(mock.patch.object(os, 'getuid'))
            del os.getuid
        if hasattr(os, 'geteuid'): raise AssertionError('POSIX API was not removed')
        yield


def snapshot(root):
    return {str(p.relative_to(root)): (p.read_bytes() if p.is_file() else None,
            stat.S_IMODE(p.lstat().st_mode), p.lstat().st_ino, p.lstat().st_mtime_ns)
            for p in sorted(root.rglob('*'))}


class ProvisionedReaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='clack-reader-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cli = load_cli()
        self.config, self.key = self.root/'client.json', self.root/'key'
        self.seed = bytes(range(32))
        self.pub = self.cli.b64u_encode(self.cli._publickey(self.seed))
        self.key.write_text(self.cli.b64u_encode(self.seed)+'\n')
        self.cfg = {'kind':self.cli.IDENTITY_KIND,'peer_name':'scratch',
                    'relay_url':'http://127.0.0.1:1','service_token':'scratch-only',
                    'relay_identity_fingerprint':'sha256:'+'1'*16,
                    'identity_pubkey':self.pub,'identity_privkey_path':str(self.key)}
        self.config.write_text(json.dumps(self.cfg))
        self.config.chmod(0o644)
        self.key.chmod(0o600)
        self.fixture = Win32Fixture()

    def read(self):
        with windows_without_posix(self.fixture):
            return self.cli.load_config(str(self.config))

    def test_real_config_reader_uses_native_owner_and_stable_handle_without_geteuid(self):
        before = snapshot(self.root)
        self.assertEqual(self.read(), self.cfg)
        self.assertEqual(snapshot(self.root), before)
        self.assertEqual(self.fixture.calls.count('EqualSid'), 2)
        self.assertEqual(self.fixture.calls.count('CreateFileW'), 2)
        self.fixture.assert_closed(self)

    def test_all_five_unrelated_dispatches_use_real_reader_without_posix_apis(self):
        identifier = '00000000-0000-4000-8000-000000000001'
        commands = [['peers'], ['receipts'], ['mint-request','--enc-v','1','--',self.pub],
                    ['redeem-request',self.cfg['relay_url']+'/join/'+identifier],
                    ['accept-handshake',identifier]]
        before = snapshot(self.root)
        with windows_without_posix(self.fixture), mock.patch.object(self.cli, 'req', return_value=(200, {'ok':True})) as req:
            for argv in commands:
                with self.subTest(command=argv[0]), mock.patch.object(sys, 'argv', ['cli','--config',str(self.config),*argv]), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(self.cli.main(), 0)
            self.assertEqual(req.call_count, 5)
        self.assertEqual(self.fixture.calls.count('EqualSid'), 16)
        self.assertEqual(snapshot(self.root), before)
        self.fixture.assert_closed(self)

    def test_different_owner_rejected_before_data_read(self):
        before = snapshot(self.root)
        self.fixture.owner_matches = False
        with self.assertRaisesRegex(ValueError, 'not owned'): self.read()
        self.assertNotIn('ReadFile', self.fixture.calls)
        self.assertEqual(snapshot(self.root), before)
        self.fixture.assert_closed(self)

    def test_hardlinks_rejected_before_data_read(self):
        os.link(self.config, self.root/'alias')
        before = snapshot(self.root)
        with self.assertRaisesRegex(ValueError, 'single-link'): self.read()
        self.assertNotIn('ReadFile', self.fixture.calls)
        self.assertEqual(snapshot(self.root), before)
        self.fixture.assert_closed(self)

    def test_reparse_handle_rejected_before_data_read(self):
        self.fixture.attributes |= 0x400
        with self.assertRaisesRegex(ValueError, 'reparse'): self.read()
        self.assertNotIn('ReadFile', self.fixture.calls)
        self.fixture.assert_closed(self)

    def test_non_disk_file_rejected_before_data_read(self):
        self.fixture.file_type = 3
        with self.assertRaisesRegex(ValueError, 'disk file'): self.read()
        self.assertNotIn('ReadFile', self.fixture.calls)
        self.fixture.assert_closed(self)

    def test_symlink_ancestor_rejected_without_opening_handle(self):
        if sys.platform == 'win32':
            # Directory junctions need no developer mode and exercise the same
            # native reparse-point rejection as a symlink ancestor.
            subprocess.run(['cmd', '/c', 'mklink', '/J', str(self.root/'link'), str(self.root)],
                           check=True, capture_output=True, text=True)
        else:
            (self.root/'link').symlink_to(self.root, target_is_directory=True)
        with windows_without_posix(self.fixture), self.assertRaisesRegex(ValueError, 'symlink'):
            self.cli.load_config(str(self.root/'link/client.json'))
        self.assertNotIn('CreateFileW', self.fixture.calls)
        self.fixture.assert_closed(self)

    def test_directory_rejected_without_data_read(self):
        # POSIX reaches the regular-file check; native Windows may reject the
        # directory at CreateFileW before a handle exists. Both fail closed.
        with windows_without_posix(self.fixture), self.assertRaises((ValueError, OSError)):
            self.cli.load_config(str(self.root))
        self.assertNotIn('ReadFile', self.fixture.calls)
        self.fixture.assert_closed(self)

    def test_native_failures_fail_closed_and_release_every_resource(self):
        for name in ('CreateFileW','GetFileType','GetFileInformationByHandle','GetSecurityInfo',
                     'OpenProcessToken','GetTokenInformation','EqualSid','ReadFile'):
            with self.subTest(api=name):
                self.fixture = Win32Fixture()
                self.fixture.fail = name
                before = snapshot(self.root)
                with self.assertRaises((OSError, ValueError)): self.read()
                self.assertEqual(snapshot(self.root), before)
                self.fixture.assert_closed(self)

    def test_oversized_token_information_rejected(self):
        self.fixture.token_size = 65537
        with self.assertRaisesRegex(ValueError, 'token user information'): self.read()
        self.assertNotIn('ReadFile', self.fixture.calls)
        self.fixture.assert_closed(self)

    def test_native_identity_drift_rejected(self):
        self.fixture.identity_drift = True
        with self.assertRaisesRegex(ValueError, 'changed'): self.read()
        self.fixture.assert_closed(self)

    def test_path_identity_drift_rejected(self):
        self.fixture.path_drift = True
        with self.assertRaisesRegex(ValueError, 'path changed'): self.read()
        self.fixture.assert_closed(self)

    def test_absent_parent_read_never_creates_directories(self):
        before = snapshot(self.root)
        with windows_without_posix(self.fixture), self.assertRaises(FileNotFoundError):
            self.cli.load_config(str(self.root/'absent/config.json'))
        self.assertEqual(snapshot(self.root), before)
        self.fixture.assert_closed(self)

    def test_native_api_unavailable_has_concise_error_not_attribute_traceback(self):
        with windows_without_posix(self.fixture), mock.patch.object(sys,'argv',['cli','--config',str(self.config),'peers']), mock.patch.object(ctypes,'WinDLL'), contextlib.redirect_stderr(io.StringIO()) as err:
            del ctypes.WinDLL
            self.assertEqual(self.cli.main(), 1)
        self.assertIn('cannot read client config:',err.getvalue())
        self.assertIn('native Windows file/security APIs',err.getvalue())
        self.assertNotIn('Traceback',err.getvalue())

    def test_linux_reader_keeps_original_single_link_owner_validation(self):
        with mock.patch.object(sys, 'platform', 'linux'), \
                mock.patch.object(os, 'geteuid', return_value=0, create=True), \
                mock.patch.object(self.cli,'_read_windows_private_config',side_effect=AssertionError('Windows path on Linux')):
            self.assertEqual(self.cli.load_config(str(self.config)),self.cfg)
            os.link(self.config,self.root/'alias')
            with self.assertRaisesRegex(ValueError,'hardlinks'): self.cli.load_config(str(self.config))

    def test_macos_publication_stays_blocked_before_reader_or_effects(self):
        commands = [['keygen','--relay-url',self.cfg['relay_url']],['attach-key'],['register-key'],
                    ['redeem','invalid-link-not-to-be-read'],['enroll','--relay',self.cfg['relay_url'],'--yes']]
        before = snapshot(self.root)
        with mock.patch.object(sys, 'platform', 'darwin'):
            for argv in commands:
                with self.subTest(command=argv[0]), mock.patch.object(sys,'argv',['cli','--config',str(self.config),*argv]), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(self.cli.main(),1)
        self.assertEqual(self.fixture.calls,[])
        self.assertEqual(snapshot(self.root),before)


if __name__ == '__main__':
    unittest.main(verbosity=2)
