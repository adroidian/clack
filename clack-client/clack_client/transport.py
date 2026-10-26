"""HTTP transport: curl primary, Python urllib fallback.

Security rules:
- NEVER put secrets in process argv (visible via ps). Use header files.
- Fall back to Python ONLY when the curl binary is missing/unlaunchable
  (CurlMissing). NEVER on TLS errors, DNS failures, timeouts, or parse
  failures — those are real errors (CurlFailed), not transport issues.
- curl runs with -q/--disable: never reads ~/.curlrc.
- Retries happen at the SIGNED-request layer (client._request), which
  re-signs with a fresh nonce per attempt. This module never retries with
  the same headers — a reused nonce is a replay.
- No redirects, ever. Bounded response size.
"""

import ctypes
import os
import re
import secrets
import subprocess
import sys
import tempfile

try:
    import msvcrt
except ImportError:
    msvcrt = None

from .errors import RelayUnreachable, CurlMissing, CurlFailed


def _windows_open_private_stage(path):
    """Create a non-shared stage with explicit caller ownership and DACL."""
    if msvcrt is None:
        raise OSError("native Windows file handles are unavailable")
    DWORD, BOOL, HANDLE = ctypes.c_uint32, ctypes.c_int32, ctypes.c_void_p

    class TOKEN_USER(ctypes.Structure):
        _fields_ = [("sid", HANDLE), ("attributes", DWORD)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    pointer = ctypes.POINTER
    for library, name, arguments, result in (
            (kernel, "CreateFileW", [ctypes.c_wchar_p, DWORD, DWORD, HANDLE, DWORD, DWORD, HANDLE], HANDLE),
            (kernel, "CloseHandle", [HANDLE], BOOL),
            (kernel, "GetCurrentProcess", [], HANDLE),
            (kernel, "LocalFree", [HANDLE], HANDLE),
            (security, "OpenProcessToken", [HANDLE, DWORD, pointer(HANDLE)], BOOL),
            (security, "GetTokenInformation", [HANDLE, DWORD, HANDLE, DWORD, pointer(DWORD)], BOOL),
            (security, "ConvertSidToStringSidW", [HANDLE, pointer(ctypes.c_wchar_p)], BOOL),
            (security, "ConvertStringSecurityDescriptorToSecurityDescriptorW",
             [ctypes.c_wchar_p, DWORD, pointer(HANDLE), pointer(DWORD)], BOOL),
            (security, "GetSecurityDescriptorDacl",
             [HANDLE, pointer(BOOL), pointer(HANDLE), pointer(BOOL)], BOOL),
            (security, "GetSecurityDescriptorOwner", [HANDLE, pointer(HANDLE), pointer(BOOL)], BOOL),
            (security, "SetSecurityInfo", [HANDLE, DWORD, DWORD, HANDLE, HANDLE, HANDLE, HANDLE], DWORD)):
        function = getattr(library, name)
        function.argtypes, function.restype = arguments, result

    token, text, descriptor = HANDLE(), ctypes.c_wchar_p(), HANDLE()
    handle = None
    try:
        if not security.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
            raise OSError(ctypes.get_last_error(), "OpenProcessToken failed")
        needed = DWORD()
        security.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        if not ctypes.sizeof(TOKEN_USER) <= needed.value <= 65536:
            raise ValueError("Windows token user information is unavailable or invalid")
        buffer = ctypes.create_string_buffer(needed.value)
        if not security.GetTokenInformation(token, 1, buffer, needed.value, ctypes.byref(needed)):
            raise OSError(ctypes.get_last_error(), "GetTokenInformation(TokenUser) failed")
        user = ctypes.cast(buffer, ctypes.POINTER(TOKEN_USER)).contents
        if not user.sid or not security.ConvertSidToStringSidW(user.sid, ctypes.byref(text)):
            raise OSError(ctypes.get_last_error(), "ConvertSidToStringSidW failed")
        sid = text.value
        sddl = "O:%sD:P(A;;FA;;;%s)" % (sid, sid)
        if not security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, 1, ctypes.byref(descriptor), None):
            raise OSError(ctypes.get_last_error(), "cannot construct Windows private security descriptor")
        present, defaulted, dacl = BOOL(), BOOL(), HANDLE()
        if not security.GetSecurityDescriptorDacl(
                descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)):
            raise OSError(ctypes.get_last_error(), "cannot read Windows private DACL")
        if not present.value or not dacl.value:
            raise ValueError("Windows private DACL is absent")
        owner, owner_defaulted = HANDLE(), BOOL()
        if not security.GetSecurityDescriptorOwner(
                descriptor, ctypes.byref(owner), ctypes.byref(owner_defaulted)) or not owner.value:
            raise OSError(ctypes.get_last_error(), "cannot read Windows private owner")

        # GENERIC_WRITE | READ_CONTROL | WRITE_DAC | WRITE_OWNER; no sharing;
        # CREATE_NEW; do not follow a final reparse point.
        handle = kernel.CreateFileW(path, 0x400E0000, 0, None, 1, 0x00200000, None)
        if handle in (None, ctypes.c_void_p(-1).value):
            handle = None
            raise OSError(ctypes.get_last_error(), "cannot create Windows private stage", path)
        # OWNER | DACL | PROTECTED_DACL. Secret bytes are written only after
        # the explicit current-token owner and caller-only DACL are in place.
        code = security.SetSecurityInfo(handle, 1, 0x80000005, owner, None, dacl, None)
        if code:
            raise OSError(code, "cannot protect Windows private artifact")
        fd = msvcrt.open_osfhandle(handle, os.O_WRONLY)
        handle = None  # The Python file descriptor now owns the native handle.
        return fd
    finally:
        if handle not in (None, ctypes.c_void_p(-1).value):
            kernel.CloseHandle(handle)
        if descriptor.value:
            kernel.LocalFree(descriptor)
        if text.value:
            kernel.LocalFree(ctypes.cast(text, ctypes.c_void_p))
        if token.value:
            kernel.CloseHandle(token)


def _write_curl_private_temp(data, suffix):
    """Write transport secrets with cleanup across every setup failure."""
    path = None
    try:
        if sys.platform == "win32":
            path = os.path.join(tempfile.gettempdir(),
                                ".clack-curl-%s%s" % (secrets.token_hex(8), suffix))
            fd = _windows_open_private_stage(path)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
        else:
            with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=suffix) as stream:
                path = stream.name
                os.chmod(path, 0o600)
                stream.write(data)
        return path
    except Exception:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass
        raise


def _parse_curl_output(output):
    """Parse curl -D - output, handling proxy CONNECT responses."""
    parts = re.split(b"\r\n\r\n|\n\n", output)
    if len(parts) < 2:
        raise ValueError("curl output missing header/body separator")
    body = parts[-1]
    header_text = parts[-2]
    status_line = header_text.strip().split(b"\n")[0].decode()
    status = int(status_line.split()[1])
    return status, body


def curl_request(method, url, headers, data=None, timeout=30):
    """Execute HTTP via curl. Secrets go in a header file, never argv.

    Raises CurlMissing only if the curl binary is absent/unlaunchable.
    Raises CurlFailed for every other failure (TLS, DNS, timeout, parse).
    """
    header_file = None
    body_file = None
    try:
        # Bearer and signature authority live only in owner-only temp files.
        header_bytes = "".join("%s: %s\n" % (k, v) for k, v in headers.items()).encode("utf-8")
        header_file = _write_curl_private_temp(header_bytes, ".headers")

        cmd = [
            "curl", "-q",  # --disable: never read ~/.curlrc
            "-s", "-m", str(timeout),
            "--no-progress-meter",
            "-X", method,
            "--header", "@" + header_file,
            "-D", "-", "-o", "-",
            "--max-redirs", "0",  # no redirects, ever
            "--max-filesize", "10485760",  # 10MB cap
            url,
        ]
        if data is not None:
            body_file = _write_curl_private_temp(data, ".json")
            cmd += ["--data-binary", "@" + body_file]

        try:
            result = subprocess.run(cmd, capture_output=True, timeout=timeout + 10)
        except FileNotFoundError:
            # curl binary not on PATH (or not executable)
            raise CurlMissing("curl binary not found or not executable")
        except OSError as e:
            # unlaunchable for another OS-level reason
            raise CurlMissing(f"curl unlaunchable: {e}")

        if result.returncode != 0:
            stderr = result.stderr.decode(errors="replace")[:300]
            # Exit 60 = TLS certificate problem, 6 = DNS, 7 = connect,
            # 28 = timeout, etc. ALL of these are real failures, never a
            # reason to downgrade to the Python transport.
            raise CurlFailed(
                f"curl failed (rc={result.returncode}): {stderr}",
                returncode=result.returncode,
            )
        try:
            status, body = _parse_curl_output(result.stdout)
        except Exception as e:
            raise CurlFailed(f"curl output parse failed: {e}")
        return status, body
    finally:
        for p in (header_file, body_file):
            if p and os.path.exists(p):
                os.unlink(p)


def python_request(method, url, headers, data=None, timeout=30):
    """Python urllib fallback — only when curl is unavailable.

    Single attempt, no retries. The headers carry a signed nonce; retrying
    with the same headers would replay the nonce. Retries belong at the
    signed-request layer (client._request), which re-signs per attempt.
    """
    import urllib.request
    import urllib.error
    import http.client

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(NoRedirect())
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in headers.items():
        req.add_header(k, v)
    req.add_header("Accept-Encoding", "identity")
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(10 * 1024 * 1024 + 1)
            if len(body) > 10 * 1024 * 1024:
                raise ValueError("Response too large")
            return resp.status, body
    except urllib.error.HTTPError as e:
        return e.code, e.read(10 * 1024 * 1024)
    except Exception as e:
        raise RelayUnreachable(f"Python transport failed: {type(e).__name__}: {e}")


def request(method, url, headers, data=None, timeout=30, allow_fallback=True):
    """Primary transport.

    Uses curl. Falls back to Python ONLY on CurlMissing (binary absent or
    unlaunchable) — never on CurlFailed (TLS, DNS, timeout, parse). A TLS
    failure downgraded to urllib would silently trade the stronger
    transport for a weaker one; that path is closed.
    """
    use_curl = os.environ.get("CLACK_USE_CURL", "1") == "1"
    if use_curl:
        try:
            return curl_request(method, url, headers, data, timeout)
        except CurlMissing:
            if not allow_fallback:
                raise
            # curl binary genuinely absent — Python is the only option left
        # CurlFailed and anything else propagate: real errors, not fallback cases
    return python_request(method, url, headers, data, timeout)
