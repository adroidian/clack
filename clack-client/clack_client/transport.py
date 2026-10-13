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

import os
import re
import subprocess
import tempfile

from .errors import RelayUnreachable, CurlMissing, CurlFailed


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
        # Write headers to a file — never in argv. Explicit 0600 even
        # though NamedTemporaryFile defaults to it; the permission is
        # load-bearing (Bearer <redacted> live here).
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.headers') as f:
            for k, v in headers.items():
                # Escape: curl -H @file reads "Header: value" lines
                f.write(f"{k}: {v}\n")
            header_file = f.name
        os.chmod(header_file, 0o600)

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
            with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.json') as f:
                f.write(data)
                body_file = f.name
            os.chmod(body_file, 0o600)
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
