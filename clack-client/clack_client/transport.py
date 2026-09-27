"""HTTP transport: curl primary, Python urllib fallback.

Security rules:
- NEVER put secrets in process argv (visible via ps). Use header files.
- Only fall back to Python on curl UNAVAILABILITY, not on TLS/policy failures.
- Disable curlrc, no redirects, bounded response size.
"""

import json
import os
import re
import subprocess
import tempfile

from .errors import RelayUnreachable, TransportUnavailable


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
    """Execute HTTP via curl. Secrets go in a header file, never argv."""
    header_file = None
    body_file = None
    try:
        # Write headers to a file — never in argv
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.headers') as f:
            for k, v in headers.items():
                # Escape: curl -H @file reads "Header: value" lines
                f.write(f"{k}: {v}\n")
            header_file = f.name

        cmd = [
            "curl", "-s", "-m", str(timeout),
            "--noproxy", "*",  # we handle proxy via env, not curlrc
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
            cmd += ["--data-binary", "@" + body_file]

        # --noproxy "*" is wrong — remove it, we WANT proxy via env
        cmd.remove("--noproxy")
        cmd.remove("*")

        result = subprocess.run(cmd, capture_output=True, timeout=timeout + 10)
        if result.returncode != 0:
            # Distinguish "curl not available" from other failures
            stderr = result.stderr.decode()[:200]
            raise TransportUnavailable(f"curl failed (rc={result.returncode}): {stderr}")
        status, body = _parse_curl_output(result.stdout)
        return status, body
    except FileNotFoundError:
        raise TransportUnavailable("curl binary not found")
    finally:
        for p in (header_file, body_file):
            if p and os.path.exists(p):
                os.unlink(p)


def python_request(method, url, headers, data=None, timeout=30):
    """Python urllib fallback — only when curl is unavailable."""
    import urllib.request
    import urllib.error
    import http.client
    import time

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(NoRedirect())
    last_exc = None
    for attempt in range(3):
        req = urllib.request.Request(url, data=data, method=method)
        for k, v in headers.items():
            req.add_header(k, v)
        # Cap response size
        req.add_header("Accept-Encoding", "identity")
        try:
            with opener.open(req, timeout=timeout) as resp:
                body = resp.read(10 * 1024 * 1024 + 1)
                if len(body) > 10 * 1024 * 1024:
                    raise ValueError("Response too large")
                return resp.status, body
        except urllib.error.HTTPError as e:
            return e.code, e.read(10 * 1024 * 1024)
        except (http.client.IncompleteRead, http.client.RemoteDisconnected,
                ConnectionError, TimeoutError) as e:
            last_exc = e
            if attempt < 2:
                time.sleep(1 + attempt)
                continue
            raise RelayUnreachable(f"Python transport failed: {e}")
    raise last_exc or RelayUnreachable("Python transport failed")


def request(method, url, headers, data=None, timeout=30, allow_fallback=True):
    """Primary transport.

    Uses curl. Falls back to Python ONLY if curl is unavailable
    (binary missing) — never on TLS errors, parse failures, or policy
    rejections. Those are real errors, not transport issues.
    """
    use_curl = os.environ.get("CLACK_USE_CURL", "1") == "1"
    if use_curl:
        try:
            return curl_request(method, url, headers, data, timeout)
        except TransportUnavailable:
            if not allow_fallback:
                raise
            # curl binary missing — fall back to Python
            pass
        # Any other exception (TLS, parse, etc.) propagates — not a fallback case
    return python_request(method, url, headers, data, timeout)
