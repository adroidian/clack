"""HTTP transport: curl primary, Python urllib fallback.

curl's TLS fingerprint is allowlisted by edges doing JA3 filtering
(Cloudflare, TypeSafe, etc.). Python's urllib gets silently dropped.
"""

import json
import os
import re
import subprocess
import tempfile
import urllib.request
import urllib.error
import http.client
import time

from .errors import RelayUnreachable


def _parse_curl_output(output):
    """Parse curl -D - output, handling proxy CONNECT responses.

    When going through a proxy, curl outputs the proxy's
    '200 Connection Established' headers before the actual response.
    We take the LAST header block + body.
    """
    parts = re.split(b"\r\n\r\n|\n\n", output)
    if len(parts) < 2:
        raise ValueError("curl output missing header/body separator")
    body = parts[-1]
    header_text = parts[-2]
    status_line = header_text.strip().split(b"\n")[0].decode()
    status = int(status_line.split()[1])
    return status, body


def curl_request(method, url, headers, data=None, timeout=30):
    """Execute HTTP via curl subprocess."""
    cmd = ["curl", "-s", "-m", str(timeout), "-X", method, url, "-D", "-", "-o", "-"]
    for k, v in headers.items():
        cmd += ["-H", f"{k}: {v}"]
    body_file = None
    if data is not None:
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.json') as f:
            f.write(data)
            body_file = f.name
        cmd += ["--data-binary", "@" + body_file]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout + 10)
        if result.returncode != 0:
            raise ConnectionError(f"curl exited {result.returncode}: {result.stderr.decode()[:200]}")
        status, body = _parse_curl_output(result.stdout)
        return status, body
    finally:
        if body_file and os.path.exists(body_file):
            os.unlink(body_file)


def python_request(method, url, headers, data=None, timeout=30):
    """Execute HTTP via Python urllib (fallback)."""
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in headers.items():
        req.add_header(k, v)
    # Don't follow redirects
    opener = urllib.request.build_opener(NoRedirectHandler())
    last_exc = None
    for attempt in range(3):
        try:
            with opener.open(req, timeout=timeout) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
        except (http.client.IncompleteRead, http.client.RemoteDisconnected,
                ConnectionError, TimeoutError) as e:
            last_exc = e
            if attempt < 2:
                time.sleep(1 + attempt)
                # Rebuild: Request objects can be single-use after failure
                req = urllib.request.Request(url, data=data, method=method)
                for k, v in headers.items():
                    req.add_header(k, v)
                continue
            raise
    raise last_exc or RelayUnreachable("Python transport failed")


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(method, url, headers, data=None, timeout=30):
    """Primary transport with fallback.

    Tries curl first (CLACK_USE_CURL=1, default). Falls back to Python
    urllib if curl fails or is disabled.
    """
    use_curl = os.environ.get("CLACK_USE_CURL", "1") == "1"
    if use_curl:
        try:
            return curl_request(method, url, headers, data, timeout)
        except Exception:
            pass  # Fall through to Python
    return python_request(method, url, headers, data, timeout)
