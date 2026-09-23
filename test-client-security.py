#!/usr/bin/env python3
"""Client transport security regression tests (Flint review F1-F5).

Scratch only, never live. Spins up one real relay (temp dir, port 18996,
fresh openssl identity key) plus tiny loopback stubs, and covers:

  F1: wrong relay pin -> req() aborts BEFORE the API request is sent
      (stub observes the identity fetch but zero API hits)
      right pin -> request goes through
      no pin -> TOFU pins and persists relay_identity_fingerprint (0600)
  F2: 302 on an authenticated request -> fail closed, redirect target
      receives nothing (no bearer, no signature headers)
      302 on the identity fetch itself -> raises, never verified
  F3: identity proof for a DIFFERENT nonce -> rejected (stale-proof replay)
      unexpected algorithm field -> rejected
  F4: 503 identity with a stored pin -> check_relay_identity aborts
      503 identity with no pin -> returns None (fresh-onboarding path)
  P1: 503 identity + token-bearing config -> req() aborts BEFORE the API
      request is sent (stub records zero API hits and no Authorization
      header anywhere: no 503 credential downgrade)
  P2: first contact + token, non-interactive -> req() aborts, pins nothing
      first contact + token, interactive YES -> confirms, pins, proceeds
      first contact + token, interactive decline -> aborts
  F5: cleartext http:// to a non-loopback origin -> loud WARNING
      (loopback http stays quiet)
"""
import contextlib
import http.server
import importlib.util
import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
RELAY_PY = os.path.join(HERE, "relay.py")
CLI = os.path.join(HERE, "relay-cli.py")
PORT = 18996
REAL = "http://127.0.0.1:%d" % PORT

PASS = 0
FAIL = 0
TMPD = tempfile.mkdtemp(prefix="clack-clientsec-")
SRV = None


def check(cond, name, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("ok   %s" % name)
    else:
        FAIL += 1
        print("FAIL %s %s" % (name, detail))


_spec = importlib.util.spec_from_file_location("relay_cli", CLI)
_rc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_rc)


def _der_ints(der):
    """Minimal DER parser returning the INTEGERs of a PKCS#1 RSAPrivateKey."""
    ints = []
    i = 0

    def read_len(j):
        n = der[j]
        j += 1
        if n & 0x80:
            k = n & 0x7F
            n = int.from_bytes(der[j:j + k], "big")
            j += k
        return n, j
    assert der[i] == 0x30
    i += 1
    _, i = read_len(i)
    while i < len(der):
        assert der[i] == 0x02
        i += 1
        ln, i = read_len(i)
        ints.append(int.from_bytes(der[i:i + ln], "big"))
        i += ln
    return ints


def gen_rsa_key():
    pem = os.path.join(TMPD, "test-id.pem")
    der = os.path.join(TMPD, "test-id.der")
    subprocess.run(["openssl", "genrsa", "-out", pem, "1024"],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "rsa", "-in", pem, "-traditional",
                    "-outform", "DER", "-out", der],
                   check=True, capture_output=True)
    with open(der, "rb") as f:
        _ver, n, e, d = _der_ints(f.read())[:4]
    return {"n": format(n, "x"), "e": format(e, "x"), "d": format(d, "x")}


def start_relay():
    global SRV
    cfg = {"port": PORT, "peers": {}, "identity_key": gen_rsa_key()}
    with open(os.path.join(TMPD, "relay-config.json"), "w") as f:
        json.dump(cfg, f)
    log = open(os.path.join(TMPD, "srv.log"), "a")
    SRV = subprocess.Popen(
        [sys.executable, RELAY_PY],
        env=dict(os.environ, CLACK_RELAY_BASE=TMPD),
        stdout=log, stderr=subprocess.STDOUT)
    for _ in range(40):
        if SRV.poll() is not None:
            raise RuntimeError("scratch relay exited during startup")
        try:
            with urllib.request.urlopen(REAL + "/health", timeout=2) as r:
                if r.status == 200:
                    return
        except Exception:
            pass
        time.sleep(0.25)
    raise RuntimeError("scratch relay did not start")


def stop_relay():
    global SRV
    if SRV and SRV.poll() is None:
        SRV.terminate()
        try:
            SRV.wait(timeout=5)
        except Exception:
            SRV.kill()
    SRV = None


def run_stub(handler_cls):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, "http://127.0.0.1:%d" % srv.server_address[1]


def proxy_identity_to_real(path):
    """Fetch the real relay's /v1/identity for the same query, verbatim."""
    with urllib.request.urlopen(REAL + path, timeout=10) as r:
        return r.status, r.read()


class CountingHandler(http.server.BaseHTTPRequestHandler):
    """Records every hit; subclasses decide what to serve."""
    hits = []          # class-level: reset per stub via fresh subclass
    mode = "proxy"

    def _record(self):
        self.hits.append((self.command, self.path,
                          dict(self.headers)))

    def do_GET(self):
        self._record()
        if self.path.startswith("/v1/identity"):
            if self.mode == "redirect":
                self.send_response(302)
                self.send_header("Location",
                                 self.server.target + "/v1/identity")
                self.end_headers()
                return
            if self.mode == "unavailable":
                body = json.dumps({"error": "identity_unavailable"}).encode()
                self.send_response(503)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            _code, body = proxy_identity_to_real(self.path)
            if self.mode == "stale-proof":
                # answer with a proof for a DIFFERENT nonce (F3)
                import urllib.parse
                other = "00" * 32
                _c2, body = proxy_identity_to_real(
                    "/v1/identity?nonce=" + other)
            if self.mode == "bad-alg":
                _c2, body = proxy_identity_to_real(self.path)
                obj = json.loads(body.decode())
                obj["algorithm"] = "rsa-sha256-bogus"
                body = json.dumps(obj).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/v1/peers") and self.mode == "redirect-api":
            self.send_response(302)
            self.send_header("Location",
                             self.server.target + "/v1/peers")
            self.end_headers()
            return
        body = json.dumps({"ok": True}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def fresh_handler(mode):
    return type("H_%s_%d" % (mode, time.time_ns()),
                (CountingHandler,), {"hits": [], "mode": mode})


@contextlib.contextmanager
def captured_stderr():
    buf = io.StringIO()
    old = sys.stderr
    sys.stderr = buf
    try:
        yield buf
    finally:
        sys.stderr = old


@contextlib.contextmanager
def captured_stdout():
    buf = io.StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        yield buf
    finally:
        sys.stdout = old


class _FakeStdin(io.StringIO):
    def __init__(self, text, tty):
        io.StringIO.__init__(self, text)
        self._is_a_tty = tty

    def isatty(self):
        return self._is_a_tty


@contextlib.contextmanager
def fake_stdin(text, tty):
    """Deterministic stdin for the P2 interactive-confirmation paths."""
    old = sys.stdin
    sys.stdin = _FakeStdin(text, tty)
    try:
        yield
    finally:
        sys.stdin = old


def check_private_file(path, name):
    """The config holds Bearer <redacted>: only owner/admins may read it.

    Platform-aware (Flint re-review note): POSIX mode bits are meaningless
    on Windows, so there we inspect the ACL via icacls and require that no
    ACE grants access to a broad identity (Everyone/Users/...).
    """
    if os.name == "nt":
        try:
            p = subprocess.run(["icacls", path], capture_output=True,
                               text=True, timeout=20)
            out = p.stdout
        except Exception as e:
            check(False, name, "icacls failed: %s" % e)
            return
        lines = [l.strip() for l in out.splitlines() if l.strip()]
        aces = lines[1:] if len(lines) > 1 else []
        broad = [a for a in aces if re.search(
            r"Everyone|\\Users\b|Authenticated Users|INTERACTIVE", a, re.I)]
        check(bool(aces) and not broad, name,
              "icacls aces: %s" % " | ".join(aces)[:220])
    else:
        mode = oct(os.stat(path).st_mode & 0o777)
        check(mode == "0o600", name, mode)


def expect_exit(fn, name):
    _rc._verified_origins.clear()
    try:
        with captured_stderr():
            fn()
    except SystemExit as e:
        check(e.code == 1, name, "exit code %r" % (e.code,))
        return True
    check(False, name, "no SystemExit raised")
    return False


def main():
    global FAIL
    start_relay()
    try:
        real_fp, _pub = _rc.fetch_relay_identity(REAL)
        check(bool(real_fp) and real_fp.startswith("sha256:"),
              "F1 scratch relay has a stable identity fingerprint", real_fp)

        # --- F1: wrong pin aborts before the API request is sent -----------
        h = fresh_handler("proxy")
        srv, stub = run_stub(h)
        srv.target = None
        cfg = {"peers": {"x": "tok"},
               "relay_identity_fingerprint": "sha256:deadbeefdeadbeef"}
        if expect_exit(lambda: _rc.req(cfg, "GET", "/health", base=stub),
                       "F1 wrong pin aborts"):
            api_hits = [x for x in h.hits if not x[1].startswith("/v1/identity")]
            check(len(api_hits) == 0,
                  "F1 wrong pin: zero API requests transmitted",
                  "saw %d" % len(api_hits))
            check(any(x[1].startswith("/v1/identity") for x in h.hits),
                  "F1 wrong pin: identity was checked first")
        srv.shutdown()

        # --- F1: right pin -> request goes through --------------------------
        _rc._verified_origins.clear()
        cfg = {"peers": {"x": "tok"},
               "relay_identity_fingerprint": real_fp}
        with captured_stderr():
            code, out = _rc.req(cfg, "GET", "/health", base=REAL)
        check(code == 200, "F1 right pin: request transmitted", code)

        # --- P2: first contact + token needs explicit confirmation ---------
        _rc._verified_origins.clear()
        cfg_path = os.path.join(TMPD, "tofu-config.json")
        with open(cfg_path, "w") as f:
            json.dump({"peers": {"x": "tok"}, "base_url": REAL}, f)
        _rc._config_path = cfg_path
        cfg = {"peers": {"x": "tok"}, "base_url": REAL}
        try:
            # Non-interactive: abort, pin nothing, send nothing.
            with fake_stdin("", False):
                if expect_exit(
                        lambda: _rc.req(cfg, "GET", "/health", base=REAL),
                        "P2 first contact + token, non-interactive aborts"):
                    pass
            saved = json.load(open(cfg_path))
            check("relay_identity_fingerprint" not in saved,
                  "P2 aborted first contact persists no pin")
            # Interactive YES: confirm out-of-band, pin, proceed.
            _rc._verified_origins.clear()
            with fake_stdin("YES\n", True):
                with captured_stdout() as out_buf:
                    code, out = _rc.req(cfg, "GET", "/health", base=REAL)
            check(code == 200, "P2 confirmed first contact succeeds", code)
            saved = json.load(open(cfg_path))
            check(saved.get("relay_identity_fingerprint") == real_fp,
                  "P2 confirmed pin persisted to config",
                  saved.get("relay_identity_fingerprint"))
            check_private_file(cfg_path, "P2 confirmed config stays private")
            check("FIRST CONTACT" in out_buf.getvalue()
                  and real_fp in out_buf.getvalue(),
                  "P2 confirmation prompt names the fingerprint")
            # Interactive decline: abort.
            _rc._verified_origins.clear()
            cfg2 = {"peers": {"x": "tok"}, "base_url": REAL}
            with fake_stdin("no\n", True):
                expect_exit(
                    lambda: _rc.req(cfg2, "GET", "/health", base=REAL),
                    "P2 first contact + token, declined aborts")
        finally:
            _rc._config_path = None

        # --- stale-cache: mid-process TOFU pin upgrades the verdict --------
        # Reproduces the redeem/enroll hello bug: the challenge request ran
        # tokenless and pinless (silent TOFU); after the pin landed in cfg
        # the hello must see "pinned", not a stale "tofu" that refuses the
        # fresh token.
        _rc._verified_origins.clear()
        cfg = {"base_url": REAL}  # tokenless, pinless: silent TOFU
        with captured_stderr():
            level = _rc._ensure_origin_verified(REAL, cfg)
        check(level == "tofu", "mid-process pin: tokenless first contact is tofu",
              level)
        # cmd_redeem/cmd_enroll now hold a token AND the TOFU pin in cfg.
        cfg["service_token"] = "tok"
        cfg["relay_identity_fingerprint"] = real_fp
        with captured_stderr():
            level = _rc._ensure_origin_verified(REAL, cfg)
        check(level == "pinned", "mid-process pin: verdict upgrades to pinned",
              level)

        # --- F2: redirect on authenticated request fails closed --------------
        hb = fresh_handler("sink")
        srv_b, url_b = run_stub(hb)
        ha = fresh_handler("redirect-api")
        srv_a, url_a = run_stub(ha)
        srv_a.target = url_b
        cfg = {"peers": {"x": "tok"},
               "relay_identity_fingerprint": real_fp}
        if expect_exit(lambda: _rc.req(cfg, "GET", "/v1/peers", base=url_a),
                       "F2 cross-origin redirect aborts"):
            leaked = [x for x in hb.hits
                      if "Authorization" in x[2] or "X-Clack-Sig" in x[2]]
            check(len(hb.hits) == 0,
                  "F2 redirect target receives nothing",
                  "saw %d hits" % len(hb.hits))
            check(len(leaked) == 0, "F2 no credential headers leak")
        srv_a.shutdown()
        srv_b.shutdown()

        # --- F2: redirect on the identity fetch itself fails closed ----------
        h = fresh_handler("redirect")
        srv, stub = run_stub(h)
        srv.target = REAL
        try:
            _rc.fetch_relay_identity(stub)
            check(False, "F2 identity redirect raises", "no exception")
        except urllib.error.HTTPError as e:
            check(300 <= e.code < 400, "F2 identity redirect raises HTTPError",
                  e.code)
        except SystemExit:
            check(False, "F2 identity redirect raises",
                  "got SystemExit, want HTTPError")
        srv.shutdown()

        # --- F3: stale proof for a different challenge is rejected -----------
        h = fresh_handler("stale-proof")
        srv, stub = run_stub(h)
        try:
            _rc.fetch_relay_identity(stub)
            check(False, "F3 stale proof rejected", "no exception")
        except ValueError as e:
            check("different challenge" in str(e), "F3 stale proof rejected", e)
        srv.shutdown()

        # --- F3: unexpected algorithm is rejected -----------------------------
        h = fresh_handler("bad-alg")
        srv, stub = run_stub(h)
        try:
            _rc.fetch_relay_identity(stub)
            check(False, "F3 bad algorithm rejected", "no exception")
        except ValueError as e:
            check("algorithm" in str(e), "F3 bad algorithm rejected", e)
        srv.shutdown()

        # --- F4: 503 + stored pin aborts; 503 without pin returns None -------
        h = fresh_handler("unavailable")
        srv, stub = run_stub(h)
        cfg = {"relay_identity_fingerprint": real_fp}
        if expect_exit(lambda: _rc.check_relay_identity(stub, cfg),
                       "F4 503 with pin aborts"):
            pass
        with captured_stderr():
            got = _rc.check_relay_identity(stub, {})
        check(got is None, "F4 503 without pin returns None", got)
        srv.shutdown()

        # --- P1: 503 identity + token-bearing config -> fail closed ----------
        # Mirrors Flint's credential-capture proof: the endpoint answers 503
        # on the identity challenge, then watches for the Bearer <redacted>
        # on the API call. The client must abort before any API request.
        h = fresh_handler("unavailable")
        srv, stub = run_stub(h)
        cfg = {"peers": {"x": "tok"}, "base_url": stub}
        if expect_exit(lambda: _rc.req(cfg, "GET", "/v1/peers", base=stub),
                       "P1 503 + token aborts before the API request"):
            api_hits = [x for x in h.hits
                        if not x[1].startswith("/v1/identity")]
            check(len(api_hits) == 0,
                  "P1 503 + token: zero API requests transmitted",
                  "saw %d" % len(api_hits))
            check(not any("Authorization" in x[2] for x in h.hits),
                  "P1 503 + token: no Authorization header observed anywhere")
            check(any(x[1].startswith("/v1/identity") for x in h.hits),
                  "P1 503 + token: identity was checked first")
        srv.shutdown()

        # --- F5: cleartext warning for non-loopback http ----------------------
        orig_fetch = _rc.fetch_relay_identity
        _rc.fetch_relay_identity = lambda url, cfg=None: (None, None)
        try:
            _rc._verified_origins.clear()
            with captured_stderr() as err:
                _rc._ensure_origin_verified("http://192.0.2.99:9", {})
            check("cleartext" in err.getvalue(),
                  "F5 cleartext non-loopback warns loudly")
            _rc._verified_origins.clear()
            with captured_stderr() as err:
                _rc._ensure_origin_verified("http://127.0.0.1:9", {})
            check("cleartext" not in err.getvalue(),
                  "F5 loopback http stays quiet")
        finally:
            _rc.fetch_relay_identity = orig_fetch
    finally:
        stop_relay()

    print("\nclient-security: %d passed, %d failed" % (PASS, FAIL))
    if FAIL:
        print("KEEPING scratch dir: %s" % TMPD)
    else:
        shutil.rmtree(TMPD, ignore_errors=True)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
