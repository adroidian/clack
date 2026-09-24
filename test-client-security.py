#!/usr/bin/env python3
"""Client transport security regression tests (Flint review F1-F5, v0.2.13 gate).

Scratch only, never live. Spins up one real relay (temp dir, port 18804,
fresh openssl identity key) plus tiny loopback stubs, and covers:
(stubs serve /v1/identity DIRECTLY with a fresh ephemeral RSA key in the
real relay's schema -- no proxying, so the genuine verify-and-pin path is
exercised against the stub endpoint itself)

  F1: wrong relay pin -> req() aborts BEFORE the API request is sent
      (stub observes the identity fetch but zero API hits)
      right pin -> request goes through
      no pin -> TOFU pins and persists relay_identity_fingerprint (0600)
  F2: 3xx on an authenticated request -> fail closed, redirect target
      receives nothing (no bearer, no signature headers, no body):
        cross-host 302, cross-port 302, scheme-change (http->https) 302,
        https->http DOWNGRADE 302 over a real TLS stub (test CA),
        and method-changing/method-preserving POST redirects
        (301/302/303/307/308) carrying a secret body
      3xx on the identity fetch itself -> raises, never verified
  F3: identity proof for a DIFFERENT nonce -> rejected (stale-proof replay)
      proof whose echoed nonce was rewritten to match the challenge but
        whose signature was made over other bytes -> rejected (the client
        verifies over its LOCAL nonce bytes, never the echo)
      response with no signature -> rejected
      unexpected algorithm field -> rejected
  F4: 503 identity aborts whether or not a pin exists -- on the enrollment
      gate (check_relay_identity) AND on the req() path. No secret,
      enrollment proof, or message body leaves the client.
      unreachable identity endpoint (transport error) aborts with and
      without a pin; the authenticated request is never even attempted.
  P1: 503 identity + token-bearing config -> req() aborts BEFORE the API
      request is sent (stub records zero API hits and no Authorization
      header anywhere: no 503 credential downgrade)
  P2: first contact + token, non-interactive -> req() aborts, pins nothing
      first contact + token, interactive YES -> confirms, pins, proceeds
      first contact + token, interactive decline -> aborts
  F5: cleartext http:// to a non-loopback origin -> loud WARNING
      (loopback http stays quiet)

Methodology (per the v0.2.13 amendment): every stub records the full
request (method, path, headers, body). Every negative case asserts ZERO
credential transmission AT THE RECEIVING SERVER: no Authorization bearer,
no claim secret, no X-Clack-Sig headers, no secret body bytes -- "the
client aborted" alone is never enough. Redirect targets are separate
recording stubs that must receive nothing. And every "correct" pin in
these tests is established through the client's genuine verify-and-pin
path against a stub identity endpoint (ephemeral keys) -- never injected
as a fixture -- so the negative cases prove the real check blocks
transmission. The one deliberate fixture is the WRONG pin: it starts as
a genuinely established pin and is then tampered with, so the test proves
the genuine comparison rejects the mismatch.
"""
import contextlib
import base64
import hashlib
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
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
RELAY_PY = os.path.join(HERE, "relay.py")
CLI = os.path.join(HERE, "relay-cli.py")
PORT = int(os.environ.get("CLACK_TEST_PORT", "18804"))
REAL = "http://127.0.0.1:%d" % PORT

# Synthetic credentials: every negative test asserts these exact values
# never reach a stub the client was not supposed to talk to.
SECRET_TOKEN = "tok-synthetic-9f2b4c1e-7d3a"
SECRET = b"synthetic-secret-9f2b4c1e"

PASS = 0
FAIL = 0
TMPD = tempfile.mkdtemp(prefix="clack-clientsec-")
SRV = None


def gen_tls_certs(d):
    """Test CA + server cert (SAN: localhost, 127.0.0.1) for the TLS stub.
    Scratch only; 1-day expiry. Generated before relay-cli is imported:
    this Python's HTTPSHandler snapshots its SSL context when the client's
    opener is built at import time, so SSL_CERT_FILE must already trust
    the test CA at that point."""
    ca_key = os.path.join(d, "ca.key")
    ca_crt = os.path.join(d, "ca.crt")
    srv_key = os.path.join(d, "srv.key")
    srv_csr = os.path.join(d, "srv.csr")
    srv_crt = os.path.join(d, "srv.crt")
    ext = os.path.join(d, "srv.ext")
    with open(ext, "w") as f:
        f.write("[san]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                    "-keyout", ca_key, "-out", ca_crt, "-days", "1",
                    "-nodes", "-subj", "/CN=clack-test-ca"],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "req", "-newkey", "rsa:2048",
                    "-keyout", srv_key, "-out", srv_csr,
                    "-nodes", "-subj", "/CN=localhost"],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "x509", "-req", "-in", srv_csr,
                    "-CA", ca_crt, "-CAkey", ca_key, "-CAcreateserial",
                    "-out", srv_crt, "-days", "1",
                    "-extfile", ext, "-extensions", "san"],
                   check=True, capture_output=True)
    return ca_crt, srv_crt, srv_key


# Trust the scratch test CA for the whole process BEFORE relay-cli builds
# its opener (see above). Nothing else in this suite needs public CAs.
_TLS_CA_CRT, _TLS_SRV_CRT, _TLS_SRV_KEY = gen_tls_certs(TMPD)
os.environ["SSL_CERT_FILE"] = _TLS_CA_CRT


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


def run_stub(handler_cls, host="127.0.0.1"):
    srv = http.server.ThreadingHTTPServer((host, 0), handler_cls)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, "http://%s:%d" % (host, srv.server_address[1])


STUB_KEY = None  # {"n","e","d"}: the stubs' ephemeral identity key, per run


def gen_stub_identity_key(d):
    """Fresh ephemeral RSA identity key for the stub endpoints (never a
    fixture, never the real relay's key). The stubs serve /v1/identity
    directly with this key, so the client's genuine verify-and-pin path is
    exercised against the stub endpoint itself."""
    key_pem = os.path.join(d, "stub-identity.pem")
    subprocess.run(["openssl", "genrsa", "-out", key_pem, "2048"],
                   check=True, capture_output=True)
    out = subprocess.run(["openssl", "rsa", "-in", key_pem,
                          "-text", "-noout"],
                         check=True, capture_output=True,
                         text=True).stdout

    def grab(label):
        chunks, ingrab = [], False
        for ln in out.splitlines():
            if not ingrab:
                if ln.startswith(label + ":"):
                    rest = ln.split(":", 1)[1].strip()
                    if rest:  # e.g. "publicExponent: 65537 (0x10001)"
                        m = re.search(r"0x([0-9a-fA-F]+)", rest)
                        return int(m.group(1), 16)
                    ingrab = True
                continue
            s = ln.strip()
            if s and re.fullmatch(r"[0-9a-fA-F:]+", s):
                chunks.append(s.replace(":", ""))
            elif chunks:
                break
        return int("".join(chunks), 16)

    return {"n": grab("modulus"),
            "e": grab("publicExponent"),
            "d": grab("privateExponent")}


def _stub_sign(nonce: bytes) -> bytes:
    """RSASSA-PKCS1-v1_5-SHA256 over the nonce bytes with the stub key --
    the same construction the real relay uses (mirrors the client's
    relay_identity_verify)."""
    t = _rc._SHA256_DINFO_HEAD + hashlib.sha256(nonce).digest()
    k = (STUB_KEY["n"].bit_length() + 7) // 8
    em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return pow(int.from_bytes(em, "big"),
               STUB_KEY["d"], STUB_KEY["n"]).to_bytes(k, "big")


def _stub_identity_proof(nonce_hex):
    """A /v1/identity proof in the real relay's schema, served directly by
    the stub: the client's nonce echoed, signed with the stub's ephemeral
    identity key."""
    return {"nonce": nonce_hex.lower(),
            "algorithm": "rsassa-pkcs1-v1_5-sha256",
            "signature": base64.b64encode(
                _stub_sign(bytes.fromhex(nonce_hex))).decode("ascii"),
            "public_key": {"n": format(STUB_KEY["n"], "x"),
                           "e": format(STUB_KEY["e"], "x")}}


class CountingHandler(http.server.BaseHTTPRequestHandler):
    """Records every hit as (command, path, headers, body_bytes); the
    `mode` class attribute decides what to serve."""
    hits = []          # class-level: reset per stub via fresh subclass
    mode = "ok"        # "ok": serve a valid identity proof directly

    def _record(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        self.hits.append((self.command, self.path,
                          dict(self.headers), body))

    def _identity_status_body(self):
        """(status, body) for /v1/identity under the current mode.

        The stub serves the proof DIRECTLY with its own ephemeral identity
        key (same schema as the real relay) -- the client's genuine
        verify-and-pin path runs against the stub endpoint itself, with no
        proxying and no dependence on the real relay's rate limiter.
        """
        if self.mode == "unavailable":
            body = json.dumps({"error": "identity_unavailable"}).encode()
            return 503, body
        q = urllib.parse.urlparse(self.path).query
        client_nonce = urllib.parse.parse_qs(q).get("nonce", [""])[0]
        try:
            valid = len(bytes.fromhex(client_nonce)) == 32
        except ValueError:
            valid = False
        if self.mode == "stale-proof":
            # answer with a proof for a DIFFERENT nonce (F3)
            proof = _stub_identity_proof("00" * 32)
        elif self.mode == "swapped-nonce":
            # MITM-grade lie: rewrite the echoed nonce to match the client's
            # challenge, but the signature was generated over different
            # bytes. Must fail: the client verifies over its LOCAL nonce
            # bytes, never the echo (F3).
            proof = _stub_identity_proof("11" * 32)
            proof["nonce"] = client_nonce
        else:
            if not valid:
                body = json.dumps(
                    {"error": "nonce_required_hex_32_bytes"}).encode()
                return 400, body
            proof = _stub_identity_proof(client_nonce)
        if self.mode == "no-sig":
            proof.pop("signature", None)
        elif self.mode == "bad-alg":
            proof["algorithm"] = "rsa-sha256-bogus"
        return 200, json.dumps(proof).encode()

    def _serve(self):
        if self.path.startswith("/v1/identity"):
            if self.mode == "redirect":
                self.send_response(302)
                self.send_header("Location",
                                 self.server.target + "/v1/identity")
                self.end_headers()
                return
            status, body = self._identity_status_body()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.mode == "redirect-api" and self.path.startswith("/v1/peers"):
            self.send_response(302)
            self.send_header("Location",
                             self.server.target + "/v1/peers")
            self.end_headers()
            return
        if self.mode == "redirect-custom" and self.path.startswith(
                getattr(self.server, "api_prefix", "/v1/")):
            self.send_response(self.server.redir_code)
            self.send_header("Location", self.server.redir_location)
            self.end_headers()
            return
        body = json.dumps({"ok": True}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._record()
        self._serve()

    def do_POST(self):
        self._record()
        self._serve()

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


def closed_port():
    """A loopback port with no listener: connections are refused."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def assert_zero_transmission(hits, name):
    """ZERO credential transmission at the receiving server.

    Every recorded request must carry: no Authorization header of any
    kind, no X-Clack-* signature/auth header, no claim secret or bearer
    token in headers or body, and no request body bytes at all. The
    identity fetch this guards is a bodiless GET; any body on the wire in
    these negative cases would be a credential or claim channel.
    Header names are matched case-insensitively.
    """
    cred_hits = []
    for cmd, path, hdrs, body in hits:
        h = {str(k).lower(): v for k, v in hdrs.items()}
        if "authorization" in h:
            cred_hits.append((cmd, path, "authorization-header"))
            continue
        if any(k.startswith("x-clack-") for k in h):
            cred_hits.append((cmd, path, "x-clack-header"))
            continue
        blob = b"\n".join(
            str(v).encode("utf-8", "replace") for v in hdrs.values())
        if SECRET in blob or SECRET_TOKEN.encode() in blob:
            cred_hits.append((cmd, path, "secret-bytes"))
            continue
        if body:
            cred_hits.append((cmd, path, "request-body-bytes"))
    check(len(cred_hits) == 0, name + ": zero credential transmission",
          cred_hits)


def tofu_pin_config(url, config_path, seed, pub, token=SECRET_TOKEN):
    """Establish the relay pin through the client's GENUINE verify-and-pin
    path -- never a fixture. Runs a token-bearing first contact with an
    interactive YES confirmation, then cross-checks the pinned value
    against an independent fresh identity verification. Returns the config
    dict with the genuinely established pin set."""
    cfg = {"kind": _rc.IDENTITY_KIND,
           "relay_url": url,
           "identity_pubkey": _rc.b64u_encode(pub),
           "identity_privkey": _rc.b64u_encode(seed),
           "peer_name": "x",
           "service_token": token}
    with open(config_path, "w") as f:
        json.dump(cfg, f)
    _rc._config_path = config_path
    try:
        _rc._verified_origins.clear()
        with fake_stdin("YES\n", True):
            with captured_stdout():
                with captured_stderr():
                    code, _ = _rc.req(dict(cfg), "GET", "/v1/peers", base=url)
        check(code == 200, "TOFU pinning request succeeds", code)
    finally:
        _rc._config_path = None
    saved = json.load(open(config_path))
    pin = saved.get("relay_identity_fingerprint")
    check(bool(pin) and pin.startswith("sha256:"),
          "pin established via genuine verify-and-pin", pin)
    fresh_fp, _ = _rc.fetch_relay_identity(url)
    check(pin == fresh_fp,
          "pinned value matches independent verification", pin)
    cfg["relay_identity_fingerprint"] = pin
    return cfg


def run_tls_stub(handler_cls, srv_crt, srv_key, host="127.0.0.1"):
    """HTTPS loopback stub with the test cert. The client trusts it because
    SSL_CERT_FILE points at the test CA for the whole process (set before
    relay-cli was imported)."""
    import ssl
    srv = http.server.ThreadingHTTPServer((host, 0), handler_cls)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=srv_crt, keyfile=srv_key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, "https://%s:%d" % (host, srv.server_address[1])


def redirect_case(name, code, location_fn, seed, pub,
                  method="GET", body=None, target_host="127.0.0.1"):
    """One 3xx-on-authenticated-request regression case (F2).

    Stub A serves a valid identity directly with its ephemeral key (so the
    pin can be genuinely established), then -- after the pin is verified -- answers `code`
    with Location `location_fn` on the API path. Stub B (the hostile
    redirect target) is a SEPARATE recording server. Asserts the client
    aborts AND that B received nothing at all: no bearer, no signature
    headers, no body bytes -- zero credential transmission at the
    receiving server.
    """
    hb = fresh_handler("sink")
    srv_b, url_b = run_stub(hb, host=target_host)
    ha = fresh_handler("ok")
    srv_a, url_a = run_stub(ha)
    cfg_path = os.path.join(TMPD, "redir-%d.json" % time.time_ns())
    try:
        # Genuine verify-and-pin against stub A's directly-served identity
        # endpoint; the pin below is established by the client itself.
        cfg = tofu_pin_config(url_a, cfg_path, seed, pub)
        mark = len(ha.hits)
        # Now the origin turns hostile: 3xx on the authenticated request.
        ha.mode = "redirect-custom"
        srv_a.redir_code = code
        srv_a.redir_location = location_fn(url_b)
        srv_a.api_prefix = "/v1/"
        # expect_exit clears _verified_origins, forcing re-verification
        # through the stored pin ("pinned" verdict) before the API call.
        path = "/v1/send" if body is not None else "/v1/peers"
        if expect_exit(lambda: _rc.req(cfg, method, path, body, base=url_a),
                       name + " aborts"):
            check(len(hb.hits) == 0,
                  name + ": redirect target receives nothing",
                  "saw %d hits" % len(hb.hits))
            assert_zero_transmission(hb.hits, name + " target")
            # Stub A (the verified origin) saw only the legitimate
            # pre-redirect API attempt after the identity re-check.
            post = [x for x in ha.hits[mark:]
                    if not x[1].startswith("/v1/identity")]
            check(len(post) == 1 and post[0][0] == method
                  and post[0][1] == path,
                  name + ": origin saw only the pre-redirect attempt",
                  [(c, p) for c, p, _h, _b in post])
    finally:
        srv_a.shutdown()
        srv_b.shutdown()


def main():
    global FAIL, STUB_KEY
    start_relay()
    try:
        real_fp, _pub = _rc.fetch_relay_identity(REAL)
        check(bool(real_fp) and real_fp.startswith("sha256:"),
              "F1 scratch relay has a stable identity fingerprint", real_fp)
        # Ephemeral stub identity key: every stub serves /v1/identity
        # directly with this key (same schema as the real relay), so test
        # pins are established through the genuine verify-and-pin path
        # against a stub endpoint -- never a fixture, never proxied.
        STUB_KEY = gen_stub_identity_key(TMPD)
        check(STUB_KEY["n"].bit_length() >= 2048,
              "stub identity key generated", STUB_KEY["e"])
        # Ephemeral client signing key: redirect-case configs carry BOTH a
        # bearer token and X-Clack-Sig headers, so the target stub can prove
        # neither crossed the origin boundary.
        seed, pub = _rc.keygen()

        # --- F1: pin mismatch aborts before the API request is sent ---------
        # The pin starts GENUINE (established via the client's own
        # verify-and-pin) and is then tampered with: the test proves the
        # genuine comparison rejects the mismatch. The stub observes the
        # identity re-check but zero API hits, and the wire carried no
        # credential material at all.
        h = fresh_handler("ok")
        srv, stub = run_stub(h)
        try:
            cfg_path = os.path.join(TMPD, "f1-wrong-pin.json")
            cfg = tofu_pin_config(stub, cfg_path, seed, pub)
            cfg["relay_identity_fingerprint"] = "sha256:deadbeefdeadbeef"
            mark = len(h.hits)
            if expect_exit(lambda: _rc.req(cfg, "GET", "/health", base=stub),
                           "F1 pin mismatch aborts"):
                api_hits = [x for x in h.hits[mark:]
                            if not x[1].startswith("/v1/identity")]
                check(len(api_hits) == 0,
                      "F1 pin mismatch: zero API requests transmitted",
                      "saw %d" % len(api_hits))
                check(any(x[1].startswith("/v1/identity")
                          for x in h.hits[mark:]),
                      "F1 pin mismatch: identity was checked first")
                assert_zero_transmission(h.hits[mark:], "F1 pin mismatch")
        finally:
            srv.shutdown()

        # --- F1: genuinely pinned origin -> request goes through ------------
        # A second request after the TOFU pinning re-verifies through the
        # stored pin ("pinned" verdict, not the "confirmed" cache) and is
        # transmitted.
        h = fresh_handler("ok")
        srv, stub = run_stub(h)
        try:
            cfg_path = os.path.join(TMPD, "f1-right-pin.json")
            cfg = tofu_pin_config(stub, cfg_path, seed, pub)
            _rc._verified_origins.clear()
            with captured_stderr():
                code, out = _rc.req(cfg, "GET", "/health", base=stub)
            check(code == 200, "F1 genuine pin: request transmitted", code)
        finally:
            srv.shutdown()

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
        # tokenless and pinless (silent TOFU, which genuinely persists the
        # pin into cfg via _persist_tofu_pin); after the pin lands in cfg
        # the hello must see "pinned", not a stale "tofu" that refuses the
        # fresh token.
        _rc._verified_origins.clear()
        cfg = {"base_url": REAL}  # tokenless, pinless: silent TOFU
        with captured_stderr():
            level = _rc._ensure_origin_verified(REAL, cfg)
        check(level == "tofu", "mid-process pin: tokenless first contact is tofu",
              level)
        check("relay_identity_fingerprint" in cfg,
              "mid-process pin: silent TOFU genuinely persisted the pin")
        # The redeem/enroll path: check_relay_identity runs the genuine
        # fetch-and-verify, and the caller pins the returned fingerprint --
        # exactly what cmd_redeem/cmd_enroll do (no fixture value).
        relay_fp = _rc.check_relay_identity(REAL, cfg)
        cfg["service_token"] = "tok"
        cfg["relay_identity_fingerprint"] = relay_fp  # TOFU pin, as cmd_redeem does
        with captured_stderr():
            level = _rc._ensure_origin_verified(REAL, cfg)
        check(level == "pinned", "mid-process pin: verdict upgrades to pinned",
              level)

        # --- F2: redirect variants fail closed, target gets nothing ---------
        # (each case establishes its pin through the genuine verify-and-pin
        # path against stub A's directly-served identity, then stub A turns
        # hostile with a 3xx on the authenticated request)
        # cross-host (127.0.0.1 -> 127.0.0.2), 302
        redirect_case("F2 cross-host redirect", 302,
                      lambda b: b + "/v1/peers",
                      seed, pub, target_host="127.0.0.2")
        # cross-port (same host, different port), 302
        redirect_case("F2 cross-port redirect", 302,
                      lambda b: b + "/v1/peers",
                      seed, pub)
        # scheme-change (http -> https), 302: the client must not even
        # attempt the TLS follow.
        redirect_case("F2 scheme-change redirect", 302,
                      lambda b: b.replace("http://", "https://", 1)
                      + "/v1/peers",
                      seed, pub)
        # method-changing and method-preserving POST redirects, each
        # carrying a body with the synthetic secret.
        secret_body = {"id": "msg-synthetic-1", "to": "peer-synthetic",
                       "text": "carrying " + SECRET.decode("ascii")}
        for code in (301, 302, 303, 307, 308):
            redirect_case("F2 POST redirect %d" % code, code,
                          lambda b: b + "/v1/send",
                          seed, pub,
                          method="POST", body=secret_body)

        # --- F2: https -> http DOWNGRADE redirect fails closed ---------------
        # Stub A is a real TLS origin (test CA); it answers 302 to a
        # plain-http URL. The client must abort rather than downgrade the
        # credential-bearing request to cleartext. The downgrade target is
        # a separate plain-HTTP recording stub that must receive nothing.
        ca_crt, srv_crt, srv_key = _TLS_CA_CRT, _TLS_SRV_CRT, _TLS_SRV_KEY
        hb = fresh_handler("sink")
        srv_b, url_b = run_stub(hb)
        ha = fresh_handler("ok")
        srv_a, url_a = run_tls_stub(ha, srv_crt, srv_key)
        try:
            cfg_path = os.path.join(TMPD, "redir-downgrade.json")
            cfg = tofu_pin_config(url_a, cfg_path, seed, pub)
            mark = len(ha.hits)
            ha.mode = "redirect-custom"
            srv_a.redir_code = 302
            srv_a.redir_location = url_b + "/v1/send"
            srv_a.api_prefix = "/v1/"
            secret_body2 = {"id": "msg-synthetic-2", "to": "peer-synthetic",
                            "text": "carrying " + SECRET.decode("ascii")}
            if expect_exit(lambda: _rc.req(cfg, "POST", "/v1/send",
                                           secret_body2, base=url_a),
                           "F2 https->http downgrade redirect aborts"):
                check(len(hb.hits) == 0,
                      "F2 downgrade: redirect target receives nothing",
                      "saw %d hits" % len(hb.hits))
                assert_zero_transmission(hb.hits, "F2 downgrade target")
                post = [x for x in ha.hits[mark:]
                        if not x[1].startswith("/v1/identity")]
                check(len(post) == 1 and post[0][0] == "POST"
                      and post[0][1] == "/v1/send",
                      "F2 downgrade: TLS origin saw only the pre-redirect "
                      "attempt",
                      [(c, p) for c, p, _h, _b in post])
        finally:
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

        # --- F3: rewritten-nonce proof is rejected ------------------------------
        # The echoed nonce matches the local challenge, but the signature
        # was made over different bytes. Passes only if the client verifies
        # over its LOCAL nonce bytes, never over ident["nonce"].
        h = fresh_handler("swapped-nonce")
        srv, stub = run_stub(h)
        try:
            _rc.fetch_relay_identity(stub)
            check(False, "F3 rewritten-nonce proof rejected", "no exception")
        except ValueError as e:
            check("signature verification failed" in str(e),
                  "F3 rewritten-nonce proof rejected", e)
        srv.shutdown()

        # --- F3: response with no signature is rejected ------------------------
        h = fresh_handler("no-sig")
        srv, stub = run_stub(h)
        try:
            _rc.fetch_relay_identity(stub)
            check(False, "F3 missing signature rejected", "no exception")
        except ValueError as e:
            check("no signature" in str(e),
                  "F3 missing signature rejected", e)
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

        # --- F4: 503 aborts whether or not a pin exists (fail closed) --------
        # check_relay_identity is the enrollment gate: no claim secret,
        # enrollment proof, or message body may leave when the relay's
        # identity cannot be verified. No warn-and-continue, no --yes
        # bypass (v0.2.13 F4). The "with pin" case uses a genuinely
        # established pin; the endpoint then starts answering 503.
        h = fresh_handler("ok")
        srv, stub = run_stub(h)
        try:
            cfg_path = os.path.join(TMPD, "f4-gate-pin.json")
            cfg = tofu_pin_config(stub, cfg_path, seed, pub)
            h.mode = "unavailable"
            expect_exit(lambda: _rc.check_relay_identity(stub, cfg),
                        "F4 503 with pin aborts (enrollment gate)")
            expect_exit(lambda: _rc.check_relay_identity(stub, {}),
                        "F4 503 without pin aborts (enrollment gate)")
        finally:
            srv.shutdown()

        # --- F4: 503 + pin on the req() path aborts before any API hit ------
        h = fresh_handler("ok")
        srv, stub = run_stub(h)
        try:
            cfg_path = os.path.join(TMPD, "f4-503-pin.json")
            cfg = tofu_pin_config(stub, cfg_path, seed, pub)
            h.mode = "unavailable"  # identity endpoint starts answering 503
            mark = len(h.hits)
            if expect_exit(lambda: _rc.req(cfg, "GET", "/v1/peers",
                                           base=stub),
                           "F4 503 + pin aborts on req()"):
                api_hits = [x for x in h.hits[mark:]
                            if not x[1].startswith("/v1/identity")]
                check(len(api_hits) == 0,
                      "F4 503 + pin: zero API requests transmitted",
                      "saw %d" % len(api_hits))
                check(any(x[1].startswith("/v1/identity")
                          for x in h.hits[mark:]),
                      "F4 503 + pin: identity was checked first")
                assert_zero_transmission(h.hits[mark:], "F4 503 + pin")
        finally:
            srv.shutdown()

        # --- F4: unreachable identity endpoint aborts, nothing attempted ----
        # No listener at all: the client must abort inside the identity
        # phase. We record every URL _open is asked for and assert the
        # authenticated API request was never even attempted -- the
        # ordering proof that no credential could have been transmitted.
        #
        # No-pin case: a bare token-bearing config against a closed port.
        dead = "http://127.0.0.1:%d" % closed_port()
        calls = []
        orig_open = _rc._open

        def recording_open(req, timeout, _calls=calls, _orig=orig_open):
            _calls.append(req.full_url)
            return _orig(req, timeout)

        cfg = {"peers": {"x": SECRET_TOKEN}, "base_url": dead}
        _rc._open = recording_open
        try:
            if expect_exit(
                    lambda: _rc.req(cfg, "GET", "/v1/peers", base=dead),
                    "F4 unreachable identity (no pin) aborts"):
                check(any("/v1/identity?nonce=" in u for u in calls),
                      "F4 unreachable (no pin): identity attempted first",
                      calls)
                check(not any(u.rstrip("/").endswith("/v1/peers")
                              for u in calls),
                      "F4 unreachable (no pin): API request never attempted",
                      calls)
        finally:
            _rc._open = orig_open

        # With-pin case: the pin is established through the GENUINE
        # verify-and-pin path against a direct-identity stub, then that
        # exact origin is shut down (server_close: the port is genuinely
        # unreachable). The client must attempt the identity transport
        # and never attempt /v1/peers.
        h = fresh_handler("ok")
        srv, stub = run_stub(h)
        pin_cfg_path = os.path.join(TMPD, "unreachable-pin.json")
        pin_cfg = tofu_pin_config(stub, pin_cfg_path, seed, pub)
        pre_kill_hits = len(h.hits)
        srv.shutdown()
        srv.server_close()
        _rc._verified_origins.clear()
        calls = []

        def recording_open(req, timeout, _calls=calls, _orig=orig_open):
            _calls.append(req.full_url)
            return _orig(req, timeout)

        _rc._open = recording_open
        try:
            if expect_exit(
                    lambda: _rc.req(pin_cfg, "GET", "/v1/peers", base=stub),
                    "F4 unreachable identity (with pin) aborts"):
                check(any("/v1/identity?nonce=" in u for u in calls),
                      "F4 unreachable (with pin): identity attempted first",
                      calls)
                check(not any(u.rstrip("/").endswith("/v1/peers")
                              for u in calls),
                      "F4 unreachable (with pin): API request never attempted",
                      calls)
                check(len(h.hits) == pre_kill_hits,
                      "F4 unreachable (with pin): dead origin got nothing "
                      "after shutdown", len(h.hits) - pre_kill_hits)
        finally:
            _rc._open = orig_open

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
            assert_zero_transmission(h.hits, "P1 503 + token")
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
