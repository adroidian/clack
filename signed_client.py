"""Ed25519-signed relay client for v0.2.17.

Replaces pinned_client.py (RSA-based, v0.2.15). Every authenticated request
carries BOTH the Bearer token AND Ed25519 signatures:
  X-Clack-Scheme: 1
  X-Clack-Key: <peer name>
  X-Clack-Nonce: <unix_seconds>:<32 hex chars>
  X-Clack-Sig: hex(Ed25519_sign(seed, "clack-ed25519-v1\\n"+METHOD+"\\n"+path+"\\n"+sha256_hex(body)+"\\n"+nonce))

Interface matches PinnedClient so runner.py needs only an import change.
"""
import base64
import hashlib
import json
import secrets
import urllib.parse
import urllib.request

# --- BEGIN vendored ed25519 (pure stdlib, from relay-cli.py) ---
b = 256
q = (1 << 255) - 19
l = (1 << 252) + 27742317777372353535851937790883648493

def _H(m):
    return hashlib.sha512(m).digest()

def _inv(x):
    return pow(x, q - 2, q)

_d = (-121665 * _inv(121666)) % q
_2d = (2 * _d) % q
_I = pow(2, (q - 1) // 4, q)

def _xrecover(y):
    xx = (y * y - 1) * _inv(_d * y * y + 1) % q
    x = pow(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0:
        x = (x * _I) % q
    if x & 1:
        x = q - x
    return x

_IDENT = (0, 1, 1, 0)

def _to_ext_affine(x, y):
    return (x % q, y % q, 1, (x * y) % q)

def _to_affine(P):
    X, Y, Z, _T = P
    iz = _inv(Z)
    return (X * iz % q, Y * iz % q)

def _point_eq(P, Q):
    X1, Y1, Z1, _t1 = P
    X2, Y2, Z2, _t2 = Q
    return (X1 * Z2 - X2 * Z1) % q == 0 and (Y1 * Z2 - Y2 * Z1) % q == 0

def _edwards_add(P, Q):
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q
    A = (Y1 - X1) * (Y2 - X2) % q
    B = (Y1 + X1) * (Y2 + X2) % q
    C = T1 * _2d % q * T2 % q
    D = (2 * Z1 % q) * Z2 % q
    E = (B - A) % q
    F = (D - C) % q
    G = (D + C) % q
    H = (B + A) % q
    return (E * F % q, G * H % q, F * G % q, E * H % q)

def _edwards_dbl(P):
    X1, Y1, Z1, _T1 = P
    A = X1 * X1 % q
    B = Y1 * Y1 % q
    C = 2 * Z1 * Z1 % q
    D = (-A) % q
    E = ((X1 + Y1) * (X1 + Y1) - A - B) % q
    G = (D + B) % q
    F = (G - C) % q
    H = (D - B) % q
    return (E * F % q, G * H % q, F * G % q, E * H % q)

def _scalarmult(P, e):
    Q = _IDENT
    for i in range(max(b, e.bit_length()) - 1, -1, -1):
        Q = _edwards_dbl(Q)
        if (e >> i) & 1:
            Q = _edwards_add(Q, P)
    return Q

_By = (4 * _inv(5)) % q
_Bx = _xrecover(_By)
_B = (_Bx, _By, 1, _Bx * _By % q)

def _bit(h, i):
    return (h[i // 8] >> (i % 8)) & 1

def _encodeint(y):
    bits = [(y >> i) & 1 for i in range(b)]
    return b"".join(
        bytes([sum(bits[i * 8 + j] << j for j in range(8))]) for i in range(b // 8)
    )

def _encodepoint(P):
    x, y = P[0], P[1]
    bits = [(y >> i) & 1 for i in range(b - 1)] + [x & 1]
    return b"".join(
        bytes([sum(bits[i * 8 + j] << j for j in range(8))]) for i in range(b // 8)
    )

def _Hint(m):
    h = _H(m)
    return sum(2**i * _bit(h, i) for i in range(2 * b))

def _publickey_point(sk):
    h = _H(sk)
    a = 2 ** (b - 2) + sum(2**i * _bit(h, i) for i in range(3, b - 2))
    return _scalarmult(_B, a)

def _publickey(sk):
    return _encodepoint(_to_affine(_publickey_point(sk)))

def _signature(m, sk, pk):
    h = _H(sk)
    a = 2 ** (b - 2) + sum(2**i * _bit(h, i) for i in range(3, b - 2))
    r = _Hint(h[b // 8 : b // 4] + m)
    Rext = _scalarmult(_B, r)
    Renc = _encodepoint(_to_affine(Rext))
    S = (r + _Hint(Renc + pk + m) * a) % l
    return Renc + _encodeint(S)

def _sign_seed(seed, msg):
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    return _signature(bytes(msg), bytes(seed), _publickey(bytes(seed)))
# --- END vendored ed25519 ---

MAX_RESPONSE = 1024 * 1024
SIGN_SCHEME_ID = "clack-ed25519-v1"


def _b64u_decode(s):
    s = s.strip()
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _load_seed(path):
    with open(path, "rb") as f:
        raw = f.read().strip()
    if len(raw) == 32:
        return raw
    try:
        seed = _b64u_decode(raw.decode("ascii"))
    except Exception:
        raise ValueError("private key file is not raw 32 bytes or b64u")
    if len(seed) != 32:
        raise ValueError("private key must decode to 32 bytes")
    return seed


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class SignedClient:
    """v0.2.17 relay client: Bearer token + Ed25519 request signing.

    Constructor takes (origin, token, private_key_path, peer_name) to match
    the call site in runner.py after its import change.
    """

    def __init__(self, origin, token, private_key_path, peer_name):
        u = urllib.parse.urlsplit(origin)
        if u.scheme != "https" or not u.hostname:
            raise ValueError("exact HTTPS origin required")
        self.origin = origin.rstrip("/")
        self.token = token
        self.peer_name = peer_name
        self.seed = _load_seed(private_key_path)
        self.opener = urllib.request.build_opener(NoRedirect())
        self.opener.addheaders = [("User-Agent", "Mozilla/5.0 MuseClack/0.2")]

    def _sign_headers(self, method, path, body_bytes):
        nonce = "%d:%s" % (int(__import__("time").time()), secrets.token_hex(16))
        canon = (
            SIGN_SCHEME_ID + "\n"
            + method.upper() + "\n"
            + path + "\n"
            + hashlib.sha256(body_bytes or b"").hexdigest() + "\n"
            + nonce
        ).encode("utf-8")
        return {
            "X-Clack-Scheme": "1",
            "X-Clack-Key": self.peer_name,
            "X-Clack-Nonce": nonce,
            "X-Clack-Sig": _sign_seed(self.seed, canon).hex(),
        }

    def request(self, path, body=None):
        if path not in ("/v1/poll?timeout=25", "/v1/ack", "/v1/send",
                        "/v1/peers", "/v1/handshakes/mint-link"):
            raise ValueError("unsupported operation: " + path)
        raw = None if body is None else json.dumps(body).encode()
        method = "POST" if raw is not None else "GET"
        headers = {
            "Authorization": "Bearer " + self.token,
            "Content-Type": "application/json",
        }
        headers.update(self._sign_headers(method, path, raw))
        req = urllib.request.Request(self.origin + path, data=raw, headers=headers,
                                     method=method)
        with self.opener.open(req, timeout=35) as response:
            data = response.read(MAX_RESPONSE + 1)
        if len(data) > MAX_RESPONSE:
            raise ValueError("response too large")
        return json.loads(data)
