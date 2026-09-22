#!/usr/bin/env python3
"""First-run relay-config.json generator for the Clack Docker image.

Reads env (all optional, sane public-relay defaults), mints a fresh RSA
identity-signing key, writes the config with mode 600. Refuses to overwrite
an existing config — identity key stability is what makes TOFU pinning work.

Env:
  CLACK_PORT            relay listen port            (default 18802)
  CLACK_BIND            relay listen address         (default 0.0.0.0 — bridge networking)
  CLACK_BASE_URL        public base URL for /join   (default https://relay.tryclack.com)
  CLACK_ENROLLMENT      gate: invite|pow|open       (default pow)
  CLACK_POW_DIFFICULTY  PoW difficulty, bits        (default 20)
  GREETER_PUBKEY        32-byte b64url ed25519 pubkey pinned to the
                        reserved name "greeter"     (default: no reservation)

Usage: init-config.py /data/relay-config.json
"""
import base64
import json
import math
import os
import secrets
import sys


def _b64u_decode(s):
    s = s.encode("ascii") if isinstance(s, str) else s
    return base64.urlsafe_b64decode(s + b"=" * (-len(s) % 4))


def _is_probable_prime(n, rounds=12):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits):
    while True:
        p = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(p):
            return p


def gen_rsa_key(bits=1024):
    """Same shape as the relay's own test harness: RSA (n, e, d), e=65537."""
    while True:
        p, q = _gen_prime(bits // 2), _gen_prime(bits // 2)
        if p != q and (p * q).bit_length() == bits and \
                math.gcd(65537, (p - 1) * (q - 1)) == 1:
            n = p * q
            d = pow(65537, -1, (p - 1) * (q - 1))
            return {"n": format(n, "x"), "e": "10001", "d": format(d, "x")}


def main():
    if len(sys.argv) != 2:
        print("usage: init-config.py /path/to/relay-config.json", file=sys.stderr)
        return 2
    out = sys.argv[1]
    if os.path.exists(out):
        print("init-config: %s exists, refusing to overwrite" % out, file=sys.stderr)
        return 1

    reserved = {}
    greeter = os.environ.get("GREETER_PUBKEY", "").strip()
    if greeter:
        try:
            key = _b64u_decode(greeter)
        except Exception:
            print("init-config: GREETER_PUBKEY is not valid base64url", file=sys.stderr)
            return 1
        if len(key) != 32:
            print("init-config: GREETER_PUBKEY decodes to %d bytes, want 32" % len(key),
                  file=sys.stderr)
            return 1
        reserved = {"greeter": greeter}

    cfg = {
        "base_url": os.environ.get("CLACK_BASE_URL", "https://relay.tryclack.com"),
        "enrollment": os.environ.get("CLACK_ENROLLMENT", "pow"),
        "pow_difficulty": int(os.environ.get("CLACK_POW_DIFFICULTY", "20")),
        "port": int(os.environ.get("CLACK_PORT", "18802")),
        "bind": os.environ.get("CLACK_BIND", "0.0.0.0"),
        "peers": {},
        "operators": [],
        "reserved_names": reserved,
        "identity_key": gen_rsa_key(),
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=1)
        f.write("\n")
    os.chmod(out, 0o600)
    print("init-config: wrote %s (mode 600)" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
