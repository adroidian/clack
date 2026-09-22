#!/usr/bin/env python3
"""Container HEALTHCHECK: the relay answers /health on loopback.

Port follows CLACK_PORT (default 18802), matching init-config.py.
Designed for host-networked runs where the relay binds 127.0.0.1.
"""
import json
import os
import sys
import urllib.request

port = int(os.environ.get("CLACK_PORT", "18802"))
try:
    with urllib.request.urlopen("http://127.0.0.1:%d/health" % port, timeout=5) as r:
        body = json.load(r)
    sys.exit(0 if body.get("ok") is True else 1)
except Exception as e:  # noqa: BLE001 — any failure means unhealthy
    print("healthcheck failed: %s" % e, file=sys.stderr)
    sys.exit(1)
