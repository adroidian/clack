#!/usr/bin/env python3
"""Container HEALTHCHECK: probe the relay's persisted runtime port on loopback.

Once `/data/relay-config.json` exists it is runtime authority, matching
`relay.py`. `CLACK_PORT` is consulted only before first-boot configuration
exists. Any malformed config or port fails closed.
"""

import json
import os
from pathlib import Path
import re
import sys
import urllib.request


def parse_port(value, source):
    if type(value) is int:  # reject bool, which is an int subclass
        port = value
    elif type(value) is str and re.fullmatch(r"[1-9][0-9]{0,4}", value):
        port = int(value)
    else:
        raise ValueError("%s port is not an integer" % source)
    if not 1 <= port <= 65535:
        raise ValueError("%s port is out of range" % source)
    return port


def runtime_port():
    base = Path(os.environ.get("CLACK_RELAY_BASE", "/data"))
    config_path = base / "relay-config.json"
    if config_path.exists():
        with config_path.open("r", encoding="utf-8") as handle:
            config = json.load(handle)
        if type(config) is not dict:
            raise ValueError("persisted relay config is not an object")
        return parse_port(config.get("port", 18802), "persisted config")
    return parse_port(os.environ.get("CLACK_PORT", "18802"), "CLACK_PORT")


try:
    port = runtime_port()
    with urllib.request.urlopen(
        "http://127.0.0.1:%d/health" % port, timeout=5
    ) as response:
        body = json.load(response)
    if type(body) is not dict or body.get("ok") is not True:
        raise ValueError("relay health response is not ok")
except Exception as error:  # noqa: BLE001 — any failure means unhealthy
    print("healthcheck failed: %s" % error, file=sys.stderr)
    sys.exit(1)
