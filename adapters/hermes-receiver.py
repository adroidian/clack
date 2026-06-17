#!/usr/bin/env python3
"""
Hermes wake receiver for Clack.

Accepts the harness-neutral Clack delivery envelope and wakes the matching
Hermes profile by launching a bounded one-shot continuation. The HTTP request
returns as soon as the Hermes process is queued.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


HOST = os.environ.get("CLACK_HERMES_RECEIVER_HOST", "127.0.0.1")
PORT = int(os.environ.get("CLACK_HERMES_RECEIVER_PORT", "15300"))
SPOOL_DIR = Path(os.environ.get("CLACK_HERMES_SPOOL_DIR", "/home/aaron/clack-gateway/hermes-receiver"))
LOG_DIR = Path(os.environ.get("CLACK_HERMES_LOG_DIR", str(SPOOL_DIR / "logs")))
HERMES_PYTHON = os.environ.get(
    "HERMES_PYTHON",
    "/home/aaron/.hermes/hermes-agent/venv/bin/python",
)
HERMES_MODULE = os.environ.get("HERMES_MODULE", "hermes_cli.main")
SESSION_PREFIX = os.environ.get("CLACK_HERMES_SESSION_PREFIX", "clack")


def _load_profile_map() -> dict[str, str]:
    raw = os.environ.get("CLACK_HERMES_PROFILES_JSON", "").strip()
    if not raw:
        return {"zari": "zari", "alf": "alf"}
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("CLACK_HERMES_PROFILES_JSON must be a JSON object")
    return {str(k): str(v) for k, v in parsed.items()}


PROFILE_MAP = _load_profile_map()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
      handle.write(json.dumps(record, sort_keys=True) + "\n")


def as_nonempty_string(value: Any, fallback: str = "") -> str:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return fallback


def validate_envelope(body: Any) -> tuple[dict[str, Any] | None, str | None]:
    if not isinstance(body, dict):
        return None, "body must be a JSON object"
    required = ["from", "to", "topic", "message", "priority", "idempotencyKey"]
    missing = [key for key in required if not as_nonempty_string(body.get(key))]
    if missing:
        return None, f"missing required fields: {', '.join(missing)}"
    target = as_nonempty_string(body.get("to"))
    if target not in PROFILE_MAP:
        return None, f"unknown Hermes target: {target}"
    return body, None


def format_prompt(envelope: dict[str, Any]) -> str:
    metadata = envelope.get("metadata")
    metadata_text = ""
    if isinstance(metadata, dict) and metadata:
        metadata_text = "\nmetadata: " + json.dumps(metadata, sort_keys=True)

    return (
        "[CLACK_WAKE]\n"
        f"from: {envelope['from']}\n"
        f"to: {envelope['to']}\n"
        f"topic: {envelope['topic']}\n"
        f"priority: {envelope['priority']}\n"
        f"idempotencyKey: {envelope['idempotencyKey']}\n"
        f"taskId: {envelope.get('taskId', '')}\n"
        f"contextId: {envelope.get('contextId', '')}"
        f"{metadata_text}\n\n"
        f"{envelope['message']}"
    )


def queue_hermes(envelope: dict[str, Any]) -> dict[str, Any]:
    target = as_nonempty_string(envelope["to"])
    profile = PROFILE_MAP[target]
    idempotency_key = as_nonempty_string(envelope["idempotencyKey"])
    session_name = f"{SESSION_PREFIX}-{target}"
    safe_id = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in idempotency_key)[:96]
    log_path = LOG_DIR / f"{target}-{safe_id or int(time.time())}.log"

    prompt = format_prompt(envelope)
    cmd = [
        HERMES_PYTHON,
        "-m",
        HERMES_MODULE,
        "--profile",
        profile,
        "--continue",
        session_name,
        "--oneshot",
        prompt,
    ]

    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_file = log_path.open("ab")
    proc = subprocess.Popen(
        cmd,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )

    return {
        "status": "queued",
        "target": target,
        "profile": profile,
        "transport": "hermes-wake",
        "pid": proc.pid,
        "session": session_name,
        "log": str(log_path),
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "clack-hermes-receiver/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        append_jsonl(LOG_DIR / "access.jsonl", {
            "ts": now_iso(),
            "client": self.client_address[0],
            "message": fmt % args,
        })

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/health":
            self._json(200, {
                "status": "ok",
                "profiles": sorted(PROFILE_MAP.keys()),
                "spool": str(SPOOL_DIR),
            })
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path != "/wake":
            self._json(404, {"error": "not found"})
            return

        try:
            length = int(self.headers.get("content-length", "0"))
            body = self.rfile.read(length)
            parsed = json.loads(body.decode("utf-8") or "{}")
        except Exception as exc:
            self._json(400, {"status": "failed", "error": f"invalid JSON: {exc}"})
            return

        envelope, error = validate_envelope(parsed)
        if error:
            self._json(400, {"status": "failed", "error": error})
            return

        assert envelope is not None
        append_jsonl(SPOOL_DIR / "received.jsonl", {"ts": now_iso(), "envelope": envelope})

        try:
            result = queue_hermes(envelope)
        except Exception as exc:
            append_jsonl(SPOOL_DIR / "failed.jsonl", {
                "ts": now_iso(),
                "error": str(exc),
                "envelope": envelope,
            })
            self._json(500, {"status": "failed", "error": str(exc)})
            return

        append_jsonl(SPOOL_DIR / "queued.jsonl", {"ts": now_iso(), **result})
        self._json(202, result)


def main() -> None:
    SPOOL_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"clack-hermes-receiver listening on {HOST}:{PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
