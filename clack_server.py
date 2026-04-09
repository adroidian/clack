#!/usr/bin/env python3
"""
Generic Clack inbox + wake server.

- accepts JSON-RPC tasks/send
- writes messages to per-agent inbox directories
- attempts wake delivery locally or via queue fallback
- retries failed wake attempts

All sensitive topology is injected by environment variables.
"""

import json
import hashlib
import logging
import os
import signal
import threading
import time
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib import request, error

PORT = int(os.environ.get("CLACK_PORT", "15100"))
CLACK_TOKEN = os.environ.get("CLACK_TOKEN", "replace-me")
INBOX_ROOT = Path(os.environ.get("CLACK_INBOX_ROOT", "/tmp/clack/inbox"))
PENDING_QUEUE_PATH = Path(os.environ.get("CLACK_PENDING_QUEUE_PATH", "/tmp/clack/pending-wake.json"))

# Example shape:
# {
#   "agent-a": {"type": "local", "url": "http://127.0.0.1:18789/hooks/agent", "token": "...", "sessionKey": "agent:agent-a:main"},
#   "agent-b": {"type": "queue", "url": "http://127.0.0.1:7331/queue/agent-b"}
# }
AGENT_GATEWAYS = json.loads(os.environ.get("CLACK_AGENT_GATEWAYS_JSON", "{}"))

DEDUPE_WINDOW = int(os.environ.get("CLACK_DEDUPE_WINDOW", "300"))
RATE_LIMIT_WINDOW = int(os.environ.get("CLACK_RATE_LIMIT_WINDOW", "60"))
RATE_LIMIT_MAX = int(os.environ.get("CLACK_RATE_LIMIT_MAX", "60"))
MAX_RETRIES = int(os.environ.get("CLACK_MAX_RETRIES", "3"))
RETRY_BASE_DELAY = int(os.environ.get("CLACK_RETRY_BASE_DELAY", "2"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("clack-server")

seen_hashes = {}
rate_counts = {}
processed_files = set()


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def is_duplicate(msg_hash: str) -> bool:
    now = time.time()
    expired = [h for h, t in seen_hashes.items() if now - t > DEDUPE_WINDOW]
    for h in expired:
        del seen_hashes[h]
    if msg_hash in seen_hashes:
        return True
    seen_hashes[msg_hash] = now
    return False


def check_rate_limit(sender: str) -> bool:
    now = time.time()
    if sender not in rate_counts:
        rate_counts[sender] = []
    rate_counts[sender] = [t for t in rate_counts[sender] if now - t < RATE_LIMIT_WINDOW]
    if len(rate_counts[sender]) >= RATE_LIMIT_MAX:
        return True
    rate_counts[sender].append(now)
    return False


def _load_pending() -> dict:
    if not PENDING_QUEUE_PATH.exists():
        return {}
    try:
        return json.loads(PENDING_QUEUE_PATH.read_text())
    except Exception:
        return {}


def _save_pending(pending: dict) -> None:
    PENDING_QUEUE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = PENDING_QUEUE_PATH.with_suffix('.tmp')
    tmp.write_text(json.dumps(pending, indent=2))
    tmp.replace(PENDING_QUEUE_PATH)


def _add_pending(agent_name: str, attempt: dict) -> None:
    pending = _load_pending()
    pending.setdefault(agent_name, []).append(attempt)
    _save_pending(pending)


def _remove_pending(agent_name: str, msg_hash: str) -> None:
    pending = _load_pending()
    if agent_name in pending:
        pending[agent_name] = [a for a in pending[agent_name] if a.get('msg_hash') != msg_hash]
        if not pending[agent_name]:
            del pending[agent_name]
        _save_pending(pending)


def save_to_inbox(agent_name: str, msg: dict) -> str:
    inbox = INBOX_ROOT / agent_name
    inbox.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H-%M-%SZ')
    msg_id = msg.get('id', content_hash(json.dumps(msg)))[:8]
    out = inbox / f"{ts}_{msg_id}.json"
    out.write_text(json.dumps(msg, indent=2))
    return str(out)


def _post_json(url: str, payload: dict, headers: dict | None = None, timeout: int = 5):
    body = json.dumps(payload).encode('utf-8')
    req = request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    with request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode('utf-8'))


def _wake_via_gateway(agent_name: str, message_summary: str, msg_hash: str) -> bool:
    gw = AGENT_GATEWAYS.get(agent_name)
    if not gw:
        log.warning("No gateway config for %s", agent_name)
        return False

    try:
        if gw.get('type') == 'queue':
            _post_json(gw['url'], {"from": "clack-server", "topic": "wake", "message": message_summary})
            return True

        headers = {}
        if gw.get('token_header') and gw.get('token'):
            headers[gw['token_header']] = gw['token']
        elif gw.get('token'):
            headers['Authorization'] = f"Bearer {gw['token']}"

        payload = {"wakeMode": "now", "message": f"[Clack] {message_summary}"}
        if gw.get('sessionKey'):
            payload['sessionKey'] = gw['sessionKey']
        if gw.get('channel'):
            payload['channel'] = gw['channel']

        _post_json(gw['url'], payload, headers=headers)
        return True
    except error.HTTPError as e:
        log.warning("Wake HTTP error for %s: %s %s", agent_name, e.code, e.reason)
    except Exception as e:
        log.warning("Wake failed for %s: %s", agent_name, e)
    return False


def wake_agent(agent_name: str, message_summary: str, msg_hash: str = ""):
    for attempt in range(1, MAX_RETRIES + 1):
        if _wake_via_gateway(agent_name, message_summary, msg_hash):
            return
        if attempt < MAX_RETRIES:
            time.sleep(RETRY_BASE_DELAY * (2 ** (attempt - 1)))
    _add_pending(agent_name, {
        "msg_hash": msg_hash,
        "message_summary": message_summary,
        "ts": datetime.now(timezone.utc).isoformat(),
        "attempts": MAX_RETRIES,
    })


def process_message(params: dict) -> dict:
    task_id = params.get('id', str(time.time()))
    metadata = params.get('metadata', {})
    message = params.get('message', {})

    from_agent = metadata.get('from') or params.get('from', 'unknown')
    to_agent = metadata.get('to') or params.get('to', '')
    topic = metadata.get('topic') or params.get('topic', 'general')
    priority = metadata.get('priority') or params.get('priority', 'normal')

    if not to_agent or to_agent not in AGENT_GATEWAYS:
        return {"error": {"code": -32001, "message": f"Unknown target agent: {to_agent}"}}

    if isinstance(message, str):
        text = message
    else:
        parts = message.get('parts', [])
        text_parts = [p.get('text', '') for p in parts if 'text' in p]
        text = "\n".join(t for t in text_parts if t) if text_parts else str(message.get('text', '') or message)

    if check_rate_limit(from_agent):
        return {"error": {"code": -32000, "message": "Rate limited"}}

    msg_hash = content_hash(f"{from_agent}:{to_agent}:{topic}:{text}")
    if is_duplicate(msg_hash):
        return {"id": task_id, "status": "duplicate"}

    internal_msg = {
        "id": task_id,
        "from": from_agent,
        "to": to_agent,
        "topic": topic,
        "priority": priority,
        "message": text,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "transport": "push",
    }

    save_to_inbox(to_agent, internal_msg)
    wake_agent(to_agent, f"From {from_agent}: [{topic}] {text}", msg_hash)

    return {
        "id": task_id,
        "status": {"state": "completed"},
        "metadata": {"received_at": internal_msg['timestamp'], "delivered_to": to_agent},
    }


class ClackHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        log.info("%s %s", self.client_address[0], format % args)

    def _json(self, data: dict, status: int = 200):
        body = json.dumps(data).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == '/health':
            self._json({"status": "ok", "uptime": time.time(), "agents": list(AGENT_GATEWAYS.keys())})
        else:
            self._json({"error": "Not found"}, 404)

    def do_POST(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length) if content_length > 0 else b''
            if not body.strip():
                return self._json({"error": {"code": -32600, "message": "Empty request"}}, 400)
            rpc = json.loads(body)
        except json.JSONDecodeError:
            return self._json({"error": {"code": -32700, "message": "Parse error"}}, 400)

        if rpc.get('jsonrpc') != '2.0':
            return self._json({"error": {"code": -32600, "message": "Invalid JSON-RPC"}}, 400)

        if rpc.get('method') == 'tasks/send':
            result = process_message(rpc.get('params', {}))
            return self._json({"jsonrpc": "2.0", "id": rpc.get('id'), "result": result})

        self._json({"jsonrpc": "2.0", "id": rpc.get('id'), "error": {"code": -32601, "message": "Method not found"}})


class InboxWatcher(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.running = True
        self._preload_existing()

    def _preload_existing(self):
        if not INBOX_ROOT.exists():
            return
        for agent_dir in INBOX_ROOT.iterdir():
            if agent_dir.is_dir():
                for f in agent_dir.glob('*.json'):
                    processed_files.add(f.name)

    def run(self):
        while self.running:
            if INBOX_ROOT.exists():
                for agent_name in AGENT_GATEWAYS:
                    inbox = INBOX_ROOT / agent_name
                    if not inbox.exists():
                        continue
                    for f in sorted(inbox.glob('*.json')):
                        if f.name in processed_files:
                            continue
                        self._process_file(f, agent_name)
            self._retry_pending()
            time.sleep(5)

    def _retry_pending(self):
        pending = _load_pending()
        for agent_name, attempts in list(pending.items()):
            if not attempts:
                continue
            oldest = attempts[0]
            if _wake_via_gateway(agent_name, oldest.get('message_summary', ''), oldest.get('msg_hash', '')):
                _remove_pending(agent_name, oldest.get('msg_hash', ''))

    def _process_file(self, filepath: Path, agent_name: str):
        try:
            msg = json.loads(filepath.read_text())
            from_agent = msg.get('from', 'unknown')
            topic = msg.get('topic', 'general')
            text = msg.get('message', '')
            msg_hash = content_hash(f"{from_agent}:{agent_name}:{topic}:{text}")
            if is_duplicate(msg_hash) or check_rate_limit(from_agent):
                processed_files.add(filepath.name)
                return
            processed_files.add(filepath.name)
            wake_agent(agent_name, f"From {from_agent}: [{topic}] {text}", msg_hash)
        except Exception as e:
            log.error("Error processing %s: %s", filepath.name, e)
            processed_files.add(filepath.name)

    def stop(self):
        self.running = False


class ReusableHTTPServer(HTTPServer):
    allow_reuse_address = True


def main():
    watcher = InboxWatcher()
    watcher.start()

    server = ReusableHTTPServer(('0.0.0.0', PORT), ClackHandler)
    log.info('Clack server listening on port %s', PORT)
    log.info('Serving agents: %s', ', '.join(AGENT_GATEWAYS.keys()) or '(none configured)')

    def shutdown(sig, frame):
        watcher.stop()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    server.serve_forever()


if __name__ == '__main__':
    main()
