"""Clack MCP Server — expose Clack relay as MCP tools.

Any MCP-compatible agent can use Clack without writing custom HTTP code.
Configure with environment variables:
    CLACK_RELAY_URL  — e.g. https://clack.kasnet.us
    CLACK_TOKEN      — Bearer <redacted>
    CLACK_PRIVKEY    — path to Ed25519 private key
    CLACK_PEER_NAME  — your peer name

Tools:
    clack_send            — send a message to a peer
    clack_poll            — poll for new messages
    clack_ack             — acknowledge message IDs
    clack_peers           — list enrolled peers
    clack_mint_handshake  — mint a handshake link
    clack_redeem_handshake — redeem a handshake link (URL or h/k)
    clack_accept_handshake — accept a pending handshake
"""

import json
import os
import sys

# Add parent to path for clack_client import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from clack_client import ClackClient, parse_handshake_link
from clack_client.errors import ClackError


def _get_client():
    return ClackClient(
        relay_url=os.environ["CLACK_RELAY_URL"],
        token=os.environ["CLACK_TOKEN"],
        privkey_path=os.environ.get("CLACK_PRIVKEY"),
        peer_name=os.environ.get("CLACK_PEER_NAME", "unknown"),
    )


TOOLS = [
    {
        "name": "clack_send",
        "description": "Send a text message to a Clack peer.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "to": {"type": "string", "description": "Recipient peer name"},
                "text": {"type": "string", "description": "Message text"},
                "topic": {"type": "string", "description": "Optional topic tag"},
            },
            "required": ["to", "text"],
        },
    },
    {
        "name": "clack_poll",
        "description": "Poll for new incoming messages.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "timeout": {"type": "integer", "description": "Poll timeout seconds", "default": 25},
            },
        },
    },
    {
        "name": "clack_ack",
        "description": "Acknowledge handled message IDs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ids": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["ids"],
        },
    },
    {
        "name": "clack_peers",
        "description": "List enrolled peer names on the relay.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "clack_mint_handshake",
        "description": "Mint a handshake link for another peer to redeem.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "clack_redeem_handshake",
        "description": "Redeem a handshake link. Accepts full URL or h/k dict.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "link": {"type": "string", "description": "Full handshake URL"},
                "h": {"type": "string", "description": "Link ID (alternative to URL)"},
                "k": {"type": "string", "description": "Claim secret (alternative to URL)"},
            },
        },
    },
    {
        "name": "clack_accept_handshake",
        "description": "Accept a pending handshake by ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "handshake_id": {"type": "string"},
            },
            "required": ["handshake_id"],
        },
    },
]


def handle_tool(name, args):
    client = _get_client()
    try:
        if name == "clack_send":
            msg_id = client.send(args["to"], args["text"], topic=args.get("topic"))
            return {"message_id": msg_id}
        elif name == "clack_poll":
            msgs = client.poll(timeout=args.get("timeout", 25))
            return {"messages": msgs}
        elif name == "clack_ack":
            return client.ack(args["ids"])
        elif name == "clack_peers":
            return {"peers": client.peers()}
        elif name == "clack_mint_handshake":
            return {"link": client.mint_handshake_link()}
        elif name == "clack_redeem_handshake":
            if args.get("link"):
                hid = client.redeem_handshake(args["link"])
            else:
                hid = client.redeem_handshake({"h": args["h"], "k": args["k"]})
            return {"handshake_id": hid}
        elif name == "clack_accept_handshake":
            return client.accept_handshake(args["handshake_id"])
        else:
            return {"error": f"Unknown tool: {name}"}
    except ClackError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


def main():
    """Simple stdio MCP server (JSON-RPC 2.0)."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        method = req.get("method")
        req_id = req.get("id")
        params = req.get("params", {})

        if method == "initialize":
            resp = {
                "jsonrpc": "2.0", "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {"name": "clack-mcp", "version": "1.0.0"},
                    "capabilities": {"tools": {}},
                },
            }
        elif method == "tools/list":
            resp = {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}
        elif method == "tools/call":
            result = handle_tool(params["name"], params.get("arguments", {}))
            resp = {
                "jsonrpc": "2.0", "id": req_id,
                "result": {"content": [{"type": "text", "text": json.dumps(result)}]},
            }
        else:
            resp = {
                "jsonrpc": "2.0", "id": req_id,
                "error": {"code": -32601, "message": f"Unknown method: {method}"},
            }
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
