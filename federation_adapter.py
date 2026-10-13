#!/usr/bin/env python3
"""Private, operator-configured Federation runtime. No bootstrap or service install."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import sqlite3
import stat
import sys
import urllib.parse
import uuid

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO / "clack-client"))
from clack_client.client import ClackClient  # noqa: E402  # pyright: ignore[reportMissingImports]
from clack_client.envelope import native_payload  # noqa: E402

SCHEMA = "clack-federation-operational-v1"


def canonical(path):
    if not isinstance(path, str) or not os.path.isabs(path) or os.path.normpath(path) != path:
        raise ValueError("path must be canonical and absolute")
    p = Path(path)
    if str(p.resolve()) != path or any(x.is_symlink() for x in (p, *p.parents)):
        raise ValueError("symlink paths are forbidden")
    return p


def private_read(path, limit=1048576):
    canonical(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o600:
            raise ValueError("reference must be an owned mode-0600 regular file")
        with os.fdopen(fd, "rb", closefd=False) as f:
            data = f.read(limit + 1)
        if len(data) > limit:
            raise ValueError("reference exceeds size limit")
        return data
    finally:
        os.close(fd)


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    def constant(_):
        raise ValueError("nonfinite JSON number")
    return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)


def fields(obj, expected):
    if type(obj) is not dict or set(obj) != set(expected):
        raise ValueError("configuration has missing or unknown fields")


def label(value):
    if not isinstance(value, str) or not value or len(value) > 256 or any(ord(c) < 32 for c in value):
        raise ValueError("invalid identifier")
    return value


def init_transport_schema(c):
    """Add transport journals only; does not create grants or change authority."""
    c.executescript("""
        CREATE TABLE IF NOT EXISTS runtime_binding(singleton INTEGER PRIMARY KEY CHECK(singleton=1), digest TEXT NOT NULL, purpose TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS runtime_payloads(msg_id TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES grants(grant_id), text TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS runtime_inbox(endpoint TEXT NOT NULL, msg_id TEXT NOT NULL, grant_id TEXT NOT NULL REFERENCES grants(grant_id), generation INTEGER NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(endpoint,msg_id));
    """)
    cols = {r[1] for r in c.execute("PRAGMA table_info(runtime_payloads)")}
    if "enc_v" not in cols:
        c.execute("ALTER TABLE runtime_payloads ADD COLUMN enc_v INTEGER NOT NULL DEFAULT 0")


class Adapter:
    def __init__(self, config_path):
        cfg = strict_json(private_read(config_path))
        fields(cfg, {"schema", "proof_only", "state_dir", "bootstrap_ref", "ndr_key_ref",
                     "verifier_pub_ref", "verifier_id", "timeout", "partition_cap_s", "endpoints", "routes"})
        if cfg["schema"] != SCHEMA or type(cfg["proof_only"]) is not bool:
            raise ValueError("invalid runtime schema or proof mode")
        base = canonical(cfg["state_dir"])
        st = base.stat()
        if not base.is_dir() or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700:
            raise ValueError("state must already be an owned mode-0700 directory")
        if base == REPO or REPO in base.parents or base in REPO.parents:
            raise ValueError("state and repository must be separate")
        fixture = (base / ".clack-fed-v098-owned.json").exists() or (base / "fixture-proof.json").exists()
        if cfg["proof_only"]:
            if Path("/tmp") not in base.parents or not fixture:
                raise ValueError("fixture proof requires a marked disposable /tmp rig")
        elif fixture or Path("/tmp") in base.parents:
            raise ValueError("fixture state cannot be operational authority")
        manifest = strict_json(private_read(cfg["bootstrap_ref"]))
        fields(manifest, {"schema", "purpose", "approval_ref", "state_dir"})
        if (manifest["schema"] != "clack-federation-bootstrap-reference-v1"
                or manifest["state_dir"] != str(base)
                or manifest["purpose"] != ("fixture-proof" if cfg["proof_only"] else "operational")):
            raise ValueError("bootstrap purpose or state mismatch")
        label(manifest["approval_ref"])
        if ((type(cfg["timeout"]) is not float and type(cfg["timeout"]) is not int)
                or not math.isfinite(cfg["timeout"]) or not 0 < cfg["timeout"] <= 60):
            raise ValueError("timeout outside finite bounds")
        if ((type(cfg["partition_cap_s"]) is not float and type(cfg["partition_cap_s"]) is not int)
                or not math.isfinite(cfg["partition_cap_s"]) or not 0 < cfg["partition_cap_s"] <= 86400):
            raise ValueError("partition cap outside finite bounds")
        if type(cfg["endpoints"]) is not dict or not cfg["endpoints"] or type(cfg["routes"]) is not dict or not cfg["routes"]:
            raise ValueError("explicit endpoint and route maps required")
        for name, ep in cfg["endpoints"].items():
            label(name)
            fields(ep, {"url", "peer", "token_ref", "key_ref", "pin_ref"})
            label(ep["peer"])
            url = urllib.parse.urlsplit(ep["url"])
            if (url.scheme not in ("http", "https") or not url.hostname or url.username
                    or url.password or url.path not in ("", "/") or url.query or url.fragment):
                raise ValueError("endpoint must be a secret-free origin")
            # This adapter is deliberately private: only numeric loopback or
            # Tailscale addresses. HTTPS still uses mandatory existing relay pins.
            import ipaddress
            address = ipaddress.ip_address(url.hostname)
            private = address.is_loopback or address in ipaddress.ip_network("100.64.0.0/10") or address in ipaddress.ip_network("fd7a:115c:a1e0::/48")
            if not private or url.port == 18802:
                raise ValueError("endpoint outside private transport scope")
            if cfg["proof_only"] and not address.is_loopback:
                raise ValueError("fixture proof may only reach loopback")
            for key in ("token_ref", "key_ref", "pin_ref"):
                private_read(ep[key])
            pins = strict_json(private_read(ep["pin_ref"]))
            if type(pins) is not dict or not isinstance(pins.get(ep["url"].rstrip("/")), str):
                raise ValueError("existing explicit origin pin required; auto-pin forbidden")
        receive_bindings = set()
        for grant, route in cfg["routes"].items():
            label(grant)
            fields(route, {"send_endpoint", "to", "receive_endpoint", "from"})
            label(route["to"])
            label(route["from"])
            if route["send_endpoint"] not in cfg["endpoints"] or route["receive_endpoint"] not in cfg["endpoints"]:
                raise ValueError("route references unknown endpoint")
            binding = (route["receive_endpoint"], route["from"])
            if binding in receive_bindings:
                raise ValueError("ambiguous receive authority")
            receive_bindings.add(binding)
        if len(private_read(cfg["ndr_key_ref"], 32)) != 32 or len(private_read(cfg["verifier_pub_ref"], 32)) != 32:
            raise ValueError("authority key references must be exactly 32 bytes")
        label(cfg["verifier_id"])
        self.cfg = cfg
        self.base = base
        # A fresh module per adapter instance isolates configured global bindings.
        spec = importlib.util.spec_from_file_location("federation_authority_runtime", REPO / "federation_authority.py")
        if spec is None or spec.loader is None:
            raise RuntimeError("authority module unavailable")
        authority = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(authority)
        authority.configure(str(base), cfg["ndr_key_ref"], cfg["verifier_pub_ref"], cfg["verifier_id"],
                            cfg["partition_cap_s"])
        self.authority = authority
        self.clients = {}
        digest = hashlib.sha256(json.dumps(cfg, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        with authority.authority_lock():
            c = authority._connect()
            try:
                # The configuration creates no grant. Every mapped grant must
                # already exist in the separately approved bootstrap authority.
                if any(authority._grant_row(c, gid) is None for gid in cfg["routes"]):
                    raise ValueError("mapped grant missing; approved bootstrap required")
                init_transport_schema(c)
                row = c.execute("SELECT digest,purpose FROM runtime_binding WHERE singleton=1").fetchone()
                binding = (digest, manifest["purpose"])
                if row is not None and row != binding:
                    raise ValueError("state bound to different configuration; explicit migration required")
                c.execute("INSERT OR IGNORE INTO runtime_binding VALUES (1,?,?)", binding)
            finally:
                c.close()

    def client(self, endpoint):
        if endpoint not in self.clients:
            ep = self.cfg["endpoints"][endpoint]
            try:
                token = private_read(ep["token_ref"], 4096).decode().strip()
                if not token or any(c.isspace() for c in token):
                    raise ValueError("invalid token reference")
                # Mandatory challenge/pin check occurs before any credentials.
                self.clients[endpoint] = ClackClient(ep["url"], token, ep["key_ref"], ep["peer"],
                    timeout=self.cfg["timeout"], pin_file=ep["pin_ref"], auto_pin=False)
            except Exception:
                raise RuntimeError("configured identity or pinned transport unavailable") from None
        return self.clients[endpoint]

    def enforce_cap(self, grant):
        # Reviewed cap logic and every generation edge remain in the one
        # authority transaction. No timer-side mirror of grant authority.
        # now=None: the trusted clock is sampled inside the authority lock,
        # and the final fence re-evaluates regardless (see authority action()).
        record = self.authority.read_grant_record(grant)
        if record and record["state"] != "REVOKED" and record["tombstone_reason"] is None:
            try:
                self.authority.apply_partition_cap(grant, None, self.cfg["partition_cap_s"])
            except ValueError:
                # Concurrent irreversible revoke is fenced at the action point.
                current = self.authority.read_grant_record(grant)
                if not current or (current["state"] != "REVOKED" and current["tombstone_reason"] is None):
                    raise

    def recheck(self, evidence_path):
        evidence = self.authority.read_recheck_evidence_file(evidence_path)
        if evidence.get("grant_id") not in self.cfg["routes"]:
            raise ValueError("recheck grant is not mapped")
        generation = self.authority.verified_recheck(evidence)
        return {"grant_id": evidence["grant_id"], "generation": generation, "proof_only": self.cfg["proof_only"]}

    def send(self, grant, msg_id, text=None, *, enc=None, enc_v=None):
        if grant not in self.cfg["routes"]:
            raise ValueError("unmapped grant")
        if str(uuid.UUID(msg_id)) != msg_id:
            raise ValueError("stable UUID required")
        encrypted = enc is not None or enc_v is not None
        enc_raw = None
        if encrypted:
            if text is not None:
                raise ValueError("native encrypted send forbids text")
            enc_raw = native_payload(enc, enc_v)
            enc = json.loads(enc_raw)  # immutable caller snapshot before journal/action
            if enc["v"] != 1:
                raise ValueError("v1-only adapter requires enc_v=1")
            enc_v = 1
            text = enc_raw  # reviewed storage contract: envelope JSON + enc_v=1
        else:
            enc_v = 0
            if not isinstance(text, str) or not 0 < len(text.encode()) <= 65536:
                raise ValueError("bounded nonempty text required")
        a = self.authority
        self.enforce_cap(grant)
        with a.authority_lock():
            c = a._connect()
            try:
                a._begin(c)
                row = c.execute("SELECT grant_id,text,enc_v FROM runtime_payloads WHERE msg_id=?", (msg_id,)).fetchone()
                if row is not None and row != (grant, text, enc_v):
                    raise ValueError("stable ID payload or grant changed")
                c.execute("INSERT OR IGNORE INTO runtime_payloads(msg_id,grant_id,text,enc_v) VALUES (?,?,?,?)", (msg_id, grant, text, enc_v))
                c.execute("COMMIT")
            except Exception:
                a._rollback_quiet(c)
                raise
            finally:
                c.close()
        route = self.cfg["routes"][grant]
        def transport(mid, body):
            try:
                if encrypted:
                    returned, accepted = self.client(route["send_endpoint"]).send(route["to"], msg_id=mid, enc=json.loads(enc_raw), enc_v=1)
                else:
                    returned, accepted = self.client(route["send_endpoint"]).send(route["to"], body, msg_id=mid)
                if returned != mid or accepted is not True:
                    return {"transport_parse_error": True}
                return {"accepted": True}
            except Exception:
                # Never persist raw client exception strings or response bodies.
                raise RuntimeError("transport outcome unknown; reconcile stable ID") from None
        outcome, _ = a.action(grant, msg_id, text, transport=transport)
        return {"id": msg_id, "outcome": outcome, "proof_only": self.cfg["proof_only"]}

    def reconcile(self):
        a = self.authority
        with a.authority_lock():
            c = a._connect()
            try:
                rows = c.execute("SELECT r.res_id,r.state,p.grant_id,p.msg_id,p.text,p.enc_v FROM runtime_payloads p LEFT JOIN reservations r ON p.msg_id=r.msg_id AND p.grant_id=r.grant_id LEFT JOIN outbox o ON o.msg_id=p.msg_id WHERE (r.state IS NULL OR r.state IN ('inflight','failed-unknown','retry','reserved')) AND (o.state IS NULL OR o.state NOT IN ('sent','released')) AND NOT EXISTS (SELECT 1 FROM ndrs n WHERE n.msg_id=p.msg_id)").fetchall()
            finally:
                c.close()
        results = []
        for res_id, state, grant, mid, text, enc_v in rows:
            # Validate the durable marker and native shape before touching the
            # reservation lifecycle. Corrupt/future state must never select the
            # plaintext branch or advance a retry boundary.
            if type(enc_v) is not int or enc_v not in (0, 1):
                raise ValueError("unsupported durable payload version")
            if enc_v == 1:
                enc_raw = native_payload(strict_json(text), enc_v)
                send_text = None
                kwargs = {"enc": json.loads(enc_raw), "enc_v": enc_v}
            else:
                send_text = text
                kwargs = {}
            if res_id is None:
                results.append(self.send(grant, mid, send_text, **kwargs))
                continue
            # Another process may have completed the reservation since selection.
            current = a.reservation_row(res_id)
            if current["state"] == "inflight":
                a.reconcile_inflight(res_id)
            current = a.reservation_row(res_id)
            if current["state"] == "failed-unknown":
                try:
                    a.schedule_retry(res_id)
                except a.ReservationError:
                    pass  # re-read/action fence resolves concurrent completion
            results.append(self.send(grant, mid, send_text, **kwargs))
        return results

    def receive(self, endpoint):
        if endpoint not in self.cfg["endpoints"]:
            raise ValueError("unmapped endpoint")
        try:
            messages = self.client(endpoint).poll(timeout=0)
        except Exception:
            raise RuntimeError("receive transport unavailable") from None
        a = self.authority
        accepted = []
        for message in messages:
            if type(message) is not dict or not isinstance(message.get("id"), str):
                continue
            try:
                if str(uuid.UUID(message["id"])) != message["id"]:
                    continue
            except ValueError:
                continue
            grant = next((g for g, r in self.cfg["routes"].items() if r["receive_endpoint"] == endpoint and r["from"] == message.get("from")), None)
            if grant is None:
                continue
            enc_v = message.get("enc_v", 0)
            if type(enc_v) is not int or enc_v not in (0, 1):
                continue
            encrypted = enc_v == 1
            if not isinstance(message.get("text"), str) or len(message["text"].encode()) > 65536:
                continue
            if encrypted:
                try:
                    native_payload(strict_json(message["text"]), enc_v)
                    if message.get("to", self.cfg["endpoints"][endpoint]["peer"]) != self.cfg["endpoints"][endpoint]["peer"]:
                        continue
                except (ValueError, TypeError):
                    continue
            self.enforce_cap(grant)
            with a.authority_lock():
                c = a._connect()
                try:
                    # Fresh trusted-clock cap evaluation inside this final
                    # serialized acceptance boundary, committed under the same
                    # continuous lock hold before the stored row is trusted.
                    a._begin(c)
                    a._enforce_cap_in_transaction(c, grant)
                    c.execute("COMMIT")
                    a._begin(c)
                    g = a._grant_row(c, grant)
                    if not g or g[2] != "OK" or g[3] is not None:
                        c.execute("ROLLBACK")
                        continue
                    # Relay redelivery counters are telemetry, not content.
                    # Persist only stable message fields so ack-loss retries
                    # cannot turn an otherwise identical message into a clash.
                    stable = {k: message.get(k) for k in ("id", "from", "topic", "text", "in_reply_to", "sent_at", "expires_at")}
                    if encrypted:
                        stable["enc_v"] = 1
                        if "to" in message:
                            stable["to"] = message["to"]
                    payload = json.dumps(stable, sort_keys=True)
                    old = c.execute("SELECT grant_id,payload FROM runtime_inbox WHERE endpoint=? AND msg_id=?", (endpoint, message["id"])).fetchone()
                    if old is not None and old != (grant, payload):
                        c.execute("ROLLBACK")
                        continue
                    c.execute("INSERT OR IGNORE INTO runtime_inbox VALUES (?,?,?,?,?)", (endpoint, message["id"], grant, g[1], payload))
                    c.execute("COMMIT")  # durable local acceptance BEFORE relay ack
                    try:
                        ack = self.client(endpoint).ack([message["id"]])
                        if (type(ack) is not dict or not isinstance(ack.get("acked"), list)
                                or not isinstance(ack.get("already_acked"), list)
                                or message["id"] not in ack["acked"] + ack["already_acked"]):
                            raise RuntimeError("relay did not confirm acknowledgement")
                    except Exception:
                        raise RuntimeError("receive persisted; ack uncertain, retry receive") from None
                    accepted.append(message["id"])
                except Exception:
                    a._rollback_quiet(c)
                    raise
                finally:
                    c.close()
        return {"accepted_ids": accepted, "proof_only": self.cfg["proof_only"]}

    def inbox_messages(self):
        with self.authority.authority_lock():
            c = self.authority._connect()
            try:
                return [json.loads(r[0]) for r in c.execute("SELECT payload FROM runtime_inbox ORDER BY rowid")]
            finally:
                c.close()

    def snapshot(self, name):
        if not isinstance(name, str) or not name or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in name):
            raise ValueError("snapshot requires a simple new name")
        path = str(self.base / ("snapshot-" + name + ".db"))
        with self.authority.authority_lock():
            fd = self.authority._open_private_regular(path, os.O_RDWR | os.O_CREAT | os.O_EXCL)
            os.close(fd)
            source = self.authority._connect()
            dest = sqlite3.connect(path)
            try:
                source.backup(dest)
                if dest.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise RuntimeError("snapshot integrity failed")
            finally:
                dest.close()
                source.close()
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        return {"snapshot": path, "integrity": "ok"}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--config", required=True)
    sub = p.add_subparsers(dest="command", required=True)
    send = sub.add_parser("send")
    send.add_argument("--grant", required=True)
    send.add_argument("--id", required=True)
    payload_arg = send.add_mutually_exclusive_group(required=True)
    payload_arg.add_argument("--text-file")
    payload_arg.add_argument("--enc-file", help="owner-encrypted envelope JSON; no key access")
    receive = sub.add_parser("receive")
    receive.add_argument("--endpoint", required=True)
    sub.add_parser("reconcile")
    sub.add_parser("status")
    recheck = sub.add_parser("recheck")
    recheck.add_argument("--evidence-file", required=True)
    snap = sub.add_parser("snapshot")
    snap.add_argument("--name", required=True)
    args = p.parse_args()
    try:
        adapter = Adapter(args.config)
        if args.command == "send":
            if args.enc_file:
                result = adapter.send(args.grant, args.id, enc=strict_json(private_read(args.enc_file, 65536)), enc_v=1)
            else:
                result = adapter.send(args.grant, args.id, private_read(args.text_file, 65536).decode())
        elif args.command == "receive":
            result = adapter.receive(args.endpoint)
        elif args.command == "reconcile":
            result = adapter.reconcile()
        elif args.command == "snapshot":
            result = adapter.snapshot(args.name)
        elif args.command == "recheck":
            result = adapter.recheck(args.evidence_file)
        else:
            result = {"ready": True, "proof_only": adapter.cfg["proof_only"], "inbox_count": len(adapter.inbox_messages())}
        print(json.dumps(result, sort_keys=True))
        if args.command == "send" and isinstance(result, dict) and result["outcome"] not in ("sent", "already_sent"):
            return 2
        return 0
    except Exception as exc:
        # No raw exception payloads: referenced credentials and message bodies
        # must not escape through generic CLI failures.
        print(json.dumps({"error": "adapter refused or outcome unknown", "class": type(exc).__name__}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
