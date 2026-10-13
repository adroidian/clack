#!/usr/bin/env python3
"""Configured persistent authority derived from reviewed successor6 0d4cad64.

The reviewed transaction, generation, hold-lineage, tombstone, recheck, NDR,
and reservation algorithms are retained and pinned by AST parity tests.
This module removes the fixture installer, fixture transport, fixture CLI,
environment defaults, and synthetic verifier identity. configure() binds an
existing uid-owned private persistent store and operator-provided key refs;
action() requires an explicit runtime transport. No grant or key is minted.

One SQLite authority and one cross-process flock still cover every action
fence through transport return. Unknown acceptance requires same-ID restart
reconciliation; stock-relay deduplication is not exactly-once application
processing. NDRs are local signed rows, not recipient-delivery receipts.
Linux only; independent review and approved real-pair proof remain external.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import math
import os
import re
import sqlite3
import stat
import subprocess
import sys
import threading
import time
import uuid
from typing import Callable, Dict, Iterator, Optional, Sequence, Tuple, cast

# Authority algorithms retained from reviewed 0d4cad64. No fixture initializer,
# fixture transport, environment defaults, key generation, or grant installation.
_REPO = os.path.dirname(os.path.abspath(__file__))
BASE = AUTH_DB = AUTH_LOCK = NDR_KEY = NDR_PUB = RECHECK_VERIFIER_PUB = ""
_BASE_ABS = ""
_CONFIGURED = False
_ROOT_IDENTITY = None
_PARTITION_CAP_S = None
import ed25519


def configure(base: str, ndr_key: str, verifier_pub: str, verifier_id: str,
              partition_cap_s: Optional[float] = None) -> None:
    """Bind one already approved authority store; never install grants or keys."""
    global BASE, _BASE_ABS, AUTH_DB, AUTH_LOCK, NDR_KEY, RECHECK_VERIFIER_PUB
    global _RECHECK_VERIFIER_ID, _CONFIGURED, _ROOT_IDENTITY, _PARTITION_CAP_S
    if _CONFIGURED:
        raise RuntimeError("authority is already configured")
    for path in (base, ndr_key, verifier_pub):
        if (not isinstance(path, str) or not os.path.isabs(path)
                or os.path.abspath(path) != path or os.path.realpath(path) != path
                or _has_symlink_component(path)):
            raise ValueError("authority references must be canonical without symlinks")
    if not isinstance(verifier_id, str) or not verifier_id or len(verifier_id) > 256:
        raise ValueError("explicit verifier identity required")
    BASE = _BASE_ABS = base
    AUTH_DB = os.path.join(base, "federation-authority.db")
    AUTH_LOCK = os.path.join(base, "federation-authority.lock")
    NDR_KEY, RECHECK_VERIFIER_PUB = ndr_key, verifier_pub
    _RECHECK_VERIFIER_ID = verifier_id
    _require_base()
    fd = _open_private_regular(AUTH_DB, os.O_RDWR)
    os.close(fd)
    _read_private_regular(NDR_KEY, expected_size=32)
    _read_private_regular(RECHECK_VERIFIER_PUB, expected_size=32)
    opened = os.stat(BASE, follow_symlinks=False)
    _ROOT_IDENTITY = (opened.st_dev, opened.st_ino)
    if partition_cap_s is not None:
        # The configured finite cap is re-evaluated with a fresh trusted-clock
        # sample inside each serialized final decision boundary.
        _PARTITION_CAP_S = _finite_number(partition_cap_s, "partition_cap_s", positive=True)
    _CONFIGURED = True


_GRANT_STATES = {"OK", "SUSPECT", "CAPPED", "REVOKED"}
_RESERVATION_STATES = {
    "reserved",
    "inflight",
    "sent",
    "failed-unknown",
    "retry",
    "released",
}
_LIVE_RESERVATION_STATES = ("reserved", "inflight", "failed-unknown", "retry")
_local_authority_lock = threading.RLock()
_RECHECK_DOMAIN = b"clack-federation-recheck-evidence/v1\n"
_RECHECK_SCHEMA = "clack-federation-recheck-evidence-v1"
_RECHECK_VERIFIER_ID = ""
_RECHECK_FIELDS = {
    "schema",
    "version",
    "evidence_id",
    "verifier_id",
    "verifier_key_id",
    "grant_id",
    "expected_generation",
    "prior_state",
    "verdict",
    "verified_at",
    "signature_hex",
}
_EVIDENCE_ID_RE = re.compile(r"ev-[0-9a-f]{32}\Z")
_KEY_ID_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SIGNATURE_RE = re.compile(r"[0-9a-f]{128}\Z")


class NonceReplay(ValueError):
    """The caller attempted to reuse a committed anti-replay nonce."""


class ReservationError(ValueError):
    """A reservation transition violated its durable binding/lifecycle."""


def _finite_number(value: object, label: str, *, positive: bool = False) -> float:
    """Validate an untrusted clock/duration before it reaches durable state."""

    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("%s must be a finite number" % label) from exc
    if not math.isfinite(number):
        raise ValueError("%s must be finite" % label)
    if positive and number <= 0:
        raise ValueError("%s must be positive" % label)
    return number


def _has_symlink_component(path: str) -> bool:
    cur = os.path.abspath(path)
    while True:
        if os.path.islink(cur):
            return True
        parent = os.path.dirname(cur)
        if parent == cur:
            return False
        cur = parent


def _under(root: str, path: str) -> bool:
    try:
        return os.path.commonpath([os.path.realpath(root), os.path.realpath(path)]) == os.path.realpath(root)
    except ValueError:
        return False


def _require_base() -> None:
    if _BASE_ABS != BASE:
        raise RuntimeError("FED_BASE is not canonical or traverses a symlink: %s" % _BASE_ABS)
    if not os.path.isdir(BASE):
        raise RuntimeError("FED_BASE does not exist: %s" % BASE)
    if _has_symlink_component(_BASE_ABS):
        raise RuntimeError("FED_BASE traverses a symlink: %s" % _BASE_ABS)
    if _under(_REPO, BASE) or _under(BASE, _REPO):
        raise RuntimeError("FED_BASE and repository must not contain one another")
    st = os.stat(BASE, follow_symlinks=False)
    if _ROOT_IDENTITY is not None and (st.st_dev, st.st_ino) != _ROOT_IDENTITY:
        raise RuntimeError("configured authority directory was replaced")
    if st.st_uid != os.getuid() or (st.st_mode & 0o777) != 0o700:
        raise RuntimeError("FED_BASE must be uid-owned mode 0700: %s" % BASE)


def _open_private_regular(path: str, flags: int) -> int:
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_uid != os.getuid():
            raise RuntimeError("authority path is not an owned regular file: %s" % path)
        mode = stat.S_IMODE(opened.st_mode)
        if mode != 0o600:
            raise RuntimeError(
                "authority path mode is %03o, expected exact 0600: %s" % (mode, path)
            )
        return fd
    except Exception:
        os.close(fd)
        raise


@contextlib.contextmanager
def authority_lock(_grant_id: Optional[str] = None) -> Iterator[None]:
    """Global cross-process federation serialization scope.

    ``_grant_id`` is accepted for compatibility and diagnostics.  A global
    lock is intentionally used: it makes mixed-grant batches and action
    fences share one ordering primitive.  ``threading.RLock`` covers threads
    in this process; ``flock`` covers independent adapter/driver processes.
    """

    _require_base()
    with _local_authority_lock:
        fd = _open_private_regular(AUTH_LOCK, os.O_RDWR | os.O_CREAT)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            # The blocking flock wait above can span ordinary operator
            # maintenance.  Re-pin the configured root identity after lock
            # acquisition and before any pathname-based DB open, so a root
            # replaced during the wait refuses subsequent mutation.
            _require_base()
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)


def grant_lock(grant_id: str) -> contextlib.AbstractContextManager:
    """Compatibility name for the now cross-process authority lock."""

    return authority_lock(grant_id)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS grants(
    grant_id TEXT PRIMARY KEY,
    generation INTEGER NOT NULL CHECK(generation >= 1),
    state TEXT NOT NULL CHECK(state IN ('OK','SUSPECT','CAPPED','REVOKED')),
    tombstone_reason TEXT,
    last_recheck_verified_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS queued_messages(
    msg_id TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    enqueued_at REAL NOT NULL,
    FOREIGN KEY(grant_id) REFERENCES grants(grant_id)
);
CREATE TABLE IF NOT EXISTS held_messages(
    msg_id TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    held_at REAL NOT NULL,
    FOREIGN KEY(grant_id) REFERENCES grants(grant_id)
);
CREATE TABLE IF NOT EXISTS ndrs(
    msg_id TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    reason TEXT NOT NULL,
    detail TEXT,
    signature_hex TEXT NOT NULL,
    issued_at REAL NOT NULL,
    FOREIGN KEY(grant_id) REFERENCES grants(grant_id)
);
CREATE TABLE IF NOT EXISTS consumed_nonces(
    nonce TEXT PRIMARY KEY,
    consumed_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS consumed_recheck_evidence(
    evidence_id TEXT PRIMARY KEY,
    verifier_key_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    expected_generation INTEGER NOT NULL,
    consumed_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS outbox(
    msg_id TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    state TEXT NOT NULL,
    detail TEXT,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS reservations(
    res_id TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    msg_id TEXT NOT NULL UNIQUE,
    snapshot_state TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN
      ('reserved','inflight','sent','failed-unknown','retry','released')),
    attempt_count INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    FOREIGN KEY(grant_id) REFERENCES grants(grant_id)
);
CREATE INDEX IF NOT EXISTS reservations_grant_state
    ON reservations(grant_id, state);
CREATE TABLE IF NOT EXISTS authority_holds(
    msg_id TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    res_id TEXT,
    FOREIGN KEY(grant_id) REFERENCES grants(grant_id)
);
"""


def _connect() -> sqlite3.Connection:
    # SQLite's Python API does not expose SQLITE_OPEN_NOFOLLOW.  Pre-open and
    # validate the path under the private authority lock so symlinks/devices are
    # rejected before SQLite touches it.
    fd = _open_private_regular(AUTH_DB, os.O_RDWR | os.O_CREAT)
    os.close(fd)
    c = sqlite3.connect(AUTH_DB, timeout=30, isolation_level=None)
    c.execute("PRAGMA busy_timeout=30000")
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA synchronous=FULL")
    c.executescript(_SCHEMA)
    return c


def _begin(c: sqlite3.Connection) -> None:
    c.execute("BEGIN IMMEDIATE")


def _rollback_quiet(c: sqlite3.Connection) -> None:
    try:
        c.execute("ROLLBACK")
    except sqlite3.Error:
        pass


def _grant_row(c: sqlite3.Connection, grant_id: str) -> Optional[sqlite3.Row]:
    return c.execute(
        "SELECT grant_id,generation,state,tombstone_reason,"
        " last_recheck_verified_at,updated_at FROM grants WHERE grant_id=?",
        (grant_id,),
    ).fetchone()


def _advance_live_generation(
    c: sqlite3.Connection, grant_id: str, previous: int, following: int
) -> None:
    """Carry exact live bindings with each grant transition, in its transaction.

    Advancing one edge at a time preserves chained suspension lineage without
    inferring an old action generation from the number of intervening states.
    Terminal and unrelated stale rows never gain authority.
    """

    # A display state of 'held' is not authority. Only the lineage recorded by
    # the ordinary SUSPECT action fence can carry a held outbox, including the
    # supported pre-reservation hold. Revalidate the complete previous binding
    # and its underlying live lifecycle inside the grant transition transaction.
    held = c.execute(
        "SELECT h.msg_id FROM authority_holds h"
        " JOIN outbox o ON o.msg_id=h.msg_id AND o.grant_id=h.grant_id"
        " AND o.generation=h.generation AND o.state='held'"
        " JOIN held_messages m ON m.msg_id=h.msg_id AND m.grant_id=h.grant_id"
        " AND m.generation=h.generation"
        " WHERE h.grant_id=? AND h.generation=?"
        " AND NOT EXISTS (SELECT 1 FROM ndrs n WHERE n.msg_id=h.msg_id)"
        " AND ((h.res_id IS NULL AND NOT EXISTS"
        " (SELECT 1 FROM reservations r WHERE r.msg_id=h.msg_id))"
        " OR EXISTS (SELECT 1 FROM reservations r WHERE r.res_id=h.res_id"
        " AND r.msg_id=h.msg_id AND r.grant_id=h.grant_id AND r.generation=?"
        " AND r.snapshot_state='OK' AND r.state IN (?,?,?,?)))",
        (grant_id, previous, previous, *_LIVE_RESERVATION_STATES),
    ).fetchall()
    c.execute(
        "UPDATE reservations SET generation=? WHERE grant_id=? AND generation=?"
        " AND snapshot_state='OK' AND state IN (?,?,?,?)",
        (following, grant_id, previous, *_LIVE_RESERVATION_STATES),
    )
    c.execute(
        "UPDATE outbox SET generation=? WHERE grant_id=? AND generation=?"
        " AND EXISTS (SELECT 1 FROM reservations r"
        " WHERE r.msg_id=outbox.msg_id AND r.grant_id=outbox.grant_id"
        " AND r.generation=? AND r.snapshot_state='OK' AND r.state=outbox.state"
        " AND r.state IN (?,?,?,?))",
        (following, grant_id, previous, following, *_LIVE_RESERVATION_STATES),
    )
    for (msg_id,) in held:
        for table in ("outbox", "held_messages", "authority_holds"):
            c.execute(
                "UPDATE " + table + " SET generation=?"
                " WHERE msg_id=? AND grant_id=? AND generation=?",
                (following, msg_id, grant_id, previous),
            )




def set_grant(grant_id: str, state: str) -> None:
    """Apply the one narrow helper transition used by the race rig.

    Installation, partition caps, revocations, and verified reopen are owned by
    their transactional APIs.  This helper may only move an existing live grant
    from OK to SUSPECT.  Same-state calls are read-only idempotence checks.
    """

    if state not in _GRANT_STATES:
        raise ValueError("invalid grant state %r" % state)
    now = time.time()
    with authority_lock(grant_id):
        c = _connect()
        try:
            _begin(c)
            row = _grant_row(c, grant_id)
            if not row:
                raise ValueError(
                    "unknown grant %s; use install_grant for installation" % grant_id
                )
            current = str(row[2])
            if state == current:
                c.execute("ROLLBACK")
                return
            if current == "REVOKED" or row[3] is not None:
                raise ValueError(
                    "terminal REVOKED tombstone cannot be created or mutated by set_grant"
                )
            if state in ("CAPPED", "REVOKED"):
                raise ValueError(
                    "%s requires its authoritative transactional API" % state
                )
            if current in ("SUSPECT", "CAPPED"):
                raise ValueError(
                    "%s may reopen only through verified_recheck" % current
                )
            if current != "OK" or state != "SUSPECT":
                raise ValueError(
                    "set_grant permits only the OK to SUSPECT transition"
                )
            c.execute(
                "UPDATE grants SET generation=generation+1,state='SUSPECT',updated_at=?"
                " WHERE grant_id=? AND state='OK' AND tombstone_reason IS NULL",
                (now, grant_id),
            )
            _advance_live_generation(c, grant_id, int(row[1]), int(row[1]) + 1)
            c.execute("COMMIT")
        except Exception:
            _rollback_quiet(c)
            raise
        finally:
            c.close()


def read_grant_record(grant_id: str) -> Optional[Dict[str, object]]:
    with authority_lock(grant_id):
        c = _connect()
        try:
            row = _grant_row(c, grant_id)
        finally:
            c.close()
    if not row:
        return None
    return {
        "grant_id": row[0],
        "generation": row[1],
        "state": row[2],
        "tombstone_reason": row[3],
        "last_recheck_verified_at": row[4],
        "updated_at": row[5],
    }


def read_grant(grant_id: str) -> str:
    row = read_grant_record(grant_id)
    if row and row["tombstone_reason"] is not None:
        return "REVOKED"
    return str(row["state"]) if row else "UNKNOWN"


def grant_generation(grant_id: str) -> Optional[int]:
    row = read_grant_record(grant_id)
    return int(row["generation"]) if row else None


def decide(grant_id: str) -> Tuple[str, str]:
    state = read_grant(grant_id)
    return ("allow" if state == "OK" else "deny", state)


def queue_message(grant_id: str, msg_id: str) -> None:
    now = time.time()
    with authority_lock(grant_id):
        c = _connect()
        try:
            _begin(c)
            row = _grant_row(c, grant_id)
            if not row:
                raise ValueError("unknown grant %s" % grant_id)
            c.execute(
                "INSERT OR REPLACE INTO queued_messages VALUES (?,?,?,?)",
                (msg_id, grant_id, row[1], now),
            )
            c.execute("COMMIT")
        except Exception:
            _rollback_quiet(c)
            raise
        finally:
            c.close()


def mark_held(grant_id: str, msg_id: str) -> None:
    now = time.time()
    with authority_lock(grant_id):
        c = _connect()
        try:
            _begin(c)
            row = _grant_row(c, grant_id)
            if not row:
                raise ValueError("unknown grant %s" % grant_id)
            c.execute(
                "INSERT OR REPLACE INTO held_messages VALUES (?,?,?,?)",
                (msg_id, grant_id, row[1], now),
            )
            c.execute("COMMIT")
        except Exception:
            _rollback_quiet(c)
            raise
        finally:
            c.close()


def resolve_queued(msg_id: str) -> None:
    """Remove one recovered queue row after its durable delivery resolves."""

    with authority_lock():
        c = _connect()
        try:
            _begin(c)
            c.execute("DELETE FROM queued_messages WHERE msg_id=?", (msg_id,))
            c.execute("COMMIT")
        except Exception:
            _rollback_quiet(c)
            raise
        finally:
            c.close()


def _hold_with_connection(
    c: sqlite3.Connection,
    msg_id: str,
    grant_id: str,
    generation: int,
    detail: str,
) -> None:
    now = time.time()
    # Other refusal paths do not inherit an earlier authoritative hold.
    c.execute("DELETE FROM authority_holds WHERE msg_id=?", (msg_id,))
    c.execute(
        "INSERT INTO outbox(msg_id,grant_id,generation,state,detail,updated_at)"
        " VALUES (?,?,?,?,?,?) ON CONFLICT(msg_id) DO UPDATE SET"
        " grant_id=excluded.grant_id,generation=excluded.generation,"
        " state=excluded.state,detail=excluded.detail,updated_at=excluded.updated_at",
        (msg_id, grant_id, generation, "held", detail, now),
    )
    c.execute(
        "INSERT OR REPLACE INTO held_messages VALUES (?,?,?,?)",
        (msg_id, grant_id, generation, now),
    )


def outbox_state(msg_id: str) -> Optional[str]:
    with authority_lock():
        c = _connect()
        try:
            row = c.execute(
                "SELECT state FROM outbox WHERE msg_id=?", (msg_id,)
            ).fetchone()
        finally:
            c.close()
    return row[0] if row else None


def reserve_dispatch(grant_id: str, msg_id: str) -> Tuple[Optional[str], str]:
    """Create a durable grant+generation+message-bound reservation."""

    with authority_lock(grant_id):
        c = _connect()
        try:
            _begin(c)
            g = _grant_row(c, grant_id)
            state = g[2] if g else "UNKNOWN"
            if g and g[3] is not None:
                state = "REVOKED"
            if not g or state != "OK":
                c.execute("ROLLBACK")
                return (None, state)
            existing = c.execute(
                "SELECT res_id,state FROM reservations WHERE msg_id=?", (msg_id,)
            ).fetchone()
            if existing:
                c.execute("ROLLBACK")
                return (existing[0], state)
            res_id = "res-" + uuid.uuid4().hex
            now = time.time()
            c.execute(
                "INSERT INTO reservations(res_id,grant_id,generation,msg_id,"
                " snapshot_state,state,attempt_count,last_error,created_at,updated_at)"
                " VALUES (?,?,?,?,?,'reserved',0,NULL,?,?)",
                (res_id, grant_id, g[1], msg_id, state, now, now),
            )
            # Adopt only the exact authoritative pre-reservation hold. The
            # insertion and binding change share this transaction and lock;
            # stale/display-only/terminal rows are not repaired or advanced.
            # Existing reservations return read-only above, so this can never
            # rebind another reservation or revive its terminal lifecycle.
            c.execute(
                "UPDATE authority_holds SET res_id=?"
                " WHERE msg_id=? AND grant_id=? AND generation=? AND res_id IS NULL"
                " AND EXISTS (SELECT 1 FROM grants g"
                " WHERE g.grant_id=authority_holds.grant_id"
                " AND g.generation=authority_holds.generation"
                " AND g.state='OK' AND g.tombstone_reason IS NULL)"
                " AND EXISTS (SELECT 1 FROM outbox o"
                " WHERE o.msg_id=authority_holds.msg_id"
                " AND o.grant_id=authority_holds.grant_id"
                " AND o.generation=authority_holds.generation AND o.state='held')"
                " AND EXISTS (SELECT 1 FROM held_messages m"
                " WHERE m.msg_id=authority_holds.msg_id"
                " AND m.grant_id=authority_holds.grant_id"
                " AND m.generation=authority_holds.generation)"
                " AND NOT EXISTS (SELECT 1 FROM ndrs n"
                " WHERE n.msg_id=authority_holds.msg_id)"
                " AND EXISTS (SELECT 1 FROM reservations r WHERE r.res_id=?"
                " AND r.msg_id=authority_holds.msg_id"
                " AND r.grant_id=authority_holds.grant_id"
                " AND r.generation=authority_holds.generation"
                " AND r.snapshot_state='OK' AND r.state='reserved')",
                (res_id, msg_id, grant_id, g[1], res_id),
            )
            c.execute("COMMIT")
            return (res_id, state)
        except Exception:
            _rollback_quiet(c)
            raise
        finally:
            c.close()


def reservation_row(res_id: str) -> Optional[Dict[str, object]]:
    with authority_lock():
        c = _connect()
        try:
            row = c.execute(
                "SELECT res_id,grant_id,generation,msg_id,snapshot_state,state,"
                " attempt_count,last_error,created_at,updated_at"
                " FROM reservations WHERE res_id=?",
                (res_id,),
            ).fetchone()
        finally:
            c.close()
    if not row:
        return None
    keys = (
        "res_id",
        "grant_id",
        "generation",
        "msg_id",
        "snapshot_state",
        "state",
        "attempt_count",
        "last_error",
        "created_at",
        "updated_at",
    )
    return dict(zip(keys, row))


def reconcile_inflight(res_id: str, detail: str = "restart observed durable inflight") -> str:
    """Turn a crash-surviving inflight reservation into failed-unknown."""

    with authority_lock():
        c = _connect()
        try:
            _begin(c)
            row = c.execute(
                "SELECT state,msg_id FROM reservations WHERE res_id=?", (res_id,)
            ).fetchone()
            if not row:
                raise ReservationError("unknown reservation %s" % res_id)
            state = row[0]
            if state == "inflight":
                now = time.time()
                c.execute(
                    "UPDATE reservations SET state='failed-unknown',last_error=?,"
                    " updated_at=? WHERE res_id=?",
                    (detail, now, res_id),
                )
                c.execute(
                    "UPDATE outbox SET state='failed-unknown',detail=?,updated_at=?"
                    " WHERE msg_id=? AND state='inflight'",
                    (detail, now, row[1]),
                )
                state = "failed-unknown"
            c.execute("COMMIT")
            return state
        except Exception:
            _rollback_quiet(c)
            raise
        finally:
            c.close()


def schedule_retry(res_id: str) -> str:
    with authority_lock():
        c = _connect()
        try:
            _begin(c)
            row = c.execute(
                "SELECT state,msg_id FROM reservations WHERE res_id=?", (res_id,)
            ).fetchone()
            if not row:
                raise ReservationError("unknown reservation %s" % res_id)
            if row[0] != "failed-unknown":
                raise ReservationError(
                    "retry requires failed-unknown, got %s" % row[0]
                )
            now = time.time()
            c.execute(
                "UPDATE reservations SET state='retry',updated_at=? WHERE res_id=?",
                (now, res_id),
            )
            c.execute(
                "UPDATE outbox SET state='retry',detail='retry scheduled',updated_at=?"
                " WHERE msg_id=? AND state='failed-unknown'",
                (now, row[1]),
            )
            c.execute("COMMIT")
            return "retry"
        except Exception:
            _rollback_quiet(c)
            raise
        finally:
            c.close()


def release_reservation(res_id: str, detail: str) -> str:
    with authority_lock():
        c = _connect()
        try:
            _begin(c)
            row = c.execute(
                "SELECT state FROM reservations WHERE res_id=?", (res_id,)
            ).fetchone()
            if not row:
                raise ReservationError("unknown reservation %s" % res_id)
            if row[0] == "sent":
                raise ReservationError("cannot release a sent reservation")
            c.execute(
                "UPDATE reservations SET state='released',last_error=?,updated_at=?"
                " WHERE res_id=?",
                (detail, time.time(), res_id),
            )
            c.execute("COMMIT")
            return "released"
        except Exception:
            _rollback_quiet(c)
            raise
        finally:
            c.close()




def action(
    grant_id: str,
    msg_id: str,
    text: str,
    res_id: Optional[str] = None,
    transport_mode: str = "real",
    timeout: float = 30.0,
    transport: Optional[Callable[[str, str], Dict[str, object]]] = None,
) -> Tuple[str, str]:
    """Execute the mandatory action fence and reservation lifecycle.

    Direct calls are not a bypass: when ``res_id`` is absent an implicit
    durable reservation is created under the same authority lock.  The
    cross-process lock remains held through the transport's return.
    """

    if transport is None or transport_mode != "real":
        raise ValueError("operational action requires an explicit transport")
    with authority_lock(grant_id):
        c = _connect()
        try:
            # Fresh trusted-clock cap evaluation inside this final serialized
            # decision boundary, committed under the same continuous lock hold
            # with the reviewed apply_partition_cap atomicity.  The unchanged
            # decision transaction below then reads post-cap authority, so
            # ordinary serialization can never cross expiry while only
            # re-reading stored OK/generation/tombstone.
            _begin(c)
            _enforce_cap_in_transaction(c, grant_id)
            c.execute("COMMIT")
            _begin(c)
            g = _grant_row(c, grant_id)
            generation = int(g[1]) if g else 0
            state = g[2] if g else "UNKNOWN"
            if g and g[3] is not None:
                state = "REVOKED"
            outbox = c.execute(
                "SELECT grant_id,generation,state FROM outbox WHERE msg_id=?", (msg_id,)
            ).fetchone()
            if outbox and (outbox[0] != grant_id or outbox[1] != generation):
                # Refusal is read-only: replacing this row with a current hold
                # would launder stale authority for the next action attempt.
                c.execute("ROLLBACK")
                return ("held", "outbox binding mismatch: grant/generation")
            if c.execute("SELECT 1 FROM ndrs WHERE msg_id=?", (msg_id,)).fetchone():
                c.execute("ROLLBACK")
                return ("held", "message already NDR-resolved")
            if outbox and outbox[2] in ("sent", "released"):
                c.execute("ROLLBACK")
                return ("already_sent" if outbox[2] == "sent" else "held",
                        "terminal outbox; no transport replay")
            if not g or state != "OK":
                reservation = c.execute(
                    "SELECT res_id,grant_id,generation,snapshot_state,state"
                    " FROM reservations WHERE msg_id=?", (msg_id,),
                ).fetchone()
                if outbox:
                    if outbox[2] == "held":
                        lineage = c.execute(
                            "SELECT res_id FROM authority_holds WHERE msg_id=?"
                            " AND grant_id=? AND generation=?",
                            (msg_id, grant_id, generation),
                        ).fetchone()
                        valid_outbox = bool(lineage and lineage[0] == (
                            reservation[0] if reservation else None))
                    else:
                        valid_outbox = bool(reservation and outbox[2] == reservation[4])
                    if not valid_outbox:
                        c.execute("ROLLBACK")
                        return ("held", "outbox has no authoritative live hold lineage")
                # Refuse mismatched/terminal reservation lineage read-only.
                # Do not turn an unrelated reservation or supplied unknown id
                # into a pre-reservation hold that can later gain authority.
                if ((reservation and (
                    reservation[1] != grant_id or reservation[2] != generation
                    or reservation[3] != "OK"
                    or reservation[4] not in _LIVE_RESERVATION_STATES
                    or (res_id is not None and res_id != reservation[0])))
                    or (not reservation and res_id is not None)):
                    c.execute("ROLLBACK")
                    return ("held", "reservation binding/lifecycle mismatch at hold")
                _hold_with_connection(
                    c,
                    msg_id,
                    grant_id,
                    generation,
                    "grant=%s at action; authority hold, no wire bytes" % state,
                )
                if state == "SUSPECT":
                    c.execute(
                        "INSERT INTO authority_holds VALUES (?,?,?,?)",
                        (msg_id, grant_id, generation,
                         reservation[0] if reservation else None),
                    )
                c.execute("COMMIT")
                return ("held", "grant=%s at authoritative action fence" % state)

            if res_id is None:
                existing = c.execute(
                    "SELECT res_id FROM reservations WHERE msg_id=?", (msg_id,)
                ).fetchone()
                if existing:
                    res_id = existing[0]
                else:
                    res_id = "res-direct-" + uuid.uuid4().hex
                    now = time.time()
                    c.execute(
                        "INSERT INTO reservations(res_id,grant_id,generation,msg_id,"
                        " snapshot_state,state,attempt_count,last_error,created_at,updated_at)"
                        " VALUES (?,?,?,?,?,'reserved',0,NULL,?,?)",
                        (res_id, grant_id, generation, msg_id, state, now, now),
                    )

            r = c.execute(
                "SELECT grant_id,generation,msg_id,snapshot_state,state,attempt_count"
                " FROM reservations WHERE res_id=?",
                (res_id,),
            ).fetchone()
            if not r:
                _hold_with_connection(
                    c, msg_id, grant_id, generation, "unknown reservation"
                )
                c.execute("COMMIT")
                return ("held", "unknown reservation %s" % res_id)
            r_gid, r_gen, r_mid, snapshot, r_state, attempts = r
            mismatch = []
            if r_gid != grant_id:
                mismatch.append("grant")
            if r_mid != msg_id:
                mismatch.append("msg_id")
            if int(r_gen) != generation:
                mismatch.append("generation")
            if snapshot != "OK":
                mismatch.append("snapshot")
            if mismatch:
                _hold_with_connection(
                    c,
                    msg_id,
                    grant_id,
                    generation,
                    "reservation binding mismatch: %s" % ",".join(mismatch),
                )
                c.execute("COMMIT")
                return (
                    "held",
                    "reservation binding mismatch: %s" % ",".join(mismatch),
                )
            if r_state == "sent":
                c.execute("ROLLBACK")
                return ("already_sent", "reservation already sent; no transport replay")
            if r_state == "released":
                _hold_with_connection(
                    c, msg_id, grant_id, generation, "reservation released"
                )
                c.execute("COMMIT")
                return ("held", "reservation released")
            if r_state in ("inflight", "failed-unknown"):
                c.execute("ROLLBACK")
                return (
                    "uncertain",
                    "reservation %s requires restart reconciliation" % r_state,
                )
            if r_state not in ("reserved", "retry"):
                raise ReservationError("invalid reservation state %s" % r_state)
            if outbox and outbox[2] not in (r_state, "held"):
                c.execute("ROLLBACK")
                return ("held", "outbox lifecycle mismatch")

            # Persist inflight BEFORE transport, then retain the cross-process
            # authority lock across the handoff.  A hard crash therefore leaves
            # an inspectable inflight row while automatically releasing flock.
            now = time.time()
            c.execute("DELETE FROM authority_holds WHERE msg_id=?", (msg_id,))
            c.execute(
                "UPDATE reservations SET state='inflight',attempt_count=?,"
                " last_error=NULL,updated_at=? WHERE res_id=?",
                (int(attempts) + 1, now, res_id),
            )
            c.execute(
                "INSERT INTO outbox(msg_id,grant_id,generation,state,detail,updated_at)"
                " VALUES (?,?,?,?,?,?) ON CONFLICT(msg_id) DO UPDATE SET"
                " state=excluded.state,detail=excluded.detail,updated_at=excluded.updated_at",
                (msg_id, grant_id, generation, "inflight", "transport handoff", now),
            )
            c.execute("COMMIT")

            try:
                payload = transport(msg_id, text)
            except subprocess.TimeoutExpired as exc:
                _begin(c)
                detail = "transport timeout; acceptance unknown: %s" % exc
                c.execute(
                    "UPDATE reservations SET state='failed-unknown',last_error=?,"
                    " updated_at=? WHERE res_id=?",
                    (detail, time.time(), res_id),
                )
                c.execute(
                    "UPDATE outbox SET state='failed-unknown',detail=?,updated_at=?"
                    " WHERE msg_id=?",
                    (detail, time.time(), msg_id),
                )
                c.execute("COMMIT")
                return ("uncertain", detail)
            except BaseException as exc:
                _begin(c)
                detail = "transport exception; acceptance unknown: %r" % exc
                c.execute(
                    "UPDATE reservations SET state='failed-unknown',last_error=?,"
                    " updated_at=? WHERE res_id=?",
                    (detail, time.time(), res_id),
                )
                c.execute(
                    "UPDATE outbox SET state='failed-unknown',detail=?,updated_at=?"
                    " WHERE msg_id=?",
                    (detail, time.time(), msg_id),
                )
                c.execute("COMMIT")
                return ("uncertain", detail)

            if payload.get("accepted"):
                _begin(c)
                detail = "wire handoff accepted id=%s duplicate=%s" % (
                    msg_id,
                    bool(payload.get("duplicate")),
                )
                c.execute(
                    "UPDATE reservations SET state='sent',last_error=NULL,updated_at=?"
                    " WHERE res_id=?",
                    (time.time(), res_id),
                )
                c.execute(
                    "UPDATE outbox SET state='sent',detail=?,updated_at=? WHERE msg_id=?",
                    (detail, time.time(), msg_id),
                )
                c.execute("DELETE FROM held_messages WHERE msg_id=?", (msg_id,))
                c.execute("COMMIT")
                return ("sent", detail)

            # An explicit parsed rejection is definitive.  A malformed/no
            # response is uncertain because the relay may have committed.
            uncertain = bool(payload.get("transport_parse_error"))
            next_state = "failed-unknown" if uncertain else "released"
            outcome = "uncertain" if uncertain else "rejected"
            detail = "transport %s: %s" % (
                "acceptance unknown" if uncertain else "rejected",
                json.dumps(payload, sort_keys=True)[:240],
            )
            _begin(c)
            c.execute(
                "UPDATE reservations SET state=?,last_error=?,updated_at=?"
                " WHERE res_id=?",
                (next_state, detail, time.time(), res_id),
            )
            c.execute(
                "UPDATE outbox SET state=?,detail=?,updated_at=? WHERE msg_id=?",
                (next_state, detail, time.time(), msg_id),
            )
            c.execute("COMMIT")
            return (outcome, detail)
        except Exception:
            _rollback_quiet(c)
            raise
        finally:
            c.close()




def ndr_canonical(
    msg_id: str, grant_id: str, generation: int, reason: str, detail: Optional[str]
) -> bytes:
    return (
        "clack-local-ndr/v1\n%s\n%s\n%d\n%s\n%s"
        % (msg_id, grant_id, generation, reason, detail or "")
    ).encode("utf-8")


def _read_private_regular(
    path: str, expected_size: Optional[int] = None, expected_mode: int = 0o600
) -> bytes:
    """Open first, then validate the exact file capability before reading."""

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise RuntimeError("private path is not a regular file: %s" % path)
        if opened.st_uid != os.getuid():
            raise RuntimeError(
                "private path owner uid %d does not match process uid: %s"
                % (opened.st_uid, path)
            )
        mode = stat.S_IMODE(opened.st_mode)
        if mode != expected_mode:
            raise RuntimeError(
                "private path mode is %03o, expected exact %03o: %s"
                % (mode, expected_mode, path)
            )
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        data = b"".join(chunks)
    finally:
        os.close(fd)
    if expected_size is not None and len(data) != expected_size:
        raise ValueError("%s has %d bytes, expected %d" % (path, len(data), expected_size))
    return data


def _parse_recheck_evidence(evidence: object) -> Dict[str, object]:
    """Validate the exact signed-evidence shape without trusting any field."""

    if type(evidence) is not dict:
        raise TypeError("recheck evidence must be an exact JSON object")
    if set(evidence) != _RECHECK_FIELDS:
        missing = sorted(_RECHECK_FIELDS - set(evidence))
        extra = sorted(set(evidence) - _RECHECK_FIELDS)
        raise ValueError(
            "recheck evidence field set mismatch; missing=%r extra=%r" % (missing, extra)
        )
    if evidence["schema"] != _RECHECK_SCHEMA:
        raise ValueError("unsupported recheck evidence schema")
    if type(evidence["version"]) is not int or evidence["version"] != 1:
        raise ValueError("recheck evidence version must be exact integer 1")
    evidence_id = evidence["evidence_id"]
    if type(evidence_id) is not str or not _EVIDENCE_ID_RE.fullmatch(evidence_id):
        raise ValueError("malformed recheck evidence_id")
    if evidence["verifier_id"] != _RECHECK_VERIFIER_ID:
        raise ValueError("untrusted recheck verifier_id")
    key_id = evidence["verifier_key_id"]
    if type(key_id) is not str or not _KEY_ID_RE.fullmatch(key_id):
        raise ValueError("malformed recheck verifier_key_id")
    grant_id = evidence["grant_id"]
    if type(grant_id) is not str or not grant_id or len(grant_id) > 256:
        raise ValueError("malformed recheck grant_id")
    generation = evidence["expected_generation"]
    if type(generation) is not int or generation < 1:
        raise ValueError("expected_generation must be an exact positive integer")
    prior_state = evidence["prior_state"]
    if type(prior_state) is not str or prior_state not in ("CAPPED", "SUSPECT"):
        raise ValueError("prior_state must be exactly CAPPED or SUSPECT")
    if evidence["verdict"] != "successful":
        raise ValueError("recheck evidence verdict must be exactly successful")
    if type(evidence["verified_at"]) not in (int, float):
        raise ValueError("verified_at must be an exact finite JSON number")
    watermark = _finite_number(evidence["verified_at"], "verified_at")
    signature_hex = evidence["signature_hex"]
    if type(signature_hex) is not str or not _SIGNATURE_RE.fullmatch(signature_hex):
        raise ValueError("malformed recheck signature_hex")

    body = {key: evidence[key] for key in _RECHECK_FIELDS if key != "signature_hex"}
    try:
        canonical = json.dumps(
            body,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("recheck evidence is not canonical JSON data") from exc
    return {
        "body": body,
        "canonical": canonical,
        "signature": bytes.fromhex(signature_hex),
        "evidence_id": evidence_id,
        "verifier_key_id": key_id,
        "grant_id": grant_id,
        "expected_generation": generation,
        "prior_state": prior_state,
        "verified_at": watermark,
    }


def _verify_recheck_signature(parsed: Dict[str, object]) -> None:
    """Verify against the one runtime-pinned synthetic verifier public key."""

    public = _read_private_regular(
        RECHECK_VERIFIER_PUB, expected_size=32, expected_mode=0o600
    )
    if not ed25519.is_valid_pubkey(public):
        raise ValueError("pinned recheck verifier key is not a valid Ed25519 key")
    expected_key_id = "sha256:" + hashlib.sha256(public).hexdigest()
    if parsed["verifier_key_id"] != expected_key_id:
        raise ValueError("recheck evidence was signed by an untrusted key")
    if not ed25519.verify(
        public,
        cast(bytes, parsed["signature"]),
        _RECHECK_DOMAIN + cast(bytes, parsed["canonical"]),
    ):
        raise ValueError("invalid recheck evidence signature")


def _reject_json_constant(value: str) -> object:
    raise ValueError("non-finite JSON number is forbidden: %s" % value)


def _strict_json_object(pairs: Sequence[Tuple[str, object]]) -> Dict[str, object]:
    result: Dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key in recheck evidence")
        result[key] = value
    return result


def read_recheck_evidence_file(path: str) -> Dict[str, object]:
    """Read one contained, owned, mode-0600 evidence file without following links."""

    if type(path) is not str or not path or not os.path.isabs(path):
        raise ValueError("recheck evidence path must be absolute")
    absolute = os.path.abspath(path)
    if absolute != path or os.path.normpath(path) != path:
        raise ValueError("recheck evidence path must be canonical")
    if _has_symlink_component(path):
        raise ValueError("recheck evidence path traverses a symlink")
    if not _under(BASE, path) or os.path.realpath(path) == BASE:
        raise ValueError("recheck evidence path must be a file beneath FED_BASE")
    raw = _read_private_regular(path, expected_mode=0o600)
    if not raw or len(raw) > 16384:
        raise ValueError("recheck evidence file size is outside bounds")
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("malformed recheck evidence JSON") from exc
    if type(document) is not dict:
        raise ValueError("recheck evidence JSON must be an object")
    return document


def _read_ndr_seed() -> bytes:
    return _read_private_regular(NDR_KEY, expected_size=32, expected_mode=0o600)


def _emit_ndr(
    c: sqlite3.Connection,
    msg_id: str,
    grant_id: str,
    generation: int,
    reason: str,
    detail: Optional[str],
) -> bool:
    if c.execute("SELECT 1 FROM ndrs WHERE msg_id=?", (msg_id,)).fetchone():
        return False
    seed = _read_ndr_seed()
    canonical = ndr_canonical(msg_id, grant_id, generation, reason, detail)
    signature = ed25519.sign(seed, canonical).hex()
    c.execute(
        "INSERT INTO ndrs(msg_id,grant_id,generation,reason,detail,"
        " signature_hex,issued_at) VALUES (?,?,?,?,?,?,?)",
        (msg_id, grant_id, generation, reason, detail, signature, time.time()),
    )
    return True


def ndr_row(msg_id: str) -> Optional[Dict[str, object]]:
    with authority_lock():
        c = _connect()
        try:
            row = c.execute(
                "SELECT msg_id,grant_id,generation,reason,detail,signature_hex,issued_at"
                " FROM ndrs WHERE msg_id=?",
                (msg_id,),
            ).fetchone()
        finally:
            c.close()
    if not row:
        return None
    keys = (
        "msg_id",
        "grant_id",
        "generation",
        "reason",
        "detail",
        "signature_hex",
        "issued_at",
    )
    return dict(zip(keys, row))


def _maybe_hard_fail(failpoint: Optional[str], boundary: str) -> None:
    if failpoint == boundary:
        os._exit(86)  # intentional process-crash injection


def commit_revoke_batch(
    nonce: str,
    grant_ids: Sequence[str],
    reason: str,
    failpoint: Optional[str] = None,
) -> Dict[str, int]:
    """Atomically consume nonce, revoke all grants, and create local NDRs.

    Failure boundaries are ``after_nonce``, ``after_grant_1..N``,
    ``after_ndr_1..M``, ``before_commit``, and ``after_commit_uncertain``.
    Before-commit process death rolls everything back.  The final boundary
    represents a caller that cannot know whether COMMIT landed.
    """

    gids = list(grant_ids)
    if not gids:
        raise ValueError("empty grant batch")
    if len(set(gids)) != len(gids):
        raise ValueError("duplicate grant IDs in revoke batch")
    with authority_lock("batch"):
        c = _connect()
        try:
            _begin(c)
            if c.execute(
                "SELECT 1 FROM consumed_nonces WHERE nonce=?", (nonce,)
            ).fetchone():
                raise NonceReplay("nonce replay: %s" % nonce)

            # Validate the complete authority set before consuming the nonce or
            # mutating any grant.  A terminal record is immutable: the first
            # tombstone generation, reason, and timestamps remain authoritative.
            rows = []
            for gid in gids:
                row = _grant_row(c, gid)
                if not row:
                    raise ValueError("unknown grant %s" % gid)
                if row[2] == "REVOKED" or row[3] is not None:
                    raise ValueError(
                        "terminal REVOKED grant or existing tombstone in batch: %s"
                        % gid
                    )
                rows.append(row)

            c.execute(
                "INSERT INTO consumed_nonces VALUES (?,?)", (nonce, time.time())
            )
            _maybe_hard_fail(failpoint, "after_nonce")

            for index, (gid, row) in enumerate(zip(gids, rows), 1):
                c.execute(
                    "UPDATE grants SET generation=generation+1,state='REVOKED',"
                    " tombstone_reason=?,updated_at=? WHERE grant_id=?",
                    (reason, time.time(), gid),
                )
                _maybe_hard_fail(failpoint, "after_grant_%d" % index)

            ndr_index = 0
            for gid in gids:
                g = _grant_row(c, gid)
                generation = int(g[1])
                rows = c.execute(
                    "SELECT msg_id FROM ("
                    " SELECT msg_id FROM queued_messages WHERE grant_id=?"
                    " UNION SELECT msg_id FROM held_messages WHERE grant_id=?"
                    ") ORDER BY msg_id",
                    (gid, gid),
                ).fetchall()
                for (msg_id,) in rows:
                    if _emit_ndr(
                        c,
                        msg_id,
                        gid,
                        generation,
                        "rejected_consent",
                        "tombstone: %s" % reason,
                    ):
                        ndr_index += 1
                        _maybe_hard_fail(failpoint, "after_ndr_%d" % ndr_index)
                c.execute("DELETE FROM queued_messages WHERE grant_id=?", (gid,))
                c.execute("DELETE FROM held_messages WHERE grant_id=?", (gid,))

            _maybe_hard_fail(failpoint, "before_commit")
            c.execute("COMMIT")
            _maybe_hard_fail(failpoint, "after_commit_uncertain")
            return {"grants": len(gids), "ndrs": ndr_index, "nonces": 1}
        except Exception:
            _rollback_quiet(c)
            raise
        finally:
            c.close()


def _apply_cap_transition(
    c: sqlite3.Connection, grant_id: str, g: sqlite3.Row
) -> Sequence[str]:
    """CAPPED transition, NDR rows, and live releases in the caller's transaction.

    These are exactly the reviewed ``apply_partition_cap`` statements, shared
    so the in-fence enforcement path cannot drift from the transactional API.
    The caller holds the authority lock and an open ``BEGIN IMMEDIATE``.
    """

    cap_generation = int(g[1]) + 1
    c.execute(
        "UPDATE grants SET generation=generation+1,state='CAPPED',updated_at=?"
        " WHERE grant_id=?",
        (time.time(), grant_id),
    )
    _advance_live_generation(c, grant_id, int(g[1]), cap_generation)
    rows = c.execute(
        "SELECT msg_id FROM ("
        " SELECT msg_id FROM queued_messages WHERE grant_id=?"
        " UNION SELECT msg_id FROM held_messages WHERE grant_id=?"
        ") ORDER BY msg_id",
        (grant_id, grant_id),
    ).fetchall()
    resolved = []
    for (msg_id,) in rows:
        if _emit_ndr(
            c,
            msg_id,
            grant_id,
            cap_generation,
            "partition_cap",
            "partition cap executed",
        ):
            resolved.append(msg_id)
        # An NDR-resolved message is terminal, not a suspended retry.
        # Complete its live reservation in this same cap transaction.
        released = c.execute(
            "UPDATE reservations SET state='released',last_error='partition_cap',"
            " updated_at=? WHERE grant_id=? AND msg_id=? AND generation=?"
            " AND state IN (?,?,?,?)",
            (time.time(), grant_id, msg_id, cap_generation, *_LIVE_RESERVATION_STATES),
        )
        if released.rowcount:
            c.execute(
                "UPDATE outbox SET generation=?,state='released',detail='partition_cap',"
                " updated_at=? WHERE grant_id=? AND msg_id=? AND generation IN (?,?)"
                " AND state IN (?,?,?,?,?)",
                (cap_generation, time.time(), grant_id, msg_id, int(g[1]),
                 cap_generation, *_LIVE_RESERVATION_STATES, "held"),
            )
    c.execute("DELETE FROM queued_messages WHERE grant_id=?", (grant_id,))
    c.execute("DELETE FROM held_messages WHERE grant_id=?", (grant_id,))
    return resolved


def _enforce_cap_in_transaction(
    c: sqlite3.Connection, grant_id: str, g: Optional[sqlite3.Row] = None
) -> Optional[sqlite3.Row]:
    """Fresh trusted-clock cap evaluation at a serialized decision boundary.

    When a finite cap is configured, the trusted clock is sampled inside this
    transaction's authority lock.  A grant that crossed its configured expiry
    during ordinary serialization is transitioned CAPPED atomically with the
    caller's fence outcome, preserving the reviewed generation/NDR/hold/replay
    semantics.  Returns the current grant row.
    """

    if g is None:
        g = _grant_row(c, grant_id)
    if _PARTITION_CAP_S is None or not g or g[2] in ("CAPPED", "REVOKED") or g[3] is not None:
        return g
    trusted_now = time.time()  # trusted sample inside the authority lock
    if trusted_now - _finite_number(g[4], "stored last_recheck_verified_at") < _PARTITION_CAP_S:
        return g
    _apply_cap_transition(c, grant_id, g)
    return _grant_row(c, grant_id)


def apply_partition_cap(
    grant_id: str,
    now: Optional[float],
    threshold_s: float,
    failpoint: Optional[str] = None,
) -> Tuple[str, Sequence[str]]:
    """Apply the CAPPED transition and local NDR rows in one transaction.

    A ``now`` of ``None`` samples the trusted clock inside the authority
    lock, so the evaluation cannot straddle the lock acquisition window.
    """

    trusted_now = None if now is None else _finite_number(now, "now")
    threshold = _finite_number(threshold_s, "threshold_s", positive=True)
    with authority_lock(grant_id):
        c = _connect()
        try:
            _begin(c)
            if trusted_now is None:
                trusted_now = time.time()  # trusted sample inside the lock
            g = _grant_row(c, grant_id)
            if not g:
                raise ValueError("unknown grant %s" % grant_id)
            if g[2] == "REVOKED" or g[3] is not None:
                raise ValueError("terminal REVOKED tombstone cannot be capped or reopened")
            if g[2] == "CAPPED":
                c.execute("ROLLBACK")
                return ("capped", [])
            watermark = _finite_number(g[4], "stored last_recheck_verified_at")
            if trusted_now - watermark < threshold:
                c.execute("ROLLBACK")
                return ("not_due", [])
            resolved = _apply_cap_transition(c, grant_id, g)
            c.execute("COMMIT")
            _maybe_hard_fail(failpoint, "after_cap_commit")
            return ("capped", resolved)
        except Exception:
            _rollback_quiet(c)
            raise
        finally:
            c.close()


def verified_recheck(evidence: Dict[str, object]) -> int:
    """Verify, consume, and apply one authenticated successful recheck.

    The exact evidence object is domain-separated canonical JSON signed by the
    runtime-pinned synthetic verifier.  Signature verification, replay
    consumption, grant checks, reopen, and live reservation/outbox generation
    rebinding all occur inside one ``BEGIN IMMEDIATE`` transaction.  Terminal
    ``sent`` and ``released`` reservations are never rewritten.
    """

    parsed = _parse_recheck_evidence(evidence)
    grant_id = cast(str, parsed["grant_id"])
    expected_generation = cast(int, parsed["expected_generation"])
    prior_state = cast(str, parsed["prior_state"])
    watermark = cast(float, parsed["verified_at"])
    with authority_lock(grant_id):
        c = _connect()
        try:
            _begin(c)
            # This cryptographic verification is deliberately inside the same
            # authority transaction that consumes the unique evidence id.
            _verify_recheck_signature(parsed)
            if c.execute(
                "SELECT 1 FROM consumed_recheck_evidence WHERE evidence_id=?",
                (parsed["evidence_id"],),
            ).fetchone():
                raise ValueError("recheck evidence replay: %s" % parsed["evidence_id"])

            g = _grant_row(c, grant_id)
            if not g:
                raise ValueError("unknown grant %s" % grant_id)
            if int(g[1]) != expected_generation:
                raise ValueError(
                    "generation changed: expected %d got %d"
                    % (expected_generation, int(g[1]))
                )
            if g[2] == "REVOKED" or g[3] is not None:
                raise ValueError("terminal REVOKED tombstone cannot be reopened")
            if g[2] != prior_state:
                raise ValueError(
                    "recheck prior_state mismatch: evidence %s authority %s"
                    % (prior_state, g[2])
                )
            if g[2] not in ("CAPPED", "SUSPECT"):
                raise ValueError(
                    "verified recheck may reopen only CAPPED or SUSPECT, got %s" % g[2]
                )
            previous_watermark = _finite_number(
                g[4], "stored last_recheck_verified_at"
            )
            if watermark <= previous_watermark:
                raise ValueError(
                    "verified_at must advance watermark: %.9f <= %.9f"
                    % (watermark, previous_watermark)
                )

            new_generation = expected_generation + 1
            consumed_at = time.time()
            c.execute(
                "INSERT INTO consumed_recheck_evidence("
                " evidence_id,verifier_key_id,grant_id,expected_generation,consumed_at)"
                " VALUES (?,?,?,?,?)",
                (
                    parsed["evidence_id"],
                    parsed["verifier_key_id"],
                    grant_id,
                    expected_generation,
                    consumed_at,
                ),
            )
            changed = c.execute(
                "UPDATE grants SET generation=?,state='OK',tombstone_reason=NULL,"
                " last_recheck_verified_at=?,updated_at=? WHERE grant_id=?"
                " AND generation=? AND state=? AND tombstone_reason IS NULL",
                (
                    new_generation,
                    watermark,
                    consumed_at,
                    grant_id,
                    expected_generation,
                    prior_state,
                ),
            )
            if changed.rowcount != 1:
                raise ValueError("grant changed during verified recheck")

            _advance_live_generation(c, grant_id, expected_generation, new_generation)
            c.execute("COMMIT")
            return new_generation
        except Exception:
            _rollback_quiet(c)
            raise
        finally:
            c.close()


def count_rows(table: str, where: str = "", params: Sequence[object] = ()) -> int:
    allowed = {
        "grants",
        "queued_messages",
        "held_messages",
        "ndrs",
        "consumed_nonces",
        "consumed_recheck_evidence",
        "outbox",
        "reservations",
    }
    if table not in allowed:
        raise ValueError("unsupported table")
    sql = "SELECT COUNT(*) FROM " + table
    if where:
        sql += " WHERE " + where
    with authority_lock():
        c = _connect()
        try:
            return int(c.execute(sql, tuple(params)).fetchone()[0])
        finally:
            c.close()
