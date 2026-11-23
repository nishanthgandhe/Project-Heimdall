"""Tamper-evident audit log.

Every event is appended to a SQLite table where each row stores the hash of
the row before it. Changing, deleting or reordering any past row breaks the
chain, and `verify()` reports exactly where.

If HEIMDALL_AUDIT_KEY is set, hashes are HMAC-SHA256 with that key, so someone
who can write to the database file but does not hold the key cannot rebuild a
valid chain after editing it. Without a key, plain SHA-256 is used: edits are
still detected unless the attacker recomputes every later hash.

Tail truncation (deleting the newest rows) can only be detected by comparing
against a head hash recorded elsewhere -- see `head()` and
`verify(expected_head=...)`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

GENESIS = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    seq        INTEGER PRIMARY KEY,
    ts         REAL    NOT NULL,
    session_id TEXT    NOT NULL,
    agent      TEXT    NOT NULL,
    event_type TEXT    NOT NULL,
    action_id  TEXT,
    payload    TEXT    NOT NULL,
    prev_hash  TEXT    NOT NULL,
    hash       TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_log(session_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action_id);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approvals (
    action_id   TEXT PRIMARY KEY,
    created_ts  REAL NOT NULL,
    session_id  TEXT NOT NULL,
    agent       TEXT NOT NULL,
    tool        TEXT NOT NULL,
    request     TEXT NOT NULL,
    policy      TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending',
    reviewer    TEXT,
    note        TEXT,
    decided_ts  REAL
);
"""


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


@dataclass
class VerifyReport:
    ok: bool
    entries: int
    head: str
    problems: list[dict[str, Any]]
    keyed: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "entries": self.entries,
            "head": self.head,
            "problems": self.problems,
            "keyed": self.keyed,
        }


class AuditLog:
    def __init__(self, db_path: str | Path, key: str | bytes | None = None):
        self.db_path = str(db_path)
        if key is None:
            key = os.environ.get("HEIMDALL_AUDIT_KEY")
        self._key = key.encode() if isinstance(key, str) else key
        self._lock = threading.Lock()
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.executescript(SCHEMA)
            conn.execute("INSERT OR IGNORE INTO meta (key, value) VALUES ('key_check', ?)", (self._key_check(),))
            stored = conn.execute("SELECT value FROM meta WHERE key = 'key_check'").fetchone()["value"]
        self.key_mismatch = stored != self._key_check()

    def _key_check(self) -> str:
        if not self._key:
            return "unkeyed"
        return hmac.new(self._key, b"heimdall-key-check", hashlib.sha256).hexdigest()[:16]

    def _key_mismatch_message(self) -> str:
        return ("this audit log was written with a different HEIMDALL_AUDIT_KEY (or with/without one); "
                "set the same key that was used to create it")

    @property
    def keyed(self) -> bool:
        return bool(self._key)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        try:
            yield conn
        finally:
            conn.close()

    # ------------------------------------------------------------------ hashing
    def _hash(self, prev_hash: str, record: dict[str, Any]) -> str:
        msg = (prev_hash + _canonical(record)).encode()
        if self._key:
            return hmac.new(self._key, msg, hashlib.sha256).hexdigest()
        return hashlib.sha256(msg).hexdigest()

    @staticmethod
    def _record(seq: int, ts: float, session_id: str, agent: str, event_type: str,
                action_id: str | None, payload: str) -> dict[str, Any]:
        return {
            "seq": seq,
            "ts": ts,
            "session_id": session_id,
            "agent": agent,
            "event_type": event_type,
            "action_id": action_id,
            "payload": payload,
        }

    # ------------------------------------------------------------------ writing
    def append(self, event_type: str, payload: dict[str, Any], *, session_id: str = "default",
               agent: str = "heimdall", action_id: str | None = None) -> dict[str, Any]:
        """Append one event. Safe across threads and processes (BEGIN IMMEDIATE)."""
        if self.key_mismatch:
            raise RuntimeError("refusing to append: " + self._key_mismatch_message())
        payload_s = _canonical(payload)
        with self._lock, self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
                seq = (row["seq"] + 1) if row else 1
                prev = row["hash"] if row else GENESIS
                ts = time.time()
                rec = self._record(seq, ts, session_id, agent, event_type, action_id, payload_s)
                h = self._hash(prev, rec)
                conn.execute(
                    "INSERT INTO audit_log (seq, ts, session_id, agent, event_type, action_id, payload, prev_hash, hash)"
                    " VALUES (?,?,?,?,?,?,?,?,?)",
                    (seq, ts, session_id, agent, event_type, action_id, payload_s, prev, h),
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        return {**rec, "payload": payload, "prev_hash": prev, "hash": h}

    # ------------------------------------------------------------------ reading
    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        try:
            d["payload"] = json.loads(d["payload"])
        except (TypeError, json.JSONDecodeError):
            pass
        return d

    def events(self, *, session_id: str | None = None, action_id: str | None = None,
               event_types: list[str] | None = None, since_seq: int = 0, limit: int = 1000) -> list[dict[str, Any]]:
        sql = "SELECT * FROM audit_log WHERE seq > ?"
        params: list[Any] = [since_seq]
        if session_id:
            sql += " AND session_id = ?"
            params.append(session_id)
        if action_id:
            sql += " AND action_id = ?"
            params.append(action_id)
        if event_types:
            sql += f" AND event_type IN ({','.join('?' * len(event_types))})"
            params.extend(event_types)
        sql += " ORDER BY seq ASC LIMIT ?"
        params.append(limit)
        with self.connect() as conn:
            return [self._row_to_dict(r) for r in conn.execute(sql, params).fetchall()]

    def sessions(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT session_id, agent, MIN(ts) AS started, MAX(ts) AS last, COUNT(*) AS events"
                " FROM audit_log GROUP BY session_id, agent ORDER BY last DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def last_seq(self) -> int:
        with self.connect() as conn:
            row = conn.execute("SELECT MAX(seq) AS m FROM audit_log").fetchone()
        return row["m"] or 0

    def head(self) -> str:
        with self.connect() as conn:
            row = conn.execute("SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        return row["hash"] if row else GENESIS

    # ------------------------------------------------------------------ verify
    def verify(self, expected_head: str | None = None) -> VerifyReport:
        if self.key_mismatch:
            return VerifyReport(ok=False, entries=self.last_seq(), head=self.head(),
                                problems=[{"seq": None, "problem": self._key_mismatch_message()}], keyed=self.keyed)
        problems: list[dict[str, Any]] = []
        prev = GENESIS
        expected_seq = 1
        count = 0
        with self.connect() as conn:
            for row in conn.execute("SELECT * FROM audit_log ORDER BY seq ASC"):
                count += 1
                seq = row["seq"]
                if seq != expected_seq:
                    problems.append({"seq": seq, "problem": f"gap in sequence: expected {expected_seq}, found {seq} (rows deleted?)"})
                if row["prev_hash"] != prev:
                    problems.append({"seq": seq, "problem": "prev_hash does not match previous entry (chain broken)"})
                rec = self._record(seq, row["ts"], row["session_id"], row["agent"], row["event_type"],
                                   row["action_id"], row["payload"])
                if self._hash(row["prev_hash"], rec) != row["hash"]:
                    problems.append({"seq": seq, "problem": "entry contents do not match its hash (entry modified)"})
                prev = row["hash"]
                expected_seq = seq + 1
        if expected_head and expected_head != prev:
            problems.append({"seq": None, "problem": "head hash differs from the expected anchor (log truncated or rewritten)"})
        return VerifyReport(ok=not problems, entries=count, head=prev, problems=problems, keyed=self.keyed)
