"""Per-session state: what an agent has done so far, and controls a person can flip.

Some of this lives only in the proxy's memory (fingerprints of sensitive data
the agent has seen). The parts a person needs to see or change -- status
(active / paused / quarantined), taint, screen-control grant -- are stored in
the shared SQLite file, so the dashboard can show them and change them while
the agent is running.
"""

from __future__ import annotations

import json
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from .audit import AuditLog

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id           TEXT PRIMARY KEY,
    agent                TEXT NOT NULL,
    status               TEXT NOT NULL DEFAULT 'active',
    status_reason        TEXT,
    screen_granted_until REAL NOT NULL DEFAULT 0,
    created_ts           REAL NOT NULL,
    updated_ts           REAL NOT NULL,
    state                TEXT NOT NULL DEFAULT '{}'
);
"""

STATUSES = ("active", "paused", "quarantined")


@dataclass
class SessionState:
    session_id: str = "default"
    agent: str = "unknown"
    # behaviour so far
    action_times: deque = field(default_factory=lambda: deque(maxlen=500))
    action_count: int = 0
    blocked_count: int = 0
    outbound_count: int = 0
    result_bytes: int = 0
    blocked_targets: list[str] = field(default_factory=list)
    # what the agent has been exposed to
    tainted: bool = False
    taint_reasons: list[str] = field(default_factory=list)
    fingerprints: dict[str, str] = field(default_factory=dict)  # sha256(value) -> "SSN from db.query"
    decoy_touched: bool = False
    # controls (mirrored from the database)
    status: str = "active"
    status_reason: str = ""
    screen_granted_until: float = 0.0
    screen_started: float | None = None
    screen_last: float | None = None
    screen_actions: int = 0

    def actions_last_minute(self, now: float | None = None) -> int:
        now = now or time.time()
        return sum(1 for t in self.action_times if now - t <= 60)

    @property
    def screen_active(self) -> bool:
        return self.screen_granted_until > time.time()

    def taint(self, reason: str) -> None:
        self.tainted = True
        if reason not in self.taint_reasons:
            self.taint_reasons.append(reason)

    def public(self) -> dict[str, Any]:
        """What gets stored for the dashboard (never the fingerprints themselves)."""
        return {
            "action_count": self.action_count,
            "blocked_count": self.blocked_count,
            "outbound_count": self.outbound_count,
            "result_bytes": self.result_bytes,
            "tainted": self.tainted,
            "taint_reasons": self.taint_reasons[-10:],
            "sensitive_values_seen": len(self.fingerprints),
            "decoy_touched": self.decoy_touched,
            "screen_started": self.screen_started,
            "screen_last": self.screen_last,
            "screen_actions": self.screen_actions,
        }


class SessionStore:
    def __init__(self, audit: AuditLog):
        self.audit = audit
        with audit.connect() as conn:
            conn.executescript(SCHEMA)

    def ensure(self, session_id: str, agent: str) -> None:
        now = time.time()
        with self.audit.connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO sessions (session_id, agent, created_ts, updated_ts) VALUES (?,?,?,?)",
                (session_id, agent, now, now),
            )

    def sync(self, state: SessionState) -> None:
        """Pull the person-controlled fields into the in-memory state."""
        self.ensure(state.session_id, state.agent)
        with self.audit.connect() as conn:
            row = conn.execute("SELECT status, status_reason, screen_granted_until FROM sessions WHERE session_id = ?",
                               (state.session_id,)).fetchone()
        state.status = row["status"]
        state.status_reason = row["status_reason"] or ""
        state.screen_granted_until = row["screen_granted_until"] or 0.0

    def save(self, state: SessionState) -> None:
        with self.audit.connect() as conn:
            conn.execute("UPDATE sessions SET state = ?, updated_ts = ? WHERE session_id = ?",
                         (json.dumps(state.public()), time.time(), state.session_id))

    def set_status(self, session_id: str, status: str, reason: str = "") -> None:
        if status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")
        with self.audit.connect() as conn:
            cur = conn.execute("UPDATE sessions SET status = ?, status_reason = ?, updated_ts = ? WHERE session_id = ?",
                               (status, reason, time.time(), session_id))
            if cur.rowcount == 0:
                raise KeyError(session_id)

    def set_screen_grant(self, session_id: str, until: float) -> None:
        with self.audit.connect() as conn:
            conn.execute("UPDATE sessions SET screen_granted_until = ?, updated_ts = ? WHERE session_id = ?",
                         (until, time.time(), session_id))

    def get(self, session_id: str) -> dict[str, Any] | None:
        with self.audit.connect() as conn:
            row = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
        return self._row(row) if row else None

    def list(self) -> list[dict[str, Any]]:
        with self.audit.connect() as conn:
            rows = conn.execute("SELECT * FROM sessions ORDER BY updated_ts DESC").fetchall()
        return [self._row(r) for r in rows]

    @staticmethod
    def _row(row: Any) -> dict[str, Any]:
        d = dict(row)
        try:
            d["state"] = json.loads(d["state"] or "{}")
        except json.JSONDecodeError:
            d["state"] = {}
        d["screen_active"] = (d.get("screen_granted_until") or 0) > time.time()
        return d
