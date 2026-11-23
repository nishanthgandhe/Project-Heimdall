"""Human-in-the-loop approval queue.

Pending approvals live in the same SQLite file as the audit log, so the proxy
(which waits) and the dashboard (where a person clicks approve/deny) can run as
separate processes.
"""

from __future__ import annotations

import json
import time
from typing import Any

import anyio

from .audit import AuditLog
from .models import ActionRequest, PolicyResult


class ApprovalQueue:
    def __init__(self, audit: AuditLog):
        self.audit = audit

    def create(self, req: ActionRequest, policy: PolicyResult) -> None:
        with self.audit.connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO approvals (action_id, created_ts, session_id, agent, tool, request, policy, status)"
                " VALUES (?,?,?,?,?,?,?, 'pending')",
                (
                    req.action_id,
                    time.time(),
                    req.session_id,
                    req.agent,
                    req.tool,
                    json.dumps({"arguments": req.arguments, "purpose": req.purpose, "target": req.target}, default=str),
                    json.dumps(policy.to_dict()),
                ),
            )

    def get(self, action_id: str) -> dict[str, Any] | None:
        with self.audit.connect() as conn:
            row = conn.execute("SELECT * FROM approvals WHERE action_id = ?", (action_id,)).fetchone()
        return self._row(row) if row else None

    def list(self, status: str | None = "pending", limit: int = 200) -> list[dict[str, Any]]:
        sql, params = "SELECT * FROM approvals", []
        if status:
            sql += " WHERE status = ?"
            params.append(status)
        sql += " ORDER BY created_ts DESC LIMIT ?"
        params.append(limit)
        with self.audit.connect() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def decide(self, action_id: str, approve: bool, reviewer: str = "reviewer", note: str = "") -> dict[str, Any]:
        status = "approved" if approve else "denied"
        with self.audit.connect() as conn:
            cur = conn.execute(
                "UPDATE approvals SET status = ?, reviewer = ?, note = ?, decided_ts = ?"
                " WHERE action_id = ? AND status = 'pending'",
                (status, reviewer, note, time.time(), action_id),
            )
            if cur.rowcount == 0:
                existing = self.get(action_id)
                if existing is None:
                    raise KeyError(f"no approval request {action_id}")
                raise ValueError(f"approval {action_id} already {existing['status']}")
        item = self.get(action_id)
        assert item is not None
        self.audit.append(
            "approval_decision",
            {"tool": item["tool"], "status": status, "reviewer": reviewer, "note": note},
            session_id=item["session_id"], agent=item["agent"], action_id=action_id,
        )
        return item

    def expire(self, action_id: str) -> bool:
        with self.audit.connect() as conn:
            cur = conn.execute(
                "UPDATE approvals SET status = 'expired', decided_ts = ? WHERE action_id = ? AND status = 'pending'",
                (time.time(), action_id),
            )
        return cur.rowcount > 0

    async def wait(self, action_id: str, timeout: float, poll: float = 0.5) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            item = self.get(action_id)
            if item and item["status"] != "pending":
                return item
            await anyio.sleep(poll)
        self.expire(action_id)
        item = self.get(action_id)
        assert item is not None
        return item

    @staticmethod
    def _row(row: Any) -> dict[str, Any]:
        d = dict(row)
        for k in ("request", "policy"):
            try:
                d[k] = json.loads(d[k])
            except (TypeError, json.JSONDecodeError):
                pass
        return d
