"""Heimdall web dashboard: live activity, approval queue, claim checks, chain integrity."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ..config import HeimdallConfig
from ..gateway import Gateway

STATIC = Path(__file__).parent / "static"


class ApprovalBody(BaseModel):
    approve: bool
    reviewer: str = "dashboard"
    note: str = ""


class StatusBody(BaseModel):
    status: str
    reason: str = ""
    by: str = "dashboard"


class ClaimBody(BaseModel):
    session_id: str
    claim: str
    agent: str = "unknown"


def actions_from_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge attempt/decision/approval/result events into one record per tool call."""
    actions: dict[str, dict[str, Any]] = {}
    for e in events:
        aid = e.get("action_id")
        if not aid:
            continue
        p = e["payload"] if isinstance(e["payload"], dict) else {}
        a = actions.setdefault(aid, {"action_id": aid, "session_id": e["session_id"], "agent": e["agent"],
                                     "seq": e["seq"], "ts": e["ts"], "status": "pending"})
        t = e["event_type"]
        if t == "attempt":
            a.update(tool=p.get("tool"), arguments=p.get("arguments"), purpose=p.get("purpose"),
                     target=p.get("target"), category=p.get("category"))
        elif t == "decision":
            a.update(decision=p.get("decision"), reasons=p.get("reasons", []), risk=p.get("risk"),
                     matched_rules=p.get("matched_rules", []), restrictions=p.get("restrictions"),
                     findings=p.get("findings") or [])
        elif t == "approval_requested":
            a["status"] = "awaiting approval"
        elif t == "approval_decision":
            a["approval"] = {"status": p.get("status"), "reviewer": p.get("reviewer"), "note": p.get("note")}
        elif t == "result":
            a.update(status=p.get("status"), message=p.get("message"), result_preview=p.get("result_preview"),
                     duration_ms=p.get("duration_ms"), redactions=p.get("redactions"), finished_ts=e["ts"],
                     after_findings=p.get("after_findings") or [])
    return sorted(actions.values(), key=lambda a: a["seq"])


def create_app(config: HeimdallConfig, gateway: Gateway | None = None) -> FastAPI:
    gw = gateway or Gateway(config)
    app = FastAPI(title="Heimdall", docs_url="/api/docs")
    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC / "index.html")

    @app.get("/api/sessions")
    def sessions() -> list[dict[str, Any]]:
        controls = {r["session_id"]: r for r in gw.sessions.list()}
        out = []
        for s in gw.audit.sessions():
            c = controls.get(s["session_id"], {})
            out.append({**s, "status": c.get("status", "active"), "status_reason": c.get("status_reason"),
                        "screen_active": c.get("screen_active", False),
                        "screen_granted_until": c.get("screen_granted_until", 0), "state": c.get("state", {}),
                        "controllable": bool(c)})
        return out

    @app.post("/api/sessions/{session_id}/status")
    def set_status(session_id: str, body: StatusBody) -> dict[str, Any]:
        try:
            gw.set_session_status(session_id, body.status, body.reason, body.by)
        except KeyError as exc:
            raise HTTPException(404, f"unknown session {exc}") from exc
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        return gw.sessions.get(session_id) or {}

    @app.post("/api/sessions/{session_id}/revoke-screen")
    def revoke_screen(session_id: str) -> dict[str, Any]:
        try:
            gw.revoke_screen(session_id, by="dashboard")
        except KeyError as exc:
            raise HTTPException(404, f"unknown session {exc}") from exc
        return gw.sessions.get(session_id) or {}

    @app.get("/api/alerts")
    def alerts(session: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        evs = gw.audit.events(session_id=session or None, event_types=["alert"], limit=1000000)
        return [{"seq": e["seq"], "ts": e["ts"], "session_id": e["session_id"], "agent": e["agent"],
                 "action_id": e["action_id"], **e["payload"]} for e in reversed(evs[-limit:])]

    @app.get("/api/screen")
    def screen() -> dict[str, Any]:
        """Who is controlling the screen right now, and every screen action recently."""
        active = [r for r in gw.sessions.list() if r["screen_active"]]
        evs = gw.audit.events(event_types=["attempt", "result", "screen_control_started", "screen_control_stopped"],
                              limit=1000000)
        timeline, pending = [], {}
        for e in evs:
            p = e["payload"]
            if e["event_type"] == "attempt" and p.get("category") == "screen":
                pending[e["action_id"]] = {"ts": e["ts"], "session_id": e["session_id"], "agent": e["agent"],
                                           "tool": p.get("tool"), "arguments": gw.redactor.any(p.get("arguments"))[0],
                                           "purpose": p.get("purpose"), "status": "pending"}
                timeline.append(pending[e["action_id"]])
            elif e["event_type"] == "result" and e["action_id"] in pending:
                pending[e["action_id"]]["status"] = p.get("status")
            elif e["event_type"].startswith("screen_control"):
                timeline.append({"ts": e["ts"], "session_id": e["session_id"], "agent": e["agent"],
                                 "event": e["event_type"], "detail": p.get("reason") or p.get("purpose")})
        return {"active": active, "timeline": list(reversed(timeline[-80:]))}

    @app.get("/api/tools")
    def tools() -> list[dict[str, Any]]:
        return gw.tools.list()

    @app.post("/api/tools/{tool}/trust")
    def trust_tool(tool: str) -> dict[str, Any]:
        try:
            gw.tools.trust(tool)
        except KeyError as exc:
            raise HTTPException(404, f"unknown tool {exc}") from exc
        gw.audit.append("tool_trusted", {"tool": tool, "by": "dashboard"})
        return {"tool": tool, "status": "trusted"}

    @app.get("/api/actions")
    def actions(session: str | None = None, limit: int = 300) -> list[dict[str, Any]]:
        events = gw.audit.events(session_id=session or None, limit=200000)
        return actions_from_events(events)[-limit:]

    @app.get("/api/overview")
    def overview(session: str | None = None) -> dict[str, Any]:
        acts = actions(session)
        count = lambda pred: sum(1 for a in acts if pred(a))  # noqa: E731
        reports = gw.audit.events(session_id=session or None, event_types=["deception_report"], limit=100000)
        alert_evs = gw.audit.events(session_id=session or None, event_types=["alert"], limit=1000000)
        ctrl = gw.sessions.list()
        v = gw.audit.verify()
        return {
            "actions": len(acts),
            "allowed": count(lambda a: a.get("status") == "succeeded"),
            "blocked": count(lambda a: a.get("status") in ("blocked", "denied")),
            "restricted": count(lambda a: a.get("decision") == "restrict"),
            "pending": len(gw.approvals.list("pending")),
            "deceptive_reports": sum(1 for r in reports if r["payload"].get("verdict") == "deceptive"),
            "critical_alerts": sum(1 for a in alert_evs if a["payload"].get("severity") == "critical"),
            "quarantined": sum(1 for r in ctrl if r["status"] == "quarantined"),
            "tools_to_review": sum(1 for t in gw.tools.list() if t["status"] != "trusted"),
            "chain": {"ok": v.ok, "entries": v.entries, "head": v.head, "keyed": v.keyed,
                      "problems": v.problems[:20]},
        }

    @app.get("/api/approvals")
    def approvals(status: str = "pending") -> list[dict[str, Any]]:
        return gw.approvals.list(status or None)

    @app.post("/api/approvals/{action_id}")
    def decide(action_id: str, body: ApprovalBody) -> dict[str, Any]:
        try:
            return gw.approvals.decide(action_id, body.approve, body.reviewer, body.note)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.get("/api/reports")
    def reports(session: str | None = None) -> list[dict[str, Any]]:
        evs = gw.audit.events(session_id=session or None, event_types=["claim", "deception_report"], limit=100000)
        out, last_claim = [], {}
        for e in evs:
            if e["event_type"] == "claim":
                last_claim[e["session_id"]] = e["payload"].get("claim")
            else:
                out.append({"seq": e["seq"], "ts": e["ts"], "session_id": e["session_id"], "agent": e["agent"],
                            "claim": last_claim.get(e["session_id"]), **e["payload"]})
        return list(reversed(out))

    @app.post("/api/claims")
    def check_claim(body: ClaimBody) -> dict[str, Any]:
        return gw.audit_claim(body.session_id, body.claim, body.agent)

    @app.get("/api/verify")
    def verify(expected_head: str | None = None) -> dict[str, Any]:
        return gw.audit.verify(expected_head).to_dict()

    @app.get("/api/policy")
    def policy() -> dict[str, Any]:
        c = config
        return {
            "thresholds": {"approve": c.approve_threshold, "block": c.block_threshold},
            "agents": {n: {"description": a.description, "allow": a.allow_tools, "deny": a.deny_tools}
                       for n, a in c.agents.items()},
            "rules": [{"name": r.name, "decision": r.decision.value, "description": r.description, "tools": r.tools}
                      for r in c.rules],
        }

    return app
