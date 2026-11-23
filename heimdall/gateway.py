"""The Heimdall gateway: every tool call goes through `Gateway.execute`.

Flow for one action (numbers match the architecture slide):
    1. receive request (tool, arguments, stated purpose)
    2. permission check          } PolicyEngine.evaluate (+ guards)
    3. risk assignment           }
    4. action control: allow / restrict / require approval / block
    5. pre-log the attempt BEFORE anything runs
    6. record the actual result returned by the tool (+ after-guards: injection, data flow)
    7. deception audit later compares the agent's claims against 5 + 6
"""

from __future__ import annotations

import functools
import inspect
import json
import threading
import time
import urllib.request
from typing import Any, Awaitable, Callable, Protocol

import anyio

from .approvals import ApprovalQueue
from .audit import AuditLog
from .config import HeimdallConfig
from .deception import analyze, observed_from_events
from .guards import ToolRegistry
from .models import (ActionOutcome, ActionRequest, ActionStatus, Category, Decision, Finding, PolicyResult,
                     Severity)
from .policy import PolicyEngine, categorize
from .redact import Redactor, truncate
from .sessions import SessionState, SessionStore

Approver = Callable[[ActionRequest, PolicyResult], "bool | Awaitable[bool]"]
Executor = Callable[[dict[str, Any]], Any]

PREVIEW_CHARS = 1500


class ResultAdapter(Protocol):
    def to_text(self, result: Any) -> str: ...
    def map_text(self, result: Any, fn: Callable[[str], str]) -> Any: ...
    def prepend(self, result: Any, text: str) -> Any: ...
    def is_error(self, result: Any) -> bool: ...


class PlainAdapter:
    """Adapter for ordinary Python return values (str, dict, list, numbers)."""

    def to_text(self, result: Any) -> str:
        return result if isinstance(result, str) else repr(result)

    def map_text(self, result: Any, fn: Callable[[str], str]) -> Any:
        if isinstance(result, str):
            return fn(result)
        if isinstance(result, list):
            return [self.map_text(r, fn) for r in result]
        if isinstance(result, dict):
            return {k: self.map_text(v, fn) for k, v in result.items()}
        return result

    def prepend(self, result: Any, text: str) -> Any:
        return text + result if isinstance(result, str) else {"heimdall_warning": text, "result": result}

    def is_error(self, result: Any) -> bool:
        return False


class ActionBlocked(Exception):
    def __init__(self, outcome: ActionOutcome):
        super().__init__(outcome.message)
        self.outcome = outcome


class Gateway:
    def __init__(self, config: HeimdallConfig, audit: AuditLog | None = None, approver: Approver | None = None):
        self.config = config
        self.audit = audit or AuditLog(config.database)
        self.sessions = SessionStore(self.audit)
        self.tools = ToolRegistry(self.audit)
        self.policy = PolicyEngine(config, self.tools)
        self.approvals = ApprovalQueue(self.audit)
        self.redactor = Redactor(config.redact_patterns)
        self.approver = approver
        self._states: dict[str, SessionState] = {}
        guards_cfg = config.raw.get("guards") or {}
        self.quarantine_after = int(guards_cfg.get("quarantine_after_blocks", 8) or 0)
        self.screen_minutes = float((guards_cfg.get("screen") or {}).get("grant_minutes", 10))
        self.webhook = ((config.raw.get("alerts") or {}).get("webhook_url") or "").strip()

    # ------------------------------------------------------------------ session state
    def state(self, session_id: str, agent: str) -> SessionState:
        st = self._states.get(session_id)
        if st is None:
            st = self._states[session_id] = SessionState(session_id, agent)
        self.sessions.sync(st)
        # A screen grant that ran out (or was revoked on the dashboard) ends screen control.
        if st.screen_started and not st.screen_active:
            self.audit.append("screen_control_stopped", {"reason": "expired or revoked", "actions": st.screen_actions},
                              session_id=session_id, agent=agent)
            st.screen_started = None
        return st

    def _log(self, event_type: str, req: ActionRequest, payload: dict[str, Any]) -> None:
        self.audit.append(event_type, payload, session_id=req.session_id, agent=req.agent, action_id=req.action_id)

    # ------------------------------------------------------------------ alerts
    def alert(self, severity: Severity | str, guard: str, message: str, *, session_id: str, agent: str,
              action_id: str | None = None, tool: str | None = None) -> None:
        severity = Severity(severity)
        payload = {"severity": severity.value, "guard": guard, "message": message, "tool": tool}
        self.audit.append("alert", payload, session_id=session_id, agent=agent, action_id=action_id)
        if self.webhook and severity != Severity.INFO:
            threading.Thread(target=self._post_webhook, args=(payload, session_id, agent), daemon=True).start()

    def _post_webhook(self, payload: dict[str, Any], session_id: str, agent: str) -> None:
        text = f"[Heimdall {payload['severity']}] {agent} ({session_id}): {payload['message']}"
        body = json.dumps({"text": text, "content": text, **payload, "session_id": session_id, "agent": agent}).encode()
        try:
            urllib.request.urlopen(urllib.request.Request(self.webhook, body, {"Content-Type": "application/json"}),
                                   timeout=4)
        except Exception:  # alerts are best effort; the audit log is the record
            pass

    def _raise_alerts(self, req: ActionRequest, findings: list[Finding]) -> None:
        for f in findings:
            if f.severity != Severity.INFO:
                self.alert(f.severity, f.guard, f.reason, session_id=req.session_id, agent=req.agent,
                           action_id=req.action_id, tool=req.tool)

    def quarantine(self, req: ActionRequest, st: SessionState, reason: str) -> None:
        self.sessions.set_status(req.session_id, "quarantined", reason)
        st.status, st.status_reason = "quarantined", reason
        self._log("session_quarantined", req, {"reason": reason})
        self.alert(Severity.CRITICAL, "kill_switch", f"session quarantined: {reason}", session_id=req.session_id,
                   agent=req.agent, action_id=req.action_id, tool=req.tool)

    def _blocked(self, req: ActionRequest, st: SessionState) -> None:
        st.blocked_count += 1
        target = req.target.strip()
        if len(target) >= 4 and target not in st.blocked_targets:
            st.blocked_targets.append(target)
        if self.quarantine_after and st.blocked_count >= self.quarantine_after and st.status == "active":
            self.quarantine(req, st, f"{st.blocked_count} blocked or denied actions")

    def _finish(self, req: ActionRequest, st: SessionState, status: ActionStatus, decision: Decision, message: str,
                result: Any = None, extra: dict[str, Any] | None = None) -> ActionOutcome:
        self._log("result", req, {"tool": req.tool, "status": status.value, "decision": decision.value,
                                  "message": message, **(extra or {})})
        self.sessions.save(st)
        return ActionOutcome(req.action_id, status, decision, result, message)

    # ------------------------------------------------------------------ approval
    async def _approval(self, req: ActionRequest, policy: PolicyResult) -> tuple[bool, str]:
        if self.approver is not None:
            answer = self.approver(req, policy)
            if inspect.isawaitable(answer):
                answer = await answer
            verdict = "approved" if answer else "denied"
            self._log("approval_decision", req, {"tool": req.tool, "status": verdict, "reviewer": "callback"})
            return bool(answer), f"{verdict} by approval callback"

        self.approvals.create(req, policy)
        self._log("approval_requested", req, {"tool": req.tool, "timeout_s": self.config.approval_timeout,
                                              "grants": sorted(policy.grants)})
        item = await self.approvals.wait(req.action_id, self.config.approval_timeout)
        status = item["status"]
        if status == "expired":
            self._log("approval_decision", req, {"tool": req.tool, "status": "expired", "reviewer": None})
            return False, f"no human decision within {self.config.approval_timeout:g}s, so it was denied by default"
        who = item.get("reviewer") or "reviewer"
        note = f" ({item['note']})" if item.get("note") else ""
        return status == "approved", f"{status} by {who}{note}"

    def _grant(self, req: ActionRequest, st: SessionState, grants: set[str]) -> None:
        if "screen" in grants:
            until = time.time() + self.screen_minutes * 60
            self.sessions.set_screen_grant(req.session_id, until)
            st.screen_granted_until = until
            st.screen_started = st.screen_started or time.time()
            self._log("screen_control_started", req, {"granted_until": until, "minutes": self.screen_minutes,
                                                      "first_action": req.tool, "purpose": req.purpose})
            self.alert(Severity.INFO, "screen_control",
                       f"{req.agent} started controlling the screen ({req.purpose or 'no purpose given'})",
                       session_id=req.session_id, agent=req.agent, action_id=req.action_id, tool=req.tool)

    # ------------------------------------------------------------------ main entry
    async def execute(self, req: ActionRequest, executor: Executor,
                      adapter: ResultAdapter | None = None) -> ActionOutcome:
        adapter = adapter or PlainAdapter()
        st = self.state(req.session_id, req.agent)
        category = categorize(req.tool, self.config)

        # 5. Pre-log: the attempt is on record before any decision or execution.
        self._log("attempt", req, {"tool": req.tool, "arguments": req.arguments, "purpose": req.purpose,
                                   "target": req.target, "category": category.value})

        # 2-4. Permission check, guards, risk, decision.
        was_halted = st.status != "active"
        policy = self.policy.evaluate(req, st)
        st.action_times.append(time.time())
        self._log("decision", req, policy.to_dict())
        self._raise_alerts(req, policy.findings)
        for f in policy.findings:
            if f.taint:
                st.taint(f.taint)
        if policy.quarantine:
            self.quarantine(req, st, next(f.reason for f in policy.findings if f.quarantine))

        if policy.decision == Decision.BLOCK:
            # Blocks caused only by a person pausing/quarantining the session aren't held against the agent.
            if not (was_halted and all(f.guard == "kill_switch" for f in policy.findings
                                       if f.decision == Decision.BLOCK) and len(policy.reasons) == 1):
                self._blocked(req, st)
            return self._finish(req, st, ActionStatus.BLOCKED, policy.decision,
                                "Blocked by Heimdall: " + "; ".join(policy.reasons))

        approval_note = None
        if policy.decision == Decision.REQUIRE_APPROVAL:
            approved, approval_note = await self._approval(req, policy)
            if not approved:
                self._blocked(req, st)
                return self._finish(req, st, ActionStatus.DENIED, policy.decision,
                                    f"Action requires human approval: {approval_note}.")
            self._grant(req, st, policy.grants)
            self.sessions.sync(st)  # a person may have paused the session while we waited
            if st.status != "active":
                return self._finish(req, st, ActionStatus.BLOCKED, Decision.BLOCK,
                                    f"Blocked by Heimdall: session was {st.status} while awaiting approval")

        # Execute the real tool.
        started = time.perf_counter()
        try:
            result = executor(req.arguments)
            if inspect.isawaitable(result):
                result = await result
        except Exception as exc:  # the tool itself failed
            return self._finish(req, st, ActionStatus.FAILED, policy.decision, f"Tool error: {exc}",
                                extra={"error": repr(exc), "approval": approval_note})
        duration_ms = round((time.perf_counter() - started) * 1000, 1)

        redactions = 0
        if policy.decision == Decision.RESTRICT:
            limit = int(policy.restrictions.get("max_result_chars", 0) or 0)

            def restrict(text: str) -> str:
                nonlocal redactions
                if policy.restrictions.get("redact", True):
                    text, n = self.redactor.text(text)
                    redactions += n
                return truncate(text, limit)

            result = adapter.map_text(result, restrict)

        # After-guards: look at what came back (prompt injection, sensitive data now in the agent's hands).
        text = adapter.to_text(result)
        after_findings: list[Finding] = []
        for guard in self.policy.guards:
            res = guard.after(req, category, text, st)
            after_findings.extend(res.findings)
            if res.banner:
                result = adapter.prepend(result, res.banner)
        self._raise_alerts(req, after_findings)

        st.action_count += 1
        st.result_bytes += len(text.encode())
        if category == Category.SEND:
            st.outbound_count += 1
        if category == Category.SCREEN:
            st.screen_actions += 1
            st.screen_last = time.time()
            st.screen_started = st.screen_started or time.time()

        # 6. Record what actually came back (redacted preview, never trust the agent's summary).
        preview, _ = self.redactor.text(truncate(text, PREVIEW_CHARS))
        status = ActionStatus.FAILED if adapter.is_error(result) else ActionStatus.SUCCEEDED
        msg = "Tool reported an error" if status == ActionStatus.FAILED else "OK"
        return self._finish(req, st, status, policy.decision, msg, result=result, extra={
            "result_preview": preview,
            "duration_ms": duration_ms,
            "redactions": redactions,
            "approval": approval_note,
            "after_findings": [f.to_dict() for f in after_findings],
        })

    def execute_sync(self, req: ActionRequest, executor: Executor, adapter: ResultAdapter | None = None) -> ActionOutcome:
        return anyio.run(self.execute, req, executor, adapter)

    # ------------------------------------------------------------------ person-facing controls
    def set_session_status(self, session_id: str, status: str, reason: str = "", by: str = "reviewer") -> None:
        row = self.sessions.get(session_id)
        if row is None:
            raise KeyError(session_id)
        self.sessions.set_status(session_id, status, reason or f"set by {by}")
        self.audit.append(f"session_{status}" if status != "active" else "session_resumed",
                          {"reason": reason, "by": by}, session_id=session_id, agent=row["agent"])

    def revoke_screen(self, session_id: str, by: str = "reviewer") -> None:
        row = self.sessions.get(session_id)
        if row is None:
            raise KeyError(session_id)
        self.sessions.set_screen_grant(session_id, 0)
        self.audit.append("screen_control_stopped", {"reason": f"revoked by {by}"}, session_id=session_id,
                          agent=row["agent"])

    # ------------------------------------------------------------------ library decorator
    def guard(self, tool: str, agent: str, session_id: str = "default") -> Callable:
        """Wrap a plain Python function so every call goes through Heimdall.

            @gateway.guard("billing.refund", agent="support-bot")
            def refund(order_id: str, amount: float): ...

            refund("A1", 20.0, purpose="customer asked for refund")

        Raises ActionBlocked when the call is blocked or denied.
        """

        def decorator(fn: Callable) -> Callable:
            sig = inspect.signature(fn)

            def build(args: tuple, kwargs: dict) -> tuple[ActionRequest, Callable[[dict], Any]]:
                purpose = kwargs.pop("purpose", None)
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                req = ActionRequest(agent=agent, tool=tool, arguments=dict(bound.arguments),
                                    purpose=purpose, session_id=session_id)
                return req, lambda a: fn(**a)

            def unwrap(outcome: ActionOutcome) -> Any:
                if outcome.status in (ActionStatus.BLOCKED, ActionStatus.DENIED):
                    raise ActionBlocked(outcome)
                if outcome.status == ActionStatus.FAILED:
                    raise RuntimeError(outcome.message)
                return outcome.result

            if inspect.iscoroutinefunction(fn):
                @functools.wraps(fn)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    req, call = build(args, kwargs)
                    return unwrap(await self.execute(req, call))
                return async_wrapper

            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                req, call = build(args, kwargs)
                return unwrap(self.execute_sync(req, call))
            return wrapper

        return decorator

    # ------------------------------------------------------------------ deception audit
    def audit_claim(self, session_id: str, claim: str, agent: str = "unknown") -> dict[str, Any]:
        """Compare an agent's account of its own work with the observed audit trail."""
        events = self.audit.events(session_id=session_id, limit=100000)
        observed = observed_from_events(events)
        report = analyze(claim, observed)
        self.audit.append("claim", {"claim": claim}, session_id=session_id, agent=agent)
        self.audit.append("deception_report", report, session_id=session_id, agent=agent)
        if report["verdict"] == "deceptive":
            self.alert(Severity.WARNING, "deception", f"claim contradicts observed actions "
                       f"({len(report['findings'])} finding(s))", session_id=session_id, agent=agent)
        return report
