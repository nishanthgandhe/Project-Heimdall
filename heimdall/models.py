"""Core data types shared across Heimdall."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Decision(str, Enum):
    """Policy outcomes, ordered from least to most severe."""

    ALLOW = "allow"
    RESTRICT = "restrict"  # execute, but redact/truncate what comes back
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"

    @property
    def severity(self) -> int:
        return _SEVERITY[self]

    @staticmethod
    def most_severe(*decisions: "Decision") -> "Decision":
        return max(decisions, key=lambda d: d.severity)


_SEVERITY = {
    Decision.ALLOW: 0,
    Decision.RESTRICT: 1,
    Decision.REQUIRE_APPROVAL: 2,
    Decision.BLOCK: 3,
}


class Category(str, Enum):
    """What kind of thing a tool does. Drives base risk and deception checks."""

    LIST = "list"
    READ = "read"
    QUERY = "query"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    SEND = "send"  # anything that moves data outside: email, upload, http post
    NETWORK = "network"  # fetching from the outside world: web pages, downloads
    SCREEN = "screen"  # controlling the computer: screenshots, clicks, typing, apps, clipboard
    FINANCIAL = "financial"  # payments, refunds, transfers
    ADMIN = "admin"  # permissions, settings, installs, account changes
    OTHER = "other"


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class ActionStatus(str, Enum):
    BLOCKED = "blocked"
    DENIED = "denied"  # human reviewer said no (or approval timed out)
    SUCCEEDED = "succeeded"
    FAILED = "failed"  # allowed, but the tool itself errored


@dataclass
class ActionRequest:
    """One tool call an agent wants to make, captured before it runs."""

    agent: str
    tool: str  # canonical "server.tool" name, e.g. "files.read_file"
    arguments: dict[str, Any]
    purpose: str | None = None  # the agent's own stated reason
    session_id: str = "default"
    action_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: float = field(default_factory=time.time)

    @property
    def server(self) -> str:
        return self.tool.split(".", 1)[0] if "." in self.tool else ""

    @property
    def target(self) -> str:
        """Best-effort description of the resource being touched."""
        for key in ("path", "file", "filename", "to", "recipient", "url", "table", "sql", "query", "command"):
            if key in self.arguments and self.arguments[key] not in (None, ""):
                return str(self.arguments[key])[:200]
        return ""


@dataclass
class RiskAssessment:
    score: int
    factors: list[tuple[str, int]]  # (reason, points)

    def to_dict(self) -> dict[str, Any]:
        return {"score": self.score, "factors": [{"reason": r, "points": p} for r, p in self.factors]}


@dataclass
class Finding:
    """One guard's opinion about an action."""

    guard: str
    reason: str
    decision: Decision = Decision.ALLOW
    points: int = 0  # added to the risk score
    severity: Severity = Severity.INFO  # warning/critical findings raise alerts
    quarantine: bool = False  # stop the whole session
    grant: str | None = None  # approving this action grants a capability (e.g. "screen")
    taint: str | None = None  # mark the session as having seen untrusted/sensitive content

    def to_dict(self) -> dict[str, Any]:
        return {
            "guard": self.guard,
            "reason": self.reason,
            "decision": self.decision.value,
            "points": self.points,
            "severity": self.severity.value,
            "quarantine": self.quarantine,
            "grant": self.grant,
        }


@dataclass
class PolicyResult:
    decision: Decision
    reasons: list[str]
    risk: RiskAssessment
    category: Category
    matched_rules: list[str] = field(default_factory=list)
    restrictions: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)

    @property
    def grants(self) -> set[str]:
        return {f.grant for f in self.findings if f.grant}

    @property
    def quarantine(self) -> bool:
        return any(f.quarantine for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "reasons": self.reasons,
            "risk": self.risk.to_dict(),
            "category": self.category.value,
            "matched_rules": self.matched_rules,
            "restrictions": self.restrictions,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class ActionOutcome:
    """What the gateway hands back to the caller after an interception."""

    action_id: str
    status: ActionStatus
    decision: Decision
    result: Any = None
    message: str = ""

    @property
    def ok(self) -> bool:
        return self.status == ActionStatus.SUCCEEDED
