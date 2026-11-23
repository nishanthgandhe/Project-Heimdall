"""Permission checks, risk scoring and the final allow/restrict/approve/block decision."""

from __future__ import annotations

import fnmatch
import json
import re
from typing import TYPE_CHECKING, Any, Iterable
from urllib.parse import urlparse

from .config import HeimdallConfig, Rule
from .models import ActionRequest, Category, Decision, PolicyResult, RiskAssessment, Severity
from .sessions import SessionState

BASE_RISK = {
    Category.LIST: 5,
    Category.READ: 10,
    Category.QUERY: 15,
    Category.NETWORK: 15,
    Category.SCREEN: 25,
    Category.WRITE: 30,
    Category.SEND: 40,
    Category.EXECUTE: 45,
    Category.FINANCIAL: 45,
    Category.ADMIN: 50,
    Category.DELETE: 55,
    Category.OTHER: 20,
}

# Words anywhere in "server.tool" that mean the tool drives the computer itself.
_SCREEN_WORDS = {"screenshot", "screen", "click", "mouse", "cursor", "scroll", "drag", "keypress", "keyboard",
                 "hotkey", "clipboard", "computer", "desktop", "zoom"}

# Order matters: the first group whose verb appears in the tool name wins.
_NAME_HEURISTICS: list[tuple[Category, tuple[str, ...]]] = [
    (Category.DELETE, ("delete", "remove", "rm", "drop", "destroy", "purge", "erase", "wipe")),
    (Category.FINANCIAL, ("pay", "payment", "payments", "refund", "charge", "purchase", "buy", "invoice", "wire",
                          "payout", "withdraw", "deposit", "checkout", "billing")),
    (Category.ADMIN, ("grant", "revoke", "permission", "permissions", "role", "roles", "admin", "sudo", "privilege",
                      "privileges", "settings", "configure", "install", "uninstall", "chmod", "chown", "invite")),
    (Category.SEND, ("send", "email", "mail", "post", "upload", "export", "share", "publish", "webhook", "transfer")),
    (Category.EXECUTE, ("exec", "execute", "run", "shell", "command", "eval", "spawn", "terminal", "bash")),
    (Category.NETWORK, ("fetch", "browse", "visit", "crawl", "scrape", "download", "web", "url", "navigate")),
    (Category.WRITE, ("write", "create", "update", "edit", "save", "put", "modify", "append", "insert", "move", "rename", "patch", "set")),
    (Category.QUERY, ("query", "sql", "select", "search")),
    (Category.READ, ("read", "get", "open", "view", "cat", "load")),
    (Category.LIST, ("list", "ls", "dir", "tree", "find")),
]

_READ_ONLY_PURPOSE = re.compile(
    r"(?i)\b(summar\w*|read\w*|review\w*|analy[sz]\w*|look\w*|check\w*|research\w*|understand\w*|inspect\w*|learn\w*|view\w*)\b"
)
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_URL = re.compile(r"https?://[^\s\"'<>]+")
_SQL_DDL = re.compile(r"(?i)\b(drop|truncate|alter)\s+(table|database|schema|index)\b")
_SQL_DELETE = re.compile(r"(?i)\bdelete\s+from\b")
_SQL_UPDATE = re.compile(r"(?i)\bupdate\s+\w+\s+set\b")
_SQL_WHERE = re.compile(r"(?i)\bwhere\b")
_SQL_SELECT_STAR = re.compile(r"(?i)\bselect\s+\*")
_SQL_LIMIT = re.compile(r"(?i)\blimit\s+\d+")


def _glob_any(name: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatchcase(name, p) for p in patterns)


def _arg_strings(arguments: dict[str, Any]) -> dict[str, str]:
    out = {}
    for k, v in arguments.items():
        out[k] = v if isinstance(v, str) else json.dumps(v, default=str)
    return out


def categorize(tool: str, config: HeimdallConfig) -> Category:
    for pattern, cat in config.tool_categories.items():
        if fnmatch.fnmatchcase(tool, pattern):
            return cat
    if set(re.split(r"[^a-z0-9]+", tool.lower())) & _SCREEN_WORDS:
        return Category.SCREEN
    short = tool.split(".", 1)[-1].lower()
    words = set(re.split(r"[^a-z0-9]+", short))
    for cat, verbs in _NAME_HEURISTICS:
        if words & set(verbs):
            return cat
    return Category.OTHER


# Kept for backwards compatibility: the gateway now uses sessions.SessionState.
SessionContext = SessionState


if TYPE_CHECKING:
    from .guards import ToolRegistry


class PolicyEngine:
    def __init__(self, config: HeimdallConfig, registry: "ToolRegistry | None" = None):
        from .guards import build_guards

        self.config = config
        self.guards = build_guards(config, registry)
        self._sensitive = [re.compile(p) for p in config.sensitive_patterns]
        self._protected = [re.compile(p) for p in config.protected_paths]

    # ------------------------------------------------------------------ risk
    def _domain_trusted(self, domain: str) -> bool:
        domain = domain.lower()
        return any(domain == d or domain.endswith("." + d) for d in self.config.trusted_domains)

    def assess_risk(self, req: ActionRequest, category: Category, ctx: SessionState | None = None) -> RiskAssessment:
        factors: list[tuple[str, int]] = [(f"base risk for '{category.value}' action", BASE_RISK[category])]
        args = _arg_strings(req.arguments)
        blob = "\n".join(args.values())

        # Sensitive data / resources
        hits = sorted({m.group(0) for p in self._sensitive for m in [p.search(blob)] if m})
        if hits:
            factors.append((f"touches sensitive resource or data ({', '.join(hits[:3])})", 35))
        if any(p.search(blob) for p in self._protected):
            factors.append(("targets a protected path (audit trail / Heimdall internals)", 50))

        # Destructive SQL
        for v in args.values():
            if _SQL_DDL.search(v):
                factors.append(("destructive schema change (DROP/TRUNCATE/ALTER)", 45))
            elif _SQL_DELETE.search(v):
                factors.append(("DELETE without WHERE clause" if not _SQL_WHERE.search(v) else "DELETE statement",
                                45 if not _SQL_WHERE.search(v) else 20))
            elif _SQL_UPDATE.search(v):
                factors.append(("UPDATE without WHERE clause" if not _SQL_WHERE.search(v) else "UPDATE statement",
                                35 if not _SQL_WHERE.search(v) else 15))
            elif _SQL_SELECT_STAR.search(v) and not _SQL_LIMIT.search(v):
                factors.append(("bulk read (SELECT * with no LIMIT)", 10))

        # Data leaving the system
        if category == Category.SEND:
            domains = {m.group(1).lower() for m in _EMAIL.finditer(blob)}
            domains |= {(urlparse(u).hostname or "").lower() for u in _URL.findall(blob)}
            untrusted = sorted(d for d in domains if d and not self._domain_trusted(d))
            if untrusted:
                factors.append((f"external destination ({', '.join(untrusted[:3])})", 30))
            if any(len(v) > 2000 for v in args.values()):
                factors.append(("large outbound payload", 15))

        # Stated purpose
        if not (req.purpose or "").strip():
            if self.config.require_purpose:
                factors.append(("no stated purpose given", 15))
        elif category in (Category.WRITE, Category.DELETE, Category.SEND, Category.EXECUTE):
            from .deception import LEXICON  # same verb lists the deception audit uses

            purpose = req.purpose or ""
            if _READ_ONLY_PURPOSE.search(purpose) and not re.search(LEXICON[category], purpose, re.I):
                factors.append((f"stated purpose sounds read-only but action is '{category.value}'", 20))

        # Session behaviour
        if ctx is not None:
            agent = self.config.agent(req.agent)
            limit = (agent.max_actions_per_minute if agent and agent.max_actions_per_minute
                     else self.config.default_max_actions_per_minute)
            if ctx.actions_last_minute() >= limit:
                factors.append((f"unusual activity rate (>= {limit} actions/min)", 25))
            if ctx.blocked_count:
                factors.append((f"{ctx.blocked_count} earlier blocked/denied action(s) this session",
                                min(30, 10 * ctx.blocked_count)))

        score = max(0, min(100, sum(p for _, p in factors)))
        return RiskAssessment(score=score, factors=factors)

    # ------------------------------------------------------------------ rules
    def _rule_matches(self, rule: Rule, req: ActionRequest) -> bool:
        if not _glob_any(req.tool, rule.tools) or not _glob_any(req.agent, rule.agents):
            return False
        args = _arg_strings(req.arguments)
        for key, pattern in rule.compiled.items():
            if key == "*":
                values = list(args.values())
            elif key == "purpose":
                values = [req.purpose or ""]
            else:
                values = [args[key]] if key in args else []
            if not any(pattern.search(v) for v in values):
                return False
        return True

    # ------------------------------------------------------------------ evaluate
    def evaluate(self, req: ActionRequest, ctx: SessionState | None = None) -> PolicyResult:
        ctx = ctx or SessionState(req.session_id, req.agent)
        category = categorize(req.tool, self.config)
        risk = self.assess_risk(req, category, ctx)
        decisions: list[Decision] = [Decision.ALLOW]
        reasons: list[str] = []
        matched: list[str] = []
        restrictions: dict[str, Any] = {}

        # 1. Permission check: is this agent explicitly allowed to use this tool?
        agent = self.config.agent(req.agent)
        if agent is None:
            decisions.append(Decision.BLOCK)
            reasons.append(f"unknown agent '{req.agent}' (no policy defined)")
        elif _glob_any(req.tool, agent.deny_tools):
            decisions.append(Decision.BLOCK)
            reasons.append(f"agent '{req.agent}' is explicitly denied '{req.tool}'")
        elif not _glob_any(req.tool, agent.allow_tools):
            decisions.append(Decision.BLOCK)
            reasons.append(f"agent '{req.agent}' is not authorized to use '{req.tool}'")

        # 2. Policy rules
        for rule in self.config.rules:
            if self._rule_matches(rule, req):
                decisions.append(rule.decision)
                matched.append(rule.name)
                reasons.append(f"rule '{rule.name}': {rule.description or rule.decision.value}")
                if rule.decision == Decision.RESTRICT:
                    restrictions.update(rule.restrictions or {"redact": True})

        # 3. Guards (screen control, shell, network, injection taint, data flow, canaries, ...)
        findings = []
        for guard in self.guards:
            findings.extend(guard.before(req, category, ctx))
        for f in findings:
            decisions.append(f.decision)
            if f.points:
                risk.factors.append((f"{f.guard}: {f.reason}", f.points))
            if f.decision != Decision.ALLOW or f.severity != Severity.INFO:
                reasons.append(f"{f.guard.replace('_', ' ')}: {f.reason}")
        risk.score = max(0, min(100, sum(p for _, p in risk.factors)))

        # 4. Risk thresholds
        if risk.score >= self.config.block_threshold:
            decisions.append(Decision.BLOCK)
            reasons.append(f"risk score {risk.score} >= block threshold {self.config.block_threshold}")
        elif risk.score >= self.config.approve_threshold:
            decisions.append(Decision.REQUIRE_APPROVAL)
            reasons.append(f"risk score {risk.score} >= approval threshold {self.config.approve_threshold}")

        final = Decision.most_severe(*decisions)
        if final == Decision.ALLOW:
            reasons.append("authorized and within risk limits")
        if final == Decision.RESTRICT and not restrictions:
            restrictions = {"redact": True}
        return PolicyResult(decision=final, reasons=reasons, risk=risk, category=category, matched_rules=matched,
                            restrictions=restrictions if final == Decision.RESTRICT else {}, findings=findings)
