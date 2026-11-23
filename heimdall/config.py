"""Loading heimdall.yaml into typed objects."""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .models import Category, Decision

DEFAULT_SENSITIVE_PATTERNS = [
    r"(?i)secret",
    r"(?i)password|passwd",
    r"(?i)\.env\b",
    r"(?i)credential",
    r"(?i)id_rsa|private[_ ]?key|\.pem\b",
    r"(?i)api[_-]?key|token",
    r"(?i)\bssn\b|social security",
]


@dataclass
class Rule:
    name: str
    decision: Decision
    tools: list[str] = field(default_factory=lambda: ["*"])
    agents: list[str] = field(default_factory=lambda: ["*"])
    match_args: dict[str, str] = field(default_factory=dict)  # arg name ("*" = any) -> regex
    description: str = ""
    restrictions: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._compiled = {k: re.compile(v) for k, v in self.match_args.items()}

    @property
    def compiled(self) -> dict[str, re.Pattern[str]]:
        return self._compiled


@dataclass
class AgentPolicy:
    name: str
    allow_tools: list[str] = field(default_factory=list)
    deny_tools: list[str] = field(default_factory=list)
    description: str = ""
    max_actions_per_minute: int | None = None


@dataclass
class ServerSpec:
    name: str
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] | None = None
    cwd: str | None = None


@dataclass
class HeimdallConfig:
    base_dir: Path
    database: Path
    require_purpose: bool = True
    approval_timeout: float = 120.0
    approve_threshold: int = 50
    block_threshold: int = 85
    default_max_actions_per_minute: int = 30
    trusted_domains: list[str] = field(default_factory=list)
    sensitive_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_SENSITIVE_PATTERNS))
    protected_paths: list[str] = field(default_factory=list)
    tool_categories: dict[str, Category] = field(default_factory=dict)
    agents: dict[str, AgentPolicy] = field(default_factory=dict)
    rules: list[Rule] = field(default_factory=list)
    servers: dict[str, ServerSpec] = field(default_factory=dict)
    redact_patterns: dict[str, str] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    def agent(self, name: str) -> AgentPolicy | None:
        return self.agents.get(name)


def heimdall_env(**extra: str) -> dict[str, str]:
    """HEIMDALL_* variables to hand to child processes.

    The MCP SDK starts subprocesses with a minimal environment, so settings like
    HEIMDALL_AUDIT_KEY must be passed on explicitly or the child would hash the
    audit log with a different key.
    """
    env = {k: v for k, v in os.environ.items() if k.startswith("HEIMDALL_")}
    env.update(extra)
    return env


def _expand(value: str, base_dir: Path) -> str:
    return value.replace("{python}", sys.executable).replace("{root}", str(base_dir))


def load_config(path: str | Path | None = None) -> HeimdallConfig:
    """Load config from `path`, $HEIMDALL_CONFIG, or ./heimdall.yaml."""
    path = Path(path or os.environ.get("HEIMDALL_CONFIG", "heimdall.yaml")).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"Heimdall config not found: {path}")
    data = yaml.safe_load(path.read_text()) or {}
    return config_from_dict(data, base_dir=path.parent)


def config_from_dict(data: dict[str, Any], base_dir: str | Path = ".") -> HeimdallConfig:
    base_dir = Path(base_dir).resolve()
    db = Path(_expand(str(data.get("database", "heimdall.db")), base_dir))
    if not db.is_absolute():
        db = base_dir / db

    risk = data.get("risk", {}) or {}
    agents = {
        name: AgentPolicy(
            name=name,
            allow_tools=list(spec.get("allow_tools", [])),
            deny_tools=list(spec.get("deny_tools", [])),
            description=spec.get("description", ""),
            max_actions_per_minute=spec.get("max_actions_per_minute"),
        )
        for name, spec in (data.get("agents") or {}).items()
    }
    rules = [
        Rule(
            name=r["name"],
            decision=Decision(r["decision"]),
            tools=list(r.get("tools", ["*"])),
            agents=list(r.get("agents", ["*"])),
            match_args=dict(r.get("match_args", {}) or {}),
            description=r.get("description", ""),
            restrictions=dict(r.get("restrictions", {}) or {}),
        )
        for r in (data.get("rules") or [])
    ]
    servers = {}
    for name, spec in (data.get("servers") or {}).items():
        servers[name] = ServerSpec(
            name=name,
            command=_expand(spec["command"], base_dir),
            args=[_expand(str(a), base_dir) for a in spec.get("args", [])],
            env={k: _expand(str(v), base_dir) for k, v in (spec.get("env") or {}).items()} or None,
            cwd=_expand(spec["cwd"], base_dir) if spec.get("cwd") else str(base_dir),
        )

    return HeimdallConfig(
        base_dir=base_dir,
        database=db,
        require_purpose=bool(data.get("require_purpose", True)),
        approval_timeout=float(data.get("approval_timeout", 120)),
        approve_threshold=int(risk.get("approve_threshold", 50)),
        block_threshold=int(risk.get("block_threshold", 85)),
        default_max_actions_per_minute=int(risk.get("max_actions_per_minute", 30)),
        trusted_domains=[d.lower() for d in data.get("trusted_domains", [])],
        sensitive_patterns=list(data.get("sensitive_patterns", DEFAULT_SENSITIVE_PATTERNS)),
        protected_paths=list(data.get("protected_paths", [])),
        tool_categories={k: Category(v) for k, v in (data.get("tool_categories") or {}).items()},
        agents=agents,
        rules=rules,
        servers=servers,
        redact_patterns=dict(data.get("redact_patterns", {}) or {}),
        raw=data,
    )
