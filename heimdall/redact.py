"""Redaction used for RESTRICT decisions and for result previews in the audit log."""

from __future__ import annotations

import re
from typing import Any

DEFAULT_REDACTIONS: dict[str, str] = {
    "EMAIL": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "CARD": r"\b(?:\d[ -]?){13,16}\b",
    "PHONE": r"\(?\b\d{3}\)?[-. ]\d{3}[-. ]\d{4}\b",
    "API_KEY": r"\b(?:sk|pk|api|key|tok)[-_][A-Za-z0-9_\-]{12,}\b",
    "AWS_KEY": r"\bAKIA[0-9A-Z]{16}\b",
    "SECRET_ASSIGNMENT": r"(?i)\b(password|passwd|secret|token|api_key)\s*[:=]\s*\S+",
    "PRIVATE_KEY": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
}

# Kinds that are always serious if they leave the system.
HIGH_RISK_KINDS = {"SSN", "CARD", "API_KEY", "AWS_KEY", "SECRET_ASSIGNMENT", "PRIVATE_KEY"}
_COMPILED = {name: re.compile(p) for name, p in DEFAULT_REDACTIONS.items()}


def find_sensitive(text: str, kinds: set[str] | None = None) -> list[tuple[str, str]]:
    """Return (kind, value) pairs for anything that looks like personal data or a secret."""
    out = []
    for name, pattern in _COMPILED.items():
        if kinds and name not in kinds:
            continue
        for m in pattern.finditer(text):
            out.append((name, m.group(0)))
    return out


class Redactor:
    def __init__(self, extra: dict[str, str] | None = None):
        patterns = {**DEFAULT_REDACTIONS, **(extra or {})}
        self._patterns = [(name, re.compile(p)) for name, p in patterns.items()]

    def text(self, value: str) -> tuple[str, int]:
        count = 0
        for name, pattern in self._patterns:
            value, n = pattern.subn(f"[REDACTED:{name}]", value)
            count += n
        return value, count

    def any(self, value: Any) -> tuple[Any, int]:
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            total, out = 0, []
            for v in value:
                r, n = self.any(v)
                out.append(r)
                total += n
            return out, total
        if isinstance(value, dict):
            total, out_d = 0, {}
            for k, v in value.items():
                r, n = self.any(v)
                out_d[k] = r
                total += n
            return out_d, total
        return value, 0


def truncate(value: str, limit: int) -> str:
    if limit and len(value) > limit:
        return value[:limit] + f"... [truncated {len(value) - limit} chars]"
    return value
