"""Shared helpers for the demo MCP servers."""

from __future__ import annotations

import os
from pathlib import Path

DEMO_DIR = Path(__file__).resolve().parent.parent


def sandbox_root() -> Path:
    root = Path(os.environ.get("HEIMDALL_SANDBOX", DEMO_DIR / "sandbox")).resolve()
    if not root.exists():
        from demo.setup_sandbox import reset_sandbox  # noqa: WPS433 (lazy import)

        reset_sandbox(root)
    return root


def safe_path(rel: str) -> Path:
    """Resolve `rel` inside the sandbox. Stops path traversal at the server level too."""
    root = sandbox_root()
    p = (root / rel).resolve()
    if p != root and root not in p.parents:
        raise PermissionError(f"path escapes the sandbox: {rel}")
    return p
