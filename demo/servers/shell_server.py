"""Demo MCP server: a SIMULATED shell.

Only a handful of read-only commands are actually answered (ls, cat, pwd,
whoami, date, echo, head, wc), and only inside the sandbox. Everything else
is recorded in sandbox/shell_log.jsonl and NOT executed, so the demo can show
Heimdall stopping `rm -rf` and `curl | sh` without any risk.
"""

from __future__ import annotations

import json
import shlex
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from mcp.server.mcpserver import MCPServer  # noqa: E402

from demo.servers._common import safe_path, sandbox_root  # noqa: E402

server = MCPServer("shell", instructions="Run shell commands in the team workspace.")


def _simulate(command: str) -> str:
    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.split()
    if not parts or any(c in command for c in "|;&><`$("):
        return "(demo shell) recorded, not executed"
    cmd, args = parts[0], parts[1:]
    if cmd == "pwd":
        return "/workspace"
    if cmd == "whoami":
        return "agent"
    if cmd == "date":
        return datetime.now().strftime("%a %b %d %H:%M:%S %Y")
    if cmd == "echo":
        return " ".join(args)
    if cmd == "ls":
        target = safe_path(args[-1] if args and not args[-1].startswith("-") else ".")
        return "\n".join(sorted(p.name + ("/" if p.is_dir() else "") for p in target.iterdir()))
    if cmd in ("cat", "head", "wc") and args:
        text = safe_path(args[-1]).read_text()
        if cmd == "head":
            return "\n".join(text.splitlines()[:10])
        if cmd == "wc":
            return f"{len(text.splitlines())} {len(text.split())} {len(text)} {args[-1]}"
        return text
    return "(demo shell) recorded, not executed"


@server.tool()
def run_command(command: str) -> str:
    """Run a shell command and return its output."""
    with open(sandbox_root() / "shell_log.jsonl", "a") as f:
        f.write(json.dumps({"ts": time.time(), "command": command}) + "\n")
    try:
        return _simulate(command)
    except (OSError, PermissionError) as exc:
        return f"error: {exc}"


if __name__ == "__main__":
    server.run()
