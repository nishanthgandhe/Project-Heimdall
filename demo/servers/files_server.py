"""Demo MCP server: a file system confined to demo/sandbox."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from mcp.server.mcpserver import MCPServer  # noqa: E402

from demo.servers._common import safe_path, sandbox_root  # noqa: E402

server = MCPServer("files", instructions="Read and write files in the team workspace.")


@server.tool()
def list_files(path: str = ".") -> str:
    """List files under a directory in the workspace."""
    base = safe_path(path)
    root = sandbox_root()
    entries = sorted(str(p.relative_to(root)) + ("/" if p.is_dir() else "")
                     for p in base.rglob("*") if not p.name.endswith(".db-wal") and not p.name.endswith(".db-shm"))
    return "\n".join(entries) or "(empty)"


@server.tool()
def read_file(path: str) -> str:
    """Read a text file from the workspace."""
    return safe_path(path).read_text()


@server.tool()
def write_file(path: str, content: str) -> str:
    """Create or overwrite a text file in the workspace."""
    p = safe_path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return f"wrote {len(content)} chars to {path}"


@server.tool()
def delete_file(path: str) -> str:
    """Delete a file from the workspace."""
    p = safe_path(path)
    p.unlink()
    return f"deleted {path}"


if __name__ == "__main__":
    server.run()
