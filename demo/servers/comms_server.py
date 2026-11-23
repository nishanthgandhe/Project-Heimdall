"""Demo MCP server: outbound communication (simulated -- nothing leaves the machine).

Emails are appended to sandbox/outbox.jsonl and HTTP posts to
sandbox/network_log.jsonl so you can see what *would* have been sent.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from mcp.server.mcpserver import MCPServer  # noqa: E402

from demo.servers._common import sandbox_root  # noqa: E402

server = MCPServer("comms", instructions="Send emails and call external web services.")


def _append(name: str, record: dict) -> None:
    with open(sandbox_root() / name, "a") as f:
        f.write(json.dumps({"ts": time.time(), **record}) + "\n")


@server.tool()
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email."""
    _append("outbox.jsonl", {"to": to, "subject": subject, "body": body})
    return f"email sent to {to}"


@server.tool()
def http_post(url: str, body: str) -> str:
    """POST data to an external URL."""
    _append("network_log.jsonl", {"url": url, "body": body})
    return f"posted {len(body)} bytes to {url}"


if __name__ == "__main__":
    server.run()
