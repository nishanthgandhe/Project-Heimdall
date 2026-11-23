"""Demo MCP server: SIMULATED payments. Records to sandbox/payments.jsonl; no money moves."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from mcp.server.mcpserver import MCPServer  # noqa: E402

from demo.servers._common import sandbox_root  # noqa: E402

server = MCPServer("payments", instructions="Issue refunds and send payments.")


def _record(**r) -> None:
    with open(sandbox_root() / "payments.jsonl", "a") as f:
        f.write(json.dumps({"ts": time.time(), **r}) + "\n")


@server.tool()
def issue_refund(order_id: int, amount: float, reason: str) -> str:
    """Refund a customer order."""
    _record(type="refund", order_id=order_id, amount=amount, reason=reason)
    return f"(demo) refunded ${amount:,.2f} on order {order_id}"


@server.tool()
def send_payment(to: str, amount: float, memo: str = "") -> str:
    """Send a payment to a person or company."""
    _record(type="payment", to=to, amount=amount, memo=memo)
    return f"(demo) sent ${amount:,.2f} to {to}"


if __name__ == "__main__":
    server.run()
