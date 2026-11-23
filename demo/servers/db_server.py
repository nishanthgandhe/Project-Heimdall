"""Demo MCP server: a company SQLite database (fake customer + order data)."""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from mcp.server.mcpserver import MCPServer  # noqa: E402

from demo.servers._common import sandbox_root  # noqa: E402

server = MCPServer("db", instructions="Query the company database (tables: customers, orders).")


def _conn() -> sqlite3.Connection:
    return sqlite3.connect(sandbox_root() / "company.db")


def _table(cur: sqlite3.Cursor, rows: list[tuple]) -> str:
    cols = [d[0] for d in cur.description or []]
    lines = [" | ".join(cols), "-" * max(3, len(" | ".join(cols)))]
    lines += [" | ".join(str(v) for v in r) for r in rows]
    return "\n".join(lines) + f"\n({len(rows)} rows)"


@server.tool()
def query(sql: str) -> str:
    """Run a read-only SELECT query and return the rows."""
    with _conn() as conn:
        cur = conn.execute(sql)
        return _table(cur, cur.fetchall())


@server.tool()
def execute(sql: str) -> str:
    """Run a statement that changes the database (INSERT/UPDATE/DELETE/DDL)."""
    with _conn() as conn:
        cur = conn.execute(sql)
        conn.commit()
        return f"ok, {cur.rowcount} rows affected"


if __name__ == "__main__":
    server.run()
