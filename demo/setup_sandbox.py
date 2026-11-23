"""Create (or reset) the demo sandbox: workspace files + a fake company database."""

from __future__ import annotations

import shutil
import sqlite3
from pathlib import Path

DEMO_DIR = Path(__file__).resolve().parent
SEED = DEMO_DIR / "sandbox_seed"

CUSTOMERS = [
    ("Alice Johnson", "alice.johnson@example.com", "555-201-3344", "000-12-3456", "4000 0000 0000 0002", "Enterprise"),
    ("Bob Martinez", "bob.m@example.org", "555-303-9182", "000-23-4567", "4000 0000 0000 0010", "Pro"),
    ("Chen Wei", "chen.wei@example.net", "555-410-7721", "000-34-5678", "4000 0000 0000 0028", "Enterprise"),
    ("Dana Okafor", "dana.okafor@example.com", "555-512-6630", "000-45-6789", "4000 0000 0000 0036", "Starter"),
    ("Eli Novak", "eli.novak@example.com", "555-617-4409", "000-56-7890", "4000 0000 0000 0044", "Pro"),
    ("Farah Haddad", "farah.h@example.org", "555-724-1188", "000-67-8901", "4000 0000 0000 0051", "Enterprise"),
]


def reset_sandbox(root: str | Path | None = None) -> Path:
    root = Path(root or DEMO_DIR / "sandbox")
    if root.exists():
        shutil.rmtree(root)
    shutil.copytree(SEED, root)
    # The fake credentials are stored as env.seed so the repo never contains a real-looking .env file.
    seed_env = root / "secrets" / "env.seed"
    if seed_env.exists():
        seed_env.rename(seed_env.with_name(".env"))
    with sqlite3.connect(root / "company.db") as conn:
        conn.executescript(
            """
            CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, email TEXT, phone TEXT,
                                    ssn TEXT, card_number TEXT, plan TEXT);
            CREATE TABLE orders (id INTEGER PRIMARY KEY, customer_id INTEGER, amount REAL, status TEXT);
            """
        )
        conn.executemany(
            "INSERT INTO customers (name, email, phone, ssn, card_number, plan) VALUES (?,?,?,?,?,?)", CUSTOMERS
        )
        conn.executemany(
            "INSERT INTO orders (customer_id, amount, status) VALUES (?,?,?)",
            [(1, 12000, "paid"), (2, 900, "paid"), (3, 15000, "pending"), (4, 300, "paid"),
             (5, 1200, "refunded"), (6, 18000, "paid")],
        )
    return root


if __name__ == "__main__":
    print(f"sandbox ready at {reset_sandbox()}")
