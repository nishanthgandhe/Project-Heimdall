import sqlite3

import pytest

from heimdall.audit import AuditLog


def _fill(log: AuditLog, n: int = 5) -> None:
    for i in range(n):
        log.append("attempt", {"i": i, "tool": "files.read_file"}, session_id="s1", agent="a", action_id=f"x{i}")


def test_fresh_chain_verifies(tmp_path):
    log = AuditLog(tmp_path / "a.db")
    _fill(log)
    report = log.verify()
    assert report.ok and report.entries == 5


def test_modified_entry_is_detected(tmp_path):
    log = AuditLog(tmp_path / "a.db")
    _fill(log)
    with sqlite3.connect(tmp_path / "a.db") as conn:
        conn.execute("UPDATE audit_log SET payload = '{\"i\":99}' WHERE seq = 3")
    report = log.verify()
    assert not report.ok
    assert report.problems[0]["seq"] == 3


def test_deleted_entry_is_detected(tmp_path):
    log = AuditLog(tmp_path / "a.db")
    _fill(log)
    with sqlite3.connect(tmp_path / "a.db") as conn:
        conn.execute("DELETE FROM audit_log WHERE seq = 2")
    problems = " ".join(p["problem"] for p in log.verify().problems)
    assert "gap in sequence" in problems and "chain broken" in problems


def test_rehashing_without_key_is_detected_when_keyed(tmp_path):
    """An attacker who edits a row and recomputes plain SHA-256 hashes can't fool a keyed log."""
    import hashlib

    from heimdall.audit import GENESIS, _canonical

    log = AuditLog(tmp_path / "a.db", key="team-secret")
    _fill(log)
    with sqlite3.connect(tmp_path / "a.db") as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("UPDATE audit_log SET payload = '{\"i\":99}' WHERE seq = 3")
        prev = GENESIS
        for row in conn.execute("SELECT * FROM audit_log ORDER BY seq").fetchall():
            rec = {k: row[k] for k in ("seq", "ts", "session_id", "agent", "event_type", "action_id", "payload")}
            h = hashlib.sha256((prev + _canonical(rec)).encode()).hexdigest()
            conn.execute("UPDATE audit_log SET prev_hash = ?, hash = ? WHERE seq = ?", (prev, h, row["seq"]))
            prev = h
    assert not log.verify().ok


def test_wrong_key_is_reported_and_refuses_writes(tmp_path):
    AuditLog(tmp_path / "a.db", key="k1").append("system", {})
    other = AuditLog(tmp_path / "a.db", key="k2")
    report = other.verify()
    assert not report.ok and "HEIMDALL_AUDIT_KEY" in report.problems[0]["problem"]
    with pytest.raises(RuntimeError):
        other.append("system", {})


def test_expected_head_detects_truncation(tmp_path):
    log = AuditLog(tmp_path / "a.db")
    _fill(log)
    head = log.head()
    with sqlite3.connect(tmp_path / "a.db") as conn:
        conn.execute("DELETE FROM audit_log WHERE seq = 5")
    assert log.verify().ok  # tail truncation alone looks valid...
    assert not log.verify(expected_head=head).ok  # ...until compared with a saved head
