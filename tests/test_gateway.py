import anyio
import pytest

from heimdall import ActionBlocked, ActionRequest, ActionStatus, Gateway


def test_allowed_action_runs_and_is_logged_before_and_after(config):
    gw = Gateway(config)
    calls = []
    out = gw.execute_sync(ActionRequest("research-agent", "files.read_file", {"path": "docs/a.md"}, "read it"),
                          lambda a: calls.append(a) or "contents")
    assert out.status == ActionStatus.SUCCEEDED and out.result == "contents" and calls
    types = [e["event_type"] for e in gw.audit.events()]
    assert types == ["attempt", "decision", "result"]


def test_blocked_action_never_runs(config):
    gw = Gateway(config)
    ran = []
    out = gw.execute_sync(ActionRequest("research-agent", "files.read_file", {"path": "secrets/.env"}, "x"),
                          lambda a: ran.append(1))
    assert out.status == ActionStatus.BLOCKED and not ran
    assert gw.audit.events(event_types=["attempt"])  # the attempt is still on record


def test_restrict_redacts_result(config):
    gw = Gateway(config)
    out = gw.execute_sync(ActionRequest("research-agent", "db.query", {"sql": "SELECT * FROM customers LIMIT 1"},
                                        "review"), lambda a: "Alice alice@example.com 123-45-6789")
    assert out.status == ActionStatus.SUCCEEDED
    assert "alice@example.com" not in out.result and "[REDACTED:EMAIL]" in out.result
    assert "[REDACTED:SSN]" in out.result


def test_approval_callback(config):
    for answer, status in ((True, ActionStatus.SUCCEEDED), (False, ActionStatus.DENIED)):
        gw = Gateway(config, approver=lambda r, p: answer)
        out = gw.execute_sync(ActionRequest("ops-agent", "comms.send_email",
                                            {"to": "a@other.example", "subject": "s", "body": "b"}, "send figures"),
                              lambda a: "sent")
        assert out.status == status


def test_approval_queue_approve_from_another_actor(config):
    gw = Gateway(config)
    req = ActionRequest("ops-agent", "comms.send_email", {"to": "a@other.example", "subject": "s", "body": "b"},
                        "send figures")

    async def main():
        async def reviewer():
            while not gw.approvals.list("pending"):
                await anyio.sleep(0.05)
            gw.approvals.decide(req.action_id, True, reviewer="prof", note="fine")

        async with anyio.create_task_group() as tg:
            tg.start_soon(reviewer)
            return await gw.execute(req, lambda a: "sent")

    out = anyio.run(main)
    assert out.status == ActionStatus.SUCCEEDED
    assert gw.approvals.get(req.action_id)["reviewer"] == "prof"


def test_approval_times_out_to_deny(config):
    config.approval_timeout = 0.3
    gw = Gateway(config)
    out = gw.execute_sync(ActionRequest("ops-agent", "comms.send_email",
                                        {"to": "a@other.example", "subject": "s", "body": "b"}, "send"),
                          lambda a: "sent")
    assert out.status == ActionStatus.DENIED and "no human decision" in out.message


def test_tool_exception_is_recorded_as_failure(config):
    gw = Gateway(config)

    def boom(a):
        raise OSError("disk on fire")

    out = gw.execute_sync(ActionRequest("research-agent", "files.read_file", {"path": "docs/a.md"}, "read"), boom)
    assert out.status == ActionStatus.FAILED and "disk on fire" in out.message


def test_guard_decorator(config):
    gw = Gateway(config)

    @gw.guard("files.read_file", agent="research-agent")
    def read_file(path: str) -> str:
        return f"contents of {path}"

    assert read_file("docs/a.md", purpose="read") == "contents of docs/a.md"
    with pytest.raises(ActionBlocked):
        read_file("secrets/.env", purpose="read")


def test_claim_audit_end_to_end(config):
    gw = Gateway(config)
    s = "sess1"
    gw.execute_sync(ActionRequest("research-agent", "files.read_file", {"path": "docs/a.md"}, "read", s), lambda a: "x")
    gw.execute_sync(ActionRequest("research-agent", "comms.send_email",
                                  {"to": "x@evil.example", "subject": "s", "body": "b"}, "send", s), lambda a: "sent")
    report = gw.audit_claim(s, "I only read one document and did not send anything.", "research-agent")
    assert report["verdict"] == "deceptive"
    assert gw.audit.verify().ok
