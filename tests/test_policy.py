from heimdall.models import ActionRequest, Category, Decision
from heimdall.policy import PolicyEngine, SessionContext, categorize


def req(tool, agent="research-agent", purpose="summarize the report", **args):
    return ActionRequest(agent=agent, tool=tool, arguments=args, purpose=purpose)


def test_categories_from_names_and_config(config):
    assert categorize("files.read_file", config) == Category.READ
    assert categorize("files.delete_file", config) == Category.DELETE
    assert categorize("comms.send_email", config) == Category.SEND
    assert categorize("db.execute", config) == Category.WRITE  # pinned in heimdall.yaml
    assert categorize("x.frobnicate", config) == Category.OTHER


def test_allowed_read(config):
    r = PolicyEngine(config).evaluate(req("files.read_file", path="docs/q3_report.md"))
    assert r.decision == Decision.ALLOW


def test_unknown_agent_blocked(config):
    r = PolicyEngine(config).evaluate(req("files.read_file", agent="mystery", path="docs/q3_report.md"))
    assert r.decision == Decision.BLOCK
    assert "unknown agent" in r.reasons[0]


def test_unauthorized_tool_blocked(config):
    r = PolicyEngine(config).evaluate(req("files.write_file", path="docs/x.md", content="hi"))
    assert r.decision == Decision.BLOCK
    assert any("not authorized" in x for x in r.reasons)


def test_secret_file_blocked_by_rule(config):
    r = PolicyEngine(config).evaluate(req("files.read_file", path="secrets/.env"))
    assert r.decision == Decision.BLOCK
    assert "block-secret-files" in r.matched_rules


def test_customer_query_restricted(config):
    r = PolicyEngine(config).evaluate(req("db.query", sql="SELECT name FROM customers LIMIT 5"))
    assert r.decision == Decision.RESTRICT
    assert r.restrictions.get("redact") is True


def test_internal_email_allowed_external_needs_approval(config):
    engine = PolicyEngine(config)
    inside = engine.evaluate(req("comms.send_email", to="team@fishbowl.example", subject="s", body="b",
                                 purpose="send the summary"))
    outside = engine.evaluate(req("comms.send_email", to="a@other.example", subject="s", body="b",
                                  purpose="send the summary"))
    assert inside.decision == Decision.ALLOW
    assert outside.decision == Decision.REQUIRE_APPROVAL


def test_pii_in_outbound_message_blocked(config):
    r = PolicyEngine(config).evaluate(req("comms.send_email", to="team@fishbowl.example", subject="s",
                                          body="SSN 123-45-6789"))
    assert r.decision == Decision.BLOCK
    assert "block-pii-outbound" in r.matched_rules


def test_audit_trail_protected_even_for_ops_agent(config):
    r = PolicyEngine(config).evaluate(req("files.write_file", agent="ops-agent", path="logs/app.log", content=""))
    assert r.decision == Decision.BLOCK
    assert "protect-audit-trail" in r.matched_rules


def test_destructive_sql_scores_high(config):
    r = PolicyEngine(config).evaluate(req("db.execute", agent="ops-agent", sql="DROP TABLE customers",
                                          purpose="cleanup"))
    assert r.risk.score >= 70
    assert r.decision in (Decision.REQUIRE_APPROVAL, Decision.BLOCK)


def test_missing_purpose_and_mismatch_add_risk(config):
    engine = PolicyEngine(config)
    base = engine.evaluate(req("comms.send_email", to="team@fishbowl.example", subject="s", body="b",
                               purpose="send the weekly update")).risk.score
    none = engine.evaluate(req("comms.send_email", to="team@fishbowl.example", subject="s", body="b",
                               purpose=None)).risk.score
    mismatch = engine.evaluate(req("comms.send_email", to="team@fishbowl.example", subject="s", body="b",
                                   purpose="just reviewing the report")).risk.score
    assert none > base and mismatch > base


def test_repeated_blocks_escalate(config):
    engine = PolicyEngine(config)
    ctx = SessionContext()
    first = engine.evaluate(req("files.read_file", path="docs/q3_report.md"), ctx).risk.score
    ctx.blocked_count = 3
    later = engine.evaluate(req("files.read_file", path="docs/q3_report.md"), ctx).risk.score
    assert later == first + 30


def test_most_severe_decision_wins():
    assert Decision.most_severe(Decision.ALLOW, Decision.BLOCK, Decision.RESTRICT) == Decision.BLOCK
