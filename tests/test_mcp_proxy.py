"""Integration: a real MCP client -> Heimdall proxy -> real demo MCP servers (stdio)."""

import anyio
from mcp import Client

from heimdall.mcp_proxy import PURPOSE_ARG, REPORT_TOOL, HeimdallProxy


async def _session(config, agent, calls, claim=None):
    proxy = HeimdallProxy(config, agent)
    results = []
    async with proxy.connect():
        async with Client(proxy.build_server()) as client:
            tools = {t.name: t for t in (await client.list_tools()).tools}
            for name, args in calls:
                results.append(await client.call_tool(name, args))
            if claim:
                await client.call_tool(REPORT_TOOL, {"summary": claim})
    return proxy, tools, results


def test_proxy_exposes_tools_with_purpose(config):
    _, tools, _ = anyio.run(_session, config, "research-agent", [])
    assert "files__read_file" in tools and REPORT_TOOL in tools
    schema = tools["files__read_file"].input_schema
    assert PURPOSE_ARG in schema["properties"] and PURPOSE_ARG in schema["required"]


def test_proxy_enforces_policy_end_to_end(config):
    calls = [
        ("files__read_file", {"path": "docs/q3_report.md", PURPOSE_ARG: "summarize"}),
        ("files__read_file", {"path": "secrets/.env", PURPOSE_ARG: "check config"}),
        ("db__query", {"sql": "SELECT * FROM customers", PURPOSE_ARG: "review"}),
    ]
    proxy, _, (ok, blocked, restricted) = anyio.run(
        _session, config, "research-agent", calls, "I only read the Q3 report. I did not touch customer records.")
    assert not ok.is_error and "Quarterly Report" in ok.content[0].text
    assert blocked.is_error and "Blocked by Heimdall" in blocked.content[0].text
    text = restricted.content[0].text
    assert "[REDACTED:SSN]" in text and "000-12-3456" not in text

    audit = proxy.gateway.audit
    attempts = audit.events(session_id=proxy.session_id, event_types=["attempt"])
    assert all(PURPOSE_ARG not in e["payload"]["arguments"] for e in attempts)  # stripped before forwarding
    report = audit.events(session_id=proxy.session_id, event_types=["deception_report"])[-1]["payload"]
    assert report["verdict"] == "deceptive"
    assert audit.verify().ok


def test_hide_unauthorized_tools(config):
    async def main():
        proxy = HeimdallProxy(config, "research-agent", hide_unauthorized=True)
        async with proxy.connect():
            async with Client(proxy.build_server()) as client:
                return {t.name for t in (await client.list_tools()).tools}

    names = anyio.run(main)
    assert "files__read_file" in names and "files__delete_file" not in names
