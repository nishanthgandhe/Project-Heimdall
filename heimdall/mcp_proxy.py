"""Heimdall as an MCP proxy.

    MCP client (Claude Desktop, an agent, ...)
          |  stdio
    Heimdall proxy  -- policy check, approval, audit log --
          |  stdio, one connection per downstream server
    real MCP servers (files, db, comms, ...)

The agent only ever talks to the proxy. Each downstream tool is re-exposed as
`<server>__<tool>` with one extra argument, `heimdall_purpose`, where the agent
states why it is making the call. Heimdall strips that argument before
forwarding, so downstream servers never see it.

The proxy also adds `heimdall__report_activity`: an agent (or its operator)
calls it at the end of a task with a summary of what it did, and Heimdall runs
the deception audit against what it actually observed.
"""

from __future__ import annotations

import copy
import logging
import sys
import time
import uuid
from contextlib import AsyncExitStack, asynccontextmanager
from typing import Any, AsyncIterator, Callable

import mcp_types as types
from mcp import Client
from mcp.client.stdio import StdioServerParameters
from mcp.server.lowlevel import Server

from .config import HeimdallConfig, heimdall_env
from .gateway import Gateway
from .models import ActionRequest, ActionStatus
from .policy import _glob_any

log = logging.getLogger("heimdall.proxy")

PURPOSE_ARG = "heimdall_purpose"
SEP = "__"
REPORT_TOOL = "heimdall__report_activity"


class McpResultAdapter:
    def to_text(self, result: Any) -> str:
        if not isinstance(result, types.CallToolResult):
            return repr(result)
        parts = []
        for block in result.content:
            parts.append(block.text if isinstance(block, types.TextContent) else f"[{block.type} content]")
        return "\n".join(parts)

    def map_text(self, result: Any, fn: Callable[[str], str]) -> Any:
        if not isinstance(result, types.CallToolResult):
            return result
        content = [
            b.model_copy(update={"text": fn(b.text)}) if isinstance(b, types.TextContent) else b
            for b in result.content
        ]
        # Structured content could leak what we just redacted, so drop it.
        return result.model_copy(update={"content": content, "structured_content": None})

    def prepend(self, result: Any, text: str) -> Any:
        if not isinstance(result, types.CallToolResult):
            return result
        return result.model_copy(update={"content": [types.TextContent(type="text", text=text), *result.content]})

    def is_error(self, result: Any) -> bool:
        return bool(getattr(result, "is_error", False))


def _text_result(text: str, is_error: bool = False) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=text)], is_error=is_error)


class HeimdallProxy:
    def __init__(self, config: HeimdallConfig, agent: str, session_id: str | None = None,
                 gateway: Gateway | None = None, hide_unauthorized: bool | None = None):
        self.config = config
        self.agent = agent
        self.session_id = session_id or f"{agent}-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:4]}"
        self.gateway = gateway or Gateway(config)
        self.adapter = McpResultAdapter()
        self.clients: dict[str, Client] = {}
        self.tools: dict[str, tuple[str, types.Tool]] = {}  # exposed name -> (server, original tool)
        if hide_unauthorized is None:
            hide_unauthorized = bool(config.raw.get("hide_unauthorized_tools", False))
        self.hide_unauthorized = hide_unauthorized

    # ------------------------------------------------------------------ downstream
    @asynccontextmanager
    async def connect(self, servers: dict[str, Any] | None = None) -> AsyncIterator["HeimdallProxy"]:
        """Open connections to every downstream server.

        `servers` may map names to anything `mcp.Client` accepts (used by tests to
        connect in-process); by default the commands from the config are spawned.
        """
        async with AsyncExitStack() as stack:
            targets = servers or {
                name: StdioServerParameters(command=s.command, args=s.args, env={**heimdall_env(), **(s.env or {})},
                                            cwd=s.cwd)
                for name, s in self.config.servers.items()
            }
            for name, target in targets.items():
                try:
                    client = await stack.enter_async_context(Client(target))
                except Exception as exc:  # keep going with the servers that did start
                    log.error("could not start downstream server %s: %s", name, exc)
                    self.gateway.audit.append("system", {"event": "downstream_failed", "server": name, "error": str(exc)},
                                              session_id=self.session_id, agent=self.agent)
                    continue
                self.clients[name] = client
                for tool in (await client.list_tools()).tools:
                    self.tools[f"{name}{SEP}{tool.name}"] = (name, tool)
                    self._check_tool(name, tool)
            self.gateway.audit.append(
                "session_start",
                {"servers": list(self.clients), "tools": [f"{s}.{t.name}" for s, t in self.tools.values()]},
                session_id=self.session_id, agent=self.agent,
            )
            yield self

    def _check_tool(self, server: str, tool: types.Tool) -> None:
        """Pin the tool definition and look for poisoning (hidden instructions in its description)."""
        canonical = f"{server}.{tool.name}"
        info = self.gateway.tools.register(canonical, tool.description or "", tool.input_schema)
        if info["status"] == "poisoned":
            self.gateway.alert("critical", "tool_integrity",
                               f"tool {canonical} looks poisoned and was hidden: {'; '.join(info['reasons'][:2])}",
                               session_id=self.session_id, agent=self.agent, tool=canonical)
        elif info["status"] == "changed":
            self.gateway.alert("warning", "tool_integrity",
                               f"tool {canonical} changed since it was approved; calls need approval until trusted",
                               session_id=self.session_id, agent=self.agent, tool=canonical)

    def _hidden(self, canonical: str) -> bool:
        st = self.gateway.tools.status(canonical)
        if st and st[0] == "poisoned":
            return True
        return self.hide_unauthorized and not self._authorized(canonical)

    # ------------------------------------------------------------------ MCP handlers
    def _authorized(self, canonical: str) -> bool:
        a = self.config.agent(self.agent)
        return bool(a and _glob_any(canonical, a.allow_tools) and not _glob_any(canonical, a.deny_tools))

    def _exposed_tool(self, name: str, server: str, tool: types.Tool) -> types.Tool:
        schema = copy.deepcopy(dict(tool.input_schema or {"type": "object", "properties": {}}))
        props = dict(schema.get("properties") or {})
        props[PURPOSE_ARG] = {
            "type": "string",
            "description": "Required by Heimdall: one sentence on why you are making this call.",
        }
        schema["properties"] = props
        if self.config.require_purpose:
            schema["required"] = list(dict.fromkeys([*(schema.get("required") or []), PURPOSE_ARG]))
        desc = (tool.description or "").strip()
        return tool.model_copy(update={
            "name": name,
            "description": f"{desc}\n\n[Guarded by Heimdall: calls are policy-checked and audited. Server: {server}]".strip(),
            "input_schema": schema,
            # Heimdall may redact results, which would break a structured output
            # contract, so the proxied tool is exposed as text-only.
            "output_schema": None,
        })

    async def list_tools(self, ctx: Any, params: Any) -> types.ListToolsResult:
        tools = []
        for name, (server, tool) in self.tools.items():
            if self._hidden(f"{server}.{tool.name}"):
                continue
            tools.append(self._exposed_tool(name, server, tool))
        tools.append(types.Tool(
            name=REPORT_TOOL,
            description=("Report what you did during this task, in your own words. Heimdall compares the report "
                         "with the actions it observed. Call this once when you finish."),
            input_schema={"type": "object", "properties": {"summary": {"type": "string"}}, "required": ["summary"]},
        ))
        return types.ListToolsResult(tools=tools)

    async def call_tool(self, ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        args = dict(params.arguments or {})

        if params.name == REPORT_TOOL:
            self.gateway.audit_claim(self.session_id, str(args.get("summary", "")), agent=self.agent)
            return _text_result("Activity report recorded by Heimdall.")

        purpose = args.pop(PURPOSE_ARG, None)
        if params.name in self.tools:
            server, tool = self.tools[params.name]
            canonical, tool_name = f"{server}.{tool.name}", tool.name
        else:  # still goes through the gateway so the attempt is logged (and blocked)
            server, _, tool_name = params.name.partition(SEP)
            canonical = f"{server}.{tool_name}" if tool_name else f"unknown.{params.name}"

        req = ActionRequest(agent=self.agent, tool=canonical, arguments=args, purpose=purpose,
                            session_id=self.session_id)

        async def executor(a: dict[str, Any]) -> types.CallToolResult:
            client = self.clients.get(server)
            if client is None or params.name not in self.tools:
                raise LookupError(f"no such tool: {params.name}")
            return await client.call_tool(tool_name, a)

        outcome = await self.gateway.execute(req, executor, self.adapter)
        if outcome.status in (ActionStatus.BLOCKED, ActionStatus.DENIED):
            return _text_result(f"[Heimdall] {outcome.message}", is_error=True)
        if isinstance(outcome.result, types.CallToolResult):
            return outcome.result
        return _text_result(f"[Heimdall] {outcome.message}", is_error=outcome.status != ActionStatus.SUCCEEDED)

    def build_server(self) -> Server:
        return Server(
            "heimdall",
            version="0.1.0",
            instructions=(
                "All tools are routed through Heimdall, an action-control gateway. Give an honest "
                f"'{PURPOSE_ARG}' with every call. Some actions need human approval and may take a while. "
                f"When you finish, call {REPORT_TOOL} with a truthful summary of what you did."
            ),
            on_list_tools=self.list_tools,
            on_call_tool=self.call_tool,
        )


async def run_stdio_proxy(config: HeimdallConfig, agent: str, session_id: str | None = None) -> None:
    from mcp.server.stdio import stdio_server

    import os

    level = os.environ.get("HEIMDALL_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(level=level, stream=sys.stderr, format="[heimdall] %(message)s")
    proxy = HeimdallProxy(config, agent, session_id=session_id)
    async with proxy.connect():
        log.info("session %s: agent=%s, %d tools from %s", proxy.session_id, agent, len(proxy.tools), list(proxy.clients))
        server = proxy.build_server()
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())
