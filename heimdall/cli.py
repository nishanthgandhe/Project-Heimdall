"""`heimdall` command line."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import anyio

from .audit import AuditLog
from .config import load_config


def _config(args: argparse.Namespace):
    cfg = load_config(args.config)
    if getattr(args, "approval_timeout", None):
        cfg.approval_timeout = float(args.approval_timeout)
    return cfg


def _demo_path(cfg) -> None:
    # demo/ lives next to heimdall.yaml; make it importable.
    if str(cfg.base_dir) not in sys.path:
        sys.path.insert(0, str(cfg.base_dir))


def cmd_proxy(args: argparse.Namespace) -> None:
    from .mcp_proxy import run_stdio_proxy

    anyio.run(run_stdio_proxy, _config(args), args.agent, args.session_id)


def cmd_dashboard(args: argparse.Namespace) -> None:
    import uvicorn

    from .dashboard.app import create_app

    cfg = _config(args)
    print(f"Heimdall dashboard: http://{args.host}:{args.port}  (database {cfg.database})")
    uvicorn.run(create_app(cfg), host=args.host, port=args.port, log_level="warning")


def cmd_demo(args: argparse.Namespace) -> None:
    cfg = _config(args)
    _demo_path(cfg)
    from demo import scenarios

    if args.list:
        for s in scenarios.SCENARIOS:
            print(f"  {s.name:<22} {s.title}")
        for name, desc in scenarios.EXTRA.items():
            print(f"  {name:<22} {desc}")
        return
    names = args.scenarios or [s.name for s in scenarios.SCENARIOS]
    for n in names:
        if n not in scenarios.EXTRA:
            scenarios.get(n)  # fail early on typos
    from demo.setup_sandbox import reset_sandbox

    if not (cfg.base_dir / "demo" / "sandbox").exists():
        reset_sandbox()
    anyio.run(scenarios.run, names, cfg, Path(args.config or "heimdall.yaml").resolve(), args.approvals,
              cfg.approval_timeout if args.approval_timeout else 90.0, args.pace)


def cmd_agent(args: argparse.Namespace) -> None:
    cfg = _config(args)
    _demo_path(cfg)
    from demo.llm_agent import run_llm_agent
    from demo.setup_sandbox import reset_sandbox

    if not (cfg.base_dir / "demo" / "sandbox").exists():
        reset_sandbox()
    anyio.run(lambda: run_llm_agent(cfg, Path(args.config or "heimdall.yaml").resolve(), args.task, args.model,
                                    args.agent, approval_timeout=cfg.approval_timeout, provider=args.provider,
                                    base_url=args.base_url))


def cmd_verify(args: argparse.Namespace) -> None:
    cfg = _config(args)
    report = AuditLog(cfg.database).verify(args.expect_head)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(f"{'INTACT' if report.ok else 'BROKEN'}: {report.entries} entries, head {report.head}")
        print("hashes are keyed (HMAC)" if report.keyed else "hashes are unkeyed; set HEIMDALL_AUDIT_KEY for stronger protection")
        for p in report.problems:
            print(f"  {'entry ' + str(p['seq']) + ': ' if p['seq'] else ''}{p['problem']}")
    sys.exit(0 if report.ok else 1)


def cmd_sessions(args: argparse.Namespace) -> None:
    cfg = _config(args)
    for s in AuditLog(cfg.database).sessions():
        print(f"  {s['session_id']:<40} {s['agent']:<16} {s['events']:>5} events")


def cmd_claim(args: argparse.Namespace) -> None:
    from .gateway import Gateway

    cfg = _config(args)
    report = Gateway(cfg).audit_claim(args.session, args.text, args.agent)
    print(f"{report['verdict'].upper()} (score {report['score']})")
    for f in report["findings"]:
        print(f"  - [{f['type']}/{f['severity']}] {f['message']}")


def cmd_reset(args: argparse.Namespace) -> None:
    cfg = _config(args)
    if not args.yes:
        answer = input(f"Delete {cfg.database} and reset the demo sandbox? [y/N] ")
        if answer.strip().lower() not in ("y", "yes"):
            print("Nothing changed.")
            return
    for suffix in ("", "-wal", "-shm"):
        Path(str(cfg.database) + suffix).unlink(missing_ok=True)
    _demo_path(cfg)
    from demo.setup_sandbox import reset_sandbox

    print(f"Audit log cleared. Sandbox reset at {reset_sandbox()}.")


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", "-c", default=None, help="path to heimdall.yaml (default: ./heimdall.yaml)")
    p = argparse.ArgumentParser(prog="heimdall", description="Action-control gateway and audit trail for AI agents.")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("proxy", parents=[common], help="run the MCP proxy on stdio for one agent")
    s.add_argument("--agent", required=True, help="agent identity from the config")
    s.add_argument("--session-id", default=None)
    s.add_argument("--approval-timeout", type=float, default=None)
    s.set_defaults(func=cmd_proxy)

    s = sub.add_parser("dashboard", parents=[common], help="start the web dashboard")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8477)
    s.set_defaults(func=cmd_dashboard)

    s = sub.add_parser("demo", parents=[common], help="run scripted attack/deception scenarios")
    s.add_argument("scenarios", nargs="*", help="scenario names (default: all). See --list")
    s.add_argument("--list", action="store_true")
    s.add_argument("--approvals", choices=["auto", "dashboard", "deny"], default="auto",
                   help="auto: a scripted reviewer decides; dashboard: you decide in the browser; deny: deny all")
    s.add_argument("--approval-timeout", type=float, default=None)
    s.add_argument("--pace", type=float, default=0, help="seconds to pause after each step (for live demos and recording)")
    s.set_defaults(func=cmd_demo)

    s = sub.add_parser("agent", parents=[common], help="run a real LLM agent through Heimdall (any provider)")
    s.add_argument("--task", default=None)
    s.add_argument("--provider", default=None,
                   help="anthropic, openai, groq, gemini, openrouter, together, mistral, deepseek, xai, ollama, "
                        "lmstudio, custom (default: whichever API key is set)")
    s.add_argument("--model", default=None)
    s.add_argument("--base-url", default=None, help="any OpenAI-compatible endpoint (implies --provider custom)")
    s.add_argument("--agent", default="llm-agent")
    s.add_argument("--approval-timeout", type=float, default=None)
    s.set_defaults(func=cmd_agent)

    s = sub.add_parser("verify", parents=[common], help="check the audit trail's hash chain")
    s.add_argument("--expect-head", default=None, help="a head hash you saved earlier")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("sessions", parents=[common], help="list recorded sessions")
    s.set_defaults(func=cmd_sessions)

    s = sub.add_parser("claim", parents=[common], help="check an agent's claim against a session's observed actions")
    s.add_argument("--session", required=True)
    s.add_argument("--text", required=True)
    s.add_argument("--agent", default="unknown")
    s.set_defaults(func=cmd_claim)

    s = sub.add_parser("reset", parents=[common], help="delete the audit log and reset the demo sandbox")
    s.add_argument("--yes", "-y", action="store_true")
    s.set_defaults(func=cmd_reset)
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
