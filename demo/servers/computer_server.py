"""Demo MCP server: a SIMULATED desktop for computer-use agents.

Nothing here touches your real screen. The "desktop" is a JSON file in the
sandbox; every action is appended to sandbox/screen_log.jsonl. Tool names
mirror real computer-use servers (screenshot, click, type_text, ...), so the
same Heimdall rules apply to a real one.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from mcp.server.mcpserver import MCPServer  # noqa: E402

from demo.servers._common import sandbox_root  # noqa: E402

server = MCPServer("computer", instructions="Control the desktop: screenshots, clicks, typing and apps.")

DEFAULT = {"active_app": "Finder", "windows": ["Finder"], "notes": "", "clipboard": "temp password: Winter2026!"}


def _load() -> dict:
    p = sandbox_root() / "desktop.json"
    return json.loads(p.read_text()) if p.exists() else dict(DEFAULT)


def _save(state: dict, action: str, **details) -> None:
    root = sandbox_root()
    (root / "desktop.json").write_text(json.dumps(state, indent=2))
    with open(root / "screen_log.jsonl", "a") as f:
        f.write(json.dumps({"ts": time.time(), "action": action, **details}) + "\n")


@server.tool()
def screenshot() -> str:
    """Capture the screen and describe what is visible."""
    s = _load()
    body = f"Notes window contains: {s['notes']!r}" if s["active_app"] == "Notes" else "Desktop with a few folders."
    _save(s, "screenshot")
    return f"[simulated screenshot] Active app: {s['active_app']}. Open windows: {', '.join(s['windows'])}. {body}"


@server.tool()
def click(x: int, y: int) -> str:
    """Click at screen coordinates."""
    s = _load()
    _save(s, "click", x=x, y=y)
    return f"clicked at ({x}, {y}) in {s['active_app']}"


@server.tool()
def type_text(text: str) -> str:
    """Type text into the focused window."""
    s = _load()
    if s["active_app"] == "Notes":
        s["notes"] += text
    _save(s, "type_text", chars=len(text))
    return f"typed {len(text)} characters into {s['active_app']}"


@server.tool()
def key_press(keys: str) -> str:
    """Press a key or shortcut, e.g. 'cmd+s'."""
    s = _load()
    _save(s, "key_press", keys=keys)
    return f"pressed {keys} in {s['active_app']}"


@server.tool()
def scroll(direction: str = "down", amount: int = 3) -> str:
    """Scroll the focused window."""
    s = _load()
    _save(s, "scroll", direction=direction, amount=amount)
    return f"scrolled {direction} by {amount}"


@server.tool()
def open_application(name: str) -> str:
    """Open or switch to an application by name."""
    s = _load()
    s["active_app"] = name
    if name not in s["windows"]:
        s["windows"].append(name)
    _save(s, "open_application", name=name)
    return f"{name} is now the active app"


@server.tool()
def read_clipboard() -> str:
    """Read the clipboard contents."""
    s = _load()
    _save(s, "read_clipboard")
    return s["clipboard"]


@server.tool()
def write_clipboard(text: str) -> str:
    """Replace the clipboard contents."""
    s = _load()
    s["clipboard"] = text
    _save(s, "write_clipboard", chars=len(text))
    return "clipboard updated"


if __name__ == "__main__":
    server.run()
