import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from heimdall.config import load_config  # noqa: E402


@pytest.fixture
def config(tmp_path, monkeypatch):
    """The real heimdall.yaml, pointed at a throwaway database and sandbox."""
    monkeypatch.delenv("HEIMDALL_AUDIT_KEY", raising=False)
    from demo.setup_sandbox import reset_sandbox

    sandbox = reset_sandbox(tmp_path / "sandbox")
    monkeypatch.setenv("HEIMDALL_SANDBOX", str(sandbox))
    cfg = load_config(ROOT / "heimdall.yaml")
    cfg.database = tmp_path / "heimdall.db"
    cfg.approval_timeout = 2
    return cfg
