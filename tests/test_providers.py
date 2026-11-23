import pytest

from demo.llm_agent import PRESETS, _clean_schema, choose_provider

KEYS = [p["env"] for p in PRESETS.values() if p["env"]] + ["HEIMDALL_PROVIDER", "HEIMDALL_MODEL", "HEIMDALL_LLM_BASE_URL"]


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for k in KEYS:
        monkeypatch.delenv(k, raising=False)


def test_no_key_gives_helpful_exit():
    with pytest.raises(SystemExit) as e:
        choose_provider(None, None, None)
    assert "ollama" in str(e.value).lower() and "heimdall demo" in str(e.value)


def test_auto_picks_provider_from_key(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    provider, base, model, key = choose_provider(None, None, None)
    assert provider == "openai" and model and key == "sk-test" and base is None


def test_anthropic_preferred_when_both(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ak-test")
    assert choose_provider(None, None, None)[0] == "anthropic"


def test_provider_without_default_model_requires_model(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "g")
    with pytest.raises(SystemExit) as e:
        choose_provider("groq", None, None)
    assert "--model" in str(e.value)
    assert choose_provider("groq", None, "some-model")[1].startswith("https://api.groq.com")


def test_ollama_needs_no_key():
    provider, base, model, key = choose_provider("ollama", None, None)
    assert base.startswith("http://localhost:11434") and model == "llama3.1"


def test_custom_base_url(monkeypatch):
    monkeypatch.setenv("HEIMDALL_LLM_API_KEY", "k")
    provider, base, model, _ = choose_provider(None, "http://my-gateway:4000/v1", "m")
    assert provider == "custom" and base == "http://my-gateway:4000/v1"


def test_clean_schema_drops_titles():
    out = _clean_schema({"title": "X", "properties": {"a": {"title": "A", "type": "string"}}})
    assert out == {"properties": {"a": {"type": "string"}}}
