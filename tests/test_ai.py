import pytest

from core import ai
from core.ai import AIError, get_provider


def test_default_is_ollama(monkeypatch):
    monkeypatch.setattr(ai.settings, "ai_provider", "ollama")
    assert get_provider().name == "ollama"


def test_anthropic_selected(monkeypatch):
    monkeypatch.setattr(ai.settings, "ai_provider", "anthropic")
    assert get_provider().name == "anthropic"


def test_unknown_provider(monkeypatch):
    monkeypatch.setattr(ai.settings, "ai_provider", "xyz")
    with pytest.raises(AIError):
        get_provider()


def test_anthropic_requires_key(monkeypatch):
    monkeypatch.setattr(ai.settings, "anthropic_api_key", "")
    with pytest.raises(AIError):
        ai.AnthropicProvider().chat("s", [{"role": "user", "content": "x"}])
