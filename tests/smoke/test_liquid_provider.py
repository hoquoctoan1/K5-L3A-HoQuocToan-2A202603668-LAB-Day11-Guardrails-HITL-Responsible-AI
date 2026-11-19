"""Offline checks for the CP1 provider customization; no real credentials."""
import asyncio
from pathlib import Path
import sys

import httpx
import pytest
from openai import OpenAI

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from core import config
from core.openai_runtime import create_blue_pair, create_openai_pair
from core.utils import chat_with_agent


def test_blue_request_uses_liquid_without_openrouter(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setenv("LIQUID_API_KEY", "liquid_test_dummy")
    monkeypatch.delenv("LIQUID_BASE_URL", raising=False)
    monkeypatch.delenv("LIQUID_MODEL", raising=False)
    agent, runner = create_blue_pair(name="test", instruction="test", app_name="test")

    def respond(request):
        import json
        assert str(request.url) == "https://api.liquid.ai/openai/v1/chat/completions"
        assert request.headers["authorization"] == "Bearer liquid_test_dummy"
        assert json.loads(request.content)["model"] == "lfm3-1.7b"
        return httpx.Response(200, json={
            "id": "test", "object": "chat.completion", "created": 0,
            "model": "lfm3-1.7b", "choices": [{"index": 0, "finish_reason": "stop",
                "message": {"role": "assistant", "content": "OK"}}],
        })

    with OpenAI(**runner.client_kwargs, http_client=httpx.Client(
        transport=httpx.MockTransport(respond))) as client:
        runner._client = lambda: client
        assert asyncio.run(chat_with_agent(agent, runner, "Hello")) == ("OK", None)
    assert runner.provider == "liquid"


@pytest.mark.parametrize("key", ["", "your-liquid-api-key-here", "sk-..."])
def test_blue_rejects_missing_key_even_with_other_keys(monkeypatch, key):
    monkeypatch.setenv("LIQUID_API_KEY", key)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-dummy")
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test-dummy")
    with pytest.raises(ValueError, match="LIQUID_API_KEY"):
        config.blue_client_kwargs()


def test_red_keeps_starter_openai_config(monkeypatch):
    monkeypatch.setenv("RED_TEAM_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-red-test-dummy")
    monkeypatch.delenv("OPENAI_MODEL", raising=False)
    _, runner = create_openai_pair(name="test", instruction="test", app_name="test")
    assert runner.provider == "openai"
    assert runner.model == "gpt-4o-mini"
    assert runner.client_kwargs == {"api_key": "sk-red-test-dummy"}
