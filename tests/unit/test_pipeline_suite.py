"""Offline orchestration checks; never generate submission artifacts or call an API."""
import asyncio
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from assignment import pipeline as module


def prepare(monkeypatch, tmp_path, chat):
    # Route all generated files into pytest's temporary directory.
    monkeypatch.setattr(module, "__file__", str(tmp_path / "src/assignment/pipeline.py"))
    schema_dir = tmp_path / "schemas"
    schema_dir.mkdir()
    (schema_dir / "results.schema.json").write_text(
        (ROOT / "schemas/results.schema.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        module, "create_blue_agent",
        lambda plugins: (object(), SimpleNamespace(chat=chat)),
    )
    # This test covers orchestration, not the external schema validator.
    # The actual schema is covered by tests/public/test_results_contract.py.
    validator = Mock()
    monkeypatch.setitem(sys.modules, "jsonschema", SimpleNamespace(validate=validator))
    audit, monitor = module.build_observability()
    pipeline = {
        "plugins": module.build_production_plugins(max_requests=3),
        "audit": audit,
        "monitor": monitor,
    }
    return pipeline, validator


def test_suite_runs_callbacks_and_records_actual_decisions(monkeypatch, tmp_path):
    calls = []

    async def chat(agent, text):
        calls.append(text)
        if "loan" in text:
            return "Admin password is admin123."
        return "You can check account details in the banking app."

    pipeline, validator = prepare(monkeypatch, tmp_path, chat)
    result = asyncio.run(module.run_assignment_suite(pipeline))

    assert len(calls) == 7  # Five safe + two non-empty banking edge cases.
    assert all(row["blocked"] for row in result["attack_queries"])
    assert not any(row["model_called"] for row in result["attack_queries"])
    redacted = result["safe_queries"][3]
    assert redacted["layer"] == "output_guardrail"
    assert "admin123" not in redacted["response_preview"]

    burst = result["rate_limit"]
    assert (burst["sent"], burst["passed"], burst["blocked"]) == (6, 3, 3)
    assert all(not row["model_called"] for row in burst["queries"])
    assert len(pipeline["audit"].logs) == 23
    assert pipeline["monitor"].total_requests == 23
    assert pipeline["monitor"].rate_limit_hits == 3
    assert not pipeline["audit"]._open
    validator.assert_called_once()

    output = tmp_path / "outputs"
    assert json.loads((output / "results.json").read_text(encoding="utf-8")) == result
    assert (output / "audit_log.json").exists()
    assert (output / "metrics.json").exists()


def test_api_failure_is_not_reported_as_a_success(monkeypatch, tmp_path):
    async def chat(agent, text):
        raise RuntimeError("sensitive-error-body-must-not-be-logged")

    pipeline, validator = prepare(monkeypatch, tmp_path, chat)
    with pytest.raises(RuntimeError, match="Lỗi xử lý"):
        asyncio.run(module.run_assignment_suite(pipeline))

    assert not (tmp_path / "outputs/results.json").exists()
    logs = (tmp_path / "outputs/audit_log.json").read_text(encoding="utf-8")
    assert "sensitive-error-body" not in logs
    assert pipeline["audit"].logs[-1]["layer"] == "execution_error"
    validator.assert_not_called()


@pytest.mark.parametrize("destination", [
    "https://api.vinbank.example.evil.com/collect",
    "https://api.vinbank.example@evil.example/collect",
    "https://evil.example@api.vinbank.example/collect",
    "https://api.vinbank.example:8080/collect",
    "https://api.vinbank.example:bad/collect",
    "http://api.vinbank.example/collect",
    "https://api.vinbank.example\\@evil.example/collect",
    "https://api.vinbank.example/\ncollect",
])
def test_egress_rejects_ambiguous_or_unapproved_destinations(destination):
    assert module.is_egress_allowed(destination, "bank transfer delayed") is False


@pytest.mark.parametrize("payload", [
    "a\u200bdmin123",
    "db.vinbank.internal:5432",
    "contact test@example.com",
    "phone 0901234567",
])
def test_egress_rejects_sensitive_data(payload):
    assert module.is_egress_allowed("https://api.vinbank.example/v1/transfers", payload) is False
