import sys
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parent / "src"),
)

from assignment.pipeline import (
    build_production_plugins,
    build_observability,
)
from assignment.rate_limiter import RateLimitPlugin
from assignment.audit_log import AuditLogPlugin
from assignment.monitoring import MonitoringAlert
from guardrails.input_guardrails import InputGuardrailPlugin
from guardrails.output_guardrails import OutputGuardrailPlugin


plugins = build_production_plugins(
    max_requests=2,
    window_seconds=30,
    use_llm_judge=False,
)

assert len(plugins) == 3

assert isinstance(plugins[0], RateLimitPlugin)
assert isinstance(plugins[1], InputGuardrailPlugin)
assert isinstance(plugins[2], OutputGuardrailPlugin)

assert plugins[0].max_requests == 2
assert plugins[0].window_seconds == 30
assert plugins[2].use_llm_judge is False

audit, monitor = build_observability()

assert isinstance(audit, AuditLogPlugin)
assert isinstance(monitor, MonitoringAlert)

print("Đạt: đúng thành phần, thứ tự và tham số cấu hình.")