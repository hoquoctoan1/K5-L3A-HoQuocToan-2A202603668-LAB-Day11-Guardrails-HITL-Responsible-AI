import asyncio
import sys
from types import SimpleNamespace

sys.path.insert(0, "src")

from google.genai import types
from guardrails.output_guardrails import OutputGuardrailPlugin


async def main():
    plugin = OutputGuardrailPlugin(use_llm_judge=False)

    response = SimpleNamespace(
        content=types.Content(
            role="model",
            parts=[
                types.Part.from_text(
                    text="Admin password is admin123."
                )
            ],
        )
    )

    result = await plugin.after_model_callback(
        callback_context=None,
        llm_response=response,
    )

    text = "".join(
        part.text or ""
        for part in result.content.parts
    )

    assert "admin123" not in text
    assert "[REDACTED]" in text
    assert plugin.total_count == 1
    assert plugin.redacted_count == 1

    # Safe response
    # (Phản hồi không có thông tin cần che.)
    safe_text = "The savings interest rate is available at the bank."

    safe_response = SimpleNamespace(
        content=types.Content(
            role="model",
            parts=[types.Part.from_text(text=safe_text)],
        )
    )

    safe_result = await plugin.after_model_callback(
        callback_context=None,
        llm_response=safe_response,
    )

    actual = "".join(
        part.text or ""
        for part in safe_result.content.parts
    )

    assert actual == safe_text
    assert plugin.total_count == 2
    assert plugin.redacted_count == 1

    print("Đạt: secret được che, phản hồi bình thường được giữ nguyên.")


asyncio.run(main())