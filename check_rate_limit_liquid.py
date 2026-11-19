import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(
    0,
    str(Path(__file__).resolve().parent / "src"),
)

from openai import OpenAI
from core import config
from assignment.rate_limiter import RateLimitPlugin


async def main():
    if not config.api_key_is_configured(
        config.get_liquid_api_key()
    ):
        print("Thiếu LIQUID_API_KEY. Hãy điền vào .env.")
        return

    limiter = RateLimitPlugin(
        max_requests=2,
        window_seconds=60,
    )

    context = SimpleNamespace(user_id="student_test")

    # Dùng client tương thích OpenAI để kết nối Liquid.
    # Endpoint và key được lấy từ cấu hình Blue của repo.
    with OpenAI(
        **config.blue_client_kwargs(),
        timeout=20.0,
        max_retries=0,
    ) as client:

        for index in range(1, 4):
            blocked = await limiter.on_user_message_callback(
                invocation_context=context,
                user_message=None,
            )

            if blocked is not None:
                print(f"Lượt {index}: bị chặn, không gọi API.")
                continue

            print(f"Lượt {index}: được phép, đang gọi Liquid.")

            try:
                response = client.chat.completions.create(
                    model=config.get_blue_model(),
                    messages=[
                        {
                            "role": "user",
                            "content": "Reply with OK.",
                        }
                    ],
                    max_tokens=128,
                )

                if (
                    response.choices
                    and response.choices[0].message.content
                ):
                    print("Liquid đã trả lời.")
                else:
                    print("API trả về nhưng không có văn bản.")

            except Exception as exc:
                status = getattr(exc, "status_code", None)
                print(
                    f"Lỗi API: {type(exc).__name__}, "
                    f"HTTP={status}"
                )

    assert limiter.total_count == 3
    assert limiter.blocked_count == 1

    print("Đạt kiểm tra giới hạn: 3 lượt đến, 1 lượt bị chặn.")


asyncio.run(main())
