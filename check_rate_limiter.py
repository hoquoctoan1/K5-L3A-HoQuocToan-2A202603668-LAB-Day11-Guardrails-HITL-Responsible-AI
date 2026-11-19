import asyncio
import sys
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, "src")

from assignment.rate_limiter import RateLimitPlugin


async def main():
    plugin = RateLimitPlugin(
        max_requests=3,
        window_seconds=60,
    )

    user_a = SimpleNamespace(user_id="user_a")
    user_b = SimpleNamespace(user_id="user_b")

    # Controlled clock
    # (Đồng hồ giả để kiểm tra, không cần chờ thực tế.)
    with patch("assignment.rate_limiter.time.time") as clock:
        clock.return_value = 1000

        # Người A: ba lượt đầu được cho qua.
        for _ in range(3):
            result = await plugin.on_user_message_callback(
                invocation_context=user_a,
                user_message=None,
            )
            assert result is None

        # Người A: lượt thứ tư bị chặn.
        result = await plugin.on_user_message_callback(
            invocation_context=user_a,
            user_message=None,
        )
        assert result is not None
        assert plugin.blocked_count == 1

        # Người B vẫn còn lượt riêng.
        result = await plugin.on_user_message_callback(
            invocation_context=user_b,
            user_message=None,
        )
        assert result is None

        # Sau 61 giây, các lượt cũ của A hết hạn.
        clock.return_value = 1061

        result = await plugin.on_user_message_callback(
            invocation_context=user_a,
            user_message=None,
        )
        assert result is None

    assert plugin.total_count == 6
    assert plugin.blocked_count == 1

    print("Đạt: giới hạn theo từng người và mở lại khi hết hạn.")


asyncio.run(main())
