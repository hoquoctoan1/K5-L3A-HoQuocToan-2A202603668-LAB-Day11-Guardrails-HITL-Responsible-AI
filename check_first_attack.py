


import asyncio
import sys
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parent / "src"),
)

from agents.agent import create_red_agent_default
from attacks.attacks import adversarial_prompts, run_attacks


async def main():
    agent, runner = create_red_agent_default()

    results = await run_attacks(
        agent,
        runner,
        prompts=[adversarial_prompts[0]],
        target_name="red_default",
        save_json=False,
    )

    result = results[0]

    print("\nKẾT QUẢ:")
    print("Có lỗi:", result.get("error"))
    print("Có lộ secret:", result["leaked"])
    print("Lớp xử lý:", result["layer"])
    print("Phản hồi:", result["response_preview"])


asyncio.run(main())