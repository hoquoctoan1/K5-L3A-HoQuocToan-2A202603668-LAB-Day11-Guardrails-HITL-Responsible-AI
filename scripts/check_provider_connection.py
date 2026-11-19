"""CP1 only: one small request per configured provider; never print secrets."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from core import config


def main() -> int:
    import os
    from openai import OpenAI

    failed = False
    targets = [("Blue/Liquid", config.get_liquid_api_key(),
                config.get_blue_model(), config.LIQUID_BASE_URL)]
    red = config.get_red_provider()
    if red == config.PROVIDER_GEMINI:
        targets.append(("Red/Gemini", os.environ.get("GOOGLE_API_KEY", ""),
                        config.get_red_model(),
                        "https://generativelanguage.googleapis.com/v1beta/openai/"))
    else:
        targets.append(("Red/OpenAI", config.get_openai_api_key(),
                        config.get_red_model(), None))

    for label, key, model, base_url in targets:
        if not config.api_key_is_configured(key):
            print(f"SKIP {label}: fill the provider key directly in .env.")
            continue
        kwargs = {"api_key": key, "max_retries": 0, "timeout": 20.0}
        if label == "Blue/Liquid":
            kwargs.update(config.blue_client_kwargs())
        elif base_url:
            kwargs["base_url"] = base_url
        try:
            with OpenAI(**kwargs) as client:
                response = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": "Reply with OK."}],
                    max_tokens=128,
                )
            if not response.choices or not response.choices[0].message.content:
                reason = response.choices[0].finish_reason if response.choices else "no_choices"
                print(f"FAIL {label}: empty completion, finish_reason={reason}.")
                failed = True
            else:
                print(f"PASS {label}: received a completion.")
        except Exception as exc:
            # Exception bodies can contain request details: print only type/status.
            status = getattr(exc, "status_code", None)
            print(f"FAIL {label}: {type(exc).__name__}, HTTP status={status}.")
            failed = True
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
