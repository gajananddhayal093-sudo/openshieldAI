"""AI provider router."""

from modules.ai.config import PROVIDER
from modules.ai.providers.gemini import GeminiProvider


def get_provider():
    if PROVIDER == "gemini":
        return GeminiProvider()

    return None


def ask_ai(prompt: str):
    try:
        provider = get_provider()

        if provider is None:
            return (
                "🧠 AI Analysis unavailable.\n"
                "No AI provider configured."
            )

        return provider.ask(prompt)

    except Exception as error:
        return (
            "🧠 AI Analysis unavailable.\n\n"
            "Reason: "
            f"{error}"
        )
