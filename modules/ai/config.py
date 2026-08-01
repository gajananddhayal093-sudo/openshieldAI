"""AI configuration."""

import os

from modules.utils.env_loader import load_env

load_env()

PROVIDER = os.getenv(
    "OPENSHIELD_AI_PROVIDER",
    "none"
)

MODEL = os.getenv(
    "OPENSHIELD_AI_MODEL",
    ""
)

GEMINI_API_KEY = os.getenv(
    "GEMINI_API_KEY",
    ""
)

REQUEST_TIMEOUT = int(
    os.getenv(
        "OPENSHIELD_AI_TIMEOUT",
        "30"
    )
)
