"""Simple .env loader without external dependency."""

from pathlib import Path
import os


def load_env(path=".env"):
    env_file = Path(path)

    if not env_file.exists():
        return

    for line in env_file.read_text().splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        if "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(
                key.strip(),
                value.strip()
            )
