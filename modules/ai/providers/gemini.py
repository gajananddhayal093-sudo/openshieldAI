"""Gemini AI provider adapter."""

import requests

from modules.ai.config import GEMINI_API_KEY, MODEL, REQUEST_TIMEOUT


class GeminiProvider:
    def __init__(self):
        self.api_key = GEMINI_API_KEY
        self.model = MODEL or "gemini-1.5-flash"

    def ask(self, prompt: str) -> str:
        if not self.api_key:
            return (
                "🧠 AI Analysis unavailable.\n"
                "Gemini API key is not configured."
            )

        url = (
            "https://generativelanguage.googleapis.com/"
            f"v1beta/models/{self.model}:generateContent"
            f"?key={self.api_key}"
        )

        payload = {
            "contents": [
                {
                    "parts": [
                        {
                            "text": prompt
                        }
                    ]
                }
            ]
        }

        try:
            response = requests.post(
                url,
                json=payload,
                timeout=REQUEST_TIMEOUT
            )

            if response.status_code == 400:
                return (
                    "🧠 AI Analysis unavailable.\n"
                    "Invalid Gemini API key or request."
                )

            response.raise_for_status()

            data = response.json()

            return (
                data.get("candidates", [{}])[0]
                .get("content", {})
                .get("parts", [{}])[0]
                .get("text", "No AI response")
            )

        except requests.Timeout:
            return (
                "🧠 AI Analysis unavailable.\n"
                "Gemini request timed out."
            )

        except Exception:
            return (
                "🧠 AI Analysis unavailable.\n"
                "Provider connection failed."
            )
