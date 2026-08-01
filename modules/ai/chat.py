"""OpenShield AI chat interface."""

from modules.ai.client import ask_ai
from modules.analyzer.report_writer import load_report


def get_latest_security_context():
    try:
        report = load_report(1)

        if not report:
            return "No security report available."

        return report.get("summary", report)

    except Exception as error:
        return f"Report context unavailable: {error}"


def ask_security_ai(question, context=None):
    if context is None:
        context = get_latest_security_context()

    prompt = f"""
You are OpenShield AI, a defensive cybersecurity assistant.

User question:
{question}

Security context:
{context}

Provide a clear defensive cybersecurity answer.

Focus on:
- Biggest risk
- First fix
- Priority actions
"""

    return ask_ai(prompt)
