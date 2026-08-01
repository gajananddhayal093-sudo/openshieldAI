"""OpenShield AI security assistant."""

from modules.ai.client import ask_ai
from modules.ai.prompts import SECURITY_ANALYST_PROMPT


def analyze_security_report(report):
    prompt = f"""
{SECURITY_ANALYST_PROMPT}

Security Report:

{report}
"""

    return ask_ai(prompt)
