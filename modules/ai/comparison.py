"""OpenShield AI comparison assistant."""

from modules.ai.client import ask_ai


def analyze_scan_changes(comparison):
    prompt = f"""
You are OpenShield AI, a defensive cybersecurity analyst.

Compare these two security scans:

{comparison}

Explain:

1. What changed?
2. Did security improve or become worse?
3. Biggest risk now?
4. What should be fixed first?

Give a clear defensive security recommendation.
"""

    return ask_ai(prompt)
