"""OpenShield AI chat interface."""

from modules.ai.client import ask_ai


def ask_security_ai(question, context=None):
    prompt = f"""
You are OpenShield AI, a defensive cybersecurity assistant.

User question:
{question}

Security context:
{context or "No additional context provided."}

Provide a clear defensive cybersecurity answer.
"""

    return ask_ai(prompt)
