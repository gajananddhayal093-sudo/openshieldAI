def generate_intelligence(summary):
    risk = str(summary.get("risk", "UNKNOWN")).upper()
    score = summary.get("score", 0)
    findings = summary.get("findings_count", 0)

    if risk == "CRITICAL":
        priority = "Immediate action required"
    elif risk == "HIGH":
        priority = "Fix high risk issues first"
    elif risk == "MEDIUM":
        priority = "Review and harden security"
    else:
        priority = "Security posture looks stable"

    return {
        "analysis": (
            f"Risk level is {risk} with score {score}/100. "
            f"Detected findings: {findings}."
        ),
        "priority": priority,
        "next_steps": [
            "Review findings",
            "Apply recommended fixes",
            "Run another security scan"
        ]
    }
