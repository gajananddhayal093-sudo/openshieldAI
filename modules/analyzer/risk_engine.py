def calculate_risk(findings):
    missing = sum(
        1 for item in findings
        if item.get("status") == "missing"
    )

    score = 0

    for item in findings:
        severity = str(item.get("severity", "")).upper()

        if severity == "CRITICAL":
            score += 50
        elif severity == "HIGH":
            score += 25
        elif severity == "MEDIUM":
            score += 10
        elif severity == "LOW":
            score += 5

    score = min(score, 100)

    if score >= 70:
        risk = "CRITICAL"
    elif score >= 40:
        risk = "HIGH"
    elif score >= 15:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    highest = None
    for item in findings:
        sev = str(item.get("severity", "")).upper()
        if sev in severities:
            if highest is None or severities.index(sev) > severities.index(highest):
                highest = sev

    if highest in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        risk = highest

    return {
        "risk": risk,
        "score": score,
        "missing_headers": missing,
        "findings": len(findings),
        "highest_severity": highest,
    }
