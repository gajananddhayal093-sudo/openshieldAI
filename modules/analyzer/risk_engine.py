from modules.analyzer.severity import severity_rank


RISK_LEVELS = (
    (80, "CRITICAL"),
    (60, "HIGH"),
    (30, "HIGH"),
    (15, "MEDIUM"),
    (1, "LOW"),
    (0, "LOW"),
)


def calculate_risk(findings):
    if not findings:
        return {
            "score": 0,
            "risk": "LOW",
            "findings_count": 0,
        }

    weights = {
        "INFO": 0,
        "LOW": 5,
        "MEDIUM": 15,
        "HIGH": 30,
        "CRITICAL": 50,
    }

    raw_score = sum(
        weights.get(
            finding.get("severity", "INFO").upper(),
            0,
        )
        for finding in findings
    )

    # Keep the public score within 0–100.
    score = min(raw_score, 100)

    risk = "LOW"

    for minimum, level in RISK_LEVELS:
        if score >= minimum:
            risk = level
            break

    highest = max(
        (
            severity_rank(
                finding.get("severity", "INFO")
            )
            for finding in findings
        ),
        default=0,
    )

    severity_levels = {
        0: "LOW",
        1: "LOW",
        2: "MEDIUM",
        3: "HIGH",
        4: "CRITICAL",
    }

    highest_name = severity_levels[highest]

    # Highest finding severity sets the minimum overall risk.
    risk_order = {
        "LOW": 0,
        "MEDIUM": 1,
        "HIGH": 2,
        "CRITICAL": 3,
    }

    if risk_order[highest_name] > risk_order[risk]:
        risk = highest_name

    return {
        "score": score,
        "risk": risk,
        "findings_count": len(findings),
        "highest_severity": (
            "CRITICAL" if highest == 4 else
            "HIGH" if highest == 3 else
            "MEDIUM" if highest == 2 else
            "LOW" if highest == 1 else
            "INFO"
        ),
    }
