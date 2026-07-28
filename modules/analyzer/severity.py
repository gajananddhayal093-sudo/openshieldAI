SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def classify_severity(
    impact="low",
    exposure="internal",
    exploitability="low",
):
    impact = impact.lower()
    exposure = exposure.lower()
    exploitability = exploitability.lower()

    score = 0

    impact_scores = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }

    exposure_scores = {
        "internal": 0,
        "limited": 1,
        "public": 2,
    }

    exploitability_scores = {
        "low": 0,
        "medium": 1,
        "high": 2,
    }

    score += impact_scores.get(impact, 1)
    score += exposure_scores.get(exposure, 0)
    score += exploitability_scores.get(exploitability, 0)

    if score >= 7:
        return "CRITICAL"
    elif score >= 5:
        return "HIGH"
    elif score >= 3:
        return "MEDIUM"
    elif score >= 1:
        return "LOW"

    return "INFO"


def severity_rank(severity):
    return SEVERITY_ORDER.get(
        severity.upper(),
        0,
    )
