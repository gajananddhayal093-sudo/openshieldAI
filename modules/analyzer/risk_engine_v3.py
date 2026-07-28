from modules.analyzer.risk_engine import calculate_risk


def calculate_smart_risk(findings):
    """
    Phase 7.2 smart risk layer.

    Keeps the existing risk engine intact while adding:
    - duplicate finding control
    - severity-aware scoring
    - capped score
    - highest severity tracking
    """

    if not findings:
        return {
            "score": 0,
            "risk": "LOW",
            "findings_count": 0,
            "unique_findings": 0,
            "highest_severity": "INFO",
        }

    unique = []
    seen = set()

    for finding in findings:
        title = str(
            finding.get("title")
            or finding.get("text")
            or "Security finding"
        ).strip()

        severity = str(
            finding.get("severity", "INFO")
        ).upper().strip()

        key = (title.lower(), severity)

        if key in seen:
            continue

        seen.add(key)

        item = dict(finding)
        item["title"] = title
        item["severity"] = severity
        unique.append(item)

    result = calculate_risk(unique)

    return {
        "score": result["score"],
        "risk": result["risk"],
        "findings_count": len(findings),
        "unique_findings": len(unique),
        "highest_severity": result["highest_severity"],
    }
