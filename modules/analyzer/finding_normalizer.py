SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def normalize_finding(
    title,
    severity,
    description,
    recommendation,
    source,
    evidence=None,
):
    severity = severity.upper()

    if severity not in SEVERITY_ORDER:
        severity = "INFO"

    return {
        "title": title,
        "severity": severity,
        "description": description,
        "recommendation": recommendation,
        "source": source,
        "evidence": evidence or {},
    }


def normalize_findings(findings):
    normalized = []

    for finding in findings:
        normalized.append(
            normalize_finding(
                title=finding.get("title", "Unknown finding"),
                severity=finding.get("severity", "INFO"),
                description=finding.get("description", ""),
                recommendation=finding.get("recommendation", ""),
                source=finding.get("source", "unknown"),
                evidence=finding.get("evidence", {}),
            )
        )

    normalized.sort(
        key=lambda item: SEVERITY_ORDER[item["severity"]],
        reverse=True,
    )

    return normalized


def highest_severity(findings):
    if not findings:
        return "INFO"

    return max(
        (
            finding["severity"]
            for finding in findings
        ),
        key=lambda severity: SEVERITY_ORDER[severity],
    )
