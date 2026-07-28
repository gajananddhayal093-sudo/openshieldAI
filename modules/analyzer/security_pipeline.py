from modules.analyzer.risk_engine import calculate_risk
from modules.analyzer.evidence_engine import create_evidence
from modules.analyzer.recommendation_engine import build_recommendations
from modules.analyzer.summary_engine import build_summary


def run_security_pipeline(target, findings):
    normalized_findings = []

    for finding in findings:
        item = dict(finding)

        item.setdefault("severity", "LOW")
        item.setdefault("title", "Security finding")

        evidence = item.get("evidence")

        if evidence is None:
            evidence = create_evidence(
                source="security_pipeline",
                target=target,
                evidence_type="finding",
                value=item["title"],
            )

        item["evidence"] = evidence
        normalized_findings.append(item)

    risk_result = calculate_risk(normalized_findings)

    recommendations = build_recommendations(
        normalized_findings
    )

    summary = build_summary(
        target=target,
        risk=risk_result["risk"],
        score=risk_result["score"],
        findings=normalized_findings,
        recommendations=recommendations,
        highest_severity=risk_result.get(
            "highest_severity"
        ),
    )

    return {
        "target": target,
        "findings": normalized_findings,
        "risk": risk_result,
        "recommendations": recommendations,
        "summary": summary,
    }
