def build_summary(
    target,
    risk,
    score,
    findings,
    recommendations,
    highest_severity="INFO",
):
    return {
        "title": "OPENSHIELD AI SECURITY ASSESSMENT",
        "target": target,
        "risk": risk,
        "score": score,
        "highest_severity": highest_severity,
        "findings_count": len(findings),
        "recommendations_count": len(recommendations),
        "findings": findings,
        "recommendations": recommendations,
    }


def format_summary(summary):
    lines = [
        "🛡️ OPENSHIELD AI",
        "SECURITY ASSESSMENT SUMMARY",
        "",
        f"🎯 Target: {summary['target']}",
        "",
        f"📊 Risk: {summary['risk']}",
        f"🎯 Score: {summary['score']}/100",
        f"⚠️ Highest Severity: {summary['highest_severity']}",
        "",
        f"🔎 Findings: {summary['findings_count']}",
        f"💡 Recommendations: {summary['recommendations_count']}",
    ]

    if summary["findings"]:
        lines.append("")
        lines.append("⚠️ FINDINGS")

        for finding in summary["findings"]:
            lines.append(
                f"• [{finding.get('severity', 'INFO')}] "
                f"{finding.get('title', 'Security finding')}"
            )

    if summary["recommendations"]:
        lines.append("")
        lines.append("💡 RECOMMENDATIONS")

        for recommendation in summary["recommendations"]:
            lines.append(
                f"• {recommendation.get('recommendation', '')}"
            )

    return "\n".join(lines)
