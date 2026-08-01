from modules.analyzer.intelligence import generate_intelligence

def format_telegram_report(result, report_type="SECURITY"):
    risk = result.get("risk", {})
    findings = result.get("findings", [])
    recommendations = result.get("recommendations", [])

    summary = {
        "risk": risk.get("risk", "LOW"),
        "score": risk.get("score", 0),
        "findings_count": len(findings),
        "highest_severity": risk.get("highest_severity"),
    }

    intelligence = generate_intelligence(summary)

    lines = [
        "🛡️ OPENSHIELD AI",
        f"{report_type} SECURITY REPORT",
        "",
        "🎯 Target",
        str(result.get("target", "Unknown")),
        "",
        "📊 Risk Assessment",
        f"{risk.get('risk', 'LOW')} — Score: {risk.get('score', 0)}/100",
        f"Highest Severity: {risk.get('highest_severity') or 'None'}",
        "",
        "⚠️ Findings",
    ]

    if findings:
        for finding in findings:
            severity = finding.get("severity", "LOW")
            title = finding.get("title", "Security finding")
            lines.append(f"• [{severity}] {title}")
    else:
        lines.append("• No findings.")

    lines.extend([
        "",
        "💡 Recommendations",
    ])

    if recommendations:
        for item in recommendations:
            text = item.get("recommendation", str(item)) if isinstance(item, dict) else str(item)
            lines.append(f"• {text}")
    else:
        lines.append("• No recommendations.")

    correlation = result.get("correlation_summary")

    if correlation:
        lines.extend([
            "",
            "🔗 Correlation",
            correlation,
        ])

    if intelligence:
        lines.extend([
            "",
            "🧠 Intelligence",
            f"Analysis: {intelligence.get('analysis', '')}",
            f"Priority: {intelligence.get('priority', '')}",
        ])

        steps = intelligence.get("next_steps", [])
        if steps:
            lines.append("Next Steps:")
            for step in steps:
                lines.append(f"• {step}")

    return "\n".join(lines)
