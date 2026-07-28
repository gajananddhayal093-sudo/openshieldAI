def format_telegram_report(result, report_type="SECURITY"):
    risk = result.get("risk", {})
    findings = result.get("findings", [])
    recommendations = result.get("recommendations", [])

    lines = [
        "🛡️ OPENSHIELD AI",
        f"{report_type} SECURITY REPORT",
        "",
        f"🎯 Target",
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
            if isinstance(item, dict):
                text = item.get("recommendation", str(item))
            else:
                text = str(item)
            lines.append(f"• {text}")
    else:
        lines.append("• No recommendations.")

    return "\n".join(lines)
