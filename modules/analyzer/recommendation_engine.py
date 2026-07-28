RECOMMENDATIONS = {
    "Content-Security-Policy": (
        "Add a suitable Content-Security-Policy and "
        "review allowed script and style sources."
    ),
    "Strict-Transport-Security": (
        "Enable HSTS after HTTPS is correctly configured."
    ),
    "X-Content-Type-Options": (
        "Add X-Content-Type-Options: nosniff."
    ),
    "X-Frame-Options": (
        "Add clickjacking protection using X-Frame-Options "
        "or CSP frame-ancestors."
    ),
    "Referrer-Policy": (
        "Set an appropriate Referrer-Policy."
    ),
    "Permissions-Policy": (
        "Restrict unnecessary browser features with "
        "Permissions-Policy."
    ),
    "Secure": (
        "Set the Secure flag on cookies containing "
        "sensitive information."
    ),
    "HttpOnly": (
        "Set the HttpOnly flag on cookies that do not "
        "need client-side JavaScript access."
    ),
    "SameSite": (
        "Set an appropriate SameSite cookie attribute."
    ),
}


def get_recommendation(key):
    return RECOMMENDATIONS.get(
        key,
        "Review this finding and apply an appropriate security control.",
    )


def build_recommendations(findings):
    recommendations = []
    seen = set()

    severity_order = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "INFO": 0,
    }

    for finding in findings:
        key = finding.get("key") or finding.get("title", "")
        title = finding.get("title", "Security finding")
        severity = finding.get("severity", "INFO").upper()

        recommendation = get_recommendation(key)

        # Remove duplicate recommendations.
        if recommendation in seen:
            continue

        seen.add(recommendation)

        recommendations.append({
            "title": title,
            "severity": severity,
            "priority": severity_order.get(severity, 0),
            "recommendation": recommendation,
        })

    # Highest severity recommendations first.
    recommendations.sort(
        key=lambda item: item["priority"],
        reverse=True,
    )

    return recommendations
