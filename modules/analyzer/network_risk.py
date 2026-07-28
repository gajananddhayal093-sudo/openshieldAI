def assess_network_risk(dns_result, port_result, tls_result):
    score = 0
    findings = []
    recommendations = []

    # DNS
    if dns_result.get("error"):
        score += 3
        findings.append("DNS resolution failed.")
        recommendations.append("Verify that the hostname exists and DNS is configured correctly.")

    # Ports
    ports = port_result.get("ports", [])

    open_ports = [
        item for item in ports
        if item.get("status") == "open"
    ]

    if open_ports:
        for item in open_ports:
            port = item.get("port")
            service = item.get("service", "Unknown")

            if port not in (80, 443):
                score += 2
                findings.append(
                    f"Port {port} ({service}) is publicly reachable."
                )
                recommendations.append(
                    f"Review whether port {port} needs to be publicly accessible."
                )

    if port_result.get("error"):
        score += 2
        findings.append("Port analysis could not be completed.")

    # TLS
    if not tls_result.get("valid"):
        score += 4
        findings.append("TLS certificate or connection validation failed.")
        recommendations.append(
            "Verify the TLS certificate, hostname, and HTTPS configuration."
        )
    else:
        days = tls_result.get("days_remaining")

        if days is not None and days < 30:
            score += 2
            findings.append(
                f"TLS certificate expires in {days} days."
            )
            recommendations.append(
                "Renew the TLS certificate before expiration."
            )

        tls_version = tls_result.get("tls_version")

        if tls_version not in ("TLSv1.2", "TLSv1.3"):
            score += 3
            findings.append(
                f"Older TLS version detected: {tls_version}."
            )
            recommendations.append(
                "Use TLS 1.2 or TLS 1.3 and disable older protocols."
            )

    # Risk level
    if score >= 8:
        risk = "CRITICAL"
    elif score >= 5:
        risk = "HIGH"
    elif score >= 2:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "risk": risk,
        "risk_score": score,
        "findings": list(dict.fromkeys(findings)),
        "recommendations": list(dict.fromkeys(recommendations)),
    }
