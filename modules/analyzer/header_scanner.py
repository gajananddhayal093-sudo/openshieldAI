SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS",
    "Content-Security-Policy": "CSP",
    "X-Frame-Options": "Clickjacking Protection",
    "X-Content-Type-Options": "MIME Protection",
    "Referrer-Policy": "Referrer Policy",
}


def analyze_headers(headers):
    findings = []

    for header, description in SECURITY_HEADERS.items():
        if header in headers:
            findings.append({
                "header": header,
                "status": "present",
                "description": description,
            })
        else:
            findings.append({
                "header": header,
                "status": "missing",
                "description": description,
            })

    return findings
