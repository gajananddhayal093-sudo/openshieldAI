from modules.analyzer.url_analyzer import analyze_url
from modules.analyzer.security_pipeline import run_security_pipeline


def run_web_pipeline(url):
    result = analyze_url(url)

    if result.get("error"):
        return {
            "target": url,
            "error": result["error"],
            "web": result,
        }

    findings = []

    # HTTPS
    if not result.get("https"):
        findings.append({
            "title": "HTTPS is not enabled",
            "key": "HTTPS",
            "severity": "HIGH",
        })

    # Missing security headers
    for item in result.get("missing_headers", []):
        findings.append({
            "title": f"Missing security header: {item}",
            "key": item,
            "severity": "MEDIUM",
        })

    # Cookie security
    for cookie in result.get("cookies", []):
        name = cookie.get("name", "unknown")

        if not cookie.get("secure"):
            findings.append({
                "title": f"Cookie missing Secure: {name}",
                "key": "Secure",
                "severity": "MEDIUM",
            })

        if not cookie.get("httponly"):
            findings.append({
                "title": f"Cookie missing HttpOnly: {name}",
                "key": "HttpOnly",
                "severity": "HIGH",
            })

        if str(cookie.get("samesite", "Not Set")).lower() == "not set":
            findings.append({
                "title": f"Cookie missing SameSite: {name}",
                "key": "SameSite",
                "severity": "MEDIUM",
            })

    pipeline = run_security_pipeline(
        url,
        findings,
    )

    return {
        "target": url,
        "web": result,
        "pipeline": pipeline,
    }
