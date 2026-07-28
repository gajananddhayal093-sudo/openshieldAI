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

    for item in result.get("missing_headers", []):
        findings.append({
            "title": f"Missing security header: {item}",
            "key": item,
            "severity": "MEDIUM",
        })

    for cookie in result.get("cookies", []):
        if not cookie.get("secure"):
            findings.append({
                "title": f"Cookie missing Secure: {cookie.get('name', 'unknown')}",
                "key": "Secure",
                "severity": "MEDIUM",
            })

        if not cookie.get("httponly"):
            findings.append({
                "title": f"Cookie missing HttpOnly: {cookie.get('name', 'unknown')}",
                "key": "HttpOnly",
                "severity": "HIGH",
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
