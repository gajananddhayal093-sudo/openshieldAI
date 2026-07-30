from modules.analyzer.url_scanner import scan_url
from modules.analyzer.header_scanner import analyze_headers
from modules.analyzer.risk_engine import calculate_risk
from modules.analyzer.ssl_checker import check_ssl
from modules.analyzer.redirect_checker import check_redirect


def scan_target(url):
    url_result = scan_url(url)

    if not url_result["reachable"]:
        return {
            "success": False,
            "error": url_result["error"],
        }

    findings = analyze_headers(url_result["headers"])
    risk = calculate_risk(findings)

    try:
        ssl_result = check_ssl(url)
    except Exception as e:
        ssl_result = {
            "valid": False,
            "error": str(e),
        }

    try:
        redirect_result = check_redirect(url)
    except Exception as e:
        redirect_result = {
            "success": False,
            "error": str(e),
        }

    return {
        "success": True,
        "target": url_result["url"],
        "status_code": url_result["status_code"],
        "headers": findings,
        "risk": risk,
        "ssl": ssl_result,
        "redirect": redirect_result,
    }
