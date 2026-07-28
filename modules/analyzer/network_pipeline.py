from modules.analyzer.dns_analyzer import analyze_dns
from modules.analyzer.port_analyzer import analyze_ports
from modules.analyzer.tls_analyzer import analyze_tls
from modules.analyzer.security_pipeline import run_security_pipeline


def run_network_pipeline(host):
    dns = analyze_dns(host)
    ports = analyze_ports(host, ports=[80, 443])
    tls = analyze_tls(host)

    findings = []

    if not dns.get("addresses"):
        findings.append({
            "title": "DNS resolution failed",
            "key": "DNS",
            "severity": "HIGH",
        })

    for item in ports.get("ports", []):
        if item.get("status") == "open" and item.get("port") not in (80, 443):
            findings.append({
                "title": f"Unexpected open port {item.get('port')}",
                "key": f"PORT_{item.get('port')}",
                "severity": "MEDIUM",
            })

    if not tls.get("valid"):
        findings.append({
            "title": "TLS validation failed",
            "key": "TLS",
            "severity": "HIGH",
        })

    result = run_security_pipeline(host, findings)

    result["dns"] = dns
    result["ports"] = ports
    result["tls"] = tls

    return result
