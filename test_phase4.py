from modules.analyzer.dns_analyzer import analyze_dns
from modules.analyzer.port_analyzer import analyze_ports
from modules.analyzer.tls_analyzer import analyze_tls
from modules.analyzer.network_risk import assess_network_risk


def test_dns():
    result = analyze_dns("example.com")
    assert result["error"] is None
    assert result["addresses"]


def test_dns_invalid():
    result = analyze_dns("not-a-real-domain.invalid")
    assert result["error"] is not None
    assert result["addresses"] == []


def test_ports():
    result = analyze_ports("example.com", ports=[80, 443])
    assert result["error"] is None
    assert len(result["ports"]) == 2


def test_tls():
    result = analyze_tls("example.com")
    assert result["valid"] is True
    assert result["tls_version"] in ("TLSv1.2", "TLSv1.3")
    assert result["error"] is None


def test_risk():
    dns = analyze_dns("example.com")
    ports = analyze_ports("example.com", ports=[80, 443])
    tls = analyze_tls("example.com")

    result = assess_network_risk(dns, ports, tls)

    assert result["risk"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert isinstance(result["risk_score"], int)
    assert isinstance(result["findings"], list)
    assert isinstance(result["recommendations"], list)


def test_invalid_tls():
    result = analyze_tls("not-a-real-domain.invalid")
    assert result["valid"] is False
    assert result["error"] is not None


if __name__ == "__main__":
    tests = [
        test_dns,
        test_dns_invalid,
        test_ports,
        test_tls,
        test_risk,
        test_invalid_tls,
    ]

    passed = 0

    for test in tests:
        test()
        print(f"✅ {test.__name__}")
        passed += 1

    print(f"\n🎯 Phase 4 Tests: {passed}/{len(tests)} PASSED")
