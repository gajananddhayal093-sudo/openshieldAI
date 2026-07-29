import unittest

from modules.analyzer.correlation_engine import (
    correlate_findings,
    correlation_summary,
)


class TestCorrelationEngine(unittest.TestCase):

    def test_header_findings_are_correlated(self):
        findings = [
            {
                "title": "Missing security header: Content-Security-Policy",
                "key": "Content-Security-Policy",
                "severity": "MEDIUM",
            },
            {
                "title": "Missing security header: X-Frame-Options",
                "key": "X-Frame-Options",
                "severity": "MEDIUM",
            },
        ]

        result = correlate_findings(findings)

        self.assertEqual(result["group_count"], 1)
        self.assertIn("headers", result["groups"])
        self.assertEqual(len(result["groups"]["headers"]), 2)
        self.assertFalse(result["correlated"])

    def test_multiple_security_areas_are_correlated(self):
        findings = [
            {
                "title": "Missing security header: X-Frame-Options",
                "key": "X-Frame-Options",
                "severity": "MEDIUM",
            },
            {
                "title": "Cookie missing HttpOnly: session",
                "key": "HttpOnly",
                "severity": "HIGH",
            },
        ]

        result = correlate_findings(findings)

        self.assertEqual(result["group_count"], 2)
        self.assertTrue(result["correlated"])
        self.assertIn("headers", result["groups"])
        self.assertIn("cookies", result["groups"])

        summary = correlation_summary(result)

        self.assertIn("Headers", summary)
        self.assertIn("Cookies", summary)


if __name__ == "__main__":
    unittest.main()
