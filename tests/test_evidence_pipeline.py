import unittest

from modules.analyzer.security_pipeline import run_security_pipeline


class TestEvidencePipeline(unittest.TestCase):

    def test_pipeline_adds_valid_evidence(self):
        findings = [
            {
                "title": "Missing security header",
                "key": "CSP",
                "severity": "MEDIUM",
            }
        ]

        result = run_security_pipeline(
            "https://example.com",
            findings,
        )

        self.assertEqual(len(result["findings"]), 1)

        evidence = result["findings"][0]["evidence"]

        self.assertTrue(evidence["source"])
        self.assertTrue(evidence["target"])
        self.assertTrue(evidence["type"])
        self.assertTrue(evidence["value"])

    def test_pipeline_keeps_correlation(self):
        findings = [
            {
                "title": "Missing security header: CSP",
                "key": "Content-Security-Policy",
                "severity": "MEDIUM",
            }
        ]

        result = run_security_pipeline(
            "https://example.com",
            findings,
        )

        self.assertIn("correlation", result)
        self.assertIn("correlation_summary", result)
        self.assertIn("headers", result["correlation"]["groups"])


if __name__ == "__main__":
    unittest.main()
