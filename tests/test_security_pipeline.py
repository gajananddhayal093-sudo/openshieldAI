import unittest

from modules.analyzer.security_pipeline import run_security_pipeline


class TestSecurityPipeline(unittest.TestCase):

    def test_medium_finding(self):
        findings = [
            {
                "title": "Missing security header",
                "severity": "MEDIUM",
            }
        ]

        result = run_security_pipeline(
            "authorized-test.local",
            findings,
        )

        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(
            result["findings"][0]["severity"],
            "MEDIUM",
        )
        self.assertEqual(
            result["risk"]["highest_severity"],
            "MEDIUM",
        )
        self.assertGreater(result["risk"]["score"], 0)
        self.assertTrue(result["recommendations"])
        self.assertTrue(result["summary"])


    def test_empty_findings(self):
        result = run_security_pipeline(
            "authorized-test.local",
            [],
        )

        self.assertEqual(result["findings"], [])
        self.assertEqual(result["risk"]["score"], 0)
        self.assertIsNone(result["risk"].get("highest_severity"))


if __name__ == "__main__":
    unittest.main()
