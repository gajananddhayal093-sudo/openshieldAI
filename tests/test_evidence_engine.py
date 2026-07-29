import unittest

from modules.analyzer.evidence_engine import (
    create_evidence,
    create_finding_evidence,
    validate_evidence,
)


class TestEvidenceEngine(unittest.TestCase):

    def test_valid_evidence(self):
        evidence = create_evidence(
            source="security_pipeline",
            target="https://example.com",
            evidence_type="finding",
            value="Missing security header",
        )

        self.assertTrue(validate_evidence(evidence))

    def test_invalid_evidence(self):
        evidence = {
            "source": "security_pipeline",
            "target": "https://example.com",
            "type": "finding",
        }

        self.assertFalse(validate_evidence(evidence))

    def test_finding_evidence_attachment(self):
        finding = {
            "title": "Missing security header",
            "severity": "MEDIUM",
        }

        evidence = create_evidence(
            source="security_pipeline",
            target="https://example.com",
            evidence_type="finding",
            value=finding["title"],
        )

        result = create_finding_evidence(
            finding,
            evidence,
        )

        self.assertIn("evidence", result)
        self.assertTrue(validate_evidence(result["evidence"]))


if __name__ == "__main__":
    unittest.main()
