import json
import unittest
from pathlib import Path
from unittest.mock import patch

from modules.analyzer.report_writer import save_report


class TestReportIntelligence(unittest.TestCase):

    @patch("modules.analyzer.report_writer.REPORT_DIR")
    def test_intelligence_is_preserved_in_saved_report(self, mock_dir):
        mock_dir.mkdir.return_value = None

        report_path = Path("reports/test_intelligence.json")

        pipeline = {
            "findings": [
                {
                    "title": "Missing security header",
                    "severity": "MEDIUM",
                    "evidence": {
                        "source": "security_pipeline",
                        "target": "https://example.com",
                        "type": "finding",
                        "value": "Missing security header",
                        "details": {},
                    },
                }
            ],
            "correlation": {
                "groups": {
                    "headers": [
                        {"title": "Missing security header"}
                    ]
                },
                "group_count": 1,
                "correlated": False,
            },
            "correlation_summary":
                "Related security areas detected: Headers.",
        }

        result = {
            "target": "https://example.com",
            "pipeline": pipeline,
        }

        # Use a real temporary directory for the actual persistence check.
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            real_dir = Path(tmp)

            with patch(
                "modules.analyzer.report_writer.REPORT_DIR",
                real_dir,
            ):
                saved = save_report(result, "WEB")

                data = json.loads(
                    Path(saved).read_text(encoding="utf-8")
                )

        self.assertEqual(data["schema_version"], "1.0")
        self.assertEqual(data["report_type"], "WEB")

        saved_pipeline = data["result"]["pipeline"]

        self.assertIn("correlation", saved_pipeline)
        self.assertIn("correlation_summary", saved_pipeline)
        self.assertIn("evidence", saved_pipeline["findings"][0])

        self.assertEqual(
            saved_pipeline["correlation"]["group_count"],
            1,
        )


if __name__ == "__main__":
    unittest.main()
