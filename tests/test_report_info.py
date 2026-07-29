import unittest
from unittest.mock import patch

from modules.analyzer.report_writer import load_report


class TestReportInfo(unittest.TestCase):

    @patch("modules.analyzer.report_writer.list_reports")
    def test_load_report_metadata(self, mock_reports):
        mock_reports.return_value = [
            "reports/web_test.json"
        ]

        with patch(
            "modules.analyzer.report_writer.Path.read_text",
            return_value='''{
                "report_type": "WEB",
                "generated_at": "2026-07-30T00:00:00+00:00",
                "result": {
                    "target": "https://example.com",
                    "pipeline": {
                        "risk": {
                            "risk": "LOW",
                            "score": 0
                        },
                        "findings": []
                    }
                }
            }'''
        ):
            result = load_report(1)

        self.assertEqual(result["report_type"], "WEB")
        self.assertEqual(
            result["result"]["target"],
            "https://example.com",
        )


if __name__ == "__main__":
    unittest.main()
