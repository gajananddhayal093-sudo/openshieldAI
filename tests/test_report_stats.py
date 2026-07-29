import unittest
from unittest.mock import patch

import modules.analyzer.report_writer as report_writer


class TestReportStats(unittest.TestCase):

    @patch("modules.analyzer.report_writer.list_reports")
    def test_report_list_available(self, mock_reports):
        mock_reports.return_value = [
            "reports/web_test.json",
            "reports/network_test.json",
        ]

        reports = report_writer.list_reports(10)

        self.assertEqual(len(reports), 2)
        self.assertIn("reports/web_test.json", reports)
        self.assertIn("reports/network_test.json", reports)


if __name__ == "__main__":
    unittest.main()
