import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from modules.analyzer.report_writer import save_report


class TestReportWriter(unittest.TestCase):

    def test_save_report(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            report_dir = Path(temp_dir)

            with patch(
                "modules.analyzer.report_writer.REPORT_DIR",
                report_dir,
            ):
                result = {
                    "target": "authorized-test.local",
                    "risk": {
                        "risk": "LOW",
                        "score": 0,
                    },
                }

                path = save_report(result, "WEB")

                saved = Path(path)

                self.assertTrue(saved.exists())

                data = json.loads(
                    saved.read_text(encoding="utf-8")
                )

                self.assertEqual(data["report_type"], "WEB")
                self.assertEqual(
                    data["result"]["target"],
                    "authorized-test.local",
                )


if __name__ == "__main__":
    unittest.main()
