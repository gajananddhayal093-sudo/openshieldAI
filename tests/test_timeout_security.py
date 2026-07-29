import unittest
from unittest.mock import patch

import requests

from modules.analyzer.url_analyzer import analyze_url


class TestTimeoutSecurity(unittest.TestCase):

    @patch(
        "modules.analyzer.url_analyzer.requests.get",
        side_effect=requests.Timeout("request timed out"),
    )
    def test_request_timeout_handled(self, mock_get):
        result = analyze_url("https://example.com")

        self.assertEqual(
            result.get("error"),
            "request timed out",
        )

        self.assertEqual(
            result.get("risk"),
            "UNKNOWN",
        )

        self.assertEqual(
            result.get("risk_score"),
            0,
        )

        self.assertEqual(mock_get.call_count, 1)


if __name__ == "__main__":
    unittest.main()
