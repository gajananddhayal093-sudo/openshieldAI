import unittest
from unittest.mock import patch, Mock

from modules.analyzer.url_analyzer import analyze_url


class TestResponseSizeSecurity(unittest.TestCase):

    @patch("modules.analyzer.url_analyzer.requests.get")
    def test_oversized_response_blocked(self, mock_get):
        response = Mock()
        response.status_code = 200
        response.is_redirect = False
        response.is_permanent_redirect = False
        response.history = []
        response.url = "https://example.com"
        response.reason = "OK"
        response.headers = {
            "Content-Length": str(3 * 1024 * 1024)
        }

        mock_get.return_value = response

        result = analyze_url("https://example.com")

        self.assertEqual(
            result.get("error"),
            "Response exceeds the maximum allowed size.",
        )

        self.assertEqual(mock_get.call_count, 1)


if __name__ == "__main__":
    unittest.main()
