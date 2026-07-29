import unittest
from unittest.mock import patch, Mock

from modules.analyzer.url_analyzer import analyze_url


class TestRedirectSecurity(unittest.TestCase):

    @patch("modules.analyzer.url_analyzer.requests.get")
    def test_private_redirect_blocked(self, mock_get):
        response = Mock()
        response.status_code = 302
        response.is_redirect = True
        response.is_permanent_redirect = False
        response.headers = {
            "Location": "http://127.0.0.1/admin"
        }

        mock_get.return_value = response

        result = analyze_url("https://example.com")

        self.assertEqual(
            result.get("error"),
            "Redirect target points to a local or private network.",
        )

        self.assertEqual(mock_get.call_count, 1)


if __name__ == "__main__":
    unittest.main()
