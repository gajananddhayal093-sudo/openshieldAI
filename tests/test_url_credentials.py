import unittest

from modules.analyzer.url_analyzer import analyze_url


class TestURLCredentials(unittest.TestCase):

    def test_credentials_blocked(self):
        result = analyze_url(
            "https://user:password@example.com"
        )

        self.assertEqual(
            result.get("error"),
            "URLs containing username or password are not allowed.",
        )


if __name__ == "__main__":
    unittest.main()
