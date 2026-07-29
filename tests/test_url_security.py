import unittest

from modules.analyzer.url_analyzer import analyze_url


class TestURLSecurity(unittest.TestCase):

    def test_localhost_blocked(self):
        result = analyze_url("http://localhost")
        self.assertEqual(
            result.get("error"),
            "Local or private network targets are not allowed.",
        )

    def test_loopback_blocked(self):
        result = analyze_url("http://127.0.0.1")
        self.assertEqual(
            result.get("error"),
            "Local or private network targets are not allowed.",
        )

    def test_private_ip_blocked(self):
        result = analyze_url("http://192.168.1.1")
        self.assertEqual(
            result.get("error"),
            "Local or private network targets are not allowed.",
        )


if __name__ == "__main__":
    unittest.main()
