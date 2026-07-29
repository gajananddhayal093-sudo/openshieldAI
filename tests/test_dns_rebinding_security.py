import unittest
from unittest.mock import patch

from modules.analyzer.url_analyzer import analyze_url


class TestDNSRebindingSecurity(unittest.TestCase):

    @patch(
        "modules.analyzer.url_analyzer.socket.getaddrinfo",
        return_value=[
            (
                2,
                1,
                6,
                "",
                ("127.0.0.1", 0),
            )
        ],
    )
    def test_hostname_resolving_to_loopback_is_blocked(
        self,
        mock_getaddrinfo,
    ):
        result = analyze_url("https://example.com")

        self.assertEqual(
            result.get("error"),
            "Local or private network targets are not allowed.",
        )

        mock_getaddrinfo.assert_called_once()


if __name__ == "__main__":
    unittest.main()
