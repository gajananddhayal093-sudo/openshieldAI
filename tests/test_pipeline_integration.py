import unittest
from unittest.mock import patch

from modules.analyzer.web_pipeline import run_web_pipeline
from modules.analyzer.network_pipeline import run_network_pipeline


class TestWebPipeline(unittest.TestCase):

    @patch("modules.analyzer.web_pipeline.analyze_url")
    def test_web_pipeline(self, mock_analyze):
        mock_analyze.return_value = {
            "url": "https://test.local",
            "https": True,
            "missing_headers": ["Content-Security-Policy"],
            "cookies": [],
            "error": None,
        }

        result = run_web_pipeline("https://test.local")

        self.assertIsNone(result.get("error"))
        self.assertEqual(len(result["pipeline"]["findings"]), 1)
        self.assertEqual(
            result["pipeline"]["findings"][0]["severity"],
            "MEDIUM",
        )


class TestNetworkPipeline(unittest.TestCase):

    @patch("modules.analyzer.network_pipeline.analyze_tls")
    @patch("modules.analyzer.network_pipeline.analyze_ports")
    @patch("modules.analyzer.network_pipeline.analyze_dns")
    def test_network_pipeline(
        self,
        mock_dns,
        mock_ports,
        mock_tls,
    ):
        mock_dns.return_value = {
            "addresses": ["192.0.2.1"]
        }

        mock_ports.return_value = {
            "ports": [
                {
                    "port": 80,
                    "status": "open",
                    "service": "http",
                },
                {
                    "port": 443,
                    "status": "open",
                    "service": "https",
                },
            ]
        }

        mock_tls.return_value = {
            "valid": True,
            "tls_version": "TLSv1.3",
            "days_remaining": 100,
        }

        result = run_network_pipeline("test.local")

        self.assertEqual(result["dns"]["addresses"], ["192.0.2.1"])
        self.assertEqual(len(result["findings"]), 0)
        self.assertEqual(result["risk"]["score"], 0)


if __name__ == "__main__":
    unittest.main()
