import os
import unittest

from database.scan_history import (
    init_database,
    save_scan,
    get_history,
)


class TestScanHistory(unittest.TestCase):

    def test_save_and_read_history(self):
        init_database()

        save_scan(
            "https://example.com",
            "WEB",
            "LOW",
            10,
        )

        history = get_history()

        self.assertTrue(history)
        self.assertEqual(
            history[0][1],
            "https://example.com",
        )


if __name__ == "__main__":
    unittest.main()
