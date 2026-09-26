import os
import unittest

from app.access import allowed


class AllowlistTests(unittest.TestCase):
    def tearDown(self):
        os.environ["MONITOR_ALLOWLIST"] = ""

    def test_network_allows_only_its_range(self):
        os.environ["MONITOR_ALLOWLIST"] = "10.8.0.0/24,203.0.113.10"
        self.assertTrue(allowed("10.8.0.15"))
        self.assertTrue(allowed("203.0.113.10"))
        self.assertFalse(allowed("10.8.1.15"))
        self.assertFalse(allowed("198.51.100.1"))

    def test_empty_allowlist_is_open(self):
        os.environ["MONITOR_ALLOWLIST"] = ""
        self.assertTrue(allowed("198.51.100.1"))

    def test_broken_allowlist_stays_closed(self):
        os.environ["MONITOR_ALLOWLIST"] = "не-адрес"
        self.assertFalse(allowed("127.0.0.1"))


if __name__ == "__main__":
    unittest.main()
