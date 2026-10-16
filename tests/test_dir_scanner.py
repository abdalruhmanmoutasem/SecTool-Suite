import unittest
from unittest.mock import patch, MagicMock

from sectool.dir_scanner import scan_directories


class TestDirectoryScanner(unittest.TestCase):
    def test_invalid_url(self):
        with self.assertRaises(ValueError):
            scan_directories("not-a-url")

    @patch("sectool.dir_scanner.requests.get")
    def test_http_status_recorded(self, get_mock):
        response = MagicMock()
        response.status_code = 200
        get_mock.return_value = response
        result = scan_directories("https://example.com", paths=["/robots.txt"])
        self.assertEqual(result["results"][0]["status_code"], 200)


if __name__ == "__main__":
    unittest.main()
