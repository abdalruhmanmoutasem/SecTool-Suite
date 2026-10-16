import unittest
from unittest.mock import patch, MagicMock

from sectool.port_scanner import scan_ports


class TestPortScanner(unittest.TestCase):
    def test_invalid_ip(self):
        with self.assertRaises(ValueError):
            scan_ports("999.999.999.999", [80])

    def test_invalid_port(self):
        with self.assertRaises(ValueError):
            scan_ports("127.0.0.1", [70000])

    @patch("sectool.port_scanner.socket.socket")
    def test_open_port(self, socket_mock):
        sock = MagicMock()
        sock.connect_ex.return_value = 0
        socket_mock.return_value.__enter__.return_value = sock
        result = scan_ports("127.0.0.1", [80])
        self.assertEqual(result["results"][0]["status"], "open")


if __name__ == "__main__":
    unittest.main()
