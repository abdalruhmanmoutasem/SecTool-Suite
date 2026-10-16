import tempfile
import unittest
from pathlib import Path

from sectool.log_analyzer import analyze_log_file, detect_brute_force


class TestLogAnalyzer(unittest.TestCase):
    def test_valid_and_invalid_ips(self):
        content = (
            "[INFO] Connected from 192.168.1.10\n"
            "[WARNING] Failed login from 10.0.0.5\n"
            "[ERROR] Attack from 999.999.999.999\n"
            "[WARNING] Failed login from 10.0.0.5\n"
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sample.log"
            path.write_text(content, encoding="utf-8")
            result = analyze_log_file(path)
        self.assertEqual(result["valid_count"], 3)
        self.assertEqual(result["invalid_count"], 1)

    def test_empty_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "empty.log"
            path.write_text("", encoding="utf-8")
            result = analyze_log_file(path)
        self.assertEqual(result["valid_count"], 0)
        self.assertEqual(result["invalid_count"], 0)

    def test_missing_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaises(FileNotFoundError):
                analyze_log_file(Path(temp_dir) / "missing.log")

    def test_brute_force_detected_in_window(self):
        content = (
            "[2026-10-16 10:00:01] Failed login from 10.0.0.5\n"
            "[2026-10-16 10:01:05] Failed login from 10.0.0.5\n"
            "[2026-10-16 10:02:08] Failed login from 10.0.0.5\n"
            "[2026-10-16 10:02:10] Successful login from 192.168.1.10\n"
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "auth.log"
            path.write_text(content, encoding="utf-8")
            result = detect_brute_force(path, threshold=3, window_minutes=5)
        self.assertEqual(result["alert_count"], 1)
        self.assertEqual(result["alerts"][0]["ip"], "10.0.0.5")

    def test_brute_force_outside_window_not_detected(self):
        content = (
            "[2026-10-16 10:00:00] Failed login from 10.0.0.5\n"
            "[2026-10-16 10:03:00] Failed login from 10.0.0.5\n"
            "[2026-10-16 10:06:00] Failed login from 10.0.0.5\n"
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "auth.log"
            path.write_text(content, encoding="utf-8")
            result = detect_brute_force(path, threshold=3, window_minutes=5)
        self.assertEqual(result["alert_count"], 0)

    def test_invalid_threshold(self):
        with self.assertRaises(ValueError):
            detect_brute_force("unused.log", threshold=0)


if __name__ == "__main__":
    unittest.main()
