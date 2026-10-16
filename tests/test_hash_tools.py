import tempfile
import unittest
from pathlib import Path

from sectool.hash_tools import sha256_text, sha256_file, verify_file_hash


class TestHashTools(unittest.TestCase):
    def test_known_text_hash(self):
        self.assertEqual(
            sha256_text("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_file_hash_and_verification(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "data.txt"
            path.write_text("abc", encoding="utf-8")
            digest = sha256_file(path)
            self.assertTrue(verify_file_hash(path, digest)["matches"])
            self.assertFalse(verify_file_hash(path, "0" * 64)["matches"])


if __name__ == "__main__":
    unittest.main()
