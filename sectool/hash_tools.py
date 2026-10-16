import hashlib
from pathlib import Path


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(file_path, chunk_size=65536):
    """Hash a file without loading the whole file into memory."""
    digest = hashlib.sha256()
    with Path(file_path).open("rb") as file:
        for chunk in iter(lambda: file.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_file_hash(file_path, expected_hash):
    actual = sha256_file(file_path)
    expected = expected_hash.strip().lower()
    return {"file": str(file_path), "expected_sha256": expected,
            "actual_sha256": actual, "matches": actual == expected}
