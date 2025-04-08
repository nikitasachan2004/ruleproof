"""Unit tests for fetch, hashing, extraction security, and quarantine handling."""

import hashlib
import zipfile
from pathlib import Path

import pytest

from ruleproof.fetch import (
    compute_sha256,
    handle_macos_quarantine,
    safe_extract_zip,
    verify_sha256,
)


def test_sha256_computation_and_verification(tmp_path: Path) -> None:
    test_file = tmp_path / "sample.bin"
    content = b"RuleProof deterministic test content"
    test_file.write_bytes(content)

    expected_hash = hashlib.sha256(content).hexdigest()
    assert compute_sha256(test_file) == expected_hash

    # Verify matching hash passes
    verify_sha256(test_file, expected_hash)

    # Verify mismatch raises ValueError
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        verify_sha256(test_file, "0000000000000000000000000000000000000000000000000000000000000000")


def test_safe_extract_zip_normal(tmp_path: Path) -> None:
    zip_path = tmp_path / "valid.zip"
    extract_dir = tmp_path / "extracted"

    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("test.txt", "hello safe extraction")

    safe_extract_zip(zip_path, extract_dir)
    assert (extract_dir / "test.txt").read_text() == "hello safe extraction"


def test_safe_extract_zip_path_traversal_detection(tmp_path: Path) -> None:
    zip_path = tmp_path / "malicious.zip"
    extract_dir = tmp_path / "extracted"

    with zipfile.ZipFile(zip_path, "w") as zf:
        # ZipSlip attempt: relative path targeting parent directory
        zf.writestr("../escaped.txt", "evil content")

    with pytest.raises(ValueError, match="Path traversal detected"):
        safe_extract_zip(zip_path, extract_dir)


def test_handle_macos_quarantine_noop_on_clean_file(tmp_path: Path) -> None:
    test_bin = tmp_path / "test_bin"
    test_bin.write_bytes(b"mock executable")
    # Should run without error on non-quarantined files
    handle_macos_quarantine(test_bin)
