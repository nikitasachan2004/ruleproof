"""Unit tests for configuration loading and validation."""

from pathlib import Path

import pytest

from ruleproof.config import get_cache_dir, get_workspace_root, load_manifest


def test_get_workspace_root() -> None:
    root = get_workspace_root()
    assert root.is_dir()
    assert (root / "manifest.toml").is_file()


def test_get_cache_dir() -> None:
    cache = get_cache_dir()
    assert cache.is_dir()
    assert cache.name == ".cache"


def test_load_manifest_success() -> None:
    manifest_path = Path(__file__).parent / "fixtures" / "manifest.toml"
    manifest = load_manifest(manifest_path)
    assert "sigmahq" in manifest.rules
    assert manifest.rules["sigmahq"].commit == "26a2c3810a4878caec599563f972a8c39587b154"
    assert "evtx_attack_samples" in manifest.datasets
    assert "chainsaw" in manifest.engines


def test_load_manifest_not_found(tmp_path: Path) -> None:
    missing = tmp_path / "nonexistent.toml"
    with pytest.raises(FileNotFoundError):
        load_manifest(missing)
