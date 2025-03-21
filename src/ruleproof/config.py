"""Configuration loader and path resolution."""

import tomllib
from pathlib import Path

from ruleproof.models import ManifestConfig


def get_workspace_root() -> Path:
    """Return the absolute path of the workspace root."""
    return Path(__file__).resolve().parent.parent.parent


def get_cache_dir() -> Path:
    """Return the base directory for downloaded rules, datasets, and engines."""
    cache_dir = get_workspace_root() / ".cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def load_manifest(manifest_path: Path | None = None) -> ManifestConfig:
    """Load and validate manifest.toml."""
    if manifest_path is None:
        manifest_path = get_workspace_root() / "manifest.toml"

    if not manifest_path.is_file():
        raise FileNotFoundError(
            f"Manifest file not found at {manifest_path}. Ensure manifest.toml exists at repo root."
        )

    with manifest_path.open("rb") as f:
        data = tomllib.load(f)

    return ManifestConfig.model_validate(data)
