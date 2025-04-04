"""Fetch and verification pipeline for external rules, datasets, and engine binaries."""

import hashlib
import logging
import platform
import shutil
import subprocess
import urllib.request
import zipfile
from pathlib import Path

from ruleproof.config import get_cache_dir, load_manifest
from ruleproof.models import EngineSourceConfig, ManifestConfig

logger = logging.getLogger(__name__)


def compute_sha256(file_path: Path) -> str:
    """Compute the SHA-256 hexadecimal digest of a local file."""
    hasher = hashlib.sha256()
    with file_path.open("rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_sha256(file_path: Path, expected_sha256: str) -> None:
    """Verify that a local file matches the expected SHA-256 digest."""
    actual_sha256 = compute_sha256(file_path)
    if actual_sha256.lower() != expected_sha256.lower():
        raise ValueError(
            f"SHA-256 mismatch for {file_path}:\n"
            f"  Expected: {expected_sha256.lower()}\n"
            f"  Actual:   {actual_sha256.lower()}"
        )


def safe_extract_zip(zip_path: Path, target_dir: Path) -> None:
    """Extract a ZIP archive ensuring no files escape target_dir (Zip Slip mitigation)."""
    target_dir.mkdir(parents=True, exist_ok=True)
    resolved_target = target_dir.resolve()

    with zipfile.ZipFile(zip_path, "r") as archive:
        for member in archive.infolist():
            destination = (target_dir / member.filename).resolve()
            if not destination.is_relative_to(resolved_target):
                raise ValueError(
                    f"Path traversal detected in archive {zip_path}: entry '{member.filename}' "
                    f"resolves outside {resolved_target}"
                )
        archive.extractall(target_dir)


def handle_macos_quarantine(binary_path: Path) -> None:
    """Remove com.apple.quarantine attribute if present on macOS, logging the operation."""
    if platform.system() != "Darwin":
        return

    # Check if quarantine attribute is present
    check_cmd = ["xattr", "-p", "com.apple.quarantine", str(binary_path)]
    result = subprocess.run(check_cmd, capture_output=True, text=True, check=False)
    if result.returncode == 0:
        logger.info(f"Detected com.apple.quarantine on {binary_path}; removing attribute.")
        remove_cmd = ["xattr", "-d", "com.apple.quarantine", str(binary_path)]
        subprocess.run(remove_cmd, check=True)


def download_file(url: str, destination: Path) -> Path:
    """Download a remote URL to a local path."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url) as response, destination.open("wb") as out_file:
        shutil.copyfileobj(response, out_file)
    return destination


def fetch_engine(name: str, config: EngineSourceConfig, cache_dir: Path) -> Path:
    """Download and verify an engine release archive, extracting executable."""
    engine_dir = cache_dir / "engines" / name / config.version
    binary_path = engine_dir / "bin" / name
    if binary_path.is_file():
        return binary_path

    archive_path = cache_dir / "downloads" / config.asset
    logger.info(f"Downloading {name} {config.version} from {config.url}")
    download_file(config.url, archive_path)

    # Security check: verify SHA-256 before any extraction
    verify_sha256(archive_path, config.sha256)

    safe_extract_zip(archive_path, engine_dir)

    binary_path.parent.mkdir(parents=True, exist_ok=True)
    found_binaries = list(engine_dir.glob(f"**/{name}*"))
    for candidate in found_binaries:
        if candidate.is_file() and not candidate.name.endswith(
            (".zip", ".yml", ".yaml", ".png", ".css", ".md", ".txt")
        ):
            candidate.chmod(0o755)
            handle_macos_quarantine(candidate)
            if candidate.resolve() != binary_path.resolve():
                shutil.copy2(candidate, binary_path)
            return binary_path

    return binary_path


def fetch_git_repo(repo_url: str, commit: str, target_dir: Path) -> Path:
    """Fetch a pinned git commit into target_dir using git CLI."""
    if target_dir.is_dir() and (target_dir / ".git").is_dir():
        # Check current commit
        res = subprocess.run(
            ["git", "-C", str(target_dir), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
        )
        if res.returncode == 0 and res.stdout.strip() == commit:
            return target_dir

    target_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", str(target_dir)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(target_dir), "remote", "add", "origin", repo_url],
        check=False,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(target_dir), "fetch", "--depth", "1", "origin", commit],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(target_dir), "checkout", commit],
        check=True,
        capture_output=True,
    )
    return target_dir


def fetch_all(manifest: ManifestConfig | None = None) -> dict[str, Path]:
    """Fetch all pinned sources defined in manifest."""
    if manifest is None:
        manifest = load_manifest()

    cache_dir = get_cache_dir()
    results: dict[str, Path] = {}

    # Fetch SigmaHQ rules
    sigma_conf = manifest.rules["sigmahq"]
    rules_dir = cache_dir / "rules" / "sigmahq"
    logger.info(f"Fetching SigmaHQ at commit {sigma_conf.commit}")
    fetch_git_repo(sigma_conf.repo, sigma_conf.commit, rules_dir)
    results["rules"] = rules_dir

    # Fetch EVTX attack samples
    dataset_conf = manifest.datasets["evtx_attack_samples"]
    samples_dir = cache_dir / "samples" / "evtx_attack_samples"
    logger.info(f"Fetching EVTX-ATTACK-SAMPLES at commit {dataset_conf.commit}")
    fetch_git_repo(dataset_conf.repo, dataset_conf.commit, samples_dir)
    results["samples"] = samples_dir

    # Fetch Chainsaw engine (primary)
    chainsaw_conf = manifest.engines["chainsaw"]
    logger.info(f"Fetching Chainsaw {chainsaw_conf.version}")
    chainsaw_bin = fetch_engine("chainsaw", chainsaw_conf, cache_dir)
    results["chainsaw"] = chainsaw_bin

    return results
