"""Integration test executing Chainsaw on downloaded repositories when available."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from ruleproof.cli import app
from ruleproof.config import get_cache_dir

runner = CliRunner()


@pytest.mark.integration
def test_full_pipeline_integration() -> None:
    cache_dir = get_cache_dir()
    rules_dir = cache_dir / "rules" / "sigmahq" / "rules" / "windows"
    samples_dir = cache_dir / "samples" / "evtx_attack_samples"
    chainsaw_bin = cache_dir / "engines" / "chainsaw" / "v2.17.1" / "bin" / "chainsaw"
    if not chainsaw_bin.is_file():
        chainsaw_bin = cache_dir / "engines" / "chainsaw" / "v2.17.1" / "chainsaw"

    if not rules_dir.is_dir() or not samples_dir.is_dir() or not chainsaw_bin.is_file():
        pytest.skip("Required real data or chainsaw binary not present in .cache")

    result = runner.invoke(app, ["run", "--output-dir", "outputs/test_run"])
    assert result.exit_code == 0
    assert (Path("outputs/test_run") / "classification.csv").is_file()
    assert (Path("outputs/test_run") / "results.jsonl").is_file()
    assert (Path("outputs/test_run") / "report.md").is_file()
