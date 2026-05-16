# cli inspect and help tests
"""Unit tests for RuleProof command line interface."""

from pathlib import Path

from typer.testing import CliRunner

from ruleproof.cli import app

runner = CliRunner()


def test_cli_help() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Reproducible harness testing Sigma rules" in result.stdout
    assert "fetch" in result.stdout
    assert "inspect" in result.stdout


def test_cli_inspect_with_fixtures() -> None:
    fixtures_dir = Path(__file__).parent / "fixtures"
    rules_dir = fixtures_dir / "rules"
    samples_dir = fixtures_dir / "samples"

    result = runner.invoke(
        app,
        [
            "inspect",
            "--rules-dir",
            str(rules_dir),
            "--samples-dir",
            str(samples_dir),
        ],
    )
    assert result.exit_code == 0
    assert "RuleProof Inspection Summary" in result.stdout
    assert "Total Rules Loaded:           2" in result.stdout  # Default filter: stable + test
    assert "Author-Labelled Samples:    0" in result.stdout or "Samples" in result.stdout


def test_cli_inspect_missing_rules_dir(tmp_path: Path) -> None:
    missing_dir = tmp_path / "nonexistent"
    result = runner.invoke(app, ["inspect", "--rules-dir", str(missing_dir)])
    assert result.exit_code == 1
    output = result.stdout or result.stderr
    assert "What to do next:" in output
