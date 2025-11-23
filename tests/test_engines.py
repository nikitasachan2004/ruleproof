"""Unit tests for engine execution failure handling, timeouts, and malformed outputs."""

import stat
from pathlib import Path

import pytest

from ruleproof.engines.base import EngineError
from ruleproof.engines.chainsaw import ChainsawEngine


def _create_fake_script(path: Path, script_body: str) -> Path:
    """Create an executable python script to act as a fake engine binary."""
    path.write_text(f"#!/usr/bin/env python3\n{script_body}\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


def test_chainsaw_engine_nonzero_exit(tmp_path: Path) -> None:
    fake_bin = _create_fake_script(
        tmp_path / "fake_chainsaw_err",
        """
import sys
sys.stderr.write("Fatal syntax error in detection logic\\n")
sys.exit(2)
""",
    )
    mapping_file = tmp_path / "mapping.yml"
    mapping_file.write_text("exclusions: []\n", encoding="utf-8")

    engine = ChainsawEngine(binary_path=fake_bin, mapping_path=mapping_file, timeout=5)
    sample_path = tmp_path / "test.evtx"
    sample_path.touch()
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

    with pytest.raises(EngineError) as exc_info:
        engine.hunt(sample_path, rules_dir)
    assert exc_info.value.returncode == 2
    assert "Fatal syntax error" in str(exc_info.value)

    with pytest.raises(EngineError) as exc_info:
        engine.get_sample_telemetry(sample_path)
    assert exc_info.value.returncode == 2


def test_chainsaw_engine_timeout(tmp_path: Path) -> None:
    fake_bin = _create_fake_script(
        tmp_path / "fake_chainsaw_timeout",
        """
import time
time.sleep(3)
""",
    )
    mapping_file = tmp_path / "mapping.yml"
    mapping_file.write_text("exclusions: []\n", encoding="utf-8")

    engine = ChainsawEngine(binary_path=fake_bin, mapping_path=mapping_file, timeout=1)
    sample_path = tmp_path / "test.evtx"
    sample_path.touch()
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

    with pytest.raises(EngineError) as exc_info:
        engine.hunt(sample_path, rules_dir)
    assert "timed out after 1s" in str(exc_info.value)

    with pytest.raises(EngineError) as exc_info:
        engine.get_sample_telemetry(sample_path)
    assert "timed out after 1s" in str(exc_info.value)


def test_chainsaw_engine_malformed_json(tmp_path: Path) -> None:
    fake_bin = _create_fake_script(
        tmp_path / "fake_chainsaw_malformed",
        """
import sys
# Output malformed json starting with [{ but broken
sys.stdout.write("[{ broken json content without closing")
sys.exit(0)
""",
    )
    mapping_file = tmp_path / "mapping.yml"
    mapping_file.write_text("exclusions: []\n", encoding="utf-8")

    engine = ChainsawEngine(binary_path=fake_bin, mapping_path=mapping_file, timeout=5)
    sample_path = tmp_path / "test.evtx"
    sample_path.touch()
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

    with pytest.raises(EngineError) as exc_info:
        engine.hunt(sample_path, rules_dir)
    assert "Failed to parse Chainsaw detection JSON" in str(exc_info.value)

    with pytest.raises(EngineError) as exc_info:
        engine.get_sample_telemetry(sample_path)
    assert "Failed to parse chainsaw analyse telemetry" in str(exc_info.value)
