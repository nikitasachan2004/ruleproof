"""Unit tests for the runner pipeline using mock engine."""

from pathlib import Path

from ruleproof.engines.base import BaseEngine
from ruleproof.models import SampleRecord, SigmaRule
from ruleproof.runner import run_engine_across_samples


class MockEngine(BaseEngine):
    @property
    def name(self) -> str:
        return "mock_engine"

    @property
    def version(self) -> str:
        return "v1.0.0"

    def hunt(self, sample_path: Path, _rules_path: Path) -> list[str]:
        # Mock firing rule-1 on sample-1
        if "sample_1" in sample_path.name:
            return ["rule-1"]
        return []

    def get_sample_telemetry(self, _sample_path: Path) -> dict[str, set[int]]:
        return {"Microsoft-Windows-Sysmon/Operational": {1, 3}}


def test_run_engine_across_samples() -> None:
    rules = [
        SigmaRule(
            rule_id="rule-1",
            title="Rule 1",
            status="stable",
            logsource={"product": "windows", "service": "sysmon"},
            techniques=["T1059.001"],
            file_path=Path("/tmp/r1.yml"),
        ),
        SigmaRule(
            rule_id="rule-2",
            title="Rule 2",
            status="test",
            logsource={"product": "windows"},
            techniques=["T1003"],
            file_path=Path("/tmp/r2.yml"),
        ),
    ]

    samples = [
        SampleRecord(
            sample_id="sample_1.evtx",
            file_path=Path("/tmp/sample_1.evtx"),
            techniques=["T1059.001"],
            is_labelled=True,
            label_source="test",
        ),
        SampleRecord(
            sample_id="sample_2.evtx",
            file_path=Path("/tmp/sample_2.evtx"),
            techniques=["T1003"],
            is_labelled=True,
            label_source="test",
        ),
    ]

    engine = MockEngine()
    results, telemetries, run_manifest = run_engine_across_samples(
        engine=engine,
        rules=rules,
        samples=samples,
        rules_dir=Path("/tmp"),
        rule_commit="c1",
        dataset_commit="c2",
    )

    assert len(results) == 4  # 2 rules * 2 samples
    assert "sample_1.evtx" in telemetries
    assert run_manifest["total_samples"] == 2
    assert run_manifest["failed_samples"] == []
    assert run_manifest["samples"]["sample_1.evtx"]["status"] == "ok"

    # Check fired result
    fired_records = [r for r in results if r.fired]
    assert len(fired_records) == 1
    assert fired_records[0].rule_id == "rule-1"
    assert fired_records[0].sample_id == "sample_1.evtx"
