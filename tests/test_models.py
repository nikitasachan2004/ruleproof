"""Unit tests for Pydantic data models and schemas."""

from pathlib import Path

from ruleproof.models import SampleRecord, SigmaRule


def test_sigma_rule_model() -> None:
    rule = SigmaRule(
        rule_id="test-123",
        title="Test Rule",
        status="stable",
        logsource={"product": "windows"},
        techniques=["T1003.001"],
        file_path=Path("/tmp/rule.yml"),
    )
    assert rule.rule_id == "test-123"
    assert rule.status == "stable"
    assert "T1003.001" in rule.techniques


def test_sample_record_model() -> None:
    sample = SampleRecord(
        sample_id="test.evtx",
        file_path=Path("/tmp/test.evtx"),
        techniques=["T1059"],
        is_labelled=True,
        label_source="manifest",
    )
    assert sample.is_labelled is True
    assert sample.techniques == ["T1059"]
