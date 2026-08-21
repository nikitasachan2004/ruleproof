"""Unit tests for Wilson interval calculations and report artifact generation."""

from pathlib import Path

from ruleproof.models import EngineResult, RuleClassification
from ruleproof.report import (
    compute_wilson_interval,
    generate_markdown_report,
    write_classification_csv,
    write_results_jsonl,
)


def test_compute_wilson_interval() -> None:
    # 0 observations
    pe, low, high = compute_wilson_interval(0, 0)
    assert pe == 0.0
    assert low == 0.0
    assert high == 0.0

    # 1 failing out of 10
    pe, low, high = compute_wilson_interval(1, 10)
    assert pe == 0.1
    assert 0.01 < low < 0.1
    assert 0.1 < high < 0.5


def test_write_artifacts(tmp_path: Path) -> None:
    classifications = [
        RuleClassification(
            rule_id="r1",
            rule_title="Rule 1",
            rule_status="stable",
            claimed_techniques=["T1059.001"],
            evaluable_samples_count=1,
            classification_exact="validated",
            classification_hierarchical="validated",
            sample_matches=["s1.evtx"],
        )
    ]
    results = [
        EngineResult(
            rule_id="r1",
            sample_id="s1.evtx",
            engine="chainsaw",
            engine_version="v2.17.1",
            rule_commit="c1",
            dataset_commit="c2",
            fired=True,
        )
    ]

    csv_path = tmp_path / "classification.csv"
    jsonl_path = tmp_path / "results.jsonl"

    write_classification_csv(classifications, csv_path)
    write_results_jsonl(results, jsonl_path)

    assert csv_path.is_file()
    assert "rule_id,rule_title" in csv_path.read_text()
    assert "r1" in csv_path.read_text()

    assert jsonl_path.is_file()
    assert '"rule_id":"r1"' in jsonl_path.read_text()


def test_generate_markdown_report() -> None:
    classifications = [
        RuleClassification(
            rule_id="r1",
            rule_title="Rule 1",
            rule_status="stable",
            claimed_techniques=["T1059.001"],
            evaluable_samples_count=1,
            classification_exact="validated",
            classification_hierarchical="validated",
            sample_matches=["s1.evtx"],
        ),
        RuleClassification(
            rule_id="r2",
            rule_title="Rule 2",
            rule_status="stable",
            claimed_techniques=["T1003.001"],
            evaluable_samples_count=1,
            classification_exact="failing",
            classification_hierarchical="failing",
            sample_matches=["s2.evtx"],
        ),
    ]

    pair_metrics = {
        "total_candidate_pairs": 2,
        "evaluable_pairs": 2,
        "missing_telemetry_pairs": 0,
        "unknown_mapping_pairs": 0,
        "fired_pairs": 1,
    }
    recall_metrics = {
        "total_samples": 2,
        "detected_samples": 1,
        "sample_details": [],
        "validated_rules_triggered": {"r1": ["s1.evtx"]},
        "top_10_failing_samples": [("s2.evtx", 1)],
    }

    fam_metrics = {
        "validated_rules": 1,
        "failing_rules": 1,
        "not_evaluable_rules": 0,
        "unvalidated_rules": 0,
        "h1_numerator": 1,
        "h1_denominator": 2,
        "sample_side_recall_k": 1,
        "sample_side_recall_n": 2,
    }
    agr_metrics = {
        "total_fired_pairs": 1,
        "relation_counts": {"exact": 1},
        "samples_with_any_fire": 1,
        "samples_with_fire_no_related": 0,
        "top_10_different_technique": [],
    }

    report = generate_markdown_report(
        classifications=classifications,
        pair_metrics_exact=pair_metrics,
        pair_metrics_hier=pair_metrics,
        recall_metrics_exact=recall_metrics,
        recall_metrics_hier=recall_metrics,
        scope_name="Default (stable + test only)",
        engine_name="chainsaw",
        engine_version="v2.17.1",
        engine_skipped_count=0,
        family_metrics=fam_metrics,
        agreement_metrics=agr_metrics,
    )

    assert "# RuleProof Evaluation Report" in report
    assert "Validated (Fired)" in report
    assert "Failing (Did Not Fire)" in report
    assert "Hypothesis H1 Evaluation" in report
    assert "Label-vs-Tag Agreement on Fired Pairs" in report
    assert "Family-Level Sensitivity Analysis" in report
    assert "Methodological Limitations" in report
    assert "Wilson Score Interval" in report
