# unit tests for classification rules
"""Unit tests for the four-class classification engine and matching policy."""

from pathlib import Path

from ruleproof.classify import (
    check_pair_evaluability,
    classify_rules,
    compute_family_sensitivity,
    compute_label_tag_agreement,
    compute_leave_one_out_recall,
    compute_pair_metrics,
    compute_sample_side_recall,
    matches_technique_exact,
    matches_technique_family,
    matches_technique_hierarchical,
)
from ruleproof.models import EngineResult, SampleRecord, SigmaRule


def test_technique_matching_policy() -> None:
    # Exact match
    assert matches_technique_exact(["T1059.001"], ["T1059.001"]) is True
    assert matches_technique_exact(["T1059"], ["T1059.001"]) is False

    # Hierarchical match (parent rule matches sub-technique sample)
    assert matches_technique_hierarchical(["T1059"], ["T1059.001"]) is True

    # Rule is sub-technique, sample is parent -> strictly NO match (ADR-003)
    assert matches_technique_hierarchical(["T1059.001"], ["T1059"]) is False


def test_evaluability_pair_level_checks() -> None:
    # Rule 259a9cdf: External Remote RDP Logon (Security 4624)
    rdp_rule = SigmaRule(
        rule_id="259a9cdf-c4dd-4fa2-b243-2269e5ab18a2",
        title="External Remote RDP Logon from Public IP",
        status="test",
        logsource={"product": "windows", "service": "security"},
        techniques=["T1133", "T1078", "T1110"],
        detection_event_ids=[4624],
        file_path=Path("rdp.yml"),
    )

    # Sample Network_Service_Guest_added_to_admins_4732.evtx: only Security 4732
    telemetry_4732 = {"Security": {4732}}
    is_eval, reason = check_pair_evaluability(rdp_rule, telemetry_4732)
    assert is_eval is False
    assert reason == "not_evaluable_missing_telemetry"

    # With 4624 present -> evaluable
    telemetry_4624 = {"Security": {4624, 4732}}
    is_eval, reason = check_pair_evaluability(rdp_rule, telemetry_4624)
    assert is_eval is True
    assert reason == "evaluable"

    # Rule b17ea6f7: Shadow Copies Creation (category: process_creation -> 1 or 4688)
    shadow_rule = SigmaRule(
        rule_id="b17ea6f7-6e90-447e-a799-e6c0a493d6ce",
        title="Shadow Copies Creation",
        status="test",
        logsource={"category": "process_creation", "product": "windows"},
        techniques=["T1003"],
        file_path=Path("shadow.yml"),
    )

    # Sample CA_DCSync_4662.evtx: only Security 4662
    telemetry_4662 = {"Security": {4662}}
    is_eval, reason = check_pair_evaluability(shadow_rule, telemetry_4662)
    assert is_eval is False
    assert reason == "not_evaluable_missing_telemetry"

    # With Sysmon 1 or Security 4688 -> evaluable
    telemetry_proc = {"Security": {4688}}
    is_eval, reason = check_pair_evaluability(shadow_rule, telemetry_proc)
    assert is_eval is True
    assert reason == "evaluable"

    # Rule with unknown category -> not_evaluable_unknown_mapping
    unknown_cat_rule = SigmaRule(
        rule_id="unknown_rule",
        title="Unknown Category Rule",
        status="test",
        logsource={"category": "unsupported_custom_category", "product": "windows"},
        techniques=["T1059"],
        file_path=Path("unknown.yml"),
    )
    is_eval, reason = check_pair_evaluability(unknown_cat_rule, telemetry_proc)
    assert is_eval is False
    assert reason == "not_evaluable_unknown_mapping"


def test_four_class_classification() -> None:
    # Rule 1: Fired on matching evaluable sample -> validated
    r1 = SigmaRule(
        rule_id="r1",
        title="Rule 1",
        status="stable",
        logsource={"category": "process_creation", "product": "windows"},
        techniques=["T1059.001"],
        file_path=Path("/tmp/r1.yml"),
    )

    # Rule 2: Did not fire on matching evaluable sample -> failing
    r2 = SigmaRule(
        rule_id="r2",
        title="Rule 2",
        status="stable",
        logsource={"category": "process_access", "product": "windows"},
        techniques=["T1003.001"],
        file_path=Path("/tmp/r2.yml"),
    )

    # Rule 3: Sample matches technique but lacks required channel/EventID -> not_evaluable
    r3 = SigmaRule(
        rule_id="r3",
        title="Rule 3",
        status="stable",
        logsource={"product": "windows", "service": "powershell"},
        techniques=["T1059.001"],
        detection_event_ids=[4104],
        file_path=Path("/tmp/r3.yml"),
    )

    # Rule 4: No sample with claimed technique -> unvalidated
    r4 = SigmaRule(
        rule_id="r4",
        title="Rule 4",
        status="stable",
        logsource={"category": "process_creation", "product": "windows"},
        techniques=["T9999"],
        file_path=Path("/tmp/r4.yml"),
    )

    s1 = SampleRecord(
        sample_id="s1.evtx",
        file_path=Path("/tmp/s1.evtx"),
        techniques=["T1059.001"],
        is_labelled=True,
        label_source="test",
    )
    s2 = SampleRecord(
        sample_id="s2.evtx",
        file_path=Path("/tmp/s2.evtx"),
        techniques=["T1003.001"],
        is_labelled=True,
        label_source="test",
    )

    results = [
        EngineResult(
            rule_id="r1",
            sample_id="s1.evtx",
            engine="chainsaw",
            engine_version="v2.17.1",
            rule_commit="c1",
            dataset_commit="c2",
            fired=True,
        ),
        EngineResult(
            rule_id="r2",
            sample_id="s2.evtx",
            engine="chainsaw",
            engine_version="v2.17.1",
            rule_commit="c1",
            dataset_commit="c2",
            fired=False,
        ),
        EngineResult(
            rule_id="r3",
            sample_id="s1.evtx",
            engine="chainsaw",
            engine_version="v2.17.1",
            rule_commit="c1",
            dataset_commit="c2",
            fired=False,
        ),
    ]

    telemetries = {
        "s1.evtx": {"Microsoft-Windows-Sysmon/Operational": {1}},
        "s2.evtx": {"Microsoft-Windows-Sysmon/Operational": {10}},
    }

    classifications = classify_rules(
        rules=[r1, r2, r3, r4],
        samples=[s1, s2],
        engine_results=results,
        sample_telemetries=telemetries,
    )

    cls_map = {c.rule_id: c for c in classifications}
    assert cls_map["r1"].classification_exact == "validated"
    assert cls_map["r2"].classification_exact == "failing"
    assert cls_map["r3"].classification_exact == "not_evaluable"
    assert cls_map["r4"].classification_exact == "unvalidated"

    # Check pair metrics
    pair_metrics = compute_pair_metrics(
        rules=[r1, r2, r3, r4],
        samples=[s1, s2],
        engine_results=results,
        sample_telemetries=telemetries,
    )
    assert pair_metrics["total_candidate_pairs"] == 3
    assert pair_metrics["evaluable_pairs"] == 2
    assert pair_metrics["missing_telemetry_pairs"] == 1
    assert pair_metrics["fired_pairs"] == 1

    # Check sample-side recall
    recall_metrics = compute_sample_side_recall(
        rules=[r1, r2, r3, r4],
        samples=[s1, s2],
        engine_results=results,
    )
    assert recall_metrics["total_samples"] == 2
    assert recall_metrics["detected_samples"] == 1  # s1 had r1 fire, s2 had r2 fail


def test_family_matching_and_agreement() -> None:
    # Family matching
    assert matches_technique_family(["T1218.011"], ["T1218"]) is True
    assert matches_technique_family(["T1218.011"], ["T1218.005"]) is True
    assert matches_technique_family(["T1059"], ["T1218"]) is False

    r_fam = SigmaRule(
        rule_id="rfam",
        title="Family Test Rule",
        status="stable",
        logsource={"category": "process_creation"},
        techniques=["T1218.011"],
        file_path=Path("rfam.yml"),
    )
    s_fam = SampleRecord(
        sample_id="sfam.evtx",
        file_path=Path("sfam.evtx"),
        techniques=["T1218.005"],
        is_labelled=True,
        label_source="test",
    )
    res_fam = [
        EngineResult(
            rule_id="rfam",
            sample_id="sfam.evtx",
            engine="chainsaw",
            engine_version="v2.17.1",
            rule_commit="c1",
            dataset_commit="c2",
            fired=True,
        )
    ]
    telemetry = {"sfam.evtx": {"Security": {4688}}}

    fam_sens = compute_family_sensitivity(
        rules=[r_fam],
        samples=[s_fam],
        engine_results=res_fam,
        sample_telemetries=telemetry,
    )
    assert fam_sens["validated_rules"] == 1
    assert fam_sens["sample_side_recall_k"] == 1

    agreement = compute_label_tag_agreement(
        rules=[r_fam],
        samples=[s_fam],
        engine_results=res_fam,
    )
    assert agreement["total_fired_pairs"] == 1
    assert agreement["relation_counts"]["family"] == 1
    assert agreement["samples_with_fire_no_related"] == 0


def test_engine_skipped_and_excluded_rules() -> None:
    r_skipped_with_sample = SigmaRule(
        rule_id="skipped-uuid",
        title="Skipped Rule",
        status="stable",
        logsource={"category": "process_creation"},
        techniques=["T1059.001"],
        file_path=Path("skip.yml"),
    )
    r_excluded_with_sample = SigmaRule(
        rule_id="excluded-uuid",
        title="Excluded Mapping Title",
        status="stable",
        logsource={"category": "process_creation"},
        techniques=["T1059.001"],
        file_path=Path("excl.yml"),
    )
    r_skipped_no_sample = SigmaRule(
        rule_id="skipped-no-sample",
        title="Skipped Rule Without Sample",
        status="stable",
        logsource={"category": "process_creation"},
        techniques=["T9998"],
        file_path=Path("skip2.yml"),
    )
    sample = SampleRecord(
        sample_id="s1.evtx",
        file_path=Path("s1.evtx"),
        techniques=["T1059.001"],
        is_labelled=True,
        label_source="test",
    )
    telemetry = {"s1.evtx": {"Security": {4688}}}
    results = [
        EngineResult(
            rule_id="skipped-uuid",
            sample_id="s1.evtx",
            engine="chainsaw",
            engine_version="v2.17.1",
            rule_commit="c1",
            dataset_commit="c2",
            fired=False,
        ),
        EngineResult(
            rule_id="excluded-uuid",
            sample_id="s1.evtx",
            engine="chainsaw",
            engine_version="v2.17.1",
            rule_commit="c1",
            dataset_commit="c2",
            fired=False,
        ),
    ]

    classifications = classify_rules(
        rules=[r_skipped_with_sample, r_excluded_with_sample, r_skipped_no_sample],
        samples=[sample],
        engine_results=results,
        sample_telemetries=telemetry,
        engine_skipped_rule_ids={"skipped-uuid", "skipped-no-sample"},
        engine_excluded_rule_titles={"Excluded Mapping Title"},
    )
    cls_map = {c.rule_id: c for c in classifications}
    assert cls_map["skipped-uuid"].classification_exact == "not_evaluable"
    assert cls_map["skipped-uuid"].skip_reason == "engine_skipped_or_failed_to_load"
    assert cls_map["excluded-uuid"].classification_exact == "not_evaluable"
    assert cls_map["excluded-uuid"].skip_reason == "engine_excluded_by_mapping"
    # Precedence rule: if no matching sample exists, classification is unvalidated
    assert cls_map["skipped-no-sample"].classification_exact == "unvalidated"
    assert cls_map["skipped-no-sample"].skip_reason == "engine_skipped_or_failed_to_load"


def test_crosswalk_mapping(tmp_path: Path) -> None:
    from ruleproof.classify import apply_crosswalk_to_samples, load_attack_crosswalk

    cw_file = tmp_path / "crosswalk.csv"
    cw_file.write_text("legacy_id,current_id\nT1086,T1059.001\nT1064,T1059.005\nT1064,T1059.007\n")

    crosswalk = load_attack_crosswalk(cw_file)
    assert crosswalk["T1086"] == ["T1059.001"]
    assert crosswalk["T1064"] == ["T1059.005", "T1059.007"]

    samples = [
        SampleRecord(
            sample_id="s1.evtx",
            file_path=Path("s1.evtx"),
            techniques=["T1086"],
            is_labelled=True,
            label_source="test",
        ),
        SampleRecord(
            sample_id="s2.evtx",
            file_path=Path("s2.evtx"),
            techniques=["T1064", "T9999"],
            is_labelled=True,
            label_source="test",
        ),
    ]

    mapped = apply_crosswalk_to_samples(samples, crosswalk)
    assert mapped[0].techniques == ["T1059.001"]
    assert mapped[1].techniques == ["T1059.005", "T1059.007", "T9999"]


def test_compute_leave_one_out_recall() -> None:
    rules = [
        SigmaRule(
            rule_id="r1",
            title="Rule 1",
            status="stable",
            logsource={"product": "windows"},
            techniques=["T1548.002"],
            file_path=Path("r1.yml"),
        ),
        SigmaRule(
            rule_id="r2",
            title="Rule 2",
            status="stable",
            logsource={"product": "windows"},
            techniques=["T1003"],
            file_path=Path("r2.yml"),
        ),
    ]
    samples = [
        SampleRecord(
            sample_id="s1.evtx",
            file_path=Path("s1.evtx"),
            techniques=["T1548.002"],
            is_labelled=True,
            label_source="test",
        ),
        SampleRecord(
            sample_id="s2.evtx",
            file_path=Path("s2.evtx"),
            techniques=["T1003"],
            is_labelled=True,
            label_source="test",
        ),
        SampleRecord(
            sample_id="s3.evtx",
            file_path=Path("s3.evtx"),
            techniques=["T1134"],
            is_labelled=True,
            label_source="test",
        ),
    ]
    results = [
        EngineResult(
            rule_id="r1",
            sample_id="s1.evtx",
            engine="chainsaw",
            engine_version="v2.17.1",
            rule_commit="c",
            dataset_commit="d",
            fired=True,
        ),
        EngineResult(
            rule_id="r2",
            sample_id="s2.evtx",
            engine="chainsaw",
            engine_version="v2.17.1",
            rule_commit="c",
            dataset_commit="d",
            fired=False,
        ),
    ]

    res = compute_leave_one_out_recall(
        rules, samples, results, top_techniques=["T1548.002", "T1003"]
    )
    assert len(res) == 4  # All, Excl T1548.002, Excl T1003, Excl all top 3
    assert res[0]["label"] == "All samples"
    assert res[0]["detected_samples"] == 1
    assert res[0]["total_samples"] == 3

    # Excl T1548.002 -> s1 excluded, remaining s2, s3 (0 detected)
    assert res[1]["label"] == "Excl. T1548.002"
    assert res[1]["detected_samples"] == 0
    assert res[1]["total_samples"] == 2
