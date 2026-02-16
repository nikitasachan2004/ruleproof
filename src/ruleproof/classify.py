# initial classifier structure
"""Classification engine assigning rules into four evaluation categories."""

import logging
from pathlib import Path
from typing import Any

from ruleproof.models import EngineResult, RuleClassification, SampleRecord, SigmaRule

logger = logging.getLogger(__name__)

# Preconditions from Chainsaw's sigma-event-logs-all.yml mapping
CHAINSAW_CATEGORY_EVENT_IDS: dict[str, set[int]] = {
    "process_creation": {1, 4688},
    "network_connection": {3},
    "sysmon_status": {4, 16},
    "process_termination": {5},
    "driver_load": {6},
    "image_load": {7},
    "create_remote_thread": {8},
    "raw_access_thread": {9},
    "process_access": {10},
    "file_event": {11},
    "registry_event": {12, 13, 14},
    "registry_add": {12},
    "registry_delete": {12},
    "registry_set": {13},
    "registry_rename": {14},
    "create_stream_hash": {15},
    "pipe_created": {17, 18},
    "wmi_event": {19, 20, 21},
    "dns_query": {22},
    "file_delete": {23},
    "clipboard_change": {24},
    "process_tampering": {25},
    "file_delete_detected": {26},
    "file_block": {27},
    "file_block_executable": {27},
    "file_block_shredding": {28},
    "file_executable_detected": {29},
    "sysmon_error": {255},
}


def matches_technique_exact(rule_techs: list[str], sample_techs: list[str]) -> bool:
    """Return True if rule and sample share at least one identical ATT&CK ID."""
    return bool(set(rule_techs) & set(sample_techs))


def matches_technique_hierarchical(rule_techs: list[str], sample_techs: list[str]) -> bool:
    """Return True if exact match or if rule specifies parent technique of sample sub-technique.

    Example: Rule has T1059, Sample has T1059.001 -> Match.
    Rule has T1059.001, Sample has T1059 -> Strictly NO match (ADR-003).
    """
    if matches_technique_exact(rule_techs, sample_techs):
        return True

    for r_tech in rule_techs:
        for s_tech in sample_techs:
            if s_tech.startswith(f"{r_tech}."):
                return True
    return False


def matches_technique_family(rule_techs: list[str], sample_techs: list[str]) -> bool:
    """Return True if rule and sample share the same parent technique ID (e.g. T1218)."""
    r_parents = {t.split(".")[0] for t in rule_techs if t.startswith("T")}
    s_parents = {t.split(".")[0] for t in sample_techs if t.startswith("T")}
    return bool(r_parents & s_parents)


def get_rule_expected_event_ids(rule: SigmaRule) -> tuple[set[int], bool]:
    """Derive expected Event IDs for a rule using Chainsaw mapping and rule detection.

    Returns:
      (expected_event_ids, is_known_mapping)
      If Chainsaw's mapping does not state Event IDs for a category, or if no category/service
      mapping or explicit EventID exists, is_known_mapping is False.
    """
    cat = str(rule.logsource.get("category") or "").strip().lower()
    if cat:
        if cat in CHAINSAW_CATEGORY_EVENT_IDS:
            return set(CHAINSAW_CATEGORY_EVENT_IDS[cat]), True
        # Category not mapped by chainsaw preconditions
        return set(), False

    # For service or product without category, check explicit detection EventID
    if rule.detection_event_ids:
        return set(rule.detection_event_ids), True

    return set(), False


def check_pair_evaluability(
    rule: SigmaRule,
    sample_telemetry: dict[str, set[int]],
) -> tuple[bool, str]:
    """Check whether a (rule, sample) pair is evaluable at the Event ID level.

    Returns:
      (is_evaluable, reason)
      Reasons:
        - 'evaluable': Sample contains at least one Event ID the rule's logsource/detection matches.
        - 'not_evaluable_missing_telemetry': Sample does not contain required Event IDs.
        - 'not_evaluable_unknown_mapping': Chainsaw mapping lacks Event IDs for rule logsource.
    """
    if not sample_telemetry:
        return False, "not_evaluable_missing_telemetry"

    expected_eids, is_known = get_rule_expected_event_ids(rule)
    if not is_known:
        return False, "not_evaluable_unknown_mapping"

    # All event IDs present in the sample across all channels
    present_eids: set[int] = set().union(*sample_telemetry.values())
    if expected_eids & present_eids:
        return True, "evaluable"

    return False, "not_evaluable_missing_telemetry"


def is_sample_telemetry_evaluable(
    logsource: dict[str, Any],
    sample_telemetry: dict[str, set[int]],
    detection_event_ids: list[int] | None = None,
) -> bool:
    """Backward-compatible helper checking if sample telemetry is evaluable."""
    dummy_rule = SigmaRule(
        rule_id="dummy",
        title="dummy",
        status="test",
        logsource=logsource,
        techniques=[],
        detection_event_ids=detection_event_ids or [],
        file_path=Path("dummy.yml"),
    )
    is_eval, _ = check_pair_evaluability(dummy_rule, sample_telemetry)
    return is_eval


def classify_rules(
    rules: list[SigmaRule],
    samples: list[SampleRecord],
    engine_results: list[EngineResult],
    sample_telemetries: dict[str, dict[str, set[int]]],
    engine_skipped_rule_ids: set[str] | None = None,
    engine_excluded_rule_titles: set[str] | None = None,
) -> list[RuleClassification]:
    """Classify each rule into: validated, failing, not_evaluable, unvalidated."""
    if engine_skipped_rule_ids is None:
        engine_skipped_rule_ids = set()
    if engine_excluded_rule_titles is None:
        engine_excluded_rule_titles = set()

    # Map (rule_id, sample_id) -> fired
    fired_map = {(r.rule_id, r.sample_id): r.fired for r in engine_results}

    classifications: list[RuleClassification] = []

    def evaluate_class(
        matching_samples: list[SampleRecord], current_rule: SigmaRule
    ) -> tuple[str, list[str], int, str | None]:
        if not matching_samples:
            return "unvalidated", [], 0, "no_matching_sample"

        # Check if fired on ANY matching sample regardless of telemetry extraction
        fired_samples = [
            s.sample_id
            for s in matching_samples
            if fired_map.get((current_rule.rule_id, s.sample_id), False)
        ]
        if fired_samples:
            return "validated", fired_samples, len(matching_samples), None

        # If not fired, check evaluability for each sample
        evaluable_samples: list[str] = []
        unknown_mapping_count = 0

        for s in matching_samples:
            is_eval, reason = check_pair_evaluability(
                current_rule, sample_telemetries.get(s.sample_id, {})
            )
            if is_eval:
                evaluable_samples.append(s.sample_id)
            elif reason == "not_evaluable_unknown_mapping":
                unknown_mapping_count += 1

        if evaluable_samples:
            return "failing", evaluable_samples, len(evaluable_samples), None

        if unknown_mapping_count > 0:
            return (
                "not_evaluable",
                [s.sample_id for s in matching_samples],
                0,
                "not_evaluable_unknown_mapping",
            )
        return (
            "not_evaluable",
            [s.sample_id for s in matching_samples],
            0,
            "not_evaluable_missing_telemetry",
        )

    for rule in rules:
        if not rule.techniques:
            classifications.append(
                RuleClassification(
                    rule_id=rule.rule_id,
                    rule_title=rule.title,
                    rule_status=rule.status,
                    claimed_techniques=[],
                    evaluable_samples_count=0,
                    classification_exact="unvalidated",
                    classification_hierarchical="unvalidated",
                    sample_matches=[],
                    skip_reason="no_claimed_techniques",
                )
            )
            continue

        exact_samples = [
            s
            for s in samples
            if s.is_labelled and matches_technique_exact(rule.techniques, s.techniques)
        ]

        hier_samples = [
            s
            for s in samples
            if s.is_labelled and matches_technique_hierarchical(rule.techniques, s.techniques)
        ]

        if rule.rule_id in engine_skipped_rule_ids:
            cls_exact = "not_evaluable" if exact_samples else "unvalidated"
            cls_hier = "not_evaluable" if hier_samples else "unvalidated"
            classifications.append(
                RuleClassification(
                    rule_id=rule.rule_id,
                    rule_title=rule.title,
                    rule_status=rule.status,
                    claimed_techniques=rule.techniques,
                    evaluable_samples_count=0,
                    classification_exact=cls_exact,
                    classification_hierarchical=cls_hier,
                    sample_matches=[],
                    skip_reason="engine_skipped_or_failed_to_load",
                )
            )
            continue

        if rule.title in engine_excluded_rule_titles:
            cls_exact = "not_evaluable" if exact_samples else "unvalidated"
            cls_hier = "not_evaluable" if hier_samples else "unvalidated"
            classifications.append(
                RuleClassification(
                    rule_id=rule.rule_id,
                    rule_title=rule.title,
                    rule_status=rule.status,
                    claimed_techniques=rule.techniques,
                    evaluable_samples_count=0,
                    classification_exact=cls_exact,
                    classification_hierarchical=cls_hier,
                    sample_matches=[],
                    skip_reason="engine_excluded_by_mapping",
                )
            )
            continue

        cls_exact, matches_exact, eval_exact, reason_exact = evaluate_class(exact_samples, rule)
        cls_hier, matches_hier, _, _ = evaluate_class(hier_samples, rule)

        classifications.append(
            RuleClassification(
                rule_id=rule.rule_id,
                rule_title=rule.title,
                rule_status=rule.status,
                claimed_techniques=rule.techniques,
                evaluable_samples_count=eval_exact,
                classification_exact=cls_exact,
                classification_hierarchical=cls_hier,
                sample_matches=sorted(set(matches_exact + matches_hier)),
                skip_reason=reason_exact,
            )
        )

    classifications.sort(key=lambda c: c.rule_id)
    return classifications


def compute_pair_metrics(
    rules: list[SigmaRule],
    samples: list[SampleRecord],
    engine_results: list[EngineResult],
    sample_telemetries: dict[str, dict[str, set[int]]],
    match_hierarchical: bool = False,
    engine_skipped_rule_ids: set[str] | None = None,
    engine_excluded_rule_titles: set[str] | None = None,
) -> dict[str, int]:
    """Compute pair-level statistics: total candidate pairs, evaluable, unknown mapping, fired."""
    fired_map = {(r.rule_id, r.sample_id): r.fired for r in engine_results}
    matcher = matches_technique_hierarchical if match_hierarchical else matches_technique_exact

    total_pairs = 0
    evaluable_pairs = 0
    missing_telemetry_pairs = 0
    unknown_mapping_pairs = 0
    fired_pairs = 0

    for rule in rules:
        for sample in samples:
            if not sample.is_labelled or not matcher(rule.techniques, sample.techniques):
                continue

            total_pairs += 1
            is_fired = fired_map.get((rule.rule_id, sample.sample_id), False)
            if is_fired:
                fired_pairs += 1

            if (engine_skipped_rule_ids and rule.rule_id in engine_skipped_rule_ids) or (
                engine_excluded_rule_titles and rule.title in engine_excluded_rule_titles
            ):
                missing_telemetry_pairs += 1
                continue

            is_eval, reason = check_pair_evaluability(
                rule, sample_telemetries.get(sample.sample_id, {})
            )
            if is_eval:
                evaluable_pairs += 1
            elif reason == "not_evaluable_unknown_mapping":
                unknown_mapping_pairs += 1
            else:
                missing_telemetry_pairs += 1

    return {
        "total_candidate_pairs": total_pairs,
        "evaluable_pairs": evaluable_pairs,
        "missing_telemetry_pairs": missing_telemetry_pairs,
        "unknown_mapping_pairs": unknown_mapping_pairs,
        "fired_pairs": fired_pairs,
    }


def compute_sample_side_recall(
    rules: list[SigmaRule],
    samples: list[SampleRecord],
    engine_results: list[EngineResult],
    match_hierarchical: bool = False,
) -> dict[str, Any]:
    """Evaluate sample-side recall: fraction of labelled samples where >= 1 claiming rule fired."""
    fired_map = {(r.rule_id, r.sample_id): r.fired for r in engine_results}
    matcher = matches_technique_hierarchical if match_hierarchical else matches_technique_exact

    labelled_samples = [s for s in samples if s.is_labelled]
    detected_samples = 0
    sample_details: list[dict[str, Any]] = []

    validated_rules_map: dict[str, list[str]] = {}  # rule_id -> list of sample_ids
    failing_pairs_per_sample: dict[str, int] = {}  # sample_id -> count of non-firing claiming rules

    for s in labelled_samples:
        claiming_rules = [r for r in rules if matcher(r.techniques, s.techniques)]
        sample_fired_rules: list[str] = []
        for r in claiming_rules:
            if fired_map.get((r.rule_id, s.sample_id), False):
                sample_fired_rules.append(r.rule_id)
                if r.rule_id not in validated_rules_map:
                    validated_rules_map[r.rule_id] = []
                validated_rules_map[r.rule_id].append(s.sample_id)

        has_detection = len(sample_fired_rules) > 0
        if has_detection:
            detected_samples += 1

        failing_rules_count = len(claiming_rules) - len(sample_fired_rules)
        failing_pairs_per_sample[s.sample_id] = failing_rules_count

        sample_details.append(
            {
                "sample_id": s.sample_id,
                "techniques": s.techniques,
                "claiming_rules_count": len(claiming_rules),
                "fired_rules_count": len(sample_fired_rules),
                "detected": has_detection,
            }
        )

    # Top 10 samples with the most non-firing claiming rules
    top_10_failing = sorted(
        failing_pairs_per_sample.items(), key=lambda item: item[1], reverse=True
    )[:10]

    return {
        "total_samples": len(labelled_samples),
        "detected_samples": detected_samples,
        "sample_details": sample_details,
        "validated_rules_triggered": validated_rules_map,
        "top_10_failing_samples": top_10_failing,
    }


def compute_family_sensitivity(
    rules: list[SigmaRule],
    samples: list[SampleRecord],
    engine_results: list[EngineResult],
    sample_telemetries: dict[str, dict[str, set[int]]],
    engine_skipped_rule_ids: set[str] | None = None,
    engine_excluded_rule_titles: set[str] | None = None,
) -> dict[str, Any]:
    """Compute sensitivity analysis where matching is based on shared parent technique ID."""
    fired_map = {(r.rule_id, r.sample_id): r.fired for r in engine_results}
    labelled_samples = [s for s in samples if s.is_labelled]

    val_rules: set[str] = set()
    fail_rules: set[str] = set()
    not_eval_rules: set[str] = set()
    unval_rules: set[str] = set()

    sample_detected: set[str] = set()

    for r in rules:
        matching_samples = [
            s for s in labelled_samples if matches_technique_family(r.techniques, s.techniques)
        ]
        if not matching_samples:
            unval_rules.add(r.rule_id)
            continue

        if (engine_skipped_rule_ids and r.rule_id in engine_skipped_rule_ids) or (
            engine_excluded_rule_titles and r.title in engine_excluded_rule_titles
        ):
            not_eval_rules.add(r.rule_id)
            continue

        fired_any = False
        eval_any = False
        for s in matching_samples:
            if fired_map.get((r.rule_id, s.sample_id), False):
                fired_any = True
                sample_detected.add(s.sample_id)
            is_eval, _ = check_pair_evaluability(r, sample_telemetries.get(s.sample_id, {}))
            if is_eval:
                eval_any = True

        if fired_any:
            val_rules.add(r.rule_id)
        elif eval_any:
            fail_rules.add(r.rule_id)
        else:
            not_eval_rules.add(r.rule_id)

    k_h1 = len(fail_rules)
    n_h1 = len(val_rules) + len(fail_rules)

    return {
        "validated_rules": len(val_rules),
        "failing_rules": len(fail_rules),
        "not_evaluable_rules": len(not_eval_rules),
        "unvalidated_rules": len(unval_rules),
        "h1_numerator": k_h1,
        "h1_denominator": n_h1,
        "sample_side_recall_k": len(sample_detected),
        "sample_side_recall_n": len(labelled_samples),
    }


def compute_label_tag_agreement(
    rules: list[SigmaRule],
    samples: list[SampleRecord],
    engine_results: list[EngineResult],
) -> dict[str, Any]:
    """Classify relation between fired rule tags and sample labels."""
    from collections import Counter, defaultdict

    rule_map = {r.rule_id: r for r in rules}
    sample_map = {s.sample_id: s for s in samples if s.is_labelled}

    fired_pairs = [
        (r.rule_id, r.sample_id)
        for r in engine_results
        if r.fired and r.rule_id in rule_map and r.sample_id in sample_map
    ]

    relation_counts: Counter[str] = Counter()
    sample_fires: defaultdict[str, list[str]] = defaultdict(list)
    diff_tech_pairs: Counter[tuple[str, str]] = Counter()

    for rid, sid in fired_pairs:
        rule = rule_map[rid]
        sample = sample_map[sid]
        r_techs = rule.techniques
        s_techs = sample.techniques

        if not r_techs:
            rel = "untagged_rule"
        elif matches_technique_exact(r_techs, s_techs):
            rel = "exact"
        elif matches_technique_hierarchical(r_techs, s_techs):
            rel = "hierarchical"
        elif matches_technique_family(r_techs, s_techs):
            rel = "family"
        else:
            rel = "different_technique"
            for st in s_techs:
                for rt in r_techs:
                    diff_tech_pairs[(st, rt)] += 1

        relation_counts[rel] += 1
        sample_fires[sid].append(rel)

    samples_with_fire_no_related = sum(
        1
        for rels in sample_fires.values()
        if not any(r in ("exact", "hierarchical", "family") for r in rels)
    )

    top_10_diff = diff_tech_pairs.most_common(10)

    return {
        "total_fired_pairs": len(fired_pairs),
        "relation_counts": dict(relation_counts),
        "samples_with_any_fire": len(sample_fires),
        "samples_with_fire_no_related": samples_with_fire_no_related,
        "top_10_different_technique": top_10_diff,
    }


def compute_per_technique_metrics(
    rules: list[SigmaRule],
    samples: list[SampleRecord],
    engine_results: list[EngineResult],
    sample_telemetries: dict[str, dict[str, set[int]]],
    engine_skipped_rule_ids: set[str] | None = None,
    engine_excluded_rule_titles: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Compute per-technique coverage and sample-side recall metrics."""
    from collections import defaultdict

    fired_map = {(r.rule_id, r.sample_id): r.fired for r in engine_results}
    labelled_samples = [s for s in samples if s.is_labelled]

    tech_samples: defaultdict[str, list[SampleRecord]] = defaultdict(list)
    for s in labelled_samples:
        for t in s.techniques:
            tech_samples[t].append(s)

    rows: list[dict[str, Any]] = []
    for t in sorted(tech_samples.keys()):
        s_list = tech_samples[t]
        s_ids = {s.sample_id for s in s_list}

        claiming_rules = [r for r in rules if t in r.techniques]

        val_cnt = 0
        fail_cnt = 0
        ne_cnt = 0

        for r in claiming_rules:
            if (engine_skipped_rule_ids and r.rule_id in engine_skipped_rule_ids) or (
                engine_excluded_rule_titles and r.title in engine_excluded_rule_titles
            ):
                ne_cnt += 1
                continue
            fired_on_t = any(fired_map.get((r.rule_id, sid), False) for sid in s_ids)
            eval_on_t = any(
                check_pair_evaluability(r, sample_telemetries.get(sid, {}))[0] for sid in s_ids
            )
            if fired_on_t:
                val_cnt += 1
            elif eval_on_t:
                fail_cnt += 1
            else:
                ne_cnt += 1

        rec_exact_k = sum(
            1
            for s in s_list
            if any(fired_map.get((r.rule_id, s.sample_id), False) for r in claiming_rules)
        )

        fam_rules = [r for r in rules if matches_technique_family(r.techniques, [t])]
        rec_fam_k = sum(
            1
            for s in s_list
            if any(fired_map.get((r.rule_id, s.sample_id), False) for r in fam_rules)
        )

        rows.append(
            {
                "technique": t,
                "samples_count": len(s_list),
                "rules_claiming": len(claiming_rules),
                "validated": val_cnt,
                "failing": fail_cnt,
                "not_evaluable": ne_cnt,
                "recall_exact": f"{rec_exact_k}/{len(s_list)}",
                "recall_family": f"{rec_fam_k}/{len(s_list)}",
            }
        )
    return rows


def load_attack_crosswalk(crosswalk_path: Path) -> dict[str, list[str]]:
    """Load ATT&CK crosswalk mapping legacy technique -> list of current techniques."""
    import csv

    crosswalk: dict[str, list[str]] = {}
    if not crosswalk_path.is_file():
        return crosswalk

    with crosswalk_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            legacy = (
                (row.get("legacy_technique_id") or row.get("legacy_id") or row.get("legacy") or "")
                .strip()
                .upper()
            )
            current_raw = (
                (
                    row.get("current_technique_ids")
                    or row.get("current_id")
                    or row.get("current")
                    or ""
                )
                .strip()
                .upper()
            )
            if legacy and current_raw:
                # Can be semicolon or comma separated
                targets = [c.strip() for c in current_raw.replace(",", ";").split(";") if c.strip()]
                if legacy not in crosswalk:
                    crosswalk[legacy] = []
                for tgt in targets:
                    if tgt not in crosswalk[legacy]:
                        crosswalk[legacy].append(tgt)
    return crosswalk


def apply_crosswalk_to_samples(
    samples: list[SampleRecord], crosswalk: dict[str, list[str]]
) -> list[SampleRecord]:
    """Return new SampleRecords with mapped techniques where crosswalk entries exist.

    If a legacy technique is mapped to multiple current techniques, all are included.
    Techniques with no mapping keep their original ID.
    """
    mapped_samples: list[SampleRecord] = []
    for s in samples:
        new_techs: list[str] = []
        for t in s.techniques:
            if t in crosswalk:
                new_techs.extend(crosswalk[t])
            else:
                new_techs.append(t)
        dedup_techs = list(dict.fromkeys(new_techs))
        mapped_samples.append(
            SampleRecord(
                sample_id=s.sample_id,
                file_path=s.file_path,
                techniques=dedup_techs,
                is_labelled=bool(dedup_techs),
                label_source=s.label_source + " (crosswalk)",
            )
        )
    return mapped_samples


def compute_side_by_side_per_technique(
    rows_pub: list[dict[str, Any]],
    rows_cw: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Merge published and crosswalk per-technique metrics side by side."""
    pub_map = {r["technique"]: r for r in rows_pub}
    cw_map = {r["technique"]: r for r in rows_cw}
    all_techs = sorted(set(pub_map.keys()) | set(cw_map.keys()))

    combined: list[dict[str, Any]] = []
    for t in all_techs:
        p = pub_map.get(t, {})
        c = cw_map.get(t, {})
        combined.append(
            {
                "technique": t,
                "pub_samples": p.get("samples_count", 0),
                "pub_rules": p.get("rules_claiming", 0),
                "pub_val": p.get("validated", 0),
                "pub_fail": p.get("failing", 0),
                "pub_not_eval": p.get("not_evaluable", 0),
                "pub_rec_exact": p.get("recall_exact", "0/0"),
                "pub_rec_fam": p.get("recall_family", "0/0"),
                "cw_samples": c.get("samples_count", 0),
                "cw_rules": c.get("rules_claiming", 0),
                "cw_val": c.get("validated", 0),
                "cw_fail": c.get("failing", 0),
                "cw_not_eval": c.get("not_evaluable", 0),
                "cw_rec_exact": c.get("recall_exact", "0/0"),
                "cw_rec_fam": c.get("recall_family", "0/0"),
            }
        )
    return combined


def compute_leave_one_out_recall(
    rules: list[SigmaRule],
    samples: list[SampleRecord],
    engine_results: list[EngineResult],
    top_techniques: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Evaluate sample-side recall excluding top techniques individually and combined.

    Calculates exact matching recall across sub-populations to test sensitivity
    to technique concentration.
    """
    import math
    from collections import Counter

    def _wilson(k: int, n: int) -> tuple[float, float, float]:
        if n == 0:
            return 0.0, 0.0, 0.0
        pe = k / n
        z = 1.959963984540054
        denom = 1.0 + (z**2) / n
        centre = (pe + (z**2) / (2 * n)) / denom
        spread = (z * math.sqrt((pe * (1 - pe) + (z**2) / (4 * n)) / n)) / denom
        return pe, max(0.0, centre - spread), min(1.0, centre + spread)

    if top_techniques is None:
        tech_counts: Counter[str] = Counter()
        for s in samples:
            for t in s.techniques:
                tech_counts[t] += 1
        top_techniques = [t for t, _ in tech_counts.most_common(3)]

    eval_scenarios: list[tuple[str, list[str]]] = [
        ("All samples", []),
    ]
    for tech in top_techniques:
        eval_scenarios.append((f"Excl. {tech}", [tech]))
    eval_scenarios.append(("Excl. all top 3", list(top_techniques)))

    results_table: list[dict[str, Any]] = []
    for label, excl in eval_scenarios:
        sub_samples = [s for s in samples if not any(t in excl for t in s.techniques)]
        rec = compute_sample_side_recall(
            rules, sub_samples, engine_results, match_hierarchical=False
        )
        k = rec["detected_samples"]
        n = rec["total_samples"]
        pe, low, high = _wilson(k, n)
        results_table.append(
            {
                "label": label,
                "excluded_techniques": excl,
                "detected_samples": k,
                "total_samples": n,
                "recall_rate": pe,
                "ci_lower": low,
                "ci_upper": high,
            }
        )

    return results_table
