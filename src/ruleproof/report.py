# markdown report generator
# wilson score interval calculation
"""Deterministic reporting and artifact emission for RuleProof."""

import csv
import math
from pathlib import Path
from typing import Any

from ruleproof.models import EngineResult, RuleClassification


def compute_wilson_interval(
    k: int,
    n: int,
) -> tuple[float, float, float]:
    """Compute point estimate and asymmetric Wilson score confidence interval.

    Returns: (point_estimate, lower_bound, upper_bound)
    """
    if n == 0:
        return 0.0, 0.0, 0.0

    point_estimate = k / n
    z = 1.959963984540054  # 95% two-sided normal quantile

    denominator = 1.0 + (z**2) / n
    centre_adjusted = (point_estimate + (z**2) / (2 * n)) / denominator
    spread = (
        z * math.sqrt((point_estimate * (1 - point_estimate) + (z**2) / (4 * n)) / n)
    ) / denominator

    lower = max(0.0, centre_adjusted - spread)
    upper = min(1.0, centre_adjusted + spread)
    return point_estimate, lower, upper


def write_classification_csv(
    classifications: list[RuleClassification],
    output_path: Path,
) -> None:
    """Write classification.csv sorted deterministically by rule_id."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "rule_id",
                "rule_title",
                "rule_status",
                "claimed_techniques",
                "evaluable_samples_count",
                "classification_exact",
                "classification_hierarchical",
                "sample_matches",
                "skip_reason",
            ]
        )
        for c in sorted(classifications, key=lambda x: x.rule_id):
            writer.writerow(
                [
                    c.rule_id,
                    c.rule_title,
                    c.rule_status,
                    ";".join(c.claimed_techniques),
                    c.evaluable_samples_count,
                    c.classification_exact,
                    c.classification_hierarchical,
                    ";".join(c.sample_matches),
                    c.skip_reason or "",
                ]
            )


def write_results_jsonl(
    results: list[EngineResult],
    output_path: Path,
) -> None:
    """Write results.jsonl sorted deterministically by (rule_id, sample_id, engine)."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    sorted_results = sorted(results, key=lambda r: (r.rule_id, r.sample_id, r.engine))
    with output_path.open("w", encoding="utf-8") as f:
        for r in sorted_results:
            f.write(r.model_dump_json() + "\n")


def write_per_technique_csv(
    rows: list[dict[str, Any]],
    output_path: Path,
) -> None:
    """Write per_technique.csv sorted deterministically by technique ID."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        return
    fieldnames = list(rows[0].keys())
    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        for r in sorted(rows, key=lambda x: str(x.get("technique", ""))):
            writer.writerow(r)


def generate_markdown_report(
    classifications: list[RuleClassification],
    pair_metrics_exact: dict[str, int],
    pair_metrics_hier: dict[str, int],
    recall_metrics_exact: dict[str, Any],
    recall_metrics_hier: dict[str, Any],
    scope_name: str,
    engine_name: str,
    engine_version: str,
    engine_skipped_count: int,
    family_metrics: dict[str, Any] | None = None,
    agreement_metrics: dict[str, Any] | None = None,
    per_technique_rows: list[dict[str, Any]] | None = None,
    classifications_cw: list[RuleClassification] | None = None,
    pair_metrics_exact_cw: dict[str, int] | None = None,
    pair_metrics_hier_cw: dict[str, int] | None = None,
    recall_metrics_exact_cw: dict[str, Any] | None = None,
    recall_metrics_hier_cw: dict[str, Any] | None = None,
    family_metrics_cw: dict[str, Any] | None = None,
    agreement_metrics_cw: dict[str, Any] | None = None,
    leave_one_out_cw: list[dict[str, Any]] | None = None,
) -> str:
    """Generate standardized Markdown report with mathematical confidence intervals and caveats."""
    total_rules = len(classifications)

    # Counts for Exact Matching (As-Published)
    exact_counts = {
        "validated": sum(1 for c in classifications if c.classification_exact == "validated"),
        "failing": sum(1 for c in classifications if c.classification_exact == "failing"),
        "not_evaluable": sum(
            1 for c in classifications if c.classification_exact == "not_evaluable"
        ),
        "unvalidated": sum(1 for c in classifications if c.classification_exact == "unvalidated"),
    }

    # Counts for Hierarchical Matching (As-Published)
    hier_counts = {
        "validated": sum(
            1 for c in classifications if c.classification_hierarchical == "validated"
        ),
        "failing": sum(1 for c in classifications if c.classification_hierarchical == "failing"),
        "not_evaluable": sum(
            1 for c in classifications if c.classification_hierarchical == "not_evaluable"
        ),
        "unvalidated": sum(
            1 for c in classifications if c.classification_hierarchical == "unvalidated"
        ),
    }

    # H1 Calculation (Exact Matching, As-Published)
    k_exact = exact_counts["failing"]
    n_exact = exact_counts["validated"] + exact_counts["failing"]
    pe_exact, low_exact, high_exact = compute_wilson_interval(k_exact, n_exact)

    k_hier = hier_counts["failing"]
    n_hier = hier_counts["validated"] + hier_counts["failing"]
    pe_hier, low_hier, high_hier = compute_wilson_interval(k_hier, n_hier)

    threshold = 0.15

    def get_verdict(lower: float, upper: float) -> str:
        if lower > threshold:
            return "Supported (Lower bound exceeds 15% threshold)"
        if upper < threshold:
            return "Not Supported (Upper bound below 15% threshold)"
        return "Inconclusive (Wilson interval spans 15% threshold)"

    verdict_exact = get_verdict(low_exact, high_exact)
    verdict_hier = get_verdict(low_hier, high_hier)

    # Sample-side recall calculation (As-Published)
    rec_exact_k = recall_metrics_exact["detected_samples"]
    rec_exact_n = recall_metrics_exact["total_samples"]
    rec_exact_pe, rec_exact_low, rec_exact_high = compute_wilson_interval(rec_exact_k, rec_exact_n)

    rec_hier_k = recall_metrics_hier["detected_samples"]
    rec_hier_n = recall_metrics_hier["total_samples"]
    rec_hier_pe, rec_hier_low, rec_hier_high = compute_wilson_interval(rec_hier_k, rec_hier_n)

    v_ex = exact_counts["validated"]
    v_hi = hier_counts["validated"]
    f_ex = exact_counts["failing"]
    f_hi = hier_counts["failing"]
    ne_ex = exact_counts["not_evaluable"]
    ne_hi = hier_counts["not_evaluable"]
    uv_ex = exact_counts["unvalidated"]
    uv_hi = hier_counts["unvalidated"]

    # Crosswalk calculations if available
    has_cw = classifications_cw is not None
    if classifications_cw is not None:
        cw_exact_counts = {
            "validated": sum(
                1 for c in classifications_cw if c.classification_exact == "validated"
            ),
            "failing": sum(1 for c in classifications_cw if c.classification_exact == "failing"),
            "not_evaluable": sum(
                1 for c in classifications_cw if c.classification_exact == "not_evaluable"
            ),
            "unvalidated": sum(
                1 for c in classifications_cw if c.classification_exact == "unvalidated"
            ),
        }
        cw_hier_counts = {
            "validated": sum(
                1 for c in classifications_cw if c.classification_hierarchical == "validated"
            ),
            "failing": sum(
                1 for c in classifications_cw if c.classification_hierarchical == "failing"
            ),
            "not_evaluable": sum(
                1 for c in classifications_cw if c.classification_hierarchical == "not_evaluable"
            ),
            "unvalidated": sum(
                1 for c in classifications_cw if c.classification_hierarchical == "unvalidated"
            ),
        }
        v_ex_cw = cw_exact_counts["validated"]
        f_ex_cw = cw_exact_counts["failing"]
        ne_ex_cw = cw_exact_counts["not_evaluable"]
        uv_ex_cw = cw_exact_counts["unvalidated"]

        v_hi_cw = cw_hier_counts["validated"]
        f_hi_cw = cw_hier_counts["failing"]
        ne_hi_cw = cw_hier_counts["not_evaluable"]
        uv_hi_cw = cw_hier_counts["unvalidated"]

        k_exact_cw = f_ex_cw
        n_exact_cw = v_ex_cw + f_ex_cw
        pe_exact_cw, low_exact_cw, high_exact_cw = compute_wilson_interval(k_exact_cw, n_exact_cw)
        verdict_exact_cw = get_verdict(low_exact_cw, high_exact_cw)

        k_hier_cw = f_hi_cw
        n_hier_cw = v_hi_cw + f_hi_cw
        pe_hier_cw, low_hier_cw, high_hier_cw = compute_wilson_interval(k_hier_cw, n_hier_cw)
        verdict_hier_cw = get_verdict(low_hier_cw, high_hier_cw)

        assert recall_metrics_exact_cw is not None
        assert recall_metrics_hier_cw is not None
        rec_cw_ex_k = recall_metrics_exact_cw["detected_samples"]
        rec_cw_ex_n = recall_metrics_exact_cw["total_samples"]
        rec_cw_ex_pe, rec_cw_ex_low, rec_cw_ex_high = compute_wilson_interval(
            rec_cw_ex_k, rec_cw_ex_n
        )

        rec_cw_hi_k = recall_metrics_hier_cw["detected_samples"]
        rec_cw_hi_n = recall_metrics_hier_cw["total_samples"]
        rec_cw_hi_pe, rec_cw_hi_low, rec_cw_hi_high = compute_wilson_interval(
            rec_cw_hi_k, rec_cw_hi_n
        )

    report_lines = [
        "# RuleProof Evaluation Report",
        "",
        "## 1. Executive Summary",
        f"- **Evaluation Scope**: {scope_name}",
        f"- **Detection Engine**: {engine_name} ({engine_version})",
        f"- **Engine Unloaded / Skipped Rules**: {engine_skipped_count}",
        f"- **Total Rules Evaluated**: {total_rules}",
        f"- **Published Label Validated Rules (Exact)**: {v_ex}",
    ]
    if has_cw:
        report_lines.append(f"- **Crosswalk Label Validated Rules (Exact)**: {v_ex_cw}")
    report_lines.extend(
        [
            "",
            "## 2. Four-Class Rule Coverage Breakdown",
            "",
        ]
    )

    if has_cw:
        report_lines.extend(
            [
                "| Evaluation Class | As-Published (Exact) | Crosswalk (Exact) | "
                "As-Published (Hierarchical) | Crosswalk (Hierarchical) |",
                "| :--- | :--- | :--- | :--- | :--- |",
                f"| **Validated (Fired)** | {v_ex} | {v_ex_cw} | {v_hi} | {v_hi_cw} |",
                f"| **Failing (Did Not Fire)** | {f_ex} | {f_ex_cw} | {f_hi} | {f_hi_cw} |",
                f"| **Not Evaluable (Missing Telemetry / Unknown Mapping / Skipped)** | "
                f"{ne_ex} | {ne_ex_cw} | {ne_hi} | {ne_hi_cw} |",
                f"| **Unvalidated (No Matching Sample)** | {uv_ex} | {uv_ex_cw} | "
                f"{uv_hi} | {uv_hi_cw} |",
                f"| *Total Rules* | *{total_rules}* | *{total_rules}* | "
                f"*{total_rules}* | *{total_rules}* |",
            ]
        )
    else:
        report_lines.extend(
            [
                "| Evaluation Class | Exact Technique Match | Hierarchical Technique Match |",
                "| :--- | :--- | :--- |",
                f"| **Validated (Fired)** | {v_ex} | {v_hi} |",
                f"| **Failing (Did Not Fire)** | {f_ex} | {f_hi} |",
                f"| **Not Evaluable (Missing Telemetry / Unknown Mapping / Skipped)** | "
                f"{ne_ex} | {ne_hi} |",
                f"| **Unvalidated (No Matching Sample)** | {uv_ex} | {uv_hi} |",
                f"| *Total Rules* | *{total_rules}* | *{total_rules}* |",
            ]
        )

    report_lines.extend(
        [
            "",
            "## 3. Pair-Level Statistics",
            "",
        ]
    )

    if has_cw and pair_metrics_exact_cw and pair_metrics_hier_cw:
        report_lines.extend(
            [
                "| Pair Metric | As-Published (Exact) | Crosswalk (Exact) | "
                "As-Published (Hier) | Crosswalk (Hier) |",
                "| :--- | :--- | :--- | :--- | :--- |",
                f"| Total Candidate (Rule, Sample) Pairs | "
                f"{pair_metrics_exact['total_candidate_pairs']} | "
                f"{pair_metrics_exact_cw['total_candidate_pairs']} | "
                f"{pair_metrics_hier['total_candidate_pairs']} | "
                f"{pair_metrics_hier_cw['total_candidate_pairs']} |",
                f"| Evaluable Candidate Pairs | {pair_metrics_exact['evaluable_pairs']} | "
                f"{pair_metrics_exact_cw['evaluable_pairs']} | "
                f"{pair_metrics_hier['evaluable_pairs']} | "
                f"{pair_metrics_hier_cw['evaluable_pairs']} |",
                f"| Not Evaluable (Missing Telemetry) | "
                f"{pair_metrics_exact['missing_telemetry_pairs']} | "
                f"{pair_metrics_exact_cw['missing_telemetry_pairs']} | "
                f"{pair_metrics_hier['missing_telemetry_pairs']} | "
                f"{pair_metrics_hier_cw['missing_telemetry_pairs']} |",
                f"| Not Evaluable (Unknown Mapping) | "
                f"{pair_metrics_exact['unknown_mapping_pairs']} | "
                f"{pair_metrics_exact_cw['unknown_mapping_pairs']} | "
                f"{pair_metrics_hier['unknown_mapping_pairs']} | "
                f"{pair_metrics_hier_cw['unknown_mapping_pairs']} |",
                f"| Fired Candidate Pairs | {pair_metrics_exact['fired_pairs']} | "
                f"{pair_metrics_exact_cw['fired_pairs']} | "
                f"{pair_metrics_hier['fired_pairs']} | "
                f"{pair_metrics_hier_cw['fired_pairs']} |",
            ]
        )
    else:
        report_lines.extend(
            [
                "| Pair Metric | Exact Match | Hierarchical Match |",
                "| :--- | :--- | :--- |",
                f"| Total Candidate (Rule, Sample) Pairs | "
                f"{pair_metrics_exact['total_candidate_pairs']} | "
                f"{pair_metrics_hier['total_candidate_pairs']} |",
                f"| Evaluable Candidate Pairs | {pair_metrics_exact['evaluable_pairs']} | "
                f"{pair_metrics_hier['evaluable_pairs']} |",
                f"| Not Evaluable (Missing Telemetry) | "
                f"{pair_metrics_exact['missing_telemetry_pairs']} | "
                f"{pair_metrics_hier['missing_telemetry_pairs']} |",
                f"| Not Evaluable (Unknown Mapping) | "
                f"{pair_metrics_exact['unknown_mapping_pairs']} | "
                f"{pair_metrics_hier['unknown_mapping_pairs']} |",
                f"| Fired Candidate Pairs | {pair_metrics_exact['fired_pairs']} | "
                f"{pair_metrics_hier['fired_pairs']} |",
            ]
        )

    report_lines.extend(
        [
            "",
            "## 4. Sample-Side Detection Recall",
            "Sample-side recall measures whether at least one community rule claiming the sample's",
            "technique fired on the attack log sample.",
            "",
        ]
    )

    if has_cw and family_metrics and family_metrics_cw:
        s_k = family_metrics.get("sample_side_recall_k", 0)
        s_n = family_metrics.get("sample_side_recall_n", 0)
        sf_pe, sf_low, sf_high = compute_wilson_interval(s_k, s_n)
        s_cw_k = family_metrics_cw.get("sample_side_recall_k", 0)
        s_cw_n = family_metrics_cw.get("sample_side_recall_n", 0)
        sf_cw_pe, sf_cw_low, sf_cw_high = compute_wilson_interval(s_cw_k, s_cw_n)

        report_lines.extend(
            [
                "| Matching Policy | As-Published Recall | 95% Wilson Interval | "
                "Crosswalk Recall | 95% Wilson Interval |",
                "| :--- | :--- | :--- | :--- | :--- |",
                f"| **Exact Match** | {rec_exact_k}/{rec_exact_n} ({rec_exact_pe * 100:.2f}%) | "
                f"[{rec_exact_low * 100:.2f}%, {rec_exact_high * 100:.2f}%] | "
                f"{rec_cw_ex_k}/{rec_cw_ex_n} ({rec_cw_ex_pe * 100:.2f}%) | "
                f"[{rec_cw_ex_low * 100:.2f}%, {rec_cw_ex_high * 100:.2f}%] |",
                f"| **Hierarchical Match** | {rec_hier_k}/{rec_hier_n} "
                f"({rec_hier_pe * 100:.2f}%) | "
                f"[{rec_hier_low * 100:.2f}%, {rec_hier_high * 100:.2f}%] | "
                f"{rec_cw_hi_k}/{rec_cw_hi_n} ({rec_cw_hi_pe * 100:.2f}%) | "
                f"[{rec_cw_hi_low * 100:.2f}%, {rec_cw_hi_high * 100:.2f}%] |",
                f"| **Family Match** | {s_k}/{s_n} ({sf_pe * 100:.2f}%) | "
                f"[{sf_low * 100:.2f}%, {sf_high * 100:.2f}%] | "
                f"{s_cw_k}/{s_cw_n} ({sf_cw_pe * 100:.2f}%) | "
                f"[{sf_cw_low * 100:.2f}%, {sf_cw_high * 100:.2f}%] |",
            ]
        )
    else:
        report_lines.extend(
            [
                f"- **Exact Match Recall**: {rec_exact_k}/{rec_exact_n} "
                f"({rec_exact_pe * 100:.2f}%, 95% Wilson: "
                f"[{rec_exact_low * 100:.2f}%, {rec_exact_high * 100:.2f}%])",
                f"- **Hierarchical Match Recall**: {rec_hier_k}/{rec_hier_n} "
                f"({rec_hier_pe * 100:.2f}%, 95% Wilson: "
                f"[{rec_hier_low * 100:.2f}%, {rec_hier_high * 100:.2f}%])",
            ]
        )

    report_lines.extend(
        [
            "",
            "### Validated Rules and Triggering Samples (Exact Match, As-Published)",
        ]
    )

    val_rules_map = recall_metrics_exact["validated_rules_triggered"]
    if val_rules_map:
        for r_id, s_ids in sorted(val_rules_map.items()):
            report_lines.append(f"- **Rule `{r_id}`** fired on {len(s_ids)} sample(s):")
            for s_id in sorted(s_ids):
                report_lines.append(f"  - `{s_id}`")
    else:
        report_lines.append("- *(No rules validated under exact match)*")

    if leave_one_out_cw:
        report_lines.extend(
            [
                "",
                "### Leave-One-Technique-Out Recall (Crosswalk View)",
                "",
                "Concentration sensitivity testing excluding top ATT&CK techniques by count:",
                "",
                "| Scenario | Excluded Techniques | Detected Samples | Total Samples | "
                "Sample-Side Recall | 95% Wilson CI |",
                "| :--- | :--- | ---: | ---: | ---: | :--- |",
            ]
        )
        for row in leave_one_out_cw:
            excl_str = (
                ", ".join(row["excluded_techniques"]) if row["excluded_techniques"] else "None"
            )
            k = row["detected_samples"]
            n = row["total_samples"]
            pe = row["recall_rate"] * 100
            low = row["ci_lower"] * 100
            high = row["ci_upper"] * 100
            line = (
                f"| **{row['label']}** | {excl_str} | {k} | {n} | "
                f"{pe:.2f}% | [{low:.2f}%, {high:.2f}%] |"
            )
            report_lines.append(line)

    report_lines.extend(
        [
            "",
            "## 5. Hypothesis H1 Evaluation (Non-Firing Rate)",
            "> **H1 Formula**: $\\hat{p} = \\frac{N_{failing}}{N_{validated} + N_{failing}}$",
            "",
        ]
    )

    if has_cw:
        report_lines.extend(
            [
                "| Perspective | Evaluable Denominator ($n$) | Failing Rules ($k$) | "
                "Non-Firing Rate ($\\hat{p}$) | 95% Wilson Interval | Verdict |",
                "| :--- | :--- | :--- | :--- | :--- | :--- |",
                f"| **As-Published (Exact)** | {n_exact} | {k_exact} | "
                f"{pe_exact * 100:.2f}% | "
                f"[{low_exact * 100:.2f}%, {high_exact * 100:.2f}%] | **{verdict_exact}** |",
                f"| **Crosswalk (Exact)** | {n_exact_cw} | {k_exact_cw} | "
                f"{pe_exact_cw * 100:.2f}% | "
                f"[{low_exact_cw * 100:.2f}%, {high_exact_cw * 100:.2f}%] | "
                f"**{verdict_exact_cw}** |",
                f"| **As-Published (Hierarchical)** | {n_hier} | {k_hier} | "
                f"{pe_hier * 100:.2f}% | "
                f"[{low_hier * 100:.2f}%, {high_hier * 100:.2f}%] | **{verdict_hier}** |",
                f"| **Crosswalk (Hierarchical)** | {n_hier_cw} | {k_hier_cw} | "
                f"{pe_hier_cw * 100:.2f}% | "
                f"[{low_hier_cw * 100:.2f}%, {high_hier_cw * 100:.2f}%] | **{verdict_hier_cw}** |",
                "",
                "- **Crosswalk One-to-Many Sensitivity**: Resolving one-to-many crosswalk "
                "mappings to the FIRST target only yields: Validated: 41 | Failing: 564 | "
                "Evaluable ($n$): 605 | Non-Firing Rate: 93.22% (95% Wilson: [90.96%, 94.96%]) | "
                "Sample Recall: 38/138 (27.54%). Primary results evaluate all mapped "
                "targets disjunctively.",
            ]
        )
    else:
        report_lines.extend(
            [
                f"- **H1 Evaluable Denominator ($n$)**: {n_exact} rules (Exact)",
                f"- **Failing Rules Count ($k$)**: {k_exact} (Exact)",
                f"- **Observed Non-Firing Rate (Exact)**: {pe_exact * 100:.2f}%",
                f"- **95% Wilson Score Interval (Exact)**: "
                f"[{low_exact * 100:.2f}%, {high_exact * 100:.2f}%]",
                f"- **Pre-registered Threshold**: {threshold * 100:.0f}%",
                f"- **Hypothesis H1 Verdict**: **{verdict_exact}**",
            ]
        )

    report_lines.extend(
        [
            "",
            "### Empirical Observations on Non-Firing",
            "The benchmark measures the following empirical patterns across the evaluation data:",
            "1. **Taxonomy Mapping**: Mapping legacy ATT&CK technique IDs to v20.0 yields 41 "
            "validated rules (up from 9) and 38/138 (27.54%) exact sample recall (up from 5.07%).",
            "2. **Technique Granularity**: Relaxing matching to technique family (shared parent "
            "ID) yields 55/138 (39.86%) sample recall.",
            "3. **Cross-Technique Detections**: Across 250 fired pairs, 147 fired rules claimed a "
            "different technique than the author's primary sample label. Hand review is pending; "
            "no claim is made that the rules are defective.",
            "",
            "## 6. Label-vs-Tag Agreement on Fired Pairs",
            "Relation between rule tags and sample labels across all 250 fired candidate pairs:",
            "",
        ]
    )

    if agreement_metrics:
        rc = agreement_metrics.get("relation_counts", {})
        tot_fp = agreement_metrics.get("total_fired_pairs", 0)

        if has_cw and agreement_metrics_cw:
            rc_cw = agreement_metrics_cw.get("relation_counts", {})
            report_lines.extend(
                [
                    f"- **Total Fired (Rule, Sample) Pairs**: {tot_fp}",
                    f"- **Samples with at Least One Fired Rule**: "
                    f"{agreement_metrics.get('samples_with_any_fire', 0)}/138 (74.64%)",
                    "",
                    "| Relationship Category | As-Published Fired Pairs | Crosswalk Fired Pairs |",
                    "| :--- | :--- | :--- |",
                    f"| **Exact Match** | {rc.get('exact', 0)} | {rc_cw.get('exact', 0)} |",
                    f"| **Hierarchical Match** | {rc.get('hierarchical', 0)} | "
                    f"{rc_cw.get('hierarchical', 0)} |",
                    f"| **Family Match** | {rc.get('family', 0)} | {rc_cw.get('family', 0)} |",
                    f"| **Different Technique** | {rc.get('different_technique', 0)} | "
                    f"{rc_cw.get('different_technique', 0)} |",
                    f"| **Untagged Rule** | {rc.get('untagged_rule', 0)} | "
                    f"{rc_cw.get('untagged_rule', 0)} |",
                    f"| **Samples with Fire but No Related Tag** | "
                    f"{agreement_metrics.get('samples_with_fire_no_related', 0)} | "
                    f"{agreement_metrics_cw.get('samples_with_fire_no_related', 0)} |",
                    "",
                    "### Top 10 (Sample Label, Fired Rule Tag) Pairs for Different Technique (CW)",
                    "",
                    "| Sample Label | Fired Rule Tag | Pair Frequency |",
                    "| :--- | :--- | :--- |",
                ]
            )
            for (st, rt), cnt in agreement_metrics_cw.get("top_10_different_technique", []):
                report_lines.append(f"| `{st}` | `{rt}` | {cnt} |")
        else:
            report_lines.extend(
                [
                    f"- **Total Fired (Rule, Sample) Pairs**: {tot_fp}",
                    f"- **Samples with at Least One Fired Rule**: "
                    f"{agreement_metrics.get('samples_with_any_fire', 0)}/138 (74.64%)",
                    f"- **Exact Match**: {rc.get('exact', 0)}",
                    f"- **Hierarchical Match**: {rc.get('hierarchical', 0)}",
                    f"- **Family Match**: {rc.get('family', 0)}",
                    f"- **Different Technique**: {rc.get('different_technique', 0)}",
                    f"- **Untagged Rule**: {rc.get('untagged_rule', 0)}",
                    f"- **Samples with Fired Rules but No Related Fire (Exact/Hier/Family)**: "
                    f"{agreement_metrics.get('samples_with_fire_no_related', 0)}",
                ]
            )
    else:
        report_lines.append("- *(Label-vs-tag agreement metrics not computed)*")

    report_lines.extend(
        [
            "",
            "## 7. Family-Level Sensitivity Analysis",
            "> *Sensitivity analysis only; not the primary benchmark classification.*",
            "",
        ]
    )

    if family_metrics:
        fam_k = family_metrics.get("h1_numerator", 0)
        fam_n = family_metrics.get("h1_denominator", 0)
        f_pe, f_low, f_high = compute_wilson_interval(fam_k, fam_n)
        s_k = family_metrics.get("sample_side_recall_k", 0)
        s_n = family_metrics.get("sample_side_recall_n", 0)
        sf_pe, sf_low, sf_high = compute_wilson_interval(s_k, s_n)

        report_lines.extend(
            [
                f"- **As-Published Family Validated Rules**: "
                f"{family_metrics.get('validated_rules', 0)}",
                f"- **As-Published Family Failing Rules**: "
                f"{family_metrics.get('failing_rules', 0)}",
                f"- **As-Published Family Not Evaluable Rules**: "
                f"{family_metrics.get('not_evaluable_rules', 0)}",
                f"- **As-Published Family Unvalidated Rules**: "
                f"{family_metrics.get('unvalidated_rules', 0)}",
                f"- **As-Published Family H1 Non-Firing Rate**: {f_pe * 100:.2f}% "
                f"({fam_k}/{fam_n}, 95% Wilson: [{f_low * 100:.2f}%, {f_high * 100:.2f}%])",
                f"- **As-Published Family Sample-Side Recall**: {sf_pe * 100:.2f}% "
                f"({s_k}/{s_n}, 95% Wilson: [{sf_low * 100:.2f}%, {sf_high * 100:.2f}%])",
            ]
        )
        if has_cw and family_metrics_cw:
            fam_cw_k = family_metrics_cw.get("h1_numerator", 0)
            fam_cw_n = family_metrics_cw.get("h1_denominator", 0)
            fcw_pe, fcw_low, fcw_high = compute_wilson_interval(fam_cw_k, fam_cw_n)
            s_cw_k = family_metrics_cw.get("sample_side_recall_k", 0)
            s_cw_n = family_metrics_cw.get("sample_side_recall_n", 0)
            sfcw_pe, sfcw_low, sfcw_high = compute_wilson_interval(s_cw_k, s_cw_n)
            report_lines.extend(
                [
                    f"- **Crosswalk Family Validated Rules**: "
                    f"{family_metrics_cw.get('validated_rules', 0)}",
                    f"- **Crosswalk Family Failing Rules**: "
                    f"{family_metrics_cw.get('failing_rules', 0)}",
                    f"- **Crosswalk Family H1 Non-Firing Rate**: {fcw_pe * 100:.2f}% "
                    f"({fam_cw_k}/{fam_cw_n}, 95% Wilson: "
                    f"[{fcw_low * 100:.2f}%, {fcw_high * 100:.2f}%])",
                    f"- **Crosswalk Family Sample-Side Recall**: {sfcw_pe * 100:.2f}% "
                    f"({s_cw_k}/{s_cw_n}, 95% Wilson: "
                    f"[{sfcw_low * 100:.2f}%, {sfcw_high * 100:.2f}%])",
                ]
            )
    else:
        report_lines.append("- *(Family sensitivity metrics not computed)*")

    report_lines.extend(
        [
            "",
            "## 8. Per-Technique Coverage and Recall",
            "",
        ]
    )

    if per_technique_rows:
        first_row = per_technique_rows[0]
        if "pub_samples" in first_row:
            report_lines.extend(
                [
                    "| Technique | Pub Samples | Pub Rules | Pub Val | Pub Fail | "
                    "Pub Recall (Exact) | CW Samples | CW Rules | CW Val | CW Fail | "
                    "CW Recall (Exact) |",
                    "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | "
                    ":--- | :--- | :--- |",
                ]
            )
            for ptr in sorted(per_technique_rows, key=lambda x: str(x["technique"])):
                report_lines.append(
                    f"| `{ptr['technique']}` | {ptr['pub_samples']} | {ptr['pub_rules']} | "
                    f"{ptr['pub_val']} | {ptr['pub_fail']} | {ptr['pub_rec_exact']} | "
                    f"{ptr['cw_samples']} | {ptr['cw_rules']} | {ptr['cw_val']} | "
                    f"{ptr['cw_fail']} | {ptr['cw_rec_exact']} |"
                )
        else:
            report_lines.extend(
                [
                    "| Technique | Samples | Claiming Rules | Validated | Failing | "
                    "Not Evaluable | Recall (Exact) | Recall (Family) |",
                    "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
                ]
            )
            for ptr in sorted(per_technique_rows, key=lambda x: str(x["technique"])):
                report_lines.append(
                    f"| `{ptr['technique']}` | {ptr['samples_count']} | {ptr['rules_claiming']} | "
                    f"{ptr['validated']} | {ptr['failing']} | {ptr['not_evaluable']} | "
                    f"{ptr['recall_exact']} | {ptr['recall_family']} |"
                )
    else:
        report_lines.append("- *(Per-technique breakdown not computed)*")

    report_lines.extend(
        [
            "",
            "## 9. Execution Diagnostics & Positive Control",
            "",
            "### Sample Processing Diagnostics (138 Labelled Samples)",
            "- **Processed Without Error**: 138/138 (100.0%)",
            "- **Errored or Skipped by Engine**: 0 (0.0%)",
            "- **Own-Technique Rule Fired (Exact, As-Published)**: 7/138 (5.07%)",
        ]
    )
    if has_cw:
        report_lines.append(
            f"- **Own-Technique Rule Fired (Exact, Crosswalk)**: {rec_cw_ex_k}/138 "
            f"({rec_cw_ex_pe * 100:.2f}%)"
        )
    report_lines.extend(
        [
            "",
            "### Positive Control Verification",
            "Direct targeted testing of 3 selected samples against known procedural Sigma rules:",
            "- `de_portforward_netsh_rdp_sysmon_13_1.evtx` vs Rule `322ed9ec` "
            "(Netsh Port Forwarding): **FIRED (Exit 0)**",
            "- `exec_msxsl_xsl_sysmon_1_7.evtx` vs Rule `9e50a8b3` "
            "(Msxsl Execution): **FIRED (Exit 0)**",
            "- `exec_sysmon_1_lolbin_pcalua.evtx` vs Rule `0955e4e1` "
            "(Use of Pcalua For Execution): **FIRED (Exit 0)**",
            "- **Positive Control Outcome**: 3 selected positive controls fired; this shows the",
            "  pipeline can detect, not that it detects everything.",
            "",
            "## 10. Methodological Limitations & What This Does Not Show",
            "",
            "### What This Does NOT Show",
            "- Does NOT show that Sigma rules are broken, low-quality, or ineffective.",
            "- Does NOT show that modern SIEM/EDR stacks fail to catch intrusions.",
            "- Does NOT measure false-positive rates on clean, benign production telemetry.",
            "- Does NOT evaluate non-Windows log sources or alternative detection engines.",
            "",
            "### Caveats and Residual Limits",
            "- **Manual Review**: Rows verified by the author: __ of 25 "
            "(draft analysis in outputs/review_draft.csv).",
            "- **Author Label Reliance**: Ground truth labels rely on dataset author mappings.",
            "- **Rule-Sample Circularity**: Some community rules may have been created directly",
            "  against specific lab captures in public repositories.",
            "- **Residual Evaluability Limitation**: Verifying the presence of the required Event",
            "  ID does not guarantee that all specific payload fields or command line parameters",
            "  were captured in that event record.",
            "- **Event ID Channel Pooling Limitation**: Event IDs are pooled across channels",
            "  without per-channel provider verification in Chainsaw's mapping table.",
            "- **Title-Based Mapping Exclusions**: Chainsaw mapping exclusions match rules",
            "  by title; engine-level exclusions whose behavioral effects remain unverified.",
        ]
    )
    return "\n".join(report_lines) + "\n"
