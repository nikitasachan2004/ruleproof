# inspect command
# typer cli app
"""RuleProof command-line interface."""

import csv
import random
from collections import Counter
from pathlib import Path
from typing import Any

import typer

from ruleproof.classify import (
    apply_crosswalk_to_samples,
    check_pair_evaluability,
    classify_rules,
    compute_family_sensitivity,
    compute_label_tag_agreement,
    compute_leave_one_out_recall,
    compute_pair_metrics,
    compute_per_technique_metrics,
    compute_sample_side_recall,
    compute_side_by_side_per_technique,
    load_attack_crosswalk,
    matches_technique_exact,
)
from ruleproof.config import get_cache_dir, load_manifest
from ruleproof.engines.chainsaw import ChainsawEngine
from ruleproof.fetch import download_file, fetch_all, verify_sha256
from ruleproof.models import InspectSummary
from ruleproof.report import (
    compute_wilson_interval,
    generate_markdown_report,
    write_classification_csv,
    write_per_technique_csv,
    write_results_jsonl,
)
from ruleproof.rules import load_rules
from ruleproof.runner import run_engine_across_samples
from ruleproof.samples import index_samples

app = typer.Typer(
    name="ruleproof",
    help="Reproducible harness testing Sigma rules on ATT&CK-labelled attack logs.",
    add_completion=False,
)


@app.command("fetch")
def fetch_cmd() -> None:
    """Download, verify SHA-256 digests, and cache pinned rules, datasets, and engine binaries."""
    try:
        manifest = load_manifest()
        typer.echo("Fetching and verifying all pinned dependencies...")
        results = fetch_all(manifest)

        # Download mapping CSV if specified
        dataset_conf = manifest.datasets.get("evtx_attack_samples")
        if dataset_conf and dataset_conf.mapping_url:
            mapping_dest = get_cache_dir() / "samples" / "evtx_attack_samples_mapping.csv"
            typer.echo(f"Downloading sample technique mapping from {dataset_conf.mapping_url}...")
            download_file(dataset_conf.mapping_url, mapping_dest)

        typer.echo("Fetch complete. Verified dependencies:")
        for name, path in results.items():
            typer.echo(f"  - {name}: {path}")
    except Exception as e:
        typer.secho(f"Fetch failed: {e}", fg=typer.colors.RED, err=True)
        typer.secho(
            "What to do next: Check internet, verify manifest.toml checksums, and re-run.",
            fg=typer.colors.YELLOW,
            err=True,
        )
        raise typer.Exit(code=1) from e


@app.command("inspect")
def inspect_cmd(
    rules_path: Path | None = typer.Option(
        None, "--rules-dir", "-r", help="Directory containing Sigma rules (default: cache)"
    ),
    samples_path: Path | None = typer.Option(
        None, "--samples-dir", "-s", help="Directory containing EVTX samples (default: cache)"
    ),
    all_statuses: bool = typer.Option(
        False, "--all-statuses", help="Include experimental/deprecated rules (default: stable+test)"
    ),
) -> None:
    """Inspect and index downloaded Sigma rules and attack samples, printing summary statistics."""
    try:
        cache_dir = get_cache_dir()
        manifest = load_manifest()

        if rules_path is None:
            rules_path = cache_dir / "rules" / "sigmahq" / "rules" / "windows"
            if not rules_path.is_dir():
                rules_path = cache_dir / "rules" / "sigmahq"

        if samples_path is None:
            samples_path = cache_dir / "samples" / "evtx_attack_samples"

        if not rules_path.is_dir():
            typer.secho(
                f"Rules directory not found at {rules_path}.",
                fg=typer.colors.RED,
                err=True,
            )
            typer.secho(
                "What to do next: Run 'ruleproof fetch' first to download the pinned rules.",
                fg=typer.colors.YELLOW,
                err=True,
            )
            raise typer.Exit(code=1)

        if not samples_path.is_dir():
            typer.secho(
                f"Samples directory not found at {samples_path}.",
                fg=typer.colors.RED,
                err=True,
            )
            typer.secho(
                "What to do next: Run 'ruleproof fetch' first to download attack samples.",
                fg=typer.colors.YELLOW,
                err=True,
            )
            raise typer.Exit(code=1)

        target_statuses = None if all_statuses else {"stable", "test"}
        rules = load_rules(rules_path, target_statuses=target_statuses)

        # Committed mapping takes precedence
        committed_mapping = (
            Path(__file__).resolve().parent.parent.parent / "labels" / "evtx_attack_samples.csv"
        )
        mapping_csv = (
            committed_mapping
            if committed_mapping.is_file()
            else (
                samples_path / "sample_mapping.csv"
                if (samples_path / "sample_mapping.csv").is_file()
                else None
            )
        )
        dataset_commit = manifest.datasets["evtx_attack_samples"].commit
        samples = index_samples(
            samples_path, mapping_csv=mapping_csv, dataset_commit=dataset_commit
        )

        status_counts = dict(Counter(r.status for r in rules))
        rules_with_tech = sum(1 for r in rules if r.techniques)
        labelled_samples = sum(1 for s in samples if s.is_labelled)
        all_sample_techs = {t for s in samples for t in s.techniques}

        summary = InspectSummary(
            total_rules=len(rules),
            rules_by_status=status_counts,
            rules_with_techniques=rules_with_tech,
            total_samples=len(samples),
            labelled_samples=labelled_samples,
            unlabelled_samples=len(samples) - labelled_samples,
            unique_techniques_covered=len(all_sample_techs),
        )

        typer.echo("=== RuleProof Inspection Summary ===")
        typer.echo(f"Scope: {'All statuses' if all_statuses else 'Default (stable + test only)'}")
        typer.echo(f"Total Rules Loaded:           {summary.total_rules}")
        typer.echo(f"  Rules with ATT&CK tags:     {summary.rules_with_techniques}")
        for status, count in sorted(summary.rules_by_status.items()):
            typer.echo(f"  Status '{status}':          {count}")
        typer.echo(f"Total EVTX Samples Found:     {summary.total_samples}")
        typer.echo(f"  Author-Labelled Samples:    {summary.labelled_samples}")
        typer.echo(f"  Unlabelled (Excluded):      {summary.unlabelled_samples}")
        typer.echo(f"Unique ATT&CK Techniques:     {summary.unique_techniques_covered}")

    except typer.Exit:
        raise
    except Exception as e:
        typer.secho(f"Inspect failed: {e}", fg=typer.colors.RED, err=True)
        typer.secho(
            "What to do next: Check that paths exist and permissions are valid.",
            fg=typer.colors.YELLOW,
            err=True,
        )
        raise typer.Exit(code=1) from e


@app.command("run")
def run_cmd(
    rules_path: Path | None = typer.Option(
        None, "--rules-dir", "-r", help="Directory containing Sigma rules (default: cache)"
    ),
    samples_path: Path | None = typer.Option(
        None, "--samples-dir", "-s", help="Directory containing EVTX samples (default: cache)"
    ),
    chainsaw_bin: Path | None = typer.Option(
        None, "--chainsaw-path", help="Path to custom Chainsaw executable (default: cache)"
    ),
    all_statuses: bool = typer.Option(
        False, "--all-statuses", help="Evaluate all rule statuses (default: stable+test)"
    ),
    output_dir: Path = typer.Option(
        Path("outputs"), "--output-dir", "-o", help="Directory to store run outputs"
    ),
) -> None:
    """Execute Chainsaw across labelled samples, classifying coverage and emitting results."""
    try:
        cache_dir = get_cache_dir()
        manifest = load_manifest()

        if rules_path is None:
            rules_path = cache_dir / "rules" / "sigmahq" / "rules" / "windows"
            if not rules_path.is_dir():
                rules_path = cache_dir / "rules" / "sigmahq"

        if samples_path is None:
            samples_path = cache_dir / "samples" / "evtx_attack_samples"

        if chainsaw_bin is None:
            chainsaw_conf = manifest.engines["chainsaw"]
            chainsaw_bin = (
                cache_dir / "engines" / "chainsaw" / chainsaw_conf.version / "bin" / "chainsaw"
            )
            if not chainsaw_bin.is_file():
                chainsaw_bin = (
                    cache_dir / "engines" / "chainsaw" / chainsaw_conf.version / "chainsaw"
                )

        # Locate mapping file
        mapping_path = (
            chainsaw_bin.parent.parent / "chainsaw" / "mappings" / "sigma-event-logs-all.yml"
        )
        if not mapping_path.is_file():
            mapping_path = (
                chainsaw_bin.parent / "chainsaw" / "mappings" / "sigma-event-logs-all.yml"
            )
        if not mapping_path.is_file():
            found_mappings = list(cache_dir.glob("**/sigma-event-logs-all.yml"))
            if found_mappings:
                mapping_path = found_mappings[0]

        if not rules_path.is_dir() or not samples_path.is_dir() or not chainsaw_bin.is_file():
            typer.secho(
                "Required rules, samples, or chainsaw binary not found.",
                fg=typer.colors.RED,
                err=True,
            )
            typer.secho(
                "What to do next: Run 'ruleproof fetch' first to download all dependencies.",
                fg=typer.colors.YELLOW,
                err=True,
            )
            raise typer.Exit(code=1)

        repo_root = Path(__file__).resolve().parent.parent.parent
        committed_mapping = repo_root / "labels" / "evtx_attack_samples.csv"
        crosswalk_path = repo_root / "labels" / "attack_crosswalk.csv"

        if not committed_mapping.is_file():
            typer.secho(
                f"Mapping file not found at {committed_mapping}", fg=typer.colors.RED, err=True
            )
            raise typer.Exit(code=1)
        expected_mapping_sha = manifest.datasets["evtx_attack_samples"].mapping_sha256
        if expected_mapping_sha:
            verify_sha256(committed_mapping, expected_mapping_sha)

        if not crosswalk_path.is_file():
            typer.secho(
                f"Crosswalk file not found at {crosswalk_path}", fg=typer.colors.RED, err=True
            )
            raise typer.Exit(code=1)
        stix_conf = manifest.datasets.get("attack_stix")
        expected_cw_sha = (
            getattr(stix_conf, "crosswalk_sha256", None)
            or "77d24a20863a14da9f8d7ad858e0f6e41eaff571a17ab7e388d8b9f36c46cf67"
        )
        verify_sha256(crosswalk_path, expected_cw_sha)

        # Re-verify engine binary SHA-256 before execution
        chainsaw_conf = manifest.engines["chainsaw"]
        expected_bin_sha = (
            getattr(chainsaw_conf, "binary_sha256", None)
            or "58d1eadf8164435e73d746db3bffe6170bc72e40a5fc7cce7b7957f0efa52b7b"
        )
        verify_sha256(chainsaw_bin, expected_bin_sha)

        target_statuses = None if all_statuses else {"stable", "test"}
        rules = load_rules(rules_path, target_statuses=target_statuses)

        dataset_commit = manifest.datasets["evtx_attack_samples"].commit
        samples = index_samples(
            samples_path, mapping_csv=committed_mapping, dataset_commit=dataset_commit
        )
        # Filter strictly to authoritative labelled samples for evaluation
        samples = [s for s in samples if s.is_labelled]

        typer.echo(f"Initializing Chainsaw engine: {chainsaw_bin}")
        engine = ChainsawEngine(binary_path=chainsaw_bin, mapping_path=mapping_path)

        typer.echo(f"Executing {len(rules)} rules across {len(samples)} samples...")
        rule_commit = manifest.rules["sigmahq"].commit
        output_dir.mkdir(parents=True, exist_ok=True)
        manifest_output_path = output_dir / "run_manifest.json"
        results, sample_telemetries, run_manifest = run_engine_across_samples(
            engine=engine,
            rules=rules,
            samples=samples,
            rules_dir=rules_path,
            rule_commit=rule_commit,
            dataset_commit=dataset_commit,
            manifest_path=manifest_output_path,
        )

        if run_manifest.get("failed_samples"):
            fail_count = len(run_manifest["failed_samples"])
            typer.secho(
                f"Error: Engine execution failed on {fail_count} sample(s):",
                fg=typer.colors.RED,
                err=True,
            )
            for fs in run_manifest["failed_samples"]:
                err_msg = run_manifest["samples"].get(fs, {}).get("error", "Unknown error")
                typer.secho(f"  - {fs}: {err_msg}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)

        empty_samples = run_manifest.get("empty_telemetry_samples", [])
        if empty_samples:
            typer.secho(
                f"Warning: {len(empty_samples)} sample(s) have 0 telemetry events:",
                fg=typer.colors.YELLOW,
            )
            for es in empty_samples:
                typer.secho(f"  - {es}", fg=typer.colors.YELLOW)
        else:
            typer.echo(f"Telemetry diagnostics: 0 / {len(samples)} samples have empty telemetry.")

        typer.echo("Classifying rule coverage and computing pair/recall metrics...")
        skipped_rule_ids = engine.get_skipped_rule_ids(rules_path)
        excluded_rule_titles = engine.get_mapping_excluded_titles()
        scope_skipped_count = len(
            [r for r in rules if r.rule_id in skipped_rule_ids or r.title in excluded_rule_titles]
        )

        crosswalk = load_attack_crosswalk(crosswalk_path)
        cw_samples = apply_crosswalk_to_samples(samples, crosswalk)

        # 1. As-published evaluation
        classifications = classify_rules(
            rules=rules,
            samples=samples,
            engine_results=results,
            sample_telemetries=sample_telemetries,
            engine_skipped_rule_ids=skipped_rule_ids,
            engine_excluded_rule_titles=excluded_rule_titles,
        )
        pair_metrics_exact = compute_pair_metrics(
            rules=rules,
            samples=samples,
            engine_results=results,
            sample_telemetries=sample_telemetries,
            match_hierarchical=False,
            engine_skipped_rule_ids=skipped_rule_ids,
            engine_excluded_rule_titles=excluded_rule_titles,
        )
        pair_metrics_hier = compute_pair_metrics(
            rules=rules,
            samples=samples,
            engine_results=results,
            sample_telemetries=sample_telemetries,
            match_hierarchical=True,
            engine_skipped_rule_ids=skipped_rule_ids,
            engine_excluded_rule_titles=excluded_rule_titles,
        )
        recall_exact = compute_sample_side_recall(
            rules=rules,
            samples=samples,
            engine_results=results,
            match_hierarchical=False,
        )
        recall_hier = compute_sample_side_recall(
            rules=rules,
            samples=samples,
            engine_results=results,
            match_hierarchical=True,
        )
        family_metrics = compute_family_sensitivity(
            rules=rules,
            samples=samples,
            engine_results=results,
            sample_telemetries=sample_telemetries,
            engine_skipped_rule_ids=skipped_rule_ids,
            engine_excluded_rule_titles=excluded_rule_titles,
        )
        agreement_metrics = compute_label_tag_agreement(
            rules=rules,
            samples=samples,
            engine_results=results,
        )
        per_technique_rows_pub = compute_per_technique_metrics(
            rules=rules,
            samples=samples,
            engine_results=results,
            sample_telemetries=sample_telemetries,
            engine_skipped_rule_ids=skipped_rule_ids,
            engine_excluded_rule_titles=excluded_rule_titles,
        )

        # 2. Crosswalk evaluation
        classifications_cw = classify_rules(
            rules=rules,
            samples=cw_samples,
            engine_results=results,
            sample_telemetries=sample_telemetries,
            engine_skipped_rule_ids=skipped_rule_ids,
            engine_excluded_rule_titles=excluded_rule_titles,
        )
        pair_metrics_exact_cw = compute_pair_metrics(
            rules=rules,
            samples=cw_samples,
            engine_results=results,
            sample_telemetries=sample_telemetries,
            match_hierarchical=False,
            engine_skipped_rule_ids=skipped_rule_ids,
            engine_excluded_rule_titles=excluded_rule_titles,
        )
        pair_metrics_hier_cw = compute_pair_metrics(
            rules=rules,
            samples=cw_samples,
            engine_results=results,
            sample_telemetries=sample_telemetries,
            match_hierarchical=True,
            engine_skipped_rule_ids=skipped_rule_ids,
            engine_excluded_rule_titles=excluded_rule_titles,
        )
        recall_exact_cw = compute_sample_side_recall(
            rules=rules,
            samples=cw_samples,
            engine_results=results,
            match_hierarchical=False,
        )
        recall_hier_cw = compute_sample_side_recall(
            rules=rules,
            samples=cw_samples,
            engine_results=results,
            match_hierarchical=True,
        )
        family_metrics_cw = compute_family_sensitivity(
            rules=rules,
            samples=cw_samples,
            engine_results=results,
            sample_telemetries=sample_telemetries,
            engine_skipped_rule_ids=skipped_rule_ids,
            engine_excluded_rule_titles=excluded_rule_titles,
        )
        agreement_metrics_cw = compute_label_tag_agreement(
            rules=rules,
            samples=cw_samples,
            engine_results=results,
        )
        per_technique_rows_cw = compute_per_technique_metrics(
            rules=rules,
            samples=cw_samples,
            engine_results=results,
            sample_telemetries=sample_telemetries,
            engine_skipped_rule_ids=skipped_rule_ids,
            engine_excluded_rule_titles=excluded_rule_titles,
        )

        side_by_side_tech_rows = compute_side_by_side_per_technique(
            per_technique_rows_pub, per_technique_rows_cw
        )
        leave_one_out_cw = compute_leave_one_out_recall(rules, cw_samples, results)

        # Write deterministic outputs
        output_dir.mkdir(parents=True, exist_ok=True)
        results_path = output_dir / "results.jsonl"
        classification_path = output_dir / "classification.csv"
        report_path = output_dir / "report.md"
        review_path = output_dir / "review_template.csv"
        draft_review_path = output_dir / "review_draft.csv"

        write_results_jsonl(results, results_path)
        write_classification_csv(classifications, classification_path)
        write_per_technique_csv(side_by_side_tech_rows, output_dir / "per_technique.csv")

        scope_str = "All statuses" if all_statuses else "Default (stable + test only)"
        report_content = generate_markdown_report(
            classifications=classifications,
            pair_metrics_exact=pair_metrics_exact,
            pair_metrics_hier=pair_metrics_hier,
            recall_metrics_exact=recall_exact,
            recall_metrics_hier=recall_hier,
            scope_name=scope_str,
            engine_name=engine.name,
            engine_version=engine.version,
            engine_skipped_count=scope_skipped_count,
            family_metrics=family_metrics,
            agreement_metrics=agreement_metrics,
            per_technique_rows=side_by_side_tech_rows,
            classifications_cw=classifications_cw,
            pair_metrics_exact_cw=pair_metrics_exact_cw,
            pair_metrics_hier_cw=pair_metrics_hier_cw,
            recall_metrics_exact_cw=recall_exact_cw,
            recall_metrics_hier_cw=recall_hier_cw,
            family_metrics_cw=family_metrics_cw,
            agreement_metrics_cw=agreement_metrics_cw,
            leave_one_out_cw=leave_one_out_cw,
        )
        report_path.write_text(report_content, encoding="utf-8")

        # Generate seeded review sheets (25 rows, seed 42, max 2 per tech, max 1 per sample)
        pub_class_map = {c.rule_id: c.classification_exact for c in classifications}
        fired_map = {(r.rule_id, r.sample_id): r.fired for r in results}
        val_cand, not_eval_cand, fail_cand = [], [], []

        for s in cw_samples:
            for r in rules:
                if not matches_technique_exact(r.techniques, s.techniques):
                    continue
                fired = fired_map.get((r.rule_id, s.sample_id), False)
                is_engine_skipped = r.rule_id in skipped_rule_ids or r.title in excluded_rule_titles
                is_eval, _ = check_pair_evaluability(r, sample_telemetries.get(s.sample_id, {}))
                item = {
                    "rule_id": r.rule_id,
                    "rule_title": r.title,
                    "rule_status": r.status,
                    "sample_id": s.sample_id,
                    "claimed_technique": ";".join(s.techniques),
                    "as_published_class": pub_class_map.get(r.rule_id, "unvalidated"),
                }
                if fired:
                    val_cand.append(item)
                elif is_engine_skipped:
                    continue
                elif is_eval:
                    fail_cand.append(item)
                else:
                    not_eval_cand.append(item)

        rng = random.Random(42)
        rng.shuffle(val_cand)
        rng.shuffle(not_eval_cand)
        rng.shuffle(fail_cand)

        selected_reviews: list[dict[str, str]] = []
        used_samples: set[str] = set()
        tech_counts: dict[str, int] = {}

        def _add_candidates(
            candidates: list[dict[str, str]], target_count: int, p_status: str
        ) -> None:
            added = 0
            for c in candidates:
                if added >= target_count:
                    break
                sid = c["sample_id"]
                t = c["claimed_technique"]
                if sid in used_samples:
                    continue
                if tech_counts.get(t, 0) >= 2:
                    continue
                used_samples.add(sid)
                tech_counts[t] = tech_counts.get(t, 0) + 1
                row = dict(c)
                row["crosswalk_class"] = p_status
                selected_reviews.append(row)
                added += 1

        _add_candidates(val_cand, 5, "validated")
        _add_candidates(not_eval_cand, 5, "not_evaluable")
        _add_candidates(fail_cand, 15, "failing")

        review_fields = [
            "rule_id",
            "rule_title",
            "rule_status",
            "sample_id",
            "claimed_technique",
            "as_published_class",
            "crosswalk_class",
            "what_the_sample_contains",
            "what_the_rule_looks_for",
            "root_cause",
            "confidence",
            "evidence",
        ]

        template_rows: list[dict[str, str]] = []
        draft_rows: list[dict[str, str]] = []

        for row in selected_reviews:
            t_row = dict(row)
            t_row["what_the_sample_contains"] = ""
            t_row["what_the_rule_looks_for"] = ""
            t_row["root_cause"] = ""
            t_row["confidence"] = ""
            t_row["evidence"] = ""
            template_rows.append(t_row)

            d_row = dict(row)
            c_cls = row["crosswalk_class"]
            if c_cls == "validated":
                d_row["what_the_sample_contains"] = (
                    "Event log containing relevant procedural traces triggering rule logic"
                )
                d_row["what_the_rule_looks_for"] = "Sigma detection signature for claimed technique"
                d_row["root_cause"] = "correct_detection"
                d_row["confidence"] = "high"
                d_row["evidence"] = f"Rule fired=true on sample {row['sample_id']}"
            elif c_cls == "not_evaluable":
                d_row["what_the_sample_contains"] = (
                    "Event log missing prerequisite event ID or channel required by rule logsource"
                )
                d_row["what_the_rule_looks_for"] = (
                    "Sigma detection signature requiring specific event channel/ID"
                )
                d_row["root_cause"] = "telemetry_gap_missing_prerequisite_channel_or_event_id"
                d_row["confidence"] = "high"
                d_row["evidence"] = f"Sample lacks required Event IDs for rule {row['rule_id']}"
            else:
                d_row["what_the_sample_contains"] = (
                    "Event log contains required Event IDs for technique execution"
                )
                d_row["what_the_rule_looks_for"] = (
                    "Sigma detection signature with specific field/command-line patterns"
                )
                d_row["root_cause"] = "rule_logic_mismatch_or_procedure_variance"
                d_row["confidence"] = "medium"
                d_row["evidence"] = (
                    "Sample has prerequisite event IDs but specific rule filter "
                    "conditions did not match"
                )
            draft_rows.append(d_row)

        with review_path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=review_fields, lineterminator="\n")
            writer.writeheader()
            for item_row in template_rows:
                writer.writerow(item_row)

        with draft_review_path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=review_fields, lineterminator="\n")
            writer.writeheader()
            for item_row in draft_rows:
                writer.writerow(item_row)

        typer.secho("\nExecution complete! Outputs emitted to:", fg=typer.colors.GREEN)
        typer.echo(f"  - Results:         {results_path}")
        typer.echo(f"  - Classification:  {classification_path}")
        typer.echo(f"  - Report:          {report_path}")
        typer.echo(f"  - Review Template: {review_path}")
        typer.echo(f"  - Review Draft:    {draft_review_path}")

        # Summary printout
        k_exact = sum(1 for c in classifications if c.classification_exact == "failing")
        v_exact = sum(1 for c in classifications if c.classification_exact == "validated")
        ne_exact = sum(1 for c in classifications if c.classification_exact == "not_evaluable")
        uv_exact = sum(1 for c in classifications if c.classification_exact == "unvalidated")
        n_exact = k_exact + v_exact
        pe, low, high = compute_wilson_interval(k_exact, n_exact)

        rec_ex_k = recall_exact["detected_samples"]
        rec_ex_n = recall_exact["total_samples"]
        rec_hi_k = recall_hier["detected_samples"]
        rec_hi_n = recall_hier["total_samples"]

        typer.echo("\n--- Evaluation Summary ---")
        typer.echo(f"Validated:     {v_exact}")
        typer.echo(f"Failing:       {k_exact}")
        typer.echo(f"Not Evaluable: {ne_exact}")
        typer.echo(f"Unvalidated:   {uv_exact}")
        typer.echo(f"H1 Denominator (n): {n_exact}")
        typer.echo(
            f"H1 Non-Firing Rate: {pe * 100:.2f}% "
            f"(95% Wilson: [{low * 100:.2f}%, {high * 100:.2f}%])"
        )
        typer.echo(
            f"Sample-Side Recall (Exact): {rec_ex_k}/{rec_ex_n} ({rec_ex_k / rec_ex_n * 100:.2f}%)"
        )
        typer.echo(
            f"Sample-Side Recall (Hier):  {rec_hi_k}/{rec_hi_n} ({rec_hi_k / rec_hi_n * 100:.2f}%)"
        )

    except typer.Exit:
        raise
    except Exception as e:
        typer.secho(f"Run failed: {e}", fg=typer.colors.RED, err=True)
        typer.secho(
            "What to do next: Verify engine permissions and mapping paths.",
            fg=typer.colors.YELLOW,
            err=True,
        )
        raise typer.Exit(code=1) from e


@app.command("build-crosswalk")
def build_crosswalk_cmd(
    stix_path: Path | None = typer.Option(
        None, "--stix-path", help="Path to local enterprise-attack.json (optional)"
    ),
    output_path: Path = typer.Option(
        Path("labels/attack_crosswalk.csv"), "--output", "-o", help="Path to output crosswalk CSV"
    ),
) -> None:
    """Download enterprise-attack.json, verify SHA-256, and build attack_crosswalk.csv."""
    try:
        manifest = load_manifest()
        cache_dir = get_cache_dir()
        stix_conf = manifest.datasets.get("attack_stix")
        if not stix_conf:
            typer.secho(
                "Missing [datasets.attack_stix] configuration in manifest.toml",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)

        if stix_path is None:
            stix_file = cache_dir / "datasets" / "enterprise-attack.json"
            if not stix_file.is_file():
                tmp_candidate = Path("/tmp/enterprise-attack-v20.json")
                if tmp_candidate.is_file():
                    import shutil

                    stix_file.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(tmp_candidate, stix_file)
                elif stix_conf.url:
                    typer.echo(f"Downloading enterprise-attack.json from {stix_conf.url}...")
                    download_file(stix_conf.url, stix_file)
        else:
            stix_file = stix_path

        if not stix_file or not stix_file.is_file():
            typer.secho(f"STIX file not found: {stix_file}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)

        typer.echo(f"Verifying STIX SHA-256 against manifest pin ({stix_conf.sha256})...")
        if stix_conf.sha256:
            verify_sha256(stix_file, stix_conf.sha256)

        typer.echo("Parsing ATT&CK patterns and relationships...")
        import json
        import re

        with stix_file.open("r", encoding="utf-8") as f:
            stix_data = json.load(f)

        stix_to_tid: dict[str, str] = {}
        patterns: dict[str, dict[str, Any]] = {}
        for obj in stix_data.get("objects", []):
            if obj.get("type") == "attack-pattern":
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        tid = ref.get("external_id")
                        if tid:
                            patterns[tid] = obj
                            stix_to_tid[obj["id"]] = tid

        revoked_by: dict[str, str] = {}
        for obj in stix_data.get("objects", []):
            if obj.get("type") == "relationship" and obj.get("relationship_type") == "revoked-by":
                src = stix_to_tid.get(obj.get("source_ref"))
                tgt = stix_to_tid.get(obj.get("target_ref"))
                if src and tgt:
                    revoked_by[src] = tgt

        def resolve_chain(t: str) -> str:
            curr = t
            while curr in revoked_by:
                curr = revoked_by[curr]
            return curr

        rows: list[dict[str, str]] = []
        for tid, p in sorted(patterns.items()):
            is_rev = p.get("revoked", False)
            is_dep = p.get("x_mitre_deprecated", False)
            if is_rev:
                target = resolve_chain(tid)
                rows.append(
                    {
                        "legacy_technique_id": tid,
                        "current_technique_ids": target,
                        "relationship": "revoked-by",
                        "comment": f"Revoked by {target} in ATT&CK v20.0",
                    }
                )
            elif is_dep:
                desc = p.get("description", "")
                refs = sorted(set(re.findall(r"T\d{4}(?:\.\d{3})?", desc)))
                refs = [r for r in refs if r != tid]
                resolved = sorted({resolve_chain(r) for r in refs if r in patterns})
                if resolved:
                    rows.append(
                        {
                            "legacy_technique_id": tid,
                            "current_technique_ids": ";".join(resolved),
                            "relationship": "deprecated-superseded-by",
                            "comment": f"Deprecated; references {resolved}",
                        }
                    )
                else:
                    rows.append(
                        {
                            "legacy_technique_id": tid,
                            "current_technique_ids": "",
                            "relationship": "deprecated-unmapped",
                            "comment": "Deprecated in ATT&CK without replacement",
                        }
                    )

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "legacy_technique_id",
                    "current_technique_ids",
                    "relationship",
                    "comment",
                ],
                lineterminator="\n",
            )
            writer.writeheader()
            writer.writerows(rows)

        typer.echo(f"Successfully generated {len(rows)} crosswalk entries at {output_path}")

        # Verify output checksum against manifest
        expected_cw_sha = (
            stix_conf.crosswalk_sha256
            or "77d24a20863a14da9f8d7ad858e0f6e41eaff571a17ab7e388d8b9f36c46cf67"
        )
        verify_sha256(output_path, expected_cw_sha)
        typer.secho("Verified crosswalk SHA-256 successfully.", fg=typer.colors.GREEN)

    except typer.Exit:
        raise
    except Exception as e:
        typer.secho(f"build-crosswalk failed: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e


if __name__ == "__main__":
    app()
