"""Runner pipeline executing detection engines across samples."""

import json
import logging
from pathlib import Path
from typing import Any

from ruleproof.engines.base import BaseEngine, EngineError
from ruleproof.models import EngineResult, SampleRecord, SigmaRule

logger = logging.getLogger(__name__)


def run_engine_across_samples(
    engine: BaseEngine,
    rules: list[SigmaRule],
    samples: list[SampleRecord],
    rules_dir: Path,
    rule_commit: str,
    dataset_commit: str,
    manifest_path: Path | None = None,
) -> tuple[list[EngineResult], dict[str, dict[str, set[int]]], dict[str, Any]]:
    """Execute the detection engine once per sample against the full ruleset.

    Records per-sample execution status in run_manifest.json.

    Returns:
      (results, sample_telemetries, run_manifest)
      - results: List of EngineResult records for every (rule, sample) combination.
      - sample_telemetries: Extracted channel/EventID maps for evaluable checks.
      - run_manifest: Status dictionary detailing per-sample execution metrics.
    """
    results: list[EngineResult] = []
    sample_telemetries: dict[str, dict[str, set[int]]] = {}
    sample_manifests: dict[str, dict[str, Any]] = {}
    failed_samples: list[str] = []
    empty_telemetry_samples: list[str] = []

    for sample in samples:
        logger.info(f"Running {engine.name} on sample {sample.sample_id}...")
        sample_info: dict[str, Any] = {
            "status": "ok",
            "returncode": 0,
            "detection_count": 0,
            "telemetry_event_id_count": 0,
            "error": None,
        }

        fired_ids: set[str] = set()
        try:
            # 1. Extract sample telemetry channels and EventIDs
            telemetry = engine.get_sample_telemetry(sample.file_path)
            sample_telemetries[sample.sample_id] = telemetry
            event_id_count = sum(len(eids) for eids in telemetry.values())
            sample_info["telemetry_event_id_count"] = event_id_count
            if event_id_count == 0:
                empty_telemetry_samples.append(sample.sample_id)

            # 2. Run engine hunting with full rules directory
            fired_ids = set(engine.hunt(sample.file_path, rules_dir))
            sample_info["detection_count"] = len(fired_ids)

        except EngineError as e:
            sample_info["status"] = "failed"
            sample_info["returncode"] = e.returncode if e.returncode is not None else -1
            sample_info["error"] = str(e)
            failed_samples.append(sample.sample_id)
            logger.error(f"Engine failed on sample {sample.sample_id}: {e}")
        except Exception as e:
            sample_info["status"] = "failed"
            sample_info["returncode"] = -1
            sample_info["error"] = str(e)
            failed_samples.append(sample.sample_id)
            logger.error(f"Unexpected error running engine on sample {sample.sample_id}: {e}")

        sample_manifests[sample.sample_id] = sample_info

        # 3. Create normalized record for each evaluated rule
        for rule in rules:
            is_fired = rule.rule_id in fired_ids
            # Fallback check by title if engine emitted title instead of uuid
            if not is_fired and rule.title in fired_ids:
                is_fired = True

            results.append(
                EngineResult(
                    rule_id=rule.rule_id,
                    sample_id=sample.sample_id,
                    engine=engine.name,
                    engine_version=engine.version,
                    rule_commit=rule_commit,
                    dataset_commit=dataset_commit,
                    fired=is_fired,
                )
            )

    # Deterministic sort
    results.sort(key=lambda r: (r.rule_id, r.sample_id, r.engine))

    manifest_data: dict[str, Any] = {
        "engine": engine.name,
        "engine_version": engine.version,
        "total_samples": len(samples),
        "successful_samples": len(samples) - len(failed_samples),
        "failed_samples": failed_samples,
        "empty_telemetry_samples": empty_telemetry_samples,
        "samples": sample_manifests,
    }

    if manifest_path is not None:
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

    return results, sample_telemetries, manifest_data
