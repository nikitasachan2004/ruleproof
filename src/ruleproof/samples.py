"""Attack log sample indexer and technique mapping loader."""

import csv
import logging
import re
from pathlib import Path

from ruleproof.models import SampleRecord

logger = logging.getLogger(__name__)

EVTX_NAME_REGEX = re.compile(r"([a-zA-Z0-9_\-\.]+\.evtx)", re.IGNORECASE)
TECHNIQUE_ID_REGEX = re.compile(r"^(T\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


def parse_mapping_csv(
    csv_path: Path,
) -> dict[str, list[str]]:
    """Parse the external sample-to-technique mapping CSV.

    Extracts (filename -> list of ATT&CK technique IDs).
    Security reasoning: CSV parsing is performed strictly through standard csv.reader
    without eval or shell interpolation.
    """
    sample_to_techniques: dict[str, set[str]] = {}

    if not csv_path.is_file():
        logger.warning(f"Mapping CSV not found at {csv_path}")
        return {}

    with csv_path.open("r", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        if not header:
            return {}

        # Expected columns: Tactic, Technique, ID, Procedure related detection traces
        for row in reader:
            if len(row) < 4:
                continue

            raw_id = row[2].strip()
            trace_text = row[3].strip()

            id_match = TECHNIQUE_ID_REGEX.match(raw_id)
            if not id_match:
                continue
            technique_id = id_match.group(1).upper()

            # Find all .evtx filenames referenced in the trace description
            evtx_matches = EVTX_NAME_REGEX.findall(trace_text)
            for evtx_name in evtx_matches:
                canonical_name = evtx_name.strip()
                if canonical_name not in sample_to_techniques:
                    sample_to_techniques[canonical_name] = set()
                sample_to_techniques[canonical_name].add(technique_id)

    # Return sorted lists
    return {k: sorted(v) for k, v in sample_to_techniques.items()}


def index_samples(
    samples_dir: Path,
    mapping_csv: Path | None = None,
    dataset_commit: str = "pinned",
) -> list[SampleRecord]:
    """Index all EVTX files in samples_dir, pairing with authoritative labels.

    Any sample lacking an unambiguous author-provided technique mapping is marked
    unlabelled (is_labelled=False) and excluded from claims validation.
    """
    default_source = f"EVTX-ATTACK-SAMPLES/README.md@commit:{dataset_commit}"
    mapping: dict[str, list[str]] = {}
    if mapping_csv is not None and mapping_csv.is_file():
        mapping = parse_mapping_csv(mapping_csv)

    records: list[SampleRecord] = []
    for evtx_path in samples_dir.rglob("*.evtx"):
        filename = evtx_path.name
        techniques = mapping.get(filename, [])

        # Ground-truth policy: If techniques are missing, mark unlabelled
        if techniques:
            is_labelled = True
            source = default_source
        else:
            is_labelled = False
            source = "unlabelled:no_author_mapping"

        record = SampleRecord(
            sample_id=filename,
            file_path=evtx_path,
            techniques=techniques,
            is_labelled=is_labelled,
            label_source=source,
        )
        records.append(record)

    records.sort(key=lambda s: s.sample_id)
    return records
