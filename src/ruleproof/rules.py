"""Sigma detection rule loader and metadata parser."""

import logging
import re
from pathlib import Path
from typing import Any

import yaml

from ruleproof.models import SigmaRule

logger = logging.getLogger(__name__)

# Regular expression matching ATT&CK technique tags: e.g. attack.t1059 or attack.t1059.001
ATTACK_TAG_REGEX = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


def parse_sigma_file(file_path: Path) -> SigmaRule | None:
    """Parse a single Sigma YAML file and extract detection metadata.

    Security reasoning: YAML files are loaded via yaml.safe_load to avoid arbitrary
    code execution or object deserialization from untrusted community rules.
    """
    try:
        with file_path.open("r", encoding="utf-8", errors="replace") as f:
            docs = list(yaml.safe_load_all(f))
    except Exception as e:
        logger.warning(f"Failed to parse YAML file {file_path}: {e}")
        return None

    if not docs or not isinstance(docs[0], dict):
        return None

    doc = docs[0]

    rule_id = str(doc.get("id") or file_path.stem)
    title = str(doc.get("title") or file_path.stem)
    status = str(doc.get("status") or "experimental").lower().strip()
    raw_logsource = doc.get("logsource")
    logsource: dict[str, Any] = (
        {str(k): v for k, v in raw_logsource.items()} if isinstance(raw_logsource, dict) else {}
    )

    raw_tags = doc.get("tags") or []
    if not isinstance(raw_tags, list):
        raw_tags = [raw_tags]

    techniques: list[str] = []
    for tag in raw_tags:
        if isinstance(tag, str):
            match = ATTACK_TAG_REGEX.match(tag.strip())
            if match:
                technique_id = match.group(1).upper()
                if technique_id not in techniques:
                    techniques.append(technique_id)

    # Extract explicit EventIDs from detection block
    detection_event_ids: list[int] = []
    seen_eids: set[int] = set()

    def _extract_eids(item: Any) -> None:
        if isinstance(item, dict):
            for k, v in item.items():
                if str(k).lower() in ("eventid", "event_id", "event-id"):
                    if isinstance(v, int):
                        if v not in seen_eids:
                            seen_eids.add(v)
                            detection_event_ids.append(v)
                    elif isinstance(v, str) and v.isdigit():
                        iv = int(v)
                        if iv not in seen_eids:
                            seen_eids.add(iv)
                            detection_event_ids.append(iv)
                    elif isinstance(v, list):
                        for el in v:
                            if isinstance(el, int) and el not in seen_eids:
                                seen_eids.add(el)
                                detection_event_ids.append(el)
                            elif isinstance(el, str) and str(el).isdigit():
                                iel = int(el)
                                if iel not in seen_eids:
                                    seen_eids.add(iel)
                                    detection_event_ids.append(iel)
                else:
                    _extract_eids(v)
        elif isinstance(item, list):
            for el in item:
                _extract_eids(el)

    _extract_eids(doc.get("detection", {}))
    detection_event_ids.sort()

    return SigmaRule(
        rule_id=rule_id,
        title=title,
        status=status,
        logsource=logsource,
        techniques=techniques,
        detection_event_ids=detection_event_ids,
        file_path=file_path,
    )


def load_rules(
    rules_dir: Path,
    target_statuses: set[str] | None = None,
) -> list[SigmaRule]:
    """Scan rules_dir recursively for .yml/.yaml rules and return parsed SigmaRule objects."""
    rules: list[SigmaRule] = []
    for ext in ("*.yml", "*.yaml"):
        for path in rules_dir.rglob(ext):
            rule = parse_sigma_file(path)
            if rule is None:
                continue

            if target_statuses is not None and rule.status not in target_statuses:
                continue

            rules.append(rule)

    rules.sort(key=lambda r: r.rule_id)
    return rules
