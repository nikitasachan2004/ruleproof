"""Hayabusa engine adapter implementation."""

import json
import logging
import subprocess
from pathlib import Path

from ruleproof.engines.base import BaseEngine

logger = logging.getLogger(__name__)


class HayabusaEngine(BaseEngine):
    """Engine adapter for Yamato Security Hayabusa."""

    def __init__(
        self,
        binary_path: Path,
        rules_path: Path,
        version: str = "v4.3.1",
    ) -> None:
        self.binary_path = binary_path
        self.rules_path = rules_path
        self._version = version

    @property
    def name(self) -> str:
        return "hayabusa"

    @property
    def version(self) -> str:
        return self._version

    def hunt(
        self,
        sample_path: Path,
        _rules_path: Path,
    ) -> list[str]:
        """Run Hayabusa dfir-timeline on a single sample against rules_path."""
        temp_out = sample_path.parent / f".tmp_{sample_path.stem}_hb.jsonl"
        cmd = [
            str(self.binary_path),
            "dfir-timeline",
            "-w",
            "-f",
            str(sample_path),
            "-r",
            str(self.rules_path),
            "-q",
            "-t",
            "jsonl",
            "-o",
            str(temp_out),
            "-C",
        ]

        logger.debug(f"Executing: {' '.join(cmd)}")
        subprocess.run(cmd, capture_output=True, text=True, check=False)

        fired_rule_ids: list[str] = []
        if temp_out.is_file():
            try:
                with temp_out.open("r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            record = json.loads(line)
                            rule_id = record.get("RuleID") or record.get("RuleTitle")
                            if rule_id and str(rule_id) not in fired_rule_ids:
                                fired_rule_ids.append(str(rule_id))
                        except json.JSONDecodeError:
                            continue
            finally:
                temp_out.unlink(missing_ok=True)

        return fired_rule_ids

    def get_sample_telemetry(self, _sample_path: Path) -> dict[str, set[int]]:
        """Fallback to empty or chainsaw analyse."""
        return {}
