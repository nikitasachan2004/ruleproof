# parse json output structure
# subprocess argument list safe execution
# chainsaw engine wrapper draft
"""Chainsaw engine implementation calling the native binary safely."""

import json
import logging
import re
import subprocess
from pathlib import Path

from ruleproof.engines.base import BaseEngine, EngineError

logger = logging.getLogger(__name__)

LOADED_RULES_REGEX = re.compile(r"Loaded\s+(\d+)\s+detection rules\s+\((\d+)\s+not loaded\)")


class ChainsawEngine(BaseEngine):
    """Engine adapter for WithSecure Chainsaw."""

    def __init__(
        self,
        binary_path: Path,
        mapping_path: Path,
        version: str = "v2.17.1",
        timeout: int = 120,
    ) -> None:
        self.binary_path = binary_path
        self.mapping_path = mapping_path
        self._version = version
        self.timeout = timeout
        self.last_skipped_rules_count = 0

    @property
    def name(self) -> str:
        return "chainsaw"

    @property
    def version(self) -> str:
        return self._version

    def hunt(
        self,
        sample_path: Path,
        rules_path: Path,
    ) -> list[str]:
        """Run Chainsaw hunting on a single sample against rules_path.

        Command contract:
        chainsaw --no-banner hunt <sample> -s <rules> -m <mapping> --json --skip-errors
        """
        cmd = [
            str(self.binary_path),
            "--no-banner",
            "hunt",
            str(sample_path),
            "-s",
            str(rules_path),
            "-m",
            str(self.mapping_path),
            "--json",
            "--skip-errors",
        ]

        logger.debug(f"Executing: {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired as e:
            err_stderr = (
                e.stderr.decode("utf-8", errors="replace")
                if isinstance(e.stderr, bytes)
                else (e.stderr or "")
            )
            raise EngineError(
                f"Chainsaw hunt timed out after {self.timeout}s on {sample_path.name}",
                returncode=-1,
                stderr=err_stderr,
            ) from e

        if result.returncode != 0:
            stderr_tail = "\n".join(result.stderr.strip().splitlines()[-10:])
            err_msg = (
                f"Chainsaw hunt failed (exit {result.returncode}) on "
                f"{sample_path.name}:\n{stderr_tail}"
            )
            raise EngineError(err_msg, returncode=result.returncode, stderr=result.stderr)

        # Parse stderr/stdout for unloaded rules count
        combined_output = f"{result.stdout}\n{result.stderr}"
        match = LOADED_RULES_REGEX.search(combined_output)
        if match:
            self.last_skipped_rules_count = int(match.group(2))

        # Chainsaw outputs JSON detections after banner/info lines.
        # Find JSON array [...] in output
        fired_rule_ids: list[str] = []
        json_start = result.stdout.find("[{")
        json_empty = result.stdout.find("[]")

        if json_start != -1:
            try:
                json_str = result.stdout[json_start:]
                # Take substring up to closing bracket of root list
                end_idx = json_str.rfind("]")
                if end_idx != -1:
                    json_str = json_str[: end_idx + 1]
                data = json.loads(json_str)
                for detection in data:
                    if isinstance(detection, dict):
                        rule_id = detection.get("id") or detection.get("name")
                        if rule_id and str(rule_id) not in fired_rule_ids:
                            fired_rule_ids.append(str(rule_id))
            except Exception as e:
                raise EngineError(
                    f"Failed to parse Chainsaw detection JSON on {sample_path.name}: {e}",
                    returncode=result.returncode,
                    stderr=result.stderr,
                ) from e
        elif json_empty != -1:
            pass  # 0 detections
        else:
            raise EngineError(
                f"Chainsaw hunt malformed output (no JSON found) on {sample_path.name}",
                returncode=result.returncode,
                stderr=result.stderr,
            )

        return fired_rule_ids

    def get_sample_telemetry(self, sample_path: Path) -> dict[str, set[int]]:
        """Extract present Windows event channels and EventIDs using chainsaw analyse evtx."""
        cmd = [
            str(self.binary_path),
            "--no-banner",
            "analyse",
            "evtx",
            str(sample_path),
            "--json",
            "--skip-errors",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired as e:
            err_stderr = (
                e.stderr.decode("utf-8", errors="replace")
                if isinstance(e.stderr, bytes)
                else (e.stderr or "")
            )
            raise EngineError(
                f"Chainsaw analyse timed out after {self.timeout}s on {sample_path.name}",
                returncode=-1,
                stderr=err_stderr,
            ) from e

        if result.returncode != 0:
            stderr_tail = "\n".join(result.stderr.strip().splitlines()[-10:])
            err_msg = (
                f"Chainsaw analyse failed (exit {result.returncode}) on "
                f"{sample_path.name}:\n{stderr_tail}"
            )
            raise EngineError(err_msg, returncode=result.returncode, stderr=result.stderr)

        channels: dict[str, set[int]] = {}
        json_start = result.stdout.find("[{")
        json_empty = result.stdout.find("[]")

        if json_start != -1:
            try:
                json_str = result.stdout[json_start:]
                end_idx = json_str.rfind("]")
                if end_idx != -1:
                    json_str = json_str[: end_idx + 1]
                data = json.loads(json_str)
                for file_entry in data:
                    if isinstance(file_entry, dict):
                        for ch_entry in file_entry.get("channels", []):
                            ch_name = ch_entry.get("channel", "")
                            if ch_name not in channels:
                                channels[ch_name] = set()
                            for eid in ch_entry.get("event_ids", []):
                                channels[ch_name].add(int(eid.get("event_id", 0)))
            except Exception as e:
                raise EngineError(
                    f"Failed to parse chainsaw analyse telemetry on {sample_path.name}: {e}",
                    returncode=result.returncode,
                    stderr=result.stderr,
                ) from e
        elif json_empty != -1:
            return channels
        else:
            raise EngineError(
                f"Chainsaw analyse malformed output (no JSON found) on {sample_path.name}",
                returncode=result.returncode,
                stderr=result.stderr,
            )

        return channels

    def get_skipped_rule_ids(self, rules_dir: Path) -> set[str]:
        """Run chainsaw lint --kind sigma to extract rule IDs that fail to load."""
        cmd = [
            str(self.binary_path),
            "--no-banner",
            "lint",
            "--kind",
            "sigma",
            str(rules_dir),
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
        )
        skipped_ids: set[str] = set()
        combined = f"{result.stdout}\n{result.stderr}"
        for line in combined.splitlines():
            if line.startswith("[!] /"):
                parts = line[4:].split(": ", 1)
                subpath = parts[0].strip("/")
                rule_file = rules_dir / subpath
                if rule_file.is_file():
                    try:
                        import yaml

                        with open(rule_file, encoding="utf-8") as f:
                            data = yaml.safe_load(f)
                            if isinstance(data, dict) and data.get("id"):
                                skipped_ids.add(str(data["id"]))
                    except Exception as e:
                        logger.warning(f"Error reading skipped rule file {rule_file}: {e}")
        return skipped_ids

    def get_mapping_excluded_titles(self) -> set[str]:
        """Read rule titles explicitly excluded in the Chainsaw mapping file."""
        if not self.mapping_path.is_file():
            return set()
        try:
            import yaml

            with open(self.mapping_path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if isinstance(data, dict):
                    return set(data.get("exclusions", []))
        except Exception as e:
            logger.warning(f"Error reading exclusions from {self.mapping_path}: {e}")
        return set()
