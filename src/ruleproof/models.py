"""Data models and schemas for RuleProof."""

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class SigmaRule(BaseModel):
    """Normalized representation of a parsed Sigma detection rule."""

    rule_id: str = Field(description="Unique rule ID or synthetic fallback if missing")
    title: str = Field(description="Human-readable rule title")
    status: str = Field(default="experimental", description="Sigma lifecycle status")
    logsource: dict[str, Any] = Field(
        default_factory=dict, description="Target log source taxonomy"
    )
    techniques: list[str] = Field(
        default_factory=list, description="Extracted ATT&CK technique IDs (e.g. T1059.001)"
    )
    detection_event_ids: list[int] = Field(
        default_factory=list, description="Explicit EventIDs extracted from detection block"
    )
    file_path: Path = Field(description="Absolute or relative path to the rule YAML")


class SampleRecord(BaseModel):
    """Metadata and ground truth technique mapping for an attack log sample."""

    sample_id: str = Field(description="File name or canonical identifier of the sample")
    file_path: Path = Field(description="Path to the EVTX sample file")
    techniques: list[str] = Field(
        default_factory=list, description="Authoritative ATT&CK technique IDs"
    )
    is_labelled: bool = Field(description="True if authoritative technique label is known")
    label_source: str = Field(
        description="Source of the technique label (e.g. manifest/doc + commit)"
    )


class RuleSourceConfig(BaseModel):
    """Configuration for a pinned rule repository."""

    repo: str
    commit: str
    license: str


class DatasetSourceConfig(BaseModel):
    """Configuration for a pinned attack dataset repository."""

    repo: str
    commit: str = ""
    license: str
    release_tag: str | None = None
    version: str | None = None
    url: str | None = None
    sha256: str | None = None
    crosswalk_file: str | None = None
    mapping_file: str | None = None
    mapping_sha256: str | None = None
    mapping_source_url: str | None = None
    mapping_source_resolved_from: str | None = None
    mapping_retrieval_date: str | None = None
    mapping_attribution: str | None = None
    mapping_url: str | None = None
    crosswalk_sha256: str | None = None


class EngineSourceConfig(BaseModel):
    """Configuration for a pinned engine binary release."""

    version: str
    platform: str
    asset: str
    url: str
    sha256: str
    binary_sha256: str | None = None
    sha256_verification_status: str
    license: str


class ManifestConfig(BaseModel):
    """Root configuration parsed from manifest.toml."""

    rules: dict[str, RuleSourceConfig]
    datasets: dict[str, DatasetSourceConfig]
    engines: dict[str, EngineSourceConfig]


class InspectSummary(BaseModel):
    """Summary metrics of rules and samples parsed during inspect."""

    total_rules: int
    rules_by_status: dict[str, int]
    rules_with_techniques: int
    total_samples: int
    labelled_samples: int
    unlabelled_samples: int
    unique_techniques_covered: int


class EngineResult(BaseModel):
    """Raw result of running an engine against a sample."""

    rule_id: str
    sample_id: str
    engine: str
    engine_version: str
    rule_commit: str
    dataset_commit: str
    fired: bool


class RuleClassification(BaseModel):
    """Final 4-class evaluation for a Sigma detection rule."""

    rule_id: str
    rule_title: str
    rule_status: str
    claimed_techniques: list[str]
    evaluable_samples_count: int
    classification_exact: str  # validated, failing, not_evaluable, unvalidated
    classification_hierarchical: str  # validated, failing, not_evaluable, unvalidated
    sample_matches: list[str]
    skip_reason: str | None = None
