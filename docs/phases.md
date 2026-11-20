# Phases and Acceptance Criteria

## Phase 0: Scaffolding and Specifications (Complete)
- **Objective**: Establish repo governance, architectural models, mathematical evaluation contracts, threat mitigations, and development toolchain.
- **Deliverables**: All docs, `.agents/` workflows, `pyproject.toml`, `Makefile`, `.gitignore`, `.github/workflows/ci.yml`.
- **Exit Gate**: Clean Ruff/mypy configuration check, zero pipeline code, and explicit user approval (`approved: Phase 0`).

## Phase 1: Fetch and Ingestion Pipeline
- **Objective**: Implement pinned artifact fetching with SHA-256 validation, Sigma rule metadata parsing, and sample index construction.
- **Deliverables**: `manifest.toml`, `src/ruleproof/fetch.py`, `rules.py`, `samples.py`, `cli.py` (`fetch`, `inspect`), and unit tests on fixtures.
- **Exit Gate**: `ruleproof fetch` downloads and verifies pinned dependencies; `ruleproof inspect` outputs parsed rule and sample counts; 100% pytest pass on fixtures; user approval (`approved: Phase 1`).

## Phase 2: MVP Execution & Evaluation (Chainsaw)
- **Objective**: Execute Chainsaw over Windows EVTX samples with Sigma rules, normalize detections, classify coverage (`validated`, `failing`, `unvalidated`), and output reports.
- **Deliverables**: `src/ruleproof/engines/chainsaw.py`, `runner.py`, `classify.py`, `report.py`, CLI commands (`run`, `report`), `results.jsonl`, `classification.csv`, `report.md`.
- **Exit Gate**: Deterministic artifact generation; dual-column exact and hierarchical matching; H1 Wilson interval calculation; user approval (`approved: Phase 2`).

## Phase 3: Multi-Engine Plausibility & Final Verification
- **Objective**: Integrate Hayabusa as an independent plausibility engine (any-rule detection rate cross-check); remove untestable H2 (0.04% shared rule IDs); release preparation.
- **Deliverables**: `src/ruleproof/engines/hayabusa.py`, positive control verification, final reports and documentation.
- **Exit Gate**: All positive controls pass; all unit and integration tests pass; user approval.

## Phase 4: Release & Hand-off
- **Status**: manual review, learning notes, clean-clone reproduction, publication: pending (user).
- **Objective**: User manual review in `outputs/review_template.csv`, completion of `learning-notes.md`, clean-clone reproduction verification, and publication. Project remains open pending user completion.

## Phase 5: Advanced Extensions (On Request Only)
- **Objective**: Log perturbation resilience testing or automated rule remediation.
- **Condition**: Executed only if explicitly requested by the user. Not planned unprompted.
