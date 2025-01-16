# Requirements Specification

## 1. Project Context & Users
- **Primary User**: A B.Tech student and junior security practitioner preparing for technical interviews in detection engineering and security operations.
- **Goal**: Provide an automated, fully reproducible tool proving whether open-source detection rules (Sigma) successfully fire on realistic, labelled attack logs (Windows EVTX), comparing "claimed coverage" against "observed detection".

## 2. Explicit Non-Goals
RuleProof is strictly **not**:
- A SIEM, telemetry collector, or real-time event pipeline.
- An interactive web application or analytics dashboard.
- An AI analyst or LLM-driven rule synthesizer.
- An offensive attack generator or exploit framework.

## 3. Functional Requirements (FR)
- **FR1: Pinned Artifact Fetching**: Download Sigma rules, attack sample datasets, and engine binaries pinned by commit or release tag and verified by SHA-256 digests in [manifest.toml](../manifest.toml).
- **FR2: Rule & Sample Parsing**:
  - Extract metadata (`id`, `title`, `logsource`, ATT&CK tags, `status`) from Windows Sigma rules.
  - Parse labelled Windows EVTX samples and index their author-declared ATT&CK techniques with provenance (`label_source`), utilizing the committed mapping in [labels/evtx_attack_samples.csv](../labels/evtx_attack_samples.csv).
- **FR3: Engine Execution**: Run offline detection engines (Chainsaw in Phase 2; Hayabusa in Phase 3) safely without shell expansion or network calls.
- **FR4: Coverage Classification**: Classify every rule as:
  - `validated`: At least one matching labelled sample exists and the rule successfully fired on it.
  - `failing`: At least one matching labelled sample exists, but the rule fired on none of them.
  - `unvalidated`: No matching labelled sample exists in the dataset.
- **FR5: Deterministic Reporting**: Emit machine-readable artifacts (`results.jsonl`, `classification.csv`) and a summary document (`report.md`) sorted deterministically and free of non-deterministic metadata.

## 4. Non-Functional Requirements (NFR)
- **NFR1: Absolute Reproducibility**: Fixed dependency locks (`uv.lock`) and pinned external inputs ensure identical outputs on identical inputs.
- **NFR2: Local & Air-gapped Runtime**: Runtime evaluation executes completely offline with zero network connectivity.
- **NFR3: Memory & Resource Efficiency**: Operates within 16 GB RAM on Apple Silicon macOS (`arm64`), utilizing single-sample streaming or sparse fetches without multi-gigabyte in-memory buffering.
- **NFR4: Security by Design**: Defensive execution treating all input logs as untrusted data (see [docs/threat-model.md](threat-model.md)).
