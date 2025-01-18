# Architecture Decision Records (ADRs) & Licenses

## 1. Architecture Decision Records

### ADR-001: Selection of Engine Binaries for Apple Silicon (darwin-arm64)
- **Status**: Accepted
- **Context**: RuleProof runs on Apple Silicon macOS (`arm64`). Incurring emulation overhead via Rosetta 2 is undesirable.
- **Evidence**:
  - *Chainsaw*: Release `v2.17.1` publishes asset `chainsaw_aarch64-apple-darwin.zip` at `https://github.com/WithSecureOpenSource/chainsaw/releases/download/v2.17.1/chainsaw_aarch64-apple-darwin.zip`. Verified executing natively on macOS M4.
  - *Hayabusa*: Release `v4.3.1` publishes asset `hayabusa-4.3.1-mac-aarch64.zip` at `https://github.com/Yamato-Security/hayabusa/releases/download/v4.3.1/hayabusa-4.3.1-mac-aarch64.zip`. Verified containing native `aarch64` binary.
- **Decision**: Pin these native Darwin-arm64 release archives directly in [manifest.toml](../manifest.toml).

### ADR-002: Primary Attack Sample Repository & Labelling Policy
- **Status**: Accepted
- **Context**: Comparing detection engines requires consistent, structured Windows EVTX inputs.
- **Evidence**: `sbousseaden/EVTX-ATTACK-SAMPLES` provides native EVTX files under GPL-3.0. Its external mapping spreadsheet (`bit.ly/2WpzQM4` -> Google Docs `https://docs.google.com/spreadsheets/d/12V5T9j6Fi3JSmMpAsMwovnWqRFKzzI9l2iXS5dEsnrs/edit?usp=sharing`) was retrieved on 2026-11-04 and committed as `labels/evtx_attack_samples.csv` (SHA-256: `2d6c1f1b74736cb6661dcdff0a6002cb52a284b94d87ab52dcd3fa619d10a881`).
- **Licensing & Redistribution**:
  - The upstream repository is licensed under GPL-3.0 (`LICENSE.GPL`).
  - The mapping spreadsheet was created and published by the repository author (Samir Bousseaden) as documentation for the project.
  - Redistribution of the mapping table in `labels/evtx_attack_samples.csv` is permitted under GPL-3.0 with preserved copyright attribution to Samir Bousseaden.
- **Decision**: Use `sbousseaden/EVTX-ATTACK-SAMPLES` with committed mapping snapshot `labels/evtx_attack_samples.csv`. Any sample lacking an explicit mapping entry is marked `unlabelled` and excluded from claims validation. Every indexed sample stores `label_source`.

### ADR-003: ATT&CK Technique Matching Granularity & Four-Class Coverage Policy
- **Status**: Accepted
- **Context**: Sigma rules frequently declare parent techniques (e.g. `T1059`) while attack logs represent sub-techniques (e.g. `T1059.001`), or vice-versa. Moreover, a rule might fail to fire simply because the log lacks the required telemetry or the engine skipped it.
- **Matching Policy**:
  1. **`exact_match`**: Rule technique ID is identical to the sample technique ID (e.g. `T1059.001` == `T1059.001`).
  2. **`hierarchical_match`**: Rule specifies a parent technique and the sample label is a sub-technique of it (e.g. rule has `T1059` and sample is `T1059.001`).
  3. **Rule tag is a sub-technique and sample is only the parent**: Evaluated strictly as **`no_match`** (a rule targeting PowerShell cannot be declared matching a generic execution log).
- **Rule Classification Taxonomy**:
  - **`validated`**: Fired on at least one labelled sample for a claimed technique (exact and hierarchical tracked separately).
  - **`failing`**: At least one *evaluable* labelled sample exists, but the rule fired on none of them.
  - **`not_evaluable`**: Labelled samples exist, but none provide the required channel/logsource, or the engine mapping lacks coverage, or the engine failed to load/skipped the rule.
  - **`unvalidated`**: No labelled sample exists in the dataset for any technique claimed by the rule.
- **Reporting & Denominator**:
  - H1 denominator is strictly `validated + failing`.
  - `not_evaluable`, `unvalidated`, and engine skip/fail counts are reported separately. Exact and hierarchical matches are never merged.

### ADR-004: Engine Binary Quarantine Handling
- **Status**: Accepted
- **Context**: macOS Gatekeeper attaches `com.apple.quarantine` attributes to downloaded archives and binaries.
- **Decision**: During `ruleproof fetch`, the quarantine attribute is removed via `xattr -d com.apple.quarantine <binary>` **only** if the attribute is present, **only** after SHA-256 validation passes, and the removal is explicitly logged. Custom user-supplied paths via `--chainsaw-path` / `--hayabusa-path` are permitted, but their SHA-256 is recorded and the run manifest is flagged `non-pinned`.

---

## 2. Licenses Inventory

| Component | Source / Repository | License | Obligations / Notes |
| :--- | :--- | :--- | :--- |
| **SigmaHQ Rules** | [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) | Detection Rule License (DRL) 1.1 / CC BY-SA 4.0 | Permitted for defensive/commercial use with attribution. Rules are consumed read-only. |
| **EVTX-ATTACK-SAMPLES** | [sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) | GNU General Public License v3.0 (GPL-3.0) | Datasets redistributed under GPLv3. Used as read-only test inputs. |
| **Chainsaw** | [WithSecureLabs/chainsaw](https://github.com/WithSecureLabs/chainsaw) | GNU General Public License v3.0 (GPL-3.0) | Standalone engine invoked as an external process via CLI. |
| **MITRE ATT&CK STIX Data** | [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data) | Apache-2.0 | Official ATT&CK ontology used to derive technique crosswalk mappings. |
### ADR-005: Final Repository Licensing
- **Status**: Accepted
- **Context**: RuleProof consumes SigmaHQ rules (Detection Rule License 1.1 / CC BY-SA 4.0), redistributes an authoritative mapping snapshot (`labels/evtx_attack_samples.csv`) under GPL-3.0, and invokes Chainsaw (GPL-3.0) and Hayabusa (Hayabusa Software License) via subprocess CLI interfaces.
- **Analysis**:
  - The committed mapping file `labels/evtx_attack_samples.csv` is licensed under GPL-3.0.
  - Subprocess invocation of external CLI tools does not constitute a derivative work under copyright law.
  - To ensure full compliance with the viral copyleft provisions of GPL-3.0 stemming from the redistribution of the mapping dataset alongside the test runner, the repository is licensed under **GNU General Public License v3.0 (GPL-3.0)**.
- **Decision**: License RuleProof under **GPL-3.0**. All original project Python code and documentation are distributed under GPL-3.0. Distinct third-party datasets and rules retain their respective upstream copyright notices.
- **Note on Mapping License**: It is **UNVERIFIED** whether the Google Sheet mapping carries its own license separate from the EVTX-ATTACK-SAMPLES repository's GPL-3.0 license. It is recommended that the user contact the dataset author directly for clarification. This statement does not constitute legal advice.

### ADR-006: Removal of Hypothesis H2 (Untestable)
- **Status**: Accepted
- **Context**: Hypothesis H2 proposed evaluating cross-engine disagreements between Chainsaw and Hayabusa on identical SigmaHQ rules.
- **Analysis**: Empirical measurement across all 5,019 Hayabusa rules vs 2,246 SigmaHQ rules revealed only 1 shared SigmaHQ rule ID (0.04% overlap). Hayabusa distributes converted, renamed, and custom rules rather than preserving SigmaHQ UUIDs. Cross-engine comparison of identical detection rules is scientifically impossible.
- **Decision**: Declare H2 untestable and remove H2 from the benchmark scope. Retain Hayabusa solely as an independent plausibility check for any-rule detection rates.

### ADR-007: Hayabusa Cross-Check Status (UNVERIFIED)
- **Status**: Accepted
- **Context**: An independent plausibility check was explored comparing Hayabusa's detection rate against Chainsaw on the 138 labelled samples.
- **Analysis**: Running Hayabusa CLI with `-m med` passed an unrecognised severity argument (`med` instead of `medium`), which caused Hayabusa to silently default to loading all rules including informational timeline events. Furthermore, Hayabusa's rule repository shares only 1 rule ID with SigmaHQ (0.04% overlap) and cannot be executed as part of the deterministic offline pipeline without ad-hoc external invocations. In addition, the upstream release archive (`hayabusa-4.3.1-mac-aarch64.zip`) does not package a license file, rendering its distribution license **UNVERIFIED**.
- **Decision**: Mark **Hayabusa cross-check: UNVERIFIED** and license as **UNVERIFIED (no license file in binary release asset)** in `manifest.toml`. Remove all Hayabusa detection rates from README and primary report artifacts to maintain strict provenance and offline reproducibility.

### ADR-008: Dual-Perspective Evaluation Policy: As-Published and ATT&CK Crosswalk
- **Status**: Accepted
- **Context**: The `EVTX-ATTACK-SAMPLES` dataset was labelled against legacy ATT&CK technique IDs (predating ATT&CK v7 sub-techniques), whereas modern SigmaHQ rules are tagged with granular sub-technique IDs (e.g. `T1059.001`). Evaluating modern Sigma rules exclusively against legacy parent IDs creates artificial non-firing ("failing") classifications due to taxonomy drift rather than detection failure.
- **Decision**: Treat the ATT&CK crosswalk view as **co-primary** alongside the as-published author labels. Both perspectives are evaluated and reported side-by-side in `outputs/report.md` and `outputs/per_technique.csv`. The crosswalk mappings (`labels/attack_crosswalk.csv`) are derived strictly from official MITRE ATT&CK STIX 2.1 data (`enterprise-attack.json` v20.0 pinned by SHA-256 in `manifest.toml`). Neither perspective is obscured: as-published reflects historical benchmark ground-truth, while the crosswalk reflects normalized contemporary ATT&CK ontology.

### ADR-009: Precedence Rule for Rule Classification
- **Status**: Accepted
- **Context**: Engine compilation skips (e.g. 29 rules skipped by Chainsaw lint) and mapping exclusions can coincide with rules that have no matching samples in the attack dataset. A precedence decision was required between:
  1. "A rule with no matching sample is unvalidated" (`evaluation.md`).
  2. "A rule skipped by the engine is not_evaluable".
- **Decision**: Precedence is given to sample availability: **"A rule with no matching sample is unvalidated"**.
- **Security & Statistical Reasoning**: Evaluability is a property of testing a rule against candidate evidence. If no sample exists in the dataset claiming the rule's technique, the rule was never eligible for evaluation; classifying it as `not_evaluable` would falsely conflate lack of benchmark test data with an engine evaluation failure. Therefore, rules with zero matching samples in the dataset remain strictly `unvalidated` (preserving `skip_reason="engine_skipped_or_failed_to_load"` or `"engine_excluded_by_mapping"`). Only rules for which matching candidate samples exist in the dataset are classified as `not_evaluable` when skipped or excluded.
