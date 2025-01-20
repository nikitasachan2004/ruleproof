# Pipeline Specification & Data Contracts

## 1. Pipeline Stages

```
[Fetch] -> [Parse & Index] -> [Execute Engine] -> [Classify Detections] -> [Emit Reports]
```

1. **Stage 1: Fetch (`ruleproof fetch`)**
   - **Inputs**: Pinned entries in [manifest.toml](../manifest.toml).
   - **Outputs**: Verified files written to `.cache/` (rules, samples, binaries).
   - **Contract**: Checksum failure immediately halts execution with non-zero exit code.
2. **Stage 2: Parse & Index (`ruleproof inspect`)**
   - **Inputs**: Sigma YAML files and EVTX sample directories.
   - **Outputs**: In-memory Pydantic index of `SigmaRule` and `SampleRecord` objects.
   - **Contract**: Reject non-authoritative technique labels. Exclude ambiguous or multi-interpretation tags.
3. **Stage 3: Execute (`ruleproof run`)**
   - **Inputs**: Verified engine binary, Sigma rules path, EVTX sample paths.
   - **Outputs**: Raw structured alerts parsed into normalized `EngineDetection` records.
   - **Contract**: Execute via `subprocess.run(..., shell=False)`.
   - **Engine Exit Code Semantics (Chainsaw)**:
     - Chainsaw returns exit code `0` on successful completion, including when 0 detections are found.
     - Chainsaw returns exit code `1` only on fatal errors (e.g., EVTX stream deserialization failure on corrupt files or unhandled syntax errors).
     - Passing `--skip-errors` allows Chainsaw to skip unparseable files with a warning and exit with `0`. The runner records any skipped files and marks rules relying on them as `not_evaluable`.
   - **Detection ID Output**:
     - Verified: In `--json` mode, Chainsaw outputs an `"id"` key directly on each detection object containing the Sigma rule UUID.
   - **Engine Skip/Fail Tracking**:
     - Chainsaw reports aggregate unloaded rules in startup logging (`[!] Loaded X detection rules (Y not loaded)`). In Phase 2, runner captures this stream to report the count of skipped/failed rules.
   - **Evaluable Determination Procedure**:
     - Channel and EventID presence in an EVTX sample is extracted using `chainsaw analyse evtx <sample> --json` (zero new external Python dependencies).
     - The rule's `logsource` (product, service, category) is checked against Chainsaw's mapping table (`sigma-event-logs-all.yml`). If mapped, the expected channel and Event IDs are cross-referenced against the sample's detected channels.
     - *Residual Limitation*: Presence of the expected channel/Event ID does not guarantee that the specific fields or command-line parameters required by rule logic were recorded during attack execution.
     - *Event ID Channel Pooling Limitation*: Chainsaw's event ID mapping pools event IDs across channels without per-channel provider verification.
     - *Title-Based Mapping Exclusions*: Chainsaw mapping exclusions match rules by title, representing engine-level exclusions whose behavioral effects remain unverified independently.
4. **Stage 4: Classify**
   - **Inputs**: Indexed `SigmaRule`, `SampleRecord`, and `EngineDetection` records.
   - **Outputs**: `RuleClassification` dataset (`validated`, `failing`, `not_evaluable`, `unvalidated`).
   - **Contract**: Enforce dual-column technique matching policy (see [docs/decisions.md](decisions.md)).
5. **Stage 5: Report**
   - **Inputs**: Classification and alert datasets.
   - **Outputs**: `classification.csv`, `results.jsonl`, `report.md`, `review_template.csv`.

## 2. Data Contracts (Pydantic Models)

### `results.jsonl` Schema
```json
{
  "rule_id": "b0533c6c-84a1-432a-b68e-e478546de542",
  "sample_id": "CA_DCSync_4662.evtx",
  "engine": "chainsaw",
  "engine_version": "v2.17.1",
  "rule_commit": "26a2c3810a4878caec599563f972a8c39587b154",
  "dataset_commit": "4ceed2f4706daf601c212a8f91c113dd85349a2c",
  "fired": true
}
```

### `classification.csv` Columns
- `rule_id` (str): Unique Sigma UUID or identifier.
- `rule_title` (str): Title of the Sigma rule.
- `rule_status` (str): `stable`, `test`, `experimental`, `deprecated`, or `unsupported`.
- `claimed_techniques` (str): Semicolon-delimited ATT&CK technique IDs (e.g. `T1003.006`).
- `evaluable_samples_count` (int): Number of evaluable samples matching this rule's technique.
- `classification_exact` (str): `validated`, `failing`, `not_evaluable`, or `unvalidated`.
- `classification_hierarchical` (str): `validated`, `failing`, `not_evaluable`, or `unvalidated`.
- `sample_matches` (str): Semicolon-delimited sample identifiers tested.
- `skip_reason` (str): Reason if skipped, unknown mapping, or missing telemetry.

## 3. Determinism Rules
- **Canonical Sorting**:
  - `results.jsonl`: Sorted lexicographically by `(rule_id, sample_id, engine)`.
  - `classification.csv`: Sorted lexicographically by `rule_id`.
- **Zero Timestamp Injection**: Hashed artifacts and output rows omit generation timestamps or randomized IDs.
- **Fixed Environments**: Explicit dependency versions locked in `uv.lock`.
