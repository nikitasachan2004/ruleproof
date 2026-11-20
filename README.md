# RuleProof

A reproducible test harness that checks whether community [Sigma](https://github.com/SigmaHQ/sigma) detection rules actually fire on public, [MITRE ATT&CK](https://attack.mitre.org/)-labelled Windows attack logs (EVTX). It compares what rules *claim* to detect against what they *actually* detect.

## Why this exists

Security teams build ATT&CK heatmaps showing "coverage" based on Sigma rule tags. But a rule tagged `T1218` (Signed Binary Proxy Execution) only detects a *specific* binary — if the attack used a different one, the rule won't fire even though the technique matches. RuleProof measures this gap.

```
EVTX Sample ──→ Chainsaw analyse ──→ Has required Event IDs?
                                         │
                                    No ──→ not_evaluable
                                    Yes ─→ Chainsaw hunt
                                              │
                                         Fired ──→ validated
                                         No hit ─→ failing (variant mismatch)
```

## Key results

Tested **2,246 SigmaHQ rules** (`stable` + `test`) against **138 labelled attack logs** from [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES):

| Metric | As-Published Labels | ATT&CK v20 Crosswalk |
|:---|:---|:---|
| Validated rules | 9 | 41 |
| Failing rules | 268 | 573 |
| Sample recall (exact) | 5.07% (7/138) | 27.54% (38/138) |
| Non-firing rate | 96.75% | 93.32% |

**Three things explain the gap:**

1. **Taxonomy drift** — The attack logs use pre-v7 ATT&CK IDs. Mapping them to v20 via STIX crosswalk quadruples validated rules (9→41).
2. **Granularity gap** — ATT&CK techniques are broad; Sigma rules match specific procedures. Relaxing to technique families bumps recall to ~40%.
3. **Multi-technique execution** — Attack samples trigger rules for *other* techniques. 75% of samples fired *some* rule, just not one matching their labelled technique.

> **This does NOT mean Sigma rules are broken.** It means technique-level tags are too coarse to validate procedure-specific detections. Hand review of individual cases is pending.

## Setup

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone <repo-url> && cd ruleproof
uv sync
```

## Usage

```bash
# 1. Download pinned rules, samples, and engine binary
uv run ruleproof fetch

# 2. Check what got loaded
uv run ruleproof inspect

# 3. Run the full evaluation
uv run ruleproof run
```

Outputs land in `outputs/`:
- `classification.csv` — per-rule 4-class verdict (validated / failing / not_evaluable / unvalidated)
- `results.jsonl` — every (rule, sample) pair result
- `report.md` — full evaluation report with Wilson confidence intervals
- `per_technique.csv` — technique-level breakdown
- `review_template.csv` — blank template for manual case review

## How it works

1. **Fetch** — Downloads SigmaHQ rules, EVTX attack samples, and Chainsaw binary. Everything is pinned by commit/tag and verified with SHA-256 checksums (`manifest.toml`).
2. **Index** — Parses Sigma rule YAML (via `yaml.safe_load`, never unsafe) extracting ATT&CK tags. Maps samples to ground-truth technique labels from the author's spreadsheet.
3. **Profile** — Runs `chainsaw analyse` on each sample to extract which Event IDs are actually present.
4. **Hunt** — Runs `chainsaw hunt` on each sample against the full rule set. All subprocess calls use `shell=False` with explicit arg lists.
5. **Classify** — For each (rule, sample) pair sharing a technique:
   - If the sample lacks the Event IDs the rule needs → `not_evaluable`
   - If Event IDs are present and the rule fires → `validated`
   - If Event IDs are present but the rule doesn't fire → `failing`
   - If no sample exists for the rule's technique → `unvalidated`
6. **Report** — Computes Wilson score confidence intervals, sample-side recall, family-level sensitivity, label-vs-tag agreement, and writes deterministic artifacts.

## Project structure

```
src/ruleproof/
├── cli.py           # Typer CLI (fetch, inspect, run, build-crosswalk)
├── config.py        # Path resolution and manifest loading
├── models.py        # Pydantic v2 schemas
├── fetch.py         # Download + SHA-256 verify + quarantine handling
├── rules.py         # Sigma YAML parser (safe_load only)
├── samples.py       # EVTX sample indexer + ground-truth mapping
├── runner.py        # Engine execution loop
├── classify.py      # 4-class classification + all metrics
├── report.py        # Markdown/CSV/JSONL output writers
└── engines/
    ├── base.py      # Abstract engine interface
    ├── chainsaw.py  # Chainsaw adapter (primary)
    └── hayabusa.py  # Hayabusa adapter (unverified, see ADR-007)

tests/               # 32 unit tests on fixtures
labels/               # Committed ground-truth mappings
docs/                 # Architecture, decisions, evaluation methodology
```

## Development

```bash
make check          # lint + format-check + typecheck + test
make test           # just pytest
make lint           # ruff check
make typecheck      # mypy strict
make format         # auto-format
make reproduce      # fetch + run + checksum outputs
```

## Pinned dependencies

All external inputs are locked in [`manifest.toml`](manifest.toml):

| Component | Version/Commit | License |
|:---|:---|:---|
| SigmaHQ rules | `26a2c381` | DRL 1.1 / CC BY-SA 4.0 |
| EVTX-ATTACK-SAMPLES | `4ceed2f4` | GPL-3.0 |
| Chainsaw | v2.17.1 (darwin-arm64) | GPL-3.0 |
| ATT&CK STIX data | v20.0 | Apache-2.0 |

## Limitations

- Only tests against one public EVTX dataset — doesn't represent all attack variants
- Event ID presence ≠ required fields being populated
- No false-positive measurement (no benign baseline logs)
- Some rules may have been written against these exact samples (circularity)
- Hayabusa cross-check is unverified (only 1 shared rule ID with SigmaHQ)

## License

GPL-3.0 — see [LICENSE](LICENSE).
