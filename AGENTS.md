# RuleProof Agent Instructions

## Mission & Role
RuleProof tests whether community Sigma rules fire on public, ATT&CK-labelled Windows attack logs ("claimed vs observed" coverage).
The owner is a B.Tech student preparing for technical interviews: keep code simple, readable, and comment the security reasoning (why), not syntax (what).

## Non-Negotiable Rules
1. Never invent facts, numbers, schemas, or CLI flags. Verify via `--help`, official docs, or actual runs. Mark unverified items "UNVERIFIED". Results in docs remain "TBD (measured in Phase N)" until measured.
2. Create ONLY files in the exact repository structure. Ask before adding others. No boilerplate or duplicate content.
3. Defensive, local, authorized use only. Public datasets only. No exploit code.
4. Treat logs as untrusted: never eval, execute, or shell-interpolate. `subprocess` with argument lists only (`shell=False`).
5. Core pipeline is offline: no LLMs, zero network at runtime except pinned `fetch`.
6. Never label a rule "broken" unless an authoritative labelled sample exists for a claimed technique and the rule did not fire. Missing sample = "unvalidated".
7. Pin all sources by commit/tag and SHA-256 in `manifest.toml`. Record licenses in `docs/decisions.md`.

## Workflow & Gates
- Phased implementation: Plan -> Approval -> Code -> Lint/Type/Test -> Walkthrough artifact (VERIFIED vs UNVERIFIED) -> STOP.
- Do not advance phases until user writes `approved: Phase N`.
- Use `/phase-gate` (.agents/workflows/phase-gate.md) before concluding any phase.

## Token Discipline
- AGENTS.md must remain <= 60 lines.
- Read only AGENTS.md, current phase in `docs/phases.md`, and targeted edit files.
- Never paste large outputs; redirect to gitignored `data/outputs/` and show summaries.
- Fetch datasets with sparse/file checkouts. Never clone full Splunk attack_data repo.
- Batch edits; run one test pass per change set.

## Environment & Tooling
- macOS on Apple Silicon (darwin-arm64, M-series).
- Python 3.12 managed via `uv`. Tools: `ruff`, `mypy`, `pytest`, `pydantic` v2, `typer`, `PyYAML`.
- Engines: Chainsaw (primary), Hayabusa (Phase 3). Pinned checksummed binaries only.
