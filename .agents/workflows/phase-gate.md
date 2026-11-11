# Phase Gate Workflow (/phase-gate)

Execute this workflow before declaring any phase complete. Do not proceed to the next phase until the user explicitly responds with `approved: Phase N`.

## Checklist Steps

1. **Safety & Code Cleanliness**:
   - Run `uv run ruff check .`
   - Run `uv run ruff format --check .`
   - Run `uv run mypy src tests` (when Python code exists)

2. **Automated Testing**:
   - Run `uv run pytest` on fixture test suites.
   - Verify 100% test pass rate with zero warnings.

3. **Determinism & Integrity**:
   - Check that all outputs (`results.jsonl`, `classification.csv`) are deterministically sorted.
   - Verify no timestamps or machine-dependent paths are embedded in hashed artifacts.
   - Verify external files and binaries match `manifest.toml` checksums.

4. **Documentation & Fact Verification**:
   - Ensure all results remain `TBD (measured in Phase N)` unless directly computed from tests in this phase.
   - Ensure `docs/decisions.md` records all architectural choices and license findings.
   - Verify `AGENTS.md` remains 60 lines or fewer (`wc -l AGENTS.md`).

5. **Phase Gate Artifact Generation**:
   - Create a Walkthrough artifact in the artifact directory detailing:
     - Implemented items.
     - Formally VERIFIED claims (with reproduction commands / outputs).
     - UNVERIFIED claims or open decisions.
   - State: "Phase N implementation complete. Awaiting your approval: `approved: Phase N`."
   - STOP calling tools.
