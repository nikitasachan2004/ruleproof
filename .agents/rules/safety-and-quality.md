# Safety and Quality Rules

## 1. Security Boundaries & Untrusted Data
- **Process Execution**: All external commands (e.g. `chainsaw`, `hayabusa`, `git`) must use `subprocess.run` with list arguments (`shell=False`). Never interpolate shell strings or execute log content.
- **Path Traversal Protection**: Validate all file paths from logs or manifests with `Path.resolve()`. Ensure target paths stay within allowed repository or cache boundaries (`workspace_root` or `.cache`).
- **Binary Integrity**: Every fetched binary or archive must be verified against its SHA-256 hash defined in `manifest.toml` before extraction or execution.
- **Quarantine Handling**: On macOS, clear `com.apple.quarantine` attributes using `xattr -d` only after SHA-256 verification passes, only if the attribute exists, and log the action.

## 2. Code Quality & Typing
- **Type Annotations**: Complete type hints on all function signatures and data models. Clean `mypy --strict` pass.
- **Data Validation**: Use Pydantic v2 models for all structured manifests, rule representations, engine outputs, and summary contracts.
- **Formatting & Linting**: Clean `ruff check .` and `ruff format --check .` passes. No dead imports or unused variables.
- **Minimal Code**: Avoid speculative abstractions, unnecessary design patterns, or bloated helper libraries. Keep functions modular and purpose-built.

## 3. Explaining Detection Engineering Concepts
- Comments must convey the detection/security rationale ("why" this log source, field, or technique matters), leaving mechanics to self-evident Python syntax.
