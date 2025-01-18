# Threat Model

## 1. System Context & Assets
RuleProof runs locally on developer/analyst machines. The assets requiring protection are:
- The local host environment and execution integrity.
- Correctness and validity of detection conclusions (avoiding false security assurances).
- Supply chain integrity of external inputs.

## 2. Threat Analysis & Mitigations

| Threat | Risk / Impact | Mitigation Strategy |
| :--- | :--- | :--- |
| **Malicious EVTX Payloads** | Untrusted log files could exploit memory bugs in Rust/C EVTX parsers or contain command injection strings. | EVTX files are never executed or parsed via shell commands. Subprocess invocations pass static argument vectors (`shell=False`). No shell interpolation is permitted. |
| **Supply Chain Tampering (Binaries)** | Compromised third-party engine binaries (`chainsaw`, `hayabusa`) executing arbitrary code on the local host. | Binaries are pinned by release tag and verified against SHA-256 digests in [manifest.toml](../manifest.toml). Note: Upstream projects do not publish official detached signatures; hashes are recorded on first-seen release assets and documented as such. |
| **Path Traversal Attacks** | Malicious paths in downloaded archives or metadata attempting to write outside `.cache/` or read host files. | All extraction and read operations validate paths using `Path.resolve()` to ensure target paths remain strictly inside the repository cache root. |
| **Arbitrary Code in Sigma Rules** | Malicious YAML constructs (e.g. `!!python/object/apply`) attempting code execution during rule parsing. | Only safe YAML loaders (`yaml.safe_load`) are used. Arbitrary object instantiation is disabled. |
| **False Conclusions (Evaluation Bias)** | Flawed classification falsely claiming a detection rule is defective or effective due to ambiguous labels or misapplied scopes. | Strict ground-truth policy: exclude unlabelled or ambiguous samples. Dual-column reporting for exact vs hierarchical ATT&CK matches. Reporting Wilson confidence intervals instead of naive point estimates. |
