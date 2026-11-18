# Learning Notes

Reference notes on the security and engineering concepts behind RuleProof. Written while building it.

---

## Phase 0: Foundations & Scaffolding

### Concept Primer: What is a Windows EVTX File?
Windows Event Log (EVTX) is a binary XML format introduced in Windows Vista. Unlike plaintext syslog, EVTX files store events as chunks containing binary XML templates and substitution arrays. This design allows rapid writing and structured indexing, but requires specialized parsers (like `libevtx`, Rust `evtx`, or engine parsers) to extract event fields (`EventID`, `Channel`, `CommandLine`, `Image`).

### Concept Primer: Sigma Rules Architecture
Sigma is a generic, open signature format for log events written in YAML. A Sigma rule defines:
1. `logsource`: Specifies the category, product, or service (e.g. `product: windows`, `service: sysmon`).
2. `detection`: Key-value selections, filters, and a boolean condition (e.g. `selection and not filter`).
3. `tags`: Taxonomic classifications, specifically MITRE ATT&CK techniques (`attack.t1059.001`).

### Q&A
- **Q: Why not just grep logs with regex?**
  - EVTX is binary XML, not flat text. Grep ignores XML structure, fails on encoded strings, matches noise in unrelated fields, and can't validate key-value relationships (like linking a specific EventID to a parent process).
- **Q: What's the difference between ATT&CK Tactic, Technique, and Procedure?**
  - Tactic = adversary goal (the "why", e.g. TA0002 Execution). Technique = general method (the "how", e.g. T1059 Command and Scripting Interpreter). Procedure = the exact implementation (e.g. `powershell.exe -enc <base64>`). Rules target procedures; datasets label techniques.
- **Q: Why `shell=False` when running engines against attack logs?**
  - Attack logs contain adversarial payloads (`; rm -rf /`, `| whoami`). If paths get shell-interpolated, those metacharacters execute on the analyst's machine. Argument lists via `subprocess.run` pass data to `execve` directly, never interpreted as code.

---

## Phase 1: Ingestion & Provenance

### Concept Primer: Ground-Truth Ambiguity in Security Datasets
In detection engineering, "ground truth" refers to knowing with certainty which malicious behavior occurred in a given log trace. Public datasets often contain background Windows OS noise (e.g. telemetry, service heartbeats) alongside the attack. If a log contains both LOLBAS execution and background service starts, asserting that an alert on that log validates the rule requires strict provenance linking the specific event to the technique.

### Q&A
- **Q: Why can't a parent technique label (T1059) validate a sub-technique rule (T1059.001)?**
  - T1059 covers PowerShell, VBScript, Python, etc. A rule detecting PowerShell (T1059.001) can't be validated by a sample that ran VBScript. Without sub-technique alignment, you get false coverage claims.
- **Q: Why SHA-256 everything before testing?**
  - Without cryptographic pinning, upstream repo changes or Google Sheet edits silently alter results. Hashing locks the baseline so anyone can reproduce the exact same evaluation.

---

## Phase 2: Engine Execution & Statistical Evaluation

### Concept Primer: Why Rules "Fail" to Fire
When a rule does not trigger on a sample claiming its technique, it does not necessarily mean the rule is broken. The sample may execute a different procedure of that technique, the required Windows auditing channel (e.g. Sysmon EventID 1 vs Security EventID 4688) may not have been turned on in the recording VM, or the engine's field mapping dictionary may not recognize the event's schema.

### Concept Primer: Wilson Score Interval vs Bare Percentages
Small sample sizes cause naive percentages ($\frac{k}{n}$) to swing wildly. A score of $1/2$ (50%) has vastly different statistical confidence than $50/100$ (50%). A 95% Wilson Score Interval calculates asymmetric confidence bounds appropriate for small sample sizes and extreme proportions near 0 or 1.

### Q&A
- **Q: How do you tell a defective rule apart from a variant mismatch?**
  - Look at what the EVTX trace actually contains vs what the rule's selection block expects. If the sample used an MSI installer but the rule looks for `verb:sync`, the rule is fine — it just targets a different procedure. If the sample ran the exact command and the rule still missed due to bad regex, that's a bug.
- **Q: Why report the denominator, not just a percentage?**
  - "100% detection" on 1 sample is meaningless. You need $k/n$ so people can judge statistical power. In RuleProof, the denominator is strictly evaluable rules (validated + failing) — you can't count rules that never had a chance to fire.

---

## Phase 3: Engine Disagreement & Normalization

### Concept Primer: Schema and Field Normalization
Sigma rules are generic, but Windows logs vary by provider. For example, process execution can appear in:
- Sysmon EventID 1: Field is `CommandLine` and `Image`.
- Windows Security EventID 4688: Field is `ProcessCommandLine` and `NewProcessName`.
Different engines (Chainsaw vs Hayabusa) use internal mapping configuration tables to translate Sigma fields to target EVTX paths. If an engine's mapping is incomplete, a valid rule will fail to fire on an otherwise matching log.

### Q&A
- **Q: Engine A fires, Engine B doesn't, same rule. What do you check?**
  1. **Field mapping** — How each engine translates abstract Sigma fields (`Image`, `CommandLine`) to the EVTX XML schema.
  2. **Operator semantics** — Regex flavors, case sensitivity, wildcard behaviour differ between engines.
  3. **Channel filtering** — Did Engine B skip the log channel entirely (e.g. Sysmon vs Security)?
- **Q: Why test on benign logs before shipping a rule?**
  - A rule that fires 100% on attack samples but also triggers on normal admin activity (service restarts, deployments) is useless in production. You need false-positive rates from clean baselines.
