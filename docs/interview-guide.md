# Interview Study Guide

Notes for talking about RuleProof in interviews. Numbers come from actual measured runs — see `outputs/report.md` for full data.

---

## 1. The Short Version
RuleProof measures the gap between what Sigma detection rules *claim* to detect (via ATT&CK technique tags) and what they *actually* detect when run against public Windows attack logs.

On 138 attack samples and 2,246 rules, only 5% of samples triggered a rule matching their labelled technique. After mapping legacy ATT&CK IDs to v20 sub-techniques, that jumps to ~28%. The takeaway: technique-level tags are way too coarse for validating specific detection rules.

Three things drive the gap:
1. **Taxonomy drift** — Samples use old ATT&CK IDs, rules use new sub-techniques. The crosswalk fix alone quadruples validated rules (9→41).
2. **Granularity gap** — `T1218` covers a dozen different binaries. A rule for `pcalua.exe` won't fire on a `stordiag.exe` sample, even though both are T1218.
3. **Multi-technique execution** — Attack tools don't do just one thing. 75% of samples fired *some* rule, just for a different technique than their label.

---

## 2. How the pipeline works

Entirely offline, no network during evaluation:

1. **Index samples** (`samples.py`) — Parse the ground-truth CSV mapping EVTX files to ATT&CK technique IDs.
2. **Load rules** (`rules.py`) — Read SigmaHQ YAML, pull out ATT&CK tags, status, logsource. Default scope: `stable` + `test` (2,246 rules).
3. **Profile telemetry** — Run `chainsaw analyse` on each EVTX to find which Event IDs are in there.
4. **Hunt** (`runner.py` → `chainsaw.py`) — Run the pinned Chainsaw binary against each sample. All subprocess calls: `shell=False`, explicit arg lists.
5. **Classify** (`classify.py`) — For each (rule, sample) pair that shares a technique: check if Event IDs match → if so, did it fire? Four outcomes: `validated`, `failing`, `not_evaluable`, `unvalidated`.
6. **Report** (`report.py`) — Wilson intervals, recall, label-vs-tag agreement, per-technique tables. Deterministic CSV/JSONL/Markdown outputs.

---

## 3. Numbers at a glance

| Metric | Measured Value | Mathematical Definition / Formula |
| :--- | :--- | :--- |
| **Total Rules Evaluated** | 2,246 | Rules loaded with `status in [stable, test]`. |
| **Total Labelled Samples** | 138 | Author-labelled attack EVTX captures from `sbousseaden/EVTX-ATTACK-SAMPLES`. |
| **Validated Rules (As-Published Exact)** | 9 | Rules that fired on $\ge 1$ evaluable sample claiming their exact technique. |
| **Validated Rules (Crosswalk Exact)** | 41 | Rules validated under ATT&CK STIX v20.0 sub-technique crosswalk. |
| **Failing Rules (As-Published Exact)** | 268 | Rules that did not fire on any evaluable sample claiming their technique. |
| **Not Evaluable Rules (Exact)** | 103 | Rules claiming a sample's technique where the sample lacked Event IDs (87 missing telemetry, 10 unknown mapping, 6 engine-excluded/skipped). |
| **Unvalidated Rules** | 1,866 | Rules claiming techniques for which no sample exists in the benchmark (includes 29 engine-skipped rules per precedence rule). |
| **H1 Evaluated Rules ($n$)** | 277 | $n = N_{\text{validated}} + N_{\text{failing}} = 9 + 268$. |
| **H1 Non-Firing Rate ($\hat{p}$)** | 96.75% | $\hat{p} = \frac{k}{n} = \frac{268}{277}$. 95% Wilson: **[93.94%, 98.28%]**. Pre-registered threshold: 15%. |
| **Sample-Side Recall (Exact, Published)** | 5.07% | Samples where $\ge 1$ rule claiming the sample's technique fired: $7 / 138$. 95% Wilson: **[2.48%, 10.10%]**. |
| **Sample-Side Recall (Exact, Crosswalk)** | 27.54% | Samples where $\ge 1$ rule claiming the crosswalk technique fired: $38 / 138$. 95% Wilson: **[20.77%, 35.52%]**. |
| **Any-Rule Fired Rate** | 74.64% | Samples firing *any* in-scope rule regardless of technique: $103 / 138$. |
| **Family-Level Validated** | 25 (Published) / 58 (Crosswalk) | Rules validated when technique matching relaxes to shared parent ID. |
| **Family-Level Sample Recall** | 15.94% (Published) / 39.86% (Crosswalk) | Samples where $\ge 1$ rule sharing technique parent fired ($22 / 138$ vs $55 / 138$). |
| **Label-vs-Tag Fired Pairs** | 250 | Total (rule, sample) firing events across all in-scope rules. |
| **Different Technique Fires** | 211 (Published) / 147 (Crosswalk) | Fired pairs where rule technique differs from sample label. |
| **Samples with Fire but No Related Fire**| 81 (Published) / 48 (Crosswalk) | Samples where rules fired, but none matched the sample's technique family. |

---

## 4. Interview Q&A

### Q1: Why did you build this?
Management sees 50 Sigma rules tagged `T1059` and thinks command execution is covered. I wanted to check if that's actually true when you run those rules against real attack logs.

### Q2: Main finding?
Only 5% of samples (7/138) triggered a rule claiming their exact technique. 97% of evaluable rules didn't fire on matching samples.

### Q3: So Sigma rules are bad?
No. T1218 alone covers a dozen different binaries. A rule for `stordiag.exe` obviously won't fire on a `pcalua.exe` sample. Same technique, different procedure. The failing cases need hand review before calling anything defective.

### Q4: How do you know the pipeline works at all?
Positive controls. I picked 3 samples where the attack procedure directly matched a known rule:
1. Netsh port forwarding sample → Rule `322ed9ec` → **fired**
2. Msxsl execution sample → Rule `9e50a8b3` → **fired**
3. Pcalua execution sample → Rule `0955e4e1` → **fired**

### Q5: What is pair-level evaluability?
Early on I was marking rules as "failing" when they didn't fire. But if a rule needs Sysmon Event ID 11 and the log only has Security 4624, it *couldn't* have fired. Now I check each (rule, sample) pair: does this sample even have the Event IDs the rule needs? If not → `not_evaluable`, not `failing`.

### Q6: Bugs you caught during development?
The first version checked evaluability per-sample, not per-pair. Rule `259a9cdf` (RDP Logon, needs Event ID 4624) got marked "failing" on a sample that only had Event ID 4732. Fixed by intersecting rule-expected Event IDs with sample-observed Event IDs at the pair level.

### Q7: What's the "granularity gap"?
ATT&CK techniques are broad — T1218 has 10+ sub-techniques. Each Sigma rule targets a narrow procedure (specific binary, specific command-line flags). The technique tag matches, but the procedure doesn't. That's the gap.

### Q8: Family-level sensitivity?
When I relaxed matching to "shares the same parent technique" (e.g., any T1218.xxx rule matches any T1218 sample), validated rules went 9→25 and recall tripled from 5% to 16%.

### Q9: Why did 103/138 samples fire rules but only 7 fired their *own* technique's rules?
Multi-technique execution. A UAC bypass sample also spawns shells, queries privileges, touches services. Rules fire — just for different techniques than the sample's label. 84% of fired pairs were cross-technique.

### Q10: Why Wilson intervals instead of normal approximation?
Normal approximation breaks near p≈0 or p≈1 and can give intervals outside [0,1]. Wilson score interval handles extreme proportions and small samples correctly.

### Q11: Security of the pipeline?
Attack logs contain adversarial payloads. So: `yaml.safe_load` only, `shell=False` everywhere, no `eval`, no network during evaluation, all binaries SHA-256 verified before execution.

### Q12: Why is Hayabusa marked UNVERIFIED?
Only 1 rule ID shared between Hayabusa and SigmaHQ out of 5,019 rules. Can't do rule-for-rule comparison. Also, the binary release has no license file. So I kept it as a secondary check and flagged it.

### Q13: Per-technique breakdown?
Legacy techniques (T1088, T1089) have 0 claiming rules — they were deprecated in ATT&CK v7. The crosswalk fixes this. High-volume ones like T1003 have 22 rules but 0/12 exact recall (5/12 at family level). Clean matches like T1220 (XSL Script Processing) got 2/2.

### Q14: Reproducibility?
Everything pinned in `manifest.toml`: rule commit, sample commit, engine version, all with SHA-256 hashes. `ruleproof run` produces deterministic outputs — same input, same checksums.

### Q15: Takeaways for enterprise detection teams?
1. Don't trust flat ATT&CK heatmaps as detection posture.
2. Tag rules with sub-technique + procedure + target binary.
3. Test against atomic procedural telemetry, not broad technique buckets.
4. Separate "do we have the right logs?" from "does the rule work?"

---

## 5. Known weaknesses
1. **Ground truth depends on one guy's labels** — Samir Bousseaden's mapping sheet. If his technique assignments are wrong, our baseline is wrong.
2. **Event ID ≠ full telemetry** — Having the right Event ID doesn't mean the required fields (CommandLine, Image, etc.) were actually populated during recording.
3. **No benign baseline** — We only tested on attack samples. No false-positive measurement.
4. **Possible circularity** — Some community rules may have been written against these exact public samples.

---

## 6. Glossary

- **EVTX** — Windows binary event log format.
- **Sigma** — Open YAML-based detection signature standard, SIEM-agnostic.
- **Logsource** — The Sigma field specifying target telemetry (`product: windows`, `service: sysmon`, `category: process_creation`).
- **Technique vs Sub-technique** — T1059 is a technique (broad). T1059.001 is a sub-technique (PowerShell specifically).
- **Technique Family** — Sub-techniques sharing a parent. T1218.011 and T1218.005 are both in the T1218 family.
- **Wilson Score Interval** — Confidence interval for proportions that works properly near 0% and 100%.
- **Evaluable Pair** — A (rule, sample) combo where the sample has the Event IDs the rule needs.
- **Positive Control** — A sample+rule pair you know should match, used to verify the pipeline works.
- **Variant Mismatch** — Sample does technique X via procedure A, rule detects technique X via procedure B. Technique matches, procedure doesn't.
