# RuleProof Evaluation Report

## 1. Executive Summary
- **Evaluation Scope**: Default (stable + test only)
- **Detection Engine**: chainsaw (v2.17.1)
- **Engine Unloaded / Skipped Rules**: 35
- **Total Rules Evaluated**: 2246
- **Published Label Validated Rules (Exact)**: 9
- **Crosswalk Label Validated Rules (Exact)**: 41

## 2. Four-Class Rule Coverage Breakdown

| Evaluation Class | As-Published (Exact) | Crosswalk (Exact) | As-Published (Hierarchical) | Crosswalk (Hierarchical) |
| :--- | :--- | :--- | :--- | :--- |
| **Validated (Fired)** | 9 | 41 | 9 | 43 |
| **Failing (Did Not Fire)** | 268 | 573 | 270 | 590 |
| **Not Evaluable (Missing Telemetry / Unknown Mapping / Skipped)** | 103 | 296 | 101 | 303 |
| **Unvalidated (No Matching Sample)** | 1866 | 1336 | 1866 | 1310 |
| *Total Rules* | *2246* | *2246* | *2246* | *2246* |

## 3. Pair-Level Statistics

| Pair Metric | As-Published (Exact) | Crosswalk (Exact) | As-Published (Hier) | Crosswalk (Hier) |
| :--- | :--- | :--- | :--- | :--- |
| Total Candidate (Rule, Sample) Pairs | 1513 | 4885 | 1520 | 6380 |
| Evaluable Candidate Pairs | 778 | 2618 | 781 | 3749 |
| Not Evaluable (Missing Telemetry) | 624 | 1900 | 628 | 2214 |
| Not Evaluable (Unknown Mapping) | 111 | 367 | 111 | 417 |
| Fired Candidate Pairs | 9 | 65 | 9 | 68 |

## 4. Sample-Side Detection Recall
Sample-side recall measures whether at least one community rule claiming the sample's
technique fired on the attack log sample.

| Matching Policy | As-Published Recall | 95% Wilson Interval | Crosswalk Recall | 95% Wilson Interval |
| :--- | :--- | :--- | :--- | :--- |
| **Exact Match** | 7/138 (5.07%) | [2.48%, 10.10%] | 38/138 (27.54%) | [20.77%, 35.52%] |
| **Hierarchical Match** | 7/138 (5.07%) | [2.48%, 10.10%] | 38/138 (27.54%) | [20.77%, 35.52%] |
| **Family Match** | 22/138 (15.94%) | [10.77%, 22.96%] | 55/138 (39.86%) | [32.07%, 48.19%] |

### Validated Rules and Triggering Samples (Exact Match, As-Published)
- **Rule `20f0ee37-5942-4e45-b7d5-c5b5db9df5cd`** fired on 1 sample(s):
  - `evasion_persis_hidden_run_keyvalue_sysmon_13.evtx`
- **Rule `218d2855-2bba-4f61-9c85-81d0ea63ac71`** fired on 1 sample(s):
  - `MSSQL_multiple_failed_logon_EventID_18456.evtx`
- **Rule `322ed9ec-fcab-4f67-9a34-e7c6aef43614`** fired on 1 sample(s):
  - `de_portforward_netsh_rdp_sysmon_13_1.evtx`
- **Rule `53ad8e36-f573-46bf-97e4-15ba5bf4bb51`** fired on 1 sample(s):
  - `4794_DSRM_password_change_t1098.evtx`
- **Rule `782d6f3e-4c5d-4b8c-92a3-1d05fed72e63`** fired on 1 sample(s):
  - `de_portforward_netsh_rdp_sysmon_13_1.evtx`
- **Rule `8d63dadf-b91b-4187-87b6-34a1114577ea`** fired on 1 sample(s):
  - `exec_wmic_xsl_internet_sysmon_3_1_11.evtx`
- **Rule `9e50a8b3-dd05-4eb8-9153-bdb6b79d50b0`** fired on 1 sample(s):
  - `exec_msxsl_xsl_sysmon_1_7.evtx`
- **Rule `a54f842a-3713-4b45-8c84-5f136fdebd3c`** fired on 1 sample(s):
  - `de_portforward_netsh_rdp_sysmon_13_1.evtx`
- **Rule `c265cf08-3f99-46c1-8d59-328247057d57`** fired on 1 sample(s):
  - `Network_Service_Guest_added_to_admins_4732.evtx`

### Leave-One-Technique-Out Recall (Crosswalk View)

Concentration sensitivity testing excluding top ATT&CK techniques by sample count:

| Scenario | Excluded Techniques | Detected Samples | Total Samples | Sample-Side Recall | 95% Wilson CI |
| :--- | :--- | ---: | ---: | ---: | :--- |
| **All samples** | None | 38 | 138 | 27.54% | [20.77%, 35.52%] |
| **Excl. T1548.002** | T1548.002 | 20 | 111 | 18.02% | [11.98%, 26.20%] |
| **Excl. T1003** | T1003 | 38 | 126 | 30.16% | [22.83%, 38.66%] |
| **Excl. T1134** | T1134 | 38 | 128 | 29.69% | [22.46%, 38.10%] |
| **Excl. all top 3** | T1548.002, T1003, T1134 | 20 | 89 | 22.47% | [15.04%, 32.18%] |

## 5. Hypothesis H1 Evaluation (Non-Firing Rate)
> **H1 Formula**: $\hat{p} = \frac{N_{failing}}{N_{validated} + N_{failing}}$

| Perspective | Evaluable Denominator ($n$) | Failing Rules ($k$) | Non-Firing Rate ($\hat{p}$) | 95% Wilson Interval | Verdict |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **As-Published (Exact)** | 277 | 268 | 96.75% | [93.94%, 98.28%] | **Supported (Lower bound exceeds 15% threshold)** |
| **Crosswalk (Exact)** | 614 | 573 | 93.32% | [91.07%, 95.04%] | **Supported (Lower bound exceeds 15% threshold)** |
| **As-Published (Hierarchical)** | 279 | 270 | 96.77% | [93.98%, 98.29%] | **Supported (Lower bound exceeds 15% threshold)** |
| **Crosswalk (Hierarchical)** | 633 | 590 | 93.21% | [90.97%, 94.92%] | **Supported (Lower bound exceeds 15% threshold)** |

- **Crosswalk One-to-Many Sensitivity**: Resolving one-to-many crosswalk mappings to the FIRST target only yields: Validated: 41 | Failing: 564 | Evaluable ($n$): 605 | Non-Firing Rate: 93.22% (95% Wilson: [90.96%, 94.96%]) | Sample Recall: 38/138 (27.54%). Primary results evaluate all mapped targets disjunctively.

### Empirical Observations on Non-Firing
The benchmark measures the following empirical patterns across the evaluation data:
1. **Taxonomy Mapping**: Mapping legacy ATT&CK technique IDs to v20.0 yields 41 validated rules (up from 9) and 38/138 (27.54%) exact sample recall (up from 5.07%).
2. **Technique Granularity**: Relaxing matching to technique family (shared parent ID) yields 55/138 (39.86%) sample recall.
3. **Cross-Technique Detections**: Across 250 fired pairs, 147 fired rules claimed a different technique than the author's primary sample label. Hand review is pending; no claim is made that the rules are defective.

## 6. Label-vs-Tag Agreement on Fired Pairs
Relation between rule tags and sample labels across all 250 fired candidate pairs:

- **Total Fired (Rule, Sample) Pairs**: 250
- **Samples with at Least One Fired Rule**: 103/138 (74.64%)

| Relationship Category | As-Published Fired Pairs | Crosswalk Fired Pairs |
| :--- | :--- | :--- |
| **Exact Match** | 9 | 65 |
| **Hierarchical Match** | 0 | 3 |
| **Family Match** | 20 | 25 |
| **Different Technique** | 211 | 147 |
| **Untagged Rule** | 10 | 10 |
| **Samples with Fire but No Related Tag** | 81 | 48 |

### Top 10 (Sample Label, Fired Rule Tag) Pairs for Different Technique (CW)

| Sample Label | Fired Rule Tag | Pair Frequency |
| :--- | :--- | :--- |
| `T1021` | `T1033` | 6 |
| `T1548.002` | `T1059` | 5 |
| `T1548.002` | `T1574.001` | 5 |
| `T1134` | `T1055` | 4 |
| `T1021` | `T1047` | 4 |
| `T1134` | `T1059` | 4 |
| `T1134` | `T1033` | 4 |
| `T1070.006` | `T1547.001` | 3 |
| `T1053` | `T1033` | 3 |
| `T1559` | `T1033` | 3 |

## 7. Family-Level Sensitivity Analysis
> *Sensitivity analysis only; not the primary benchmark classification.*

- **As-Published Family Validated Rules**: 25
- **As-Published Family Failing Rules**: 591
- **As-Published Family Not Evaluable Rules**: 335
- **As-Published Family Unvalidated Rules**: 1295
- **As-Published Family H1 Non-Firing Rate**: 95.94% (591/616, 95% Wilson: [94.08%, 97.24%])
- **As-Published Family Sample-Side Recall**: 15.94% (22/138, 95% Wilson: [10.77%, 22.96%])
- **Crosswalk Family Validated Rules**: 64
- **Crosswalk Family Failing Rules**: 817
- **Crosswalk Family H1 Non-Firing Rate**: 92.74% (817/881, 95% Wilson: [90.83%, 94.27%])
- **Crosswalk Family Sample-Side Recall**: 39.86% (55/138, 95% Wilson: [32.07%, 48.19%])

## 8. Per-Technique Coverage and Recall

| Technique | Pub Samples | Pub Rules | Pub Val | Pub Fail | Pub Recall (Exact) | CW Samples | CW Rules | CW Val | CW Fail | CW Recall (Exact) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `T1003` | 12 | 22 | 0 | 15 | 0/12 | 12 | 22 | 0 | 15 | 0/12 |
| `T1014` | 1 | 0 | 0 | 0 | 0/1 | 1 | 0 | 0 | 0 | 0/1 |
| `T1015` | 1 | 0 | 0 | 0 | 0/1 | 0 | 0 | 0 | 0 | 0/0 |
| `T1021` | 4 | 3 | 0 | 3 | 0/4 | 8 | 3 | 0 | 3 | 0/8 |
| `T1021.001` | 0 | 0 | 0 | 0 | 0/0 | 4 | 12 | 0 | 8 | 0/4 |
| `T1021.002` | 0 | 0 | 0 | 0 | 0/0 | 2 | 31 | 0 | 10 | 0/2 |
| `T1021.006` | 0 | 0 | 0 | 0 | 0/0 | 2 | 8 | 1 | 1 | 1/2 |
| `T1028` | 2 | 0 | 0 | 0 | 0/2 | 0 | 0 | 0 | 0 | 0/0 |
| `T1037` | 1 | 0 | 0 | 0 | 0/1 | 1 | 0 | 0 | 0 | 0/1 |
| `T1037.001` | 1 | 3 | 0 | 1 | 0/1 | 1 | 3 | 0 | 1 | 0/1 |
| `T1047` | 1 | 39 | 0 | 30 | 0/1 | 1 | 39 | 0 | 30 | 0/1 |
| `T1051` | 1 | 0 | 0 | 0 | 0/1 | 1 | 0 | 0 | 0 | 0/1 |
| `T1053` | 1 | 5 | 0 | 4 | 0/1 | 5 | 5 | 0 | 4 | 0/5 |
| `T1055` | 7 | 24 | 0 | 14 | 0/7 | 7 | 24 | 0 | 14 | 0/7 |
| `T1059` | 1 | 53 | 0 | 44 | 0/1 | 2 | 53 | 0 | 46 | 0/2 |
| `T1059.001` | 0 | 0 | 0 | 0 | 0/0 | 2 | 176 | 0 | 80 | 0/2 |
| `T1060` | 1 | 0 | 0 | 0 | 0/1 | 0 | 0 | 0 | 0 | 0/0 |
| `T1064` | 1 | 0 | 0 | 0 | 0/1 | 0 | 0 | 0 | 0 | 0/0 |
| `T1068` | 4 | 9 | 0 | 5 | 0/4 | 4 | 9 | 0 | 5 | 0/4 |
| `T1070.006` | 0 | 0 | 0 | 0 | 0/0 | 2 | 2 | 0 | 0 | 0/2 |
| `T1073` | 1 | 0 | 0 | 0 | 0/1 | 0 | 0 | 0 | 0 | 0/0 |
| `T1076` | 4 | 0 | 0 | 0 | 0/4 | 0 | 0 | 0 | 0 | 0/0 |
| `T1077` | 2 | 0 | 0 | 0 | 0/2 | 0 | 0 | 0 | 0 | 0/0 |
| `T1078` | 3 | 9 | 1 | 0 | 1/3 | 3 | 9 | 1 | 0 | 1/3 |
| `T1081` | 2 | 0 | 0 | 0 | 0/2 | 0 | 0 | 0 | 0 | 0/0 |
| `T1084` | 2 | 0 | 0 | 0 | 0/2 | 0 | 0 | 0 | 0 | 0/0 |
| `T1085` | 5 | 0 | 0 | 0 | 0/5 | 0 | 0 | 0 | 0 | 0/0 |
| `T1086` | 1 | 0 | 0 | 0 | 0/1 | 0 | 0 | 0 | 0 | 0/0 |
| `T1087` | 1 | 14 | 0 | 0 | 0/1 | 1 | 14 | 0 | 0 | 0/1 |
| `T1088` | 27 | 0 | 0 | 0 | 0/27 | 0 | 0 | 0 | 0 | 0/0 |
| `T1089` | 9 | 0 | 0 | 0 | 0/9 | 0 | 0 | 0 | 0 | 0/0 |
| `T1090` | 2 | 14 | 3 | 9 | 1/2 | 2 | 14 | 3 | 9 | 1/2 |
| `T1098` | 1 | 12 | 1 | 0 | 1/1 | 1 | 12 | 1 | 0 | 1/1 |
| `T1099` | 2 | 0 | 0 | 0 | 0/2 | 0 | 0 | 0 | 0 | 0/0 |
| `T1110` | 2 | 7 | 1 | 1 | 1/2 | 2 | 7 | 1 | 1 | 1/2 |
| `T1117` | 2 | 0 | 0 | 0 | 0/2 | 0 | 0 | 0 | 0 | 0/0 |
| `T1122` | 2 | 0 | 0 | 0 | 0/2 | 0 | 0 | 0 | 0 | 0/0 |
| `T1134` | 10 | 2 | 0 | 1 | 0/10 | 10 | 2 | 0 | 1 | 0/10 |
| `T1138` | 1 | 0 | 0 | 0 | 0/1 | 0 | 0 | 0 | 0 | 0/0 |
| `T1175` | 4 | 0 | 0 | 0 | 0/4 | 0 | 0 | 0 | 0 | 0/0 |
| `T1183` | 1 | 0 | 0 | 0 | 0/1 | 0 | 0 | 0 | 0 | 0/0 |
| `T1189` | 1 | 0 | 0 | 0 | 0/1 | 1 | 0 | 0 | 0 | 0/1 |
| `T1196` | 1 | 0 | 0 | 0 | 0/1 | 0 | 0 | 0 | 0 | 0/0 |
| `T1197` | 2 | 13 | 0 | 8 | 0/2 | 2 | 13 | 0 | 8 | 0/2 |
| `T1203` | 0 | 0 | 0 | 0 | 0/0 | 1 | 8 | 0 | 6 | 0/1 |
| `T1218` | 6 | 124 | 0 | 115 | 0/6 | 6 | 124 | 0 | 115 | 0/6 |
| `T1218.001` | 0 | 0 | 0 | 0 | 0/0 | 1 | 5 | 2 | 3 | 1/1 |
| `T1218.002` | 0 | 0 | 0 | 0 | 0/0 | 1 | 1 | 0 | 1 | 0/1 |
| `T1218.010` | 0 | 0 | 0 | 0 | 0/0 | 2 | 17 | 3 | 12 | 1/2 |
| `T1218.011` | 0 | 0 | 0 | 0 | 0/0 | 5 | 27 | 2 | 20 | 5/5 |
| `T1220` | 2 | 5 | 2 | 3 | 2/2 | 2 | 5 | 2 | 3 | 2/2 |
| `T1223` | 1 | 0 | 0 | 0 | 0/1 | 0 | 0 | 0 | 0 | 0/0 |
| `T1546.003` | 0 | 0 | 0 | 0 | 0/0 | 2 | 11 | 1 | 3 | 1/2 |
| `T1546.008` | 0 | 0 | 0 | 0 | 0/0 | 1 | 6 | 0 | 6 | 0/1 |
| `T1546.011` | 0 | 0 | 0 | 0 | 0/0 | 1 | 6 | 0 | 0 | 0/1 |
| `T1546.012` | 0 | 0 | 0 | 0 | 0/0 | 1 | 2 | 1 | 1 | 1/1 |
| `T1546.015` | 0 | 0 | 0 | 0 | 0/0 | 2 | 7 | 1 | 5 | 1/2 |
| `T1547` | 1 | 7 | 0 | 2 | 0/1 | 1 | 7 | 0 | 2 | 0/1 |
| `T1547.001` | 1 | 26 | 1 | 18 | 1/1 | 2 | 26 | 2 | 17 | 2/2 |
| `T1548.002` | 0 | 0 | 0 | 0 | 0/0 | 27 | 54 | 19 | 34 | 18/27 |
| `T1552.001` | 0 | 0 | 0 | 0 | 0/0 | 2 | 8 | 0 | 0 | 0/2 |
| `T1559` | 0 | 0 | 0 | 0 | 0/0 | 4 | 0 | 0 | 0 | 0/4 |
| `T1559.002` | 0 | 0 | 0 | 0 | 0/0 | 4 | 1 | 0 | 0 | 0/4 |
| `T1566.001` | 0 | 0 | 0 | 0 | 0/0 | 1 | 16 | 0 | 7 | 0/1 |
| `T1574` | 1 | 5 | 0 | 3 | 0/1 | 1 | 5 | 0 | 3 | 0/1 |
| `T1574.001` | 0 | 0 | 0 | 0 | 0/0 | 1 | 75 | 1 | 61 | 1/1 |
| `T1685` | 0 | 0 | 0 | 0 | 0/0 | 9 | 109 | 0 | 75 | 0/9 |

## 9. Execution Diagnostics & Positive Control

### Sample Processing Diagnostics (138 Labelled Samples)
- **Processed Without Error**: 138/138 (100.0%)
- **Errored or Skipped by Engine**: 0 (0.0%)
- **Own-Technique Rule Fired (Exact, As-Published)**: 7/138 (5.07%)
- **Own-Technique Rule Fired (Exact, Crosswalk)**: 38/138 (27.54%)

### Positive Control Verification
Direct targeted testing of 3 selected samples against known procedural Sigma rules:
- `de_portforward_netsh_rdp_sysmon_13_1.evtx` vs Rule `322ed9ec` (Netsh Port Forwarding): **FIRED (Exit 0)**
- `exec_msxsl_xsl_sysmon_1_7.evtx` vs Rule `9e50a8b3` (Msxsl Execution): **FIRED (Exit 0)**
- `exec_sysmon_1_lolbin_pcalua.evtx` vs Rule `0955e4e1` (Use of Pcalua For Execution): **FIRED (Exit 0)**
- **Positive Control Outcome**: 3 selected positive controls fired; this shows the
  pipeline can detect, not that it detects everything.

## 10. Methodological Limitations & What This Does Not Show

### What This Does NOT Show
- Does NOT show that Sigma rules are broken, low-quality, or ineffective.
- Does NOT show that modern SIEM/EDR stacks fail to catch intrusions.
- Does NOT measure false-positive rates on clean, benign production telemetry.
- Does NOT evaluate non-Windows log sources or alternative detection engines.

### Caveats and Residual Limits
- **Manual Review**: Rows verified by the author: __ of 25 (draft analysis in outputs/review_draft.csv).
- **Author Label Reliance**: Ground truth labels rely on dataset author mappings.
- **Rule-Sample Circularity**: Some community rules may have been created directly
  against specific lab captures in public repositories.
- **Residual Evaluability Limitation**: Verifying the presence of the required Event
  ID does not guarantee that all specific payload fields or command line parameters
  were captured in that event record.
- **Event ID Channel Pooling Limitation**: Event IDs are pooled across channels without
  per-channel provider verification in Chainsaw's mapping table.
- **Title-Based Mapping Exclusions**: Chainsaw mapping exclusions match rules by title,
  representing engine-level exclusion whose behavioral effects remain unverified independently.
