# Evaluation Methodology & Hypotheses

## 1. Research Hypotheses

### Hypothesis H1 (Detection Non-Firing & Granularity Gap)
> **H1 Formulation**: A meaningful fraction of community Sigma rules claiming a technique for which an evaluable labelled Windows attack sample exists do not fire on that sample.

- **Unit of Analysis**: A distinct Sigma rule claiming at least one ATT&CK technique present in the evaluated sample set.
- **Pair-Level Definition of Evaluable**: A `(rule, sample)` pair is *evaluable* if and only if:
  1. The sample carries an author ground-truth label matching a technique claimed by the rule (exact or hierarchical).
  2. The sample contains at least one Windows Event ID that the rule's `logsource` can match (derived from Chainsaw's `sigma-event-logs-all.yml` mapping preconditions or explicit rule detection EventIDs).
  3. The engine's mapping configuration supports the required logsource and fields.
  4. The engine compiled the rule without skipping or syntax errors.
- **Unknown Mapping Handling**: Where Chainsaw's mapping does not state Event IDs for a category, the pair is classified as `not_evaluable_unknown_mapping` and counted separately, never silently assumed evaluable.
- **Residual Limitation of Evaluability**: Verifying the presence of the required Event ID does not guarantee that required fields (e.g., `CommandLine`, `Image`, or specific XML attributes) were captured during execution.
- **Four Rule Classification Categories**:
  1. **`validated`**: Fired on at least one labelled sample for a claimed technique (exact and hierarchical reported separately).
  2. **`failing`**: At least one *evaluable* labelled sample exists, and the rule fired on none of its evaluable samples.
  3. **`not_evaluable`**: Labelled samples exist for a claimed technique, but none are evaluable (missing telemetry, unknown mapping, or engine skipped/excluded rule).
  4. **`unvalidated`**: No labelled sample exists in the dataset for any technique claimed by the rule.
  - **Classification Precedence**: Sample availability strictly precedes engine evaluability. A rule with no candidate labelled sample in the dataset is classified as `unvalidated` (even if skipped by the engine or excluded by mapping), preserving its engine skip reason in metadata. A rule is classified as `not_evaluable` only when candidate matching samples exist in the dataset but cannot be evaluated.
- **Reframing & Security Interpretation of Non-Firing**:
  - Non-firing does **NOT** indicate defective, broken, or low-quality rules.
  - Rather, H1 quantifies the **granularity gap** between MITRE ATT&CK technique tags and procedure-specific Sigma detection logic. ATT&CK techniques represent abstract goals (e.g., T1059 Command and Scripting Interpreter); individual Sigma rules detect concrete procedural signatures (e.g., specific command line flags, LOLBAS parents). Non-firing on a sample executing a different procedure reflects correct rule specificity, not detection failure.
- **Statistical Metric & Denominator**:
  - **H1 Denominator**: Rules with evaluable samples only: $\text{Denominator} = N_{\text{validated}} + N_{\text{failing}}$.
  - `not_evaluable`, `unvalidated`, and engine skip/fail counts are reported separately.
  - Non-firing proportion $\hat{p} = \frac{k}{n}$, where $k = N_{\text{failing}}$ and $n = N_{\text{validated}} + N_{\text{failing}}$.
  - 95% Wilson Score Confidence Interval:
    $$\hat{p}_{wilson} = \frac{k + \frac{z^2}{2}}{n + z^2} \pm \frac{z}{n + z^2} \sqrt{\frac{k(n - k)}{n} + \frac{z^2}{4}} \quad (z = 1.96)$$
- **Decision Threshold**:
  - Pre-registered arbitrary threshold: $\tau = 15\%$.
  - **Verdict Rule**:
    - **Supported**: Wilson interval lower bound $> 15\%$.
    - **Not Supported**: Wilson interval upper bound $< 15\%$.
    - **Inconclusive**: Wilson interval spans $15\%$.

### Sample-Side Recall Metric
In addition to rule-centric evaluation, RuleProof computes sample-side detection recall:
- **Definition**: Per labelled attack log sample, did at least one community rule claiming its technique fire?
- Computed separately for exact technique matches and hierarchical matches with 95% Wilson score intervals.

## 2. Experimental Controls & Limitations
- **Author Label Reliance**: Ground truth labels rely on dataset author mappings.
- **Rule-Sample Circularity**: Some community rules were developed specifically against particular public EVTX repositories.
- **Residual Evaluability Limitation**: Event ID presence does not guarantee required payload fields were recorded.
- **No False Positive Baseline**: Only malicious lab captures were evaluated; false positive rates across benign production telemetry are out of scope.
- **Scope Reporting**: Metrics are reported separately for `stable + test` (default) and `--all-statuses`.
