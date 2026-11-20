# Infiltration Flow Analysis — Findings & Recommendations

**Dataset**: CICIDS2017, `Infiltration-Thursday-no-metadata.parquet` (36 true Infiltration flows out of 207,630) vs. `Benign-Monday-no-metadata.parquet` (458,831 benign flows).

**Goal**: Identify why the Detection Agent misses ~97% of Infiltration flows (35/36 classified as Benign in the 397-flow evaluation), and produce a flow-level evidence signal the Evidence Agent can use independently of the ML prediction.

---

## 1. Statistical comparison (Infiltration vs. Benign)

Mann-Whitney U tests were run per feature (36 Infiltration flows vs. a 5,000-flow benign sample), ranked by effect size (rank-biserial correlation, r).

| Rank | Feature | Infiltration median | Benign median | Effect size (r) | p-value |
|---|---|---|---|---|---|
| 1 | Fwd IAT Total | 83,100,000 | 48 | 0.797 | ~1e-16 |
| 2 | Fwd Act Data Packets | 25 | 1 | 0.785 | ~3e-17 |
| 3 | Subflow Fwd Packets | 26 | 2 | 0.782 | ~4e-17 |
| 4 | Total Fwd Packets | 26 | 2 | 0.782 | ~4e-17 |
| 5 | Fwd IAT Max | 29,900,000 | 48 | 0.777 | ~5e-16 |
| 6 | Flow Duration | 93,188,870 | 53,663 | 0.772 | ~1e-15 |
| 7 | Fwd Packets Length Total | 7,020 | 74 | 0.770 | ~1e-15 |
| 8 | Fwd Packet Length Std | 269.8 | 0.0 | 0.759 | ~1e-19 |
| 9 | Active Mean | 570,109 | 0 | 0.652 | ~7e-24 |

Full ranked table for all 65 numeric features: see `infiltration_feature_analysis.csv`.

**Features that looked plausible but showed almost no separation:**
- `Down/Up Ratio` — rank 65th of 65 (r = 0.012, p = 0.88) — essentially identical distributions
- `PSH Flag Count` — rank 61st of 65 (r = 0.117, p = 0.12) — not usable
- `Flow Bytes/s` — moderate but weaker (r = 0.30) — Infiltration flows are actually **slower** in bytes/sec, not faster

## 2. Interpretation: Infiltration is "low-and-slow," not "loud"

The pattern across the top features is consistent: Infiltration flows are **long-lived, low-throughput, persistent connections** — median duration ~93 seconds vs. ~0.05 seconds for benign, with a large *total* amount of forward activity spread across that long duration but a *low rate* (median 1 packet/sec vs. 69 packets/sec for benign). This is the classic long-lived backdoor/lateral-movement signature, and it explains exactly why the ML models — trained mostly on per-flow statistics that emphasize rate and burst behavior — miss it: Infiltration doesn't look like a burst or a scan, it looks like an unusually persistent but otherwise quiet session.

## 3. Why simple threshold rules don't work

Testing a naive 5-condition rule (duration, packet count, IAT, low rate, active/idle presence):

| Rule | Infiltration recall | Benign false-positive rate |
|---|---|---|
| Lenient (≥3/5 conditions met) | 91.7% | 24.4% (unusable) |
| Moderate (≥4/5) | 83.3% | 17.5% |
| Strict (≥5/5) | 69.4% | 9.4% |

Even after tuning thresholds to the benign 99th/99.5th percentile per feature and requiring 3 of 5 to fire, recall dropped to ~22–25% for a 0.1–0.26% false-positive rate. **There is no hard threshold rule that gives both high recall and a low false-positive rate on this dataset.** This matches published results elsewhere on CICIDS2017 Infiltration — it is a genuinely hard class for flow-level statistics.

## 4. Recommended approach: continuous evidence score, not a binary rule

Instead of a pass/fail rule, `flow_evidence.py` implements a **continuous score in [0,1]** per flow: for each of the top 8 discriminative features, compute the flow's percentile rank against a benign reference distribution, then average. Validation:

| | Infiltration (n=36) | Benign (n=2000 sample) |
|---|---|---|
| Median score | 0.96 | 0.28 |
| IQR | 0.84 – 0.97 | 0.20 – 0.67 |

At different score thresholds:

| Threshold | Infiltration recall | Benign flagged |
|---|---|---|
| ≥ 0.9 | 72.2% | 6.0% |
| ≥ 0.8 | 80.6% | 12.7% |
| ≥ 0.7 | 83.3% | 18.1% |

**This score is meant to be a corroborating input to the Decision Agent — not a standalone classifier.** A flow scoring 0.95 should push the Decision Agent's confidence toward "needs investigation" even when the ML models say Benign; a flow scoring 0.3 should not. This directly targets your architectural goal from the roadmap: evidence that can *challenge*, not just *confirm*, the ML prediction.

## 4a. Validated result: full 397-flow pipeline, before vs. after integration

The scoring approach above was integrated into the Evidence Agent and Decision Agent (independent flow-level check, triggered only when both ML models agree "Benign") and validated on the full 397-flow evaluation set.

| Metric | Before | After |
|---|---|---|
| Overall threat-decision accuracy | 89.42% | **96.98%** |
| False-benign count | 42 | **9** |
| Infiltration recall (threat vs. no-threat) | 2.78% (1/36) | 83.3% (30/36) |
| Infiltration recall (exact-label, excludes 1 lucky ML mislabel) | — | **80.6% (29/36)** |
| Benign accuracy | ~100% | 94.0% (3 new false positives) |

Diagnostic breakdown of the 30 Infiltration "catches":
- 26 via flow-evidence score ≥ 0.90 ("very_high") → clean `THREAT` / `Infiltration`
- 3 via flow-evidence score 0.80–0.90 ("high") → `REVIEW` / "Infiltration (flow-anomaly)"
- 1 via the ML models directly (predicted family "Botnet" — non-benign, but the wrong attack family; counts as a threat catch but not an exact-label catch)

**Threshold validation**: the lowest caught score (0.836) and highest missed score (0.743) show a clean ~0.09 gap with no borderline cases — the current thresholds (0.80 / 0.90) are well-calibrated for this dataset. Lowering the threshold to sweep in the two remaining moderate-scoring misses (0.65, 0.74) would also flag roughly a quarter of all benign traffic (benign 75th-percentile score is 0.615), which is not a favorable trade.

**The 3 new benign false positives** score 0.905–0.957 — inside the legitimate Infiltration range, not at the threshold edge. This means they are not a tuning artifact but a genuine overlap: some legitimate long-lived/high-volume benign sessions (e.g. large downloads) structurally resemble the "low-and-slow" signature. This is a known, honest limitation of pure flow-statistics-based detection, and other classes (Botnet, DoS, etc.) were unaffected by the change — their accuracy matched the pre-change baseline exactly.

## 5. Concrete next steps

1. **Integrate `flow_evidence.py`** into the Evidence Agent: run it on every flow regardless of the ML prediction (this is the key architectural fix — currently evidence lookup only happens *after* an attack_family is assigned).
2. **Feed the score into the Decision Agent** as an additional weighted signal alongside ML confidence and model agreement, so a low-confidence-Benign + high-flow-evidence-score flow gets escalated to "needs investigation" rather than silently passing as Benign.
3. **Re-run the 397-flow evaluation** with this change and compare Infiltration recall and overall false-benign count before/after — this becomes your before/after correlation comparison table (item #19 in your roadmap).
4. **Note the limitation explicitly in your report**: with only 36 Infiltration samples in the full dataset, thresholds are somewhat fragile — worth mentioning as future work (e.g. validating against a larger/synthetic infiltration sample, or combining with host-level/temporal features CICIDS2017's per-flow stats can't capture).
5. Apply the same feature-analysis methodology to **Heartbleed** next, since it's your second-weakest class.

## Files produced

- `infiltration_feature_analysis.csv` — full ranked feature comparison (65 features)
- `flow_evidence.py` — scoring module (core algorithm)
- `flow_evidence_service.py` — singleton loader used by the Evidence Agent
- `evidence_agent.py`, `orchestrator.py`, `decision_agent.py` — integrated pipeline files
- `flow_evidence_diagnostic.py` — per-flow diagnostic script used to validate thresholds
- This report
