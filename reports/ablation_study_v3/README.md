# Pipeline ablation study v3

- Dataset: Existing capture-held-out CICIDS2017/CSE-CIC-IDS2018 test captures
- Seeds: 42, 43, 44, 45, 46
- Maximum sample size per seed: 1000; actual sample sizes and files are shown below.
- Pipeline version: 1.0.0
- Git commit: 5b929ca (dirty)
- Git tree clean at report writing: no
- Models directory: `models\experimental\lodo`
- Model mode: LODO candidate models; not promoted
- Metric definitions: overall recall counts ATTACK or REVIEW on attack flows; strict recall counts ATTACK only; benign false-alarm rate counts ATTACK or REVIEW on benign flows; precision is the attack share of non-BENIGN verdicts.
- Confidence intervals: 95% percentile intervals from 10,000 bootstrap draws resampling whole capture files, not individual flows, across all five seeds.

## Capture files and production-model training provenance

The active detector loads the CICIDS2017-named artifacts in `detection/model_predictor.py`. `train_multidataset.py` trains separate candidates under `models/multidataset/`; it does not establish training membership for the active artifacts. The existing source check reports that exact CICIDS2017 capture-level membership is unknown. LODO candidates use the shared 11-feature mapping; their binary-only predictions feed the existing downstream decision stages.

| Capture file | Dataset | Used to train active production models? |
|---|---|---|
| `Botnet-Friday-02-03-2018_TrafficForML_CICFlowMeter.parquet` | CSE-CIC-IDS2018 | no — CSE-CIC-IDS2018 is documented as external to active CICIDS2017 artifacts |
| `Bruteforce-Wednesday-14-02-2018_TrafficForML_CICFlowMeter.parquet` | CSE-CIC-IDS2018 | no — CSE-CIC-IDS2018 is documented as external to active CICIDS2017 artifacts |
| `DDoS2-Wednesday-21-02-2018_TrafficForML_CICFlowMeter.parquet` | CSE-CIC-IDS2018 | no — CSE-CIC-IDS2018 is documented as external to active CICIDS2017 artifacts |
| `DoS-Wednesday-no-metadata.parquet` | CICIDS2017 | unknown — CICIDS2017 is the active models' training source, but exact capture membership is undocumented |
| `Infil2-Thursday-01-03-2018_TrafficForML_CICFlowMeter.parquet` | CSE-CIC-IDS2018 | no — CSE-CIC-IDS2018 is documented as external to active CICIDS2017 artifacts |
| `Web1-Thursday-22-02-2018_TrafficForML_CICFlowMeter.parquet` | CSE-CIC-IDS2018 | no — CSE-CIC-IDS2018 is documented as external to active CICIDS2017 artifacts |

### Files present in each seed's sample

| Seed | Sample size | Exact capture files represented |
|---:|---:|---|
| 42 | 1000 | `Botnet-Friday-02-03-2018_TrafficForML_CICFlowMeter.parquet`, `Bruteforce-Wednesday-14-02-2018_TrafficForML_CICFlowMeter.parquet`, `DDoS2-Wednesday-21-02-2018_TrafficForML_CICFlowMeter.parquet`, `DoS-Wednesday-no-metadata.parquet`, `Infil2-Thursday-01-03-2018_TrafficForML_CICFlowMeter.parquet`, `Web1-Thursday-22-02-2018_TrafficForML_CICFlowMeter.parquet` |
| 43 | 1000 | `Botnet-Friday-02-03-2018_TrafficForML_CICFlowMeter.parquet`, `Bruteforce-Wednesday-14-02-2018_TrafficForML_CICFlowMeter.parquet`, `DDoS2-Wednesday-21-02-2018_TrafficForML_CICFlowMeter.parquet`, `DoS-Wednesday-no-metadata.parquet`, `Infil2-Thursday-01-03-2018_TrafficForML_CICFlowMeter.parquet`, `Web1-Thursday-22-02-2018_TrafficForML_CICFlowMeter.parquet` |
| 44 | 1000 | `Botnet-Friday-02-03-2018_TrafficForML_CICFlowMeter.parquet`, `Bruteforce-Wednesday-14-02-2018_TrafficForML_CICFlowMeter.parquet`, `DDoS2-Wednesday-21-02-2018_TrafficForML_CICFlowMeter.parquet`, `DoS-Wednesday-no-metadata.parquet`, `Infil2-Thursday-01-03-2018_TrafficForML_CICFlowMeter.parquet`, `Web1-Thursday-22-02-2018_TrafficForML_CICFlowMeter.parquet` |
| 45 | 1000 | `Botnet-Friday-02-03-2018_TrafficForML_CICFlowMeter.parquet`, `Bruteforce-Wednesday-14-02-2018_TrafficForML_CICFlowMeter.parquet`, `DDoS2-Wednesday-21-02-2018_TrafficForML_CICFlowMeter.parquet`, `DoS-Wednesday-no-metadata.parquet`, `Infil2-Thursday-01-03-2018_TrafficForML_CICFlowMeter.parquet`, `Web1-Thursday-22-02-2018_TrafficForML_CICFlowMeter.parquet` |
| 46 | 1000 | `Botnet-Friday-02-03-2018_TrafficForML_CICFlowMeter.parquet`, `Bruteforce-Wednesday-14-02-2018_TrafficForML_CICFlowMeter.parquet`, `DDoS2-Wednesday-21-02-2018_TrafficForML_CICFlowMeter.parquet`, `DoS-Wednesday-no-metadata.parquet`, `Infil2-Thursday-01-03-2018_TrafficForML_CICFlowMeter.parquet`, `Web1-Thursday-22-02-2018_TrafficForML_CICFlowMeter.parquet` |

## Overall results across seeds

Mean and sample standard deviation are calculated over the five seed-level metrics. The 95% confidence intervals resample whole capture files to account for flow correlation within a capture.

| Configuration | Recall mean ± SD | Strict recall mean ± SD | Benign FPR mean ± SD | Recall 95% CI | Benign FPR 95% CI | REVIEW mean ± SD | Precision mean ± SD |
|---|---:|---:|---:|---:|---:|---:|---:|
| RF only | 0.1036 ± 0.0162 | 0.1036 ± 0.0162 | 0.0069 ± 0.0043 | [0.0004, 0.1976] | [0.0022, 0.0132] | 0.0000 ± 0.0000 | 0.9521 ± 0.0238 |
| XGB only | 0.1398 ± 0.0257 | 0.1398 ± 0.0257 | 0.0298 ± 0.0091 | [0.0021, 0.2601] | [0.0115, 0.0535] | 0.0000 ± 0.0000 | 0.8601 ± 0.0193 |
| RF+XGB | 0.1444 ± 0.0259 | 0.0990 ± 0.0171 | 0.0316 ± 0.0114 | [0.0021, 0.2690] | [0.0123, 0.0571] | 0.0372 ± 0.0113 | 0.8574 ± 0.0261 |
| +rare_family | 0.1483 ± 0.0261 | 0.1025 ± 0.0171 | 0.0316 ± 0.0114 | [0.0026, 0.2761] | [0.0123, 0.0571] | 0.0374 ± 0.0113 | 0.8606 ± 0.0263 |
| +investigation | 0.1700 ± 0.0274 | 0.1338 ± 0.0227 | 0.0403 ± 0.0153 | [0.0026, 0.3142] | [0.0136, 0.0790] | 0.0312 ± 0.0069 | 0.8475 ± 0.0375 |
| +evidence/flow-evidence | 0.2204 ± 0.0376 | 0.1462 ± 0.0270 | 0.0495 ± 0.0142 | [0.0038, 0.4038] | [0.0172, 0.0953] | 0.0556 ± 0.0112 | 0.8532 ± 0.0203 |
| +threat_intel (full) | 0.2204 ± 0.0376 | 0.1462 ± 0.0270 | 0.0495 ± 0.0142 | [0.0038, 0.4038] | [0.0172, 0.0953] | 0.0556 ± 0.0112 | 0.8532 ± 0.0203 |

## Family recall across seeds

Values are mean ± sample standard deviation across seeds; support_mean is the average per-seed family support.

| Configuration | Family | Mean support | Recall mean ± SD | Strict recall mean ± SD |
|---|---|---:|---:|---:|
| RF only | Botnet | 82.4 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| RF only | BruteForce | 87.8 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| RF only | DDoS | 69.0 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| RF only | DoS | 233.6 | 0.2457 ± 0.0389 | 0.2457 ± 0.0389 |
| RF only | Heartbleed | 2.0 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| RF only | Infiltration | 71.8 | 0.0028 ± 0.0062 | 0.0028 ± 0.0062 |
| RF only | WebAttack | 17.0 | 0.0471 ± 0.0263 | 0.0471 ± 0.0263 |
| XGB only | Botnet | 82.4 | 0.0024 ± 0.0055 | 0.0024 ± 0.0055 |
| XGB only | BruteForce | 87.8 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| XGB only | DDoS | 69.0 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| XGB only | DoS | 233.6 | 0.3204 ± 0.0710 | 0.3204 ± 0.0710 |
| XGB only | Heartbleed | 2.0 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| XGB only | Infiltration | 71.8 | 0.0112 ± 0.0063 | 0.0112 ± 0.0063 |
| XGB only | WebAttack | 17.0 | 0.1765 ± 0.1176 | 0.1765 ± 0.1176 |
| RF+XGB | Botnet | 82.4 | 0.0024 ± 0.0055 | 0.0000 ± 0.0000 |
| RF+XGB | BruteForce | 87.8 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| RF+XGB | DDoS | 69.0 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| RF+XGB | DoS | 233.6 | 0.3316 ± 0.0720 | 0.2345 ± 0.0405 |
| RF+XGB | Heartbleed | 2.0 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| RF+XGB | Infiltration | 71.8 | 0.0112 ± 0.0063 | 0.0028 ± 0.0062 |
| RF+XGB | WebAttack | 17.0 | 0.1765 ± 0.1176 | 0.0471 ± 0.0263 |
| +rare_family | Botnet | 82.4 | 0.0049 ± 0.0067 | 0.0000 ± 0.0000 |
| +rare_family | BruteForce | 87.8 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| +rare_family | DDoS | 69.0 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| +rare_family | DoS | 233.6 | 0.3316 ± 0.0720 | 0.2345 ± 0.0405 |
| +rare_family | Heartbleed | 2.0 | 1.0000 ± 0.0000 | 1.0000 ± 0.0000 |
| +rare_family | Infiltration | 71.8 | 0.0112 ± 0.0063 | 0.0028 ± 0.0062 |
| +rare_family | WebAttack | 17.0 | 0.1765 ± 0.1176 | 0.0471 ± 0.0263 |
| +investigation | Botnet | 82.4 | 0.0049 ± 0.0067 | 0.0000 ± 0.0000 |
| +investigation | BruteForce | 87.8 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| +investigation | DDoS | 69.0 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| +investigation | DoS | 233.6 | 0.3770 ± 0.0714 | 0.3015 ± 0.0520 |
| +investigation | Heartbleed | 2.0 | 1.0000 ± 0.0000 | 1.0000 ± 0.0000 |
| +investigation | Infiltration | 71.8 | 0.0112 ± 0.0063 | 0.0028 ± 0.0062 |
| +investigation | WebAttack | 17.0 | 0.2706 ± 0.1534 | 0.1647 ± 0.1832 |
| +evidence/flow-evidence | Botnet | 82.4 | 0.0049 ± 0.0067 | 0.0000 ± 0.0000 |
| +evidence/flow-evidence | BruteForce | 87.8 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| +evidence/flow-evidence | DDoS | 69.0 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| +evidence/flow-evidence | DoS | 233.6 | 0.4749 ± 0.0935 | 0.3316 ± 0.0622 |
| +evidence/flow-evidence | Heartbleed | 2.0 | 1.0000 ± 0.0000 | 1.0000 ± 0.0000 |
| +evidence/flow-evidence | Infiltration | 71.8 | 0.0195 ± 0.0158 | 0.0028 ± 0.0062 |
| +evidence/flow-evidence | WebAttack | 17.0 | 0.5647 ± 0.2584 | 0.1647 ± 0.1832 |
| +threat_intel (full) | Botnet | 82.4 | 0.0049 ± 0.0067 | 0.0000 ± 0.0000 |
| +threat_intel (full) | BruteForce | 87.8 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| +threat_intel (full) | DDoS | 69.0 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| +threat_intel (full) | DoS | 233.6 | 0.4749 ± 0.0935 | 0.3316 ± 0.0622 |
| +threat_intel (full) | Heartbleed | 2.0 | 1.0000 ± 0.0000 | 1.0000 ± 0.0000 |
| +threat_intel (full) | Infiltration | 71.8 | 0.0195 ± 0.0158 | 0.0028 ± 0.0062 |
| +threat_intel (full) | WebAttack | 17.0 | 0.5647 ± 0.2584 | 0.1647 ± 0.1832 |

## Candidate model acceptance gate

Overall gate: **IMPROVE** (no model was promoted).
- LODO Random Forest: **IMPROVE** — DDoS priority-family recall below 80% or missing; DoS priority-family recall below 80% or missing; Botnet priority-family recall below 80% or missing; BruteForce priority-family recall below 80% or missing; Infiltration priority-family recall below 80% or missing
- LODO XGBoost: **IMPROVE** — benign false-positive rate exceeds the limit or is missing; DDoS priority-family recall below 80% or missing; DoS priority-family recall below 80% or missing; Botnet priority-family recall below 80% or missing; BruteForce priority-family recall below 80% or missing; Infiltration priority-family recall below 80% or missing
