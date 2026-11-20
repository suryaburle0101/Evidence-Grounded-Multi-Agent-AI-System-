# Pipeline ablation study v2

- Dataset: Existing capture-held-out CICIDS2017/CSE-CIC-IDS2018 test captures
- Seeds: 42, 43, 44, 45, 46
- Maximum sample size per seed: 1000; actual sample sizes and files are shown below.
- Pipeline version: 1.0.0
- Git commit: 5fc8914 (dirty)
- Models: existing production artifacts only; no training or model artifacts written.
- Metric definitions: overall recall counts ATTACK or REVIEW on attack flows; strict recall counts ATTACK only; benign false-alarm rate counts ATTACK or REVIEW on benign flows; precision is the attack share of non-BENIGN verdicts.
- Confidence intervals: 95% percentile intervals from 10,000 nonparametric bootstrap draws over pooled flow-level outcomes across all five seeds.

## Capture files and production-model training provenance

The active detector loads the CICIDS2017-named artifacts in `detection/model_predictor.py`. `train_multidataset.py` trains separate candidates under `models/multidataset/`; it does not establish training membership for the active artifacts. The existing source check reports that exact CICIDS2017 capture-level membership is unknown.

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

Mean and sample standard deviation are calculated over the five seed-level metrics. The 95% confidence intervals use pooled per-flow outcomes.

| Configuration | Recall mean ± SD | Strict recall mean ± SD | Benign FPR mean ± SD | Recall 95% CI | Benign FPR 95% CI | REVIEW mean ± SD | Precision mean ± SD |
|---|---:|---:|---:|---:|---:|---:|---:|
| RF only | 0.4272 ± 0.0000 | 0.4272 ± 0.0000 | 0.0000 ± 0.0000 | [0.4095, 0.4448] | [0.0000, 0.0000] | 0.0000 ± 0.0000 | 1.0000 ± 0.0000 |
| XGB only | 0.4278 ± 0.0009 | 0.4278 ± 0.0009 | 0.0005 ± 0.0011 | [0.4101, 0.4455] | [0.0000, 0.0015] | 0.0000 ± 0.0000 | 0.9992 ± 0.0017 |
| RF+XGB | 0.4282 ± 0.0009 | 0.4268 ± 0.0007 | 0.0005 ± 0.0011 | [0.4105, 0.4458] | [0.0000, 0.0015] | 0.0010 ± 0.0010 | 0.9992 ± 0.0017 |
| +rare_family | 0.4285 ± 0.0014 | 0.4265 ± 0.0009 | 0.0010 ± 0.0014 | [0.4108, 0.4462] | [0.0000, 0.0026] | 0.0016 ± 0.0015 | 0.9985 ± 0.0021 |
| +investigation | 0.4311 ± 0.0038 | 0.4291 ± 0.0031 | 0.0010 ± 0.0014 | [0.4134, 0.4488] | [0.0000, 0.0026] | 0.0016 ± 0.0015 | 0.9985 ± 0.0021 |
| +evidence/flow-evidence | 0.4370 ± 0.0045 | 0.4298 ± 0.0034 | 0.0010 ± 0.0014 | [0.4193, 0.4547] | [0.0000, 0.0026] | 0.0048 ± 0.0016 | 0.9985 ± 0.0020 |
| +threat_intel (full) | 0.4370 ± 0.0045 | 0.4298 ± 0.0034 | 0.0010 ± 0.0014 | [0.4193, 0.4547] | [0.0000, 0.0026] | 0.0048 ± 0.0016 | 0.9985 ± 0.0020 |

## Family recall across seeds

Values are mean ± sample standard deviation across seeds; support_mean is the average per-seed family support.

| Configuration | Family | Mean support | Recall mean ± SD | Strict recall mean ± SD |
|---|---|---:|---:|---:|
| RF only | Botnet | 65.0 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| RF only | BruteForce | 68.0 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| RF only | DDoS | 130.0 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| RF only | DoS | 259.0 | 1.0000 ± 0.0000 | 1.0000 ± 0.0000 |
| RF only | Heartbleed | 2.0 | 1.0000 ± 0.0000 | 1.0000 ± 0.0000 |
| RF only | Infiltration | 65.0 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| RF only | WebAttack | 22.0 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| XGB only | Botnet | 65.0 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| XGB only | BruteForce | 68.0 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| XGB only | DDoS | 130.0 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| XGB only | DoS | 259.0 | 0.9992 ± 0.0017 | 0.9992 ± 0.0017 |
| XGB only | Heartbleed | 2.0 | 1.0000 ± 0.0000 | 1.0000 ± 0.0000 |
| XGB only | Infiltration | 65.0 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| XGB only | WebAttack | 22.0 | 0.0273 ± 0.0249 | 0.0273 ± 0.0249 |
| RF+XGB | Botnet | 65.0 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| RF+XGB | BruteForce | 68.0 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| RF+XGB | DDoS | 130.0 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| RF+XGB | DoS | 259.0 | 1.0000 ± 0.0000 | 0.9992 ± 0.0017 |
| RF+XGB | Heartbleed | 2.0 | 1.0000 ± 0.0000 | 1.0000 ± 0.0000 |
| RF+XGB | Infiltration | 65.0 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| RF+XGB | WebAttack | 22.0 | 0.0273 ± 0.0249 | 0.0000 ± 0.0000 |
| +rare_family | Botnet | 65.0 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| +rare_family | BruteForce | 68.0 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| +rare_family | DDoS | 130.0 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| +rare_family | DoS | 259.0 | 1.0000 ± 0.0000 | 0.9985 ± 0.0021 |
| +rare_family | Heartbleed | 2.0 | 1.0000 ± 0.0000 | 1.0000 ± 0.0000 |
| +rare_family | Infiltration | 65.0 | 0.0031 ± 0.0069 | 0.0000 ± 0.0000 |
| +rare_family | WebAttack | 22.0 | 0.0273 ± 0.0249 | 0.0000 ± 0.0000 |
| +investigation | Botnet | 65.0 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| +investigation | BruteForce | 68.0 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| +investigation | DDoS | 130.0 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| +investigation | DoS | 259.0 | 1.0000 ± 0.0000 | 0.9985 ± 0.0021 |
| +investigation | Heartbleed | 2.0 | 1.0000 ± 0.0000 | 1.0000 ± 0.0000 |
| +investigation | Infiltration | 65.0 | 0.0031 ± 0.0069 | 0.0000 ± 0.0000 |
| +investigation | WebAttack | 22.0 | 0.1000 ± 0.1037 | 0.0727 ± 0.0943 |
| +evidence/flow-evidence | Botnet | 65.0 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| +evidence/flow-evidence | BruteForce | 68.0 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| +evidence/flow-evidence | DDoS | 130.0 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| +evidence/flow-evidence | DoS | 259.0 | 1.0000 ± 0.0000 | 1.0000 ± 0.0000 |
| +evidence/flow-evidence | Heartbleed | 2.0 | 1.0000 ± 0.0000 | 1.0000 ± 0.0000 |
| +evidence/flow-evidence | Infiltration | 65.0 | 0.0031 ± 0.0069 | 0.0000 ± 0.0000 |
| +evidence/flow-evidence | WebAttack | 22.0 | 0.2636 ± 0.1261 | 0.0727 ± 0.0943 |
| +threat_intel (full) | Botnet | 65.0 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| +threat_intel (full) | BruteForce | 68.0 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| +threat_intel (full) | DDoS | 130.0 | 0.0000 ± 0.0000 | 0.0000 ± 0.0000 |
| +threat_intel (full) | DoS | 259.0 | 1.0000 ± 0.0000 | 1.0000 ± 0.0000 |
| +threat_intel (full) | Heartbleed | 2.0 | 1.0000 ± 0.0000 | 1.0000 ± 0.0000 |
| +threat_intel (full) | Infiltration | 65.0 | 0.0031 ± 0.0069 | 0.0000 ± 0.0000 |
| +threat_intel (full) | WebAttack | 22.0 | 0.2636 ± 0.1261 | 0.0727 ± 0.0943 |
