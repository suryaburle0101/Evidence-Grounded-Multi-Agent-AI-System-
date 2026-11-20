# Pipeline ablation study

- Dataset: Existing capture-held-out CICIDS2017/CSE-CIC-IDS2018 test captures
- Held-out captures: DoS-Wednesday-no-metadata.parquet;Botnet-Friday-02-03-2018_TrafficForML_CICFlowMeter.parquet;Bruteforce-Wednesday-14-02-2018_TrafficForML_CICFlowMeter.parquet;DDoS2-Wednesday-21-02-2018_TrafficForML_CICFlowMeter.parquet;Infil2-Thursday-01-03-2018_TrafficForML_CICFlowMeter.parquet;Web1-Thursday-22-02-2018_TrafficForML_CICFlowMeter.parquet
- Seed: 42
- Stratified sample size: 1000 (maximum 1000)
- Pipeline version: 1.0.0
- Git commit: 5fc8914
- Model handling: existing production models only; no training or model files written.
- Metric definitions: attack recall counts ATTACK or REVIEW as detected; benign false-alarm rate counts either non-BENIGN verdict; precision is the attack share of all non-BENIGN verdicts. REVIEW rate is across all sampled flows.

## Summary

| Configuration | Family | Support | Attack recall | Benign false-alarm rate | REVIEW rate | Precision |
|---|---|---:|---:|---:|---:|---:|
| RF only | Botnet | 65 | 0.0000 | 0.0000 | 0.0000 | 1.0000 |
| RF only | BruteForce | 68 | 0.0000 | 0.0000 | 0.0000 | 1.0000 |
| RF only | DDoS | 130 | 0.0000 | 0.0000 | 0.0000 | 1.0000 |
| RF only | DoS | 259 | 1.0000 | 0.0000 | 0.0000 | 1.0000 |
| RF only | Heartbleed | 2 | 1.0000 | 0.0000 | 0.0000 | 1.0000 |
| RF only | Infiltration | 65 | 0.0000 | 0.0000 | 0.0000 | 1.0000 |
| RF only | WebAttack | 22 | 0.0000 | 0.0000 | 0.0000 | 1.0000 |
| XGB only | Botnet | 65 | 0.0000 | 0.0026 | 0.0000 | 0.9962 |
| XGB only | BruteForce | 68 | 0.0000 | 0.0026 | 0.0000 | 0.9962 |
| XGB only | DDoS | 130 | 0.0000 | 0.0026 | 0.0000 | 0.9962 |
| XGB only | DoS | 259 | 1.0000 | 0.0026 | 0.0000 | 0.9962 |
| XGB only | Heartbleed | 2 | 1.0000 | 0.0026 | 0.0000 | 0.9962 |
| XGB only | Infiltration | 65 | 0.0000 | 0.0026 | 0.0000 | 0.9962 |
| XGB only | WebAttack | 22 | 0.0455 | 0.0026 | 0.0000 | 0.9962 |
| RF+XGB | Botnet | 65 | 0.0000 | 0.0026 | 0.0020 | 0.9962 |
| RF+XGB | BruteForce | 68 | 0.0000 | 0.0026 | 0.0020 | 0.9962 |
| RF+XGB | DDoS | 130 | 0.0000 | 0.0026 | 0.0020 | 0.9962 |
| RF+XGB | DoS | 259 | 1.0000 | 0.0026 | 0.0020 | 0.9962 |
| RF+XGB | Heartbleed | 2 | 1.0000 | 0.0026 | 0.0020 | 0.9962 |
| RF+XGB | Infiltration | 65 | 0.0000 | 0.0026 | 0.0020 | 0.9962 |
| RF+XGB | WebAttack | 22 | 0.0455 | 0.0026 | 0.0020 | 0.9962 |
| +rare_family | Botnet | 65 | 0.0000 | 0.0026 | 0.0030 | 0.9962 |
| +rare_family | BruteForce | 68 | 0.0000 | 0.0026 | 0.0030 | 0.9962 |
| +rare_family | DDoS | 130 | 0.0000 | 0.0026 | 0.0030 | 0.9962 |
| +rare_family | DoS | 259 | 1.0000 | 0.0026 | 0.0030 | 0.9962 |
| +rare_family | Heartbleed | 2 | 1.0000 | 0.0026 | 0.0030 | 0.9962 |
| +rare_family | Infiltration | 65 | 0.0000 | 0.0026 | 0.0030 | 0.9962 |
| +rare_family | WebAttack | 22 | 0.0455 | 0.0026 | 0.0030 | 0.9962 |
| +investigation | Botnet | 65 | 0.0000 | 0.0026 | 0.0030 | 0.9963 |
| +investigation | BruteForce | 68 | 0.0000 | 0.0026 | 0.0030 | 0.9963 |
| +investigation | DDoS | 130 | 0.0000 | 0.0026 | 0.0030 | 0.9963 |
| +investigation | DoS | 259 | 1.0000 | 0.0026 | 0.0030 | 0.9963 |
| +investigation | Heartbleed | 2 | 1.0000 | 0.0026 | 0.0030 | 0.9963 |
| +investigation | Infiltration | 65 | 0.0000 | 0.0026 | 0.0030 | 0.9963 |
| +investigation | WebAttack | 22 | 0.2727 | 0.0026 | 0.0030 | 0.9963 |
| +evidence/flow-evidence | Botnet | 65 | 0.0000 | 0.0026 | 0.0050 | 0.9963 |
| +evidence/flow-evidence | BruteForce | 68 | 0.0000 | 0.0026 | 0.0050 | 0.9963 |
| +evidence/flow-evidence | DDoS | 130 | 0.0000 | 0.0026 | 0.0050 | 0.9963 |
| +evidence/flow-evidence | DoS | 259 | 1.0000 | 0.0026 | 0.0050 | 0.9963 |
| +evidence/flow-evidence | Heartbleed | 2 | 1.0000 | 0.0026 | 0.0050 | 0.9963 |
| +evidence/flow-evidence | Infiltration | 65 | 0.0000 | 0.0026 | 0.0050 | 0.9963 |
| +evidence/flow-evidence | WebAttack | 22 | 0.4091 | 0.0026 | 0.0050 | 0.9963 |
| +threat_intel (full) | Botnet | 65 | 0.0000 | 0.0026 | 0.0050 | 0.9963 |
| +threat_intel (full) | BruteForce | 68 | 0.0000 | 0.0026 | 0.0050 | 0.9963 |
| +threat_intel (full) | DDoS | 130 | 0.0000 | 0.0026 | 0.0050 | 0.9963 |
| +threat_intel (full) | DoS | 259 | 1.0000 | 0.0026 | 0.0050 | 0.9963 |
| +threat_intel (full) | Heartbleed | 2 | 1.0000 | 0.0026 | 0.0050 | 0.9963 |
| +threat_intel (full) | Infiltration | 65 | 0.0000 | 0.0026 | 0.0050 | 0.9963 |
| +threat_intel (full) | WebAttack | 22 | 0.4091 | 0.0026 | 0.0050 | 0.9963 |
