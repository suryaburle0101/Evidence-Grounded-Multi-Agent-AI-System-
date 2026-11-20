# Family-level IDS redesign: initial results

## Step 1 — family definitions

`families.json` records the requested five-family taxonomy, an exploratory three-family coarsening, and the separate 12-type taxonomy. The primary map is: DoS/DDoS (five DoS and DDoS types), Brute_force (FTP/SSH/Web brute force), Web_attack (SQL injection/XSS), Botnet, and Infiltration. The coarse “Other attack” group pools unlike behaviors and is only a label-granularity sensitivity check.

## Step 2 — capture-held-out comparison

The primary model used XGBoost with the existing 77 features, cap of 1,000 rows per raw label, 18 capture-held-out folds, and seeds 42–44. For every fold, one or two designated benign captures were kept out of training; per-capture 99th-percentile thresholds were combined conservatively using the maximum. Exact train/test feature-vector duplicates were removed. These reduced-sample results are exploratory.

| Variant | Mean attack recall ± SD across 3 seed means | Mean capture PR-AUC ± SD | Mean capture FPR | Pooled FPR | Worst-capture FPR |
|---|---:|---:|---:|---:|---:|
| separate_12_type | 22.4% ± 4.4% | 0.777 ± 0.010 | 0.56% ± 0.27% | 0.56% | 3.90% |
| coarse_3 | 21.1% ± 5.9% | 0.801 ± 0.007 | 0.43% ± 0.10% | 0.43% | 2.10% |
| primary_5 | 23.0% ± 1.8% | 0.797 ± 0.006 | 0.38% ± 0.06% | 0.38% | 2.00% |

Per-family recall and one-vs-rest PR-AUC are in `family_performance_rollup.csv`; full seed/capture details are in `family_capture_metrics_3seeds.csv`, `family_per_class_3seeds.csv`, and `family_confusion_3seeds.csv`.

### Paired capture bootstrap against the 12-type model

| Family taxonomy | Mean recall difference | 95% capture-bootstrap interval | Interpretation |
|---|---:|---:|---|
| primary_5 | +0.6% | [-5.0%, +7.0%] | interval includes zero; no established gain |
| coarse_3 | -1.3% | [-8.7%, +7.1%] | interval includes zero; no established gain |

The requested five-family model’s estimated gain over the 12-type baseline is not statistically established: its paired capture-bootstrap interval includes zero. Per the stop rule, the 20/30/40-feature search and the new two-level subtype architecture are skipped. The existing 12-type model remains available as the separate-class baseline.

## Step 4 — reliability labels

Rule: “reliable” requires recall above 70% on more than half of positive held-out captures and the model’s worst-capture FPR at or below 2%. “Partial” means that rule is not met but capture-weighted mean recall is at least 20%; otherwise “experimental.” Exactly two positive captures is marked low-confidence regardless of status. The 12-type entries use five-seed baseline data; family entries use the new three-seed model.

| Kind | Label | Captures | Mean recall | Captures >70% | Worst FPR | Confidence | Status |
|---|---|---:|---:|---:|---:|---|---|
| attack_type | Botnet | 2 | 0.2% | 0/2 | 12.60% | low-confidence | experimental |
| attack_type | DDoS | 3 | 39.3% | 0/3 | 12.60% | standard | partial |
| attack_type | DoS-GoldenEye | 2 | 15.0% | 0/2 | 12.60% | low-confidence | experimental |
| attack_type | DoS-Hulk | 2 | 6.1% | 0/2 | 12.60% | low-confidence | experimental |
| attack_type | DoS-SlowHTTPTest | 2 | 57.7% | 1/2 | 12.60% | low-confidence | partial |
| attack_type | DoS-Slowloris | 2 | 68.1% | 1/2 | 12.60% | low-confidence | partial |
| attack_type | FTP-BruteForce | 2 | 50.1% | 1/2 | 12.60% | low-confidence | partial |
| attack_type | Infiltration | 3 | 5.9% | 0/3 | 12.60% | standard | experimental |
| attack_type | SQL-Injection | 3 | 52.4% | 1/3 | 12.60% | standard | partial |
| attack_type | SSH-BruteForce | 2 | 0.0% | 0/2 | 12.60% | low-confidence | experimental |
| attack_type | Web-BruteForce | 3 | 42.5% | 1/3 | 12.60% | standard | partial |
| attack_type | Web-XSS | 3 | 49.9% | 1/3 | 12.60% | standard | partial |
| family | Botnet | 2 | 0.0% | 0/2 | 2.00% | low-confidence | experimental |
| family | Brute_force | 5 | 24.4% | 0/5 | 2.00% | standard | partial |
| family | DoS_DDoS | 6 | 36.8% | 1/6 | 2.00% | standard | partial |
| family | Infiltration | 3 | 0.6% | 0/3 | 2.00% | standard | experimental |
| family | Web_attack | 3 | 36.0% | 0/3 | 2.00% | standard | partial |

## Skipped and pending tasks

- **Task 3, stable 20/30/40-feature selection:** skipped by the no-established-family-gain stop rule. No held-out data was used to select features.
- **Task 5, two-level detector/family/subtype output:** skipped by the same stop rule.
- **Task 6, conservative threshold:** completed at 1.0% and 0.5% calibration targets using the same three seeds and LOCO folds. See `family_threshold_comparison.csv` and `family_threshold_0_5_per_family.csv`.
- **Task 7, cross-dataset transfer:** completed in both directions using source-only calibration; see the `cross_dataset_family_*.csv` outputs.
- **Task 8, optional datasets:** LycoS-IDS2017, LycoS-Unicas-IDS2018, CIC-DDoS2019, and CTU-13 were not found locally. UNSW-NB15 and CIC-IDS Collection are present but do not support this direct 77-feature capture-held-out comparison.

### Five-family detection results

| Family | Positive captures | Recall mean ± seed SD | Mean one-vs-rest PR-AUC |
|---|---:|---:|---:|
| Botnet | 2 | 0.0% ± 0.0% | 0.796 |
| Brute_force | 5 | 24.4% ± 3.6% | 0.840 |
| DoS_DDoS | 6 | 36.8% ± 5.3% | 0.984 |
| Infiltration | 3 | 0.6% ± 0.3% | 0.478 |
| Web_attack | 3 | 36.0% ± 2.1% | 0.763 |

The five-family taxonomy modestly raises estimated attack recall by 0.6 percentage points, but its 95% paired capture-bootstrap interval is −5.0 to +7.0 points. That interval includes no change, so the apparent gain may be sampling noise.

## Step 6 — threshold sensitivity

| Calibration target | Attack recall mean ± seed SD | Mean capture FPR | Pooled FPR | Worst-capture FPR |
|---|---:|---:|---:|---:|
| 0.5% | 9.6% ± 6.8% | 0.12% | 0.12% | 1.30% |
| 1.0% | 23.0% ± 1.8% | 0.38% | 0.38% | 2.00% |

The 0.5% target costs 13.4% recall compared with 1%, while worst-capture FPR falls from 2.00% to 1.30%. Even this conservative setting leaves attack recall low and worst-capture FPR above 1%.

## Step 7 — cross-dataset family transfer

| Train → test | Attack recall mean ± seed SD | Mean capture FPR | Worst capture FPR |
|---|---:|---:|---:|
| CICIDS2017 → CSE-CIC-IDS2018 | 9.4% ± 4.4% | 1.27% | 5.70% |
| CSE-CIC-IDS2018 → CICIDS2017 | 22.5% ± 1.1% | 11.26% | 20.70% |

Per-family recalls and family-attributed benign FPRs for both directions are in `cross_dataset_family_rollup.csv`. Results are strongly directional and neither direction meets the “near 1% on every capture” goal.

| Transfer direction | Family | Recall | Mean family-attributed FPR | Worst family-attributed FPR |
|---|---|---:|---:|---:|
| CICIDS2017 → CSE-CIC-IDS2018 | Botnet | 0.0% | 0.10% | 0.30% |
| CICIDS2017 → CSE-CIC-IDS2018 | Brute_force | 0.0% | 0.00% | 0.00% |
| CICIDS2017 → CSE-CIC-IDS2018 | DoS_DDoS | 16.9% | 0.77% | 5.00% |
| CICIDS2017 → CSE-CIC-IDS2018 | Infiltration | 0.0% | 0.00% | 0.00% |
| CICIDS2017 → CSE-CIC-IDS2018 | Web_attack | 11.7% | 0.00% | 0.00% |
| CSE-CIC-IDS2018 → CICIDS2017 | Botnet | 0.0% | 0.00% | 0.00% |
| CSE-CIC-IDS2018 → CICIDS2017 | Brute_force | 25.3% | 0.48% | 0.80% |
| CSE-CIC-IDS2018 → CICIDS2017 | DoS_DDoS | 24.3% | 5.37% | 9.10% |
| CSE-CIC-IDS2018 → CICIDS2017 | Infiltration | 0.0% | 2.57% | 4.10% |
| CSE-CIC-IDS2018 → CICIDS2017 | Web_attack | 1.9% | 1.63% | 3.20% |

## Step 8 — optional local datasets

No LycoS-IDS2017, LycoS-Unicas-IDS2018, CIC-DDoS2019, or CTU-13 files were found. UNSW-NB15 and CIC-IDS Collection are present, but have incompatible or incomplete schema/provenance for this direct 77-feature capture-held-out comparison.

## Remaining data by family

| Family | What is still needed |
|---|---|
| Botnet | More independent Botnet scenarios and benign captures; CTU-13 could help only after schema harmonization and capture-level labeling. |
| Brute_force | Independent FTP, SSH, and Web-BruteForce sessions; specifically add SSH captures and separate the three brute-force modalities. |
| DoS_DDoS | More held-out DDoS and each named DoS subtype across varied days; CIC-DDoS2019 can add DDoS, but not the CIC DoS subtypes without compatible labels/features. |
| Infiltration | Multiple independent Infiltration scenarios plus varied benign network captures; current recall is near zero. |
| Web_attack | More independent SQL-Injection and Web-XSS captures; present SQL support is especially small. |
## Provisional verdict

No variant is ready for a production trial. The five-family model has roughly 23% mean attack recall and 2.0% worst-capture FPR over these three reduced-sample seeds; it does not establish a gain over the 12-type baseline. The 12-type model also misses most attacks and its recorded five-seed worst-capture FPR exceeds the requested 2% reliability bound. These are exploratory estimates from only 18 capture files, and most attack families have two or three positive captures.
