# Larger samples and calibration coverage

## Question

Can more rows per label improve the 12-type capture-held-out model, and can a more representative benign calibration pool control its false alarms? All candidates use XGBoost on the same 18 CICIDS2017/CSE-CIC-IDS2018 capture identities, whole-capture test folds, separate benign calibration captures, a maximum of per-capture 99th-percentile thresholds, and the existing duplicate-removal rule. Every run is one seed and is exploratory.

The 5,000-row run uses the existing loader with a larger cap; it does not turn additional rows from the same source file into new capture environments. The dataset-matched follow-up reserves four non-held-out calibration captures from the held-out capture's known dataset. It selects those captures by greedy farthest-point coverage of benign-feature medians and excludes them from fitting. Since this calibration selection was proposed after seeing dataset-specific false alarms, treat it as a follow-up exploratory analysis, not a preregistered confirmatory test.

## Results

| Candidate | Rows per raw label | Calibration pool | Mean attack recall | Pooled FPR | Worst-capture FPR | Mean capture PR-AUC | Mean correct-type recall |
|---|---:|---|---:|---:|---:|---:|---:|
| Existing baseline | 1,000 | CICIDS2017 benign captures | 22.4% | 0.61% | 3.50% | 0.777 | 13.9% |
| Larger sample | 5,000 | CICIDS2017 benign captures | 37.0% | 5.20% | 20.48% | 0.749 | 14.9% |
| Dataset-matched, broad calibration | 1,000 | Four diverse benign captures from held-out dataset | 18.6% | 0.28% | 1.10% | 0.720 | 13.3% |
| Larger sample plus broad calibration | 5,000 | Four diverse benign captures from held-out dataset | 19.3% | 0.48% | 2.68% | 0.764 | 12.6% |

Increasing the cap alone raised mean capture recall by 14.6 points (capture-bootstrap 95% interval +8.3 to +21.8), but its pooled FPR rose to 5.20% and its worst capture reached 20.48%. The extra recall therefore did not produce an acceptable operating point.

Using four same-dataset calibration captures at the 1,000-row cap brought the worst observed FPR to 1.10%, but mean recall fell to 18.6%; its paired recall change versus the existing baseline was −3.8 points (95% interval −9.2 to −0.6). At the 5,000-row cap the broad calibration pool held pooled FPR to 0.48%, but worst-capture FPR was still 2.68%, mean recall was 19.3%, and the paired recall interval (−13.0 to +5.5 points) included zero. Dataset-matched metrics are in each run folder's `dataset_matched_calibration_comparison.json`.

## Per-type correct-label recall

For the 5,000-row, four-capture calibration candidate, mean correct-type recall across positive held-out captures was:

| Attack type | Correct-type recall |
|---|---:|
| Botnet | 0.0% |
| DDoS | 2.1% |
| DoS-GoldenEye | 14.0% |
| DoS-Hulk | 0.04% |
| DoS-SlowHTTPTest | 0.0% |
| DoS-Slowloris | 51.8% |
| FTP-BruteForce | 0.0% |
| Infiltration | 0.9% |
| SQL-Injection | 19.6% |
| SSH-BruteForce | 44.6% |
| Web-BruteForce | 34.5% |
| Web-XSS | 44.1% |

These results still fail the all-12 requirement. A broader calibration pool improves the false-alarm operating point for some settings, but trades away recall; a larger cap raises recall only when false alarms rise sharply. No variant was promoted to production.

## Reproduction

Run the 5,000-row LOCO experiment:

```powershell
.\.venv\Scripts\python.exe experiments\unseen_generalization_20261117\run_cap5000_loco.py
```

Rebuild its matched summary from saved outputs:

```powershell
.\.venv\Scripts\python.exe experiments\unseen_generalization_20261117\run_cap5000_loco.py --summarize
```

Run the four-capture dataset-matched calibration candidate at 1,000 rows:

```powershell
.\.venv\Scripts\python.exe experiments\unseen_generalization_20261117\run_dataset_matched_calibration.py
```

Run that candidate at 5,000 rows:

```powershell
.\.venv\Scripts\python.exe experiments\unseen_generalization_20261117\run_dataset_matched_calibration.py --cap 5000
```

All outputs stay in this experiment folder. The active production models, decision logic, `data/`, and existing `reports/` were not changed.
