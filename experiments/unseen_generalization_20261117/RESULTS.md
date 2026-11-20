# 12-type unseen-capture experiment

## Candidate and method

I evaluated 12 independent one-vs-rest XGBoost detectors against the existing multiclass XGBoost model. This is an exploratory one-seed run on the existing seed-42 samples (up to 1,000 rows per raw label per capture), with all 18 capture identities held out in turn. The detectors were trained only on training captures; exact feature-vector overlaps were removed across train, calibration, and test splits. Each class detector received a calibration false-positive budget of 1% / 12 using benign rows from separate calibration capture(s); the maximum per-capture threshold was used. No test capture was used to select thresholds.

Run the experiment with:

```powershell
.\.venv\Scripts\python.exe experiments\unseen_generalization_20261117\run_ovr_loco.py
```

Rebuild the summary from the saved outputs without refitting:

```powershell
.\.venv\Scripts\python.exe experiments\unseen_generalization_20261117\run_ovr_loco.py --summarize
```

## Comparison to the matched seed-42 multiclass baseline

| Measure | 12-type multiclass baseline | 12 one-vs-rest candidate |
|---|---:|---:|
| Mean capture attack recall | 22.4% | 25.0% |
| Pooled attack recall | 22.3% | 22.3% |
| Mean capture correct-type recall | 13.9% | 19.9% |
| Macro correct-type recall over 12 labels | 17.3% | 20.7% |
| Mean / pooled benign FPR | 0.61% / 0.61% | 10.35% / 10.35% |
| Worst-capture FPR | 3.5% | 53.7% |
| Mean capture attack PR-AUC | 0.777 | 0.664 |

The capture-mean attack-recall difference was +2.6 percentage points, but the paired bootstrap interval across 16 attack-bearing captures was −9.2 to +14.3 points and includes zero. Pooled recall was effectively unchanged. Although macro correct-type recall rose in this single run, the candidate's benign false-alarm rates are far above the 1% target, and its PR-AUC was lower; it is not a usable improvement and was not promoted.

## Per-type comparison

| Attack type | Baseline correct-type recall | Candidate detected recall (any label) | Candidate correct-type recall |
|---|---:|---:|---:|
| Botnet | 0.0% | 0.4% | 0.0% |
| DDoS | 8.6% | 14.1% | 8.5% |
| DoS-GoldenEye | 15.1% | 20.0% | 14.3% |
| DoS-Hulk | 4.2% | 17.2% | 14.8% |
| DoS-SlowHTTPTest | 0.0% | 55.1% | 0.0% |
| DoS-Slowloris | 60.2% | 58.6% | 58.1% |
| FTP-BruteForce | 0.0% | 0.1% | 0.0% |
| Infiltration | 2.9% | 34.5% | 34.1% |
| SQL-Injection | 27.1% | 70.8% | 20.3% |
| SSH-BruteForce | 0.0% | 5.4% | 0.0% |
| Web-BruteForce | 41.8% | 50.0% | 35.5% |
| Web-XSS | 48.2% | 62.8% | 62.5% |

“Detected recall” means at least one class detector fired; it can include a wrong attack-type label. The gap between that value and correct-type recall is substantial for SQL-Injection and DoS-SlowHTTPTest. The latter was frequently flagged but never correctly assigned in this candidate. Per-capture counts and confusion rows are in `ovr_loco_per_type.csv` and `ovr_loco_confusion.csv`.

## Decision

Reject this candidate for the dashboard. Its extra recall comes with severe capture-specific false alarms, while the paired interval does not establish a general recall gain. The best evidence-backed next step remains adding independent, metadata-bearing captures; this run does not show that the existing 18 captures can support reliable detection of all 12 labels on unseen data.

All outputs in this folder are research-only. No files under `data/`, `models/`, or existing `reports/` were changed.
