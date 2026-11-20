# Family-level IDS design pilot

This folder evaluates the requested five-family taxonomy and a coarse three-family alternative using existing prepared CICIDS2017/CSE-CIC-IDS2018 capture samples. It also includes reliability labels, a 0.5% threshold sensitivity run, and bidirectional family-level cross-dataset transfer.

## Rerun

From the project root in PowerShell:

```powershell
.\.venv\Scripts\python.exe experiments\family_design_20261116\run_all.py
```

The run reuses sampled captures and loader/schema settings from `experiments/failing_types_20261113/`. It retrains XGBoost for the LOCO, threshold, and cross-dataset folds; expect a long CPU run. All generated artifacts stay in this folder.

## Main outputs

- `families.json`: five-family, coarse three-family, and separate 12-type mappings.
- `family_capture_metrics_3seeds.csv`, `family_per_class_3seeds.csv`, and `family_confusion_3seeds.csv`: per-seed/per-capture results.
- `family_vs_12type_bootstrap.csv`: paired capture-cluster confidence intervals.
- `reliability_labels.csv` and `.json`: frontend-ready reliability status and confidence labels.
- `family_threshold_comparison.csv`: 1% versus 0.5% operating-point sensitivity.
- `cross_dataset_family_rollup.csv`: transfer recall and family-attributed false-positive rates.
- `remaining_data_by_family.csv`: data gaps for each family.
- `RESULTS.md`: findings, stop-rule decisions, limitations, and verdict.

The results are exploratory: 1,000 rows per raw label, three seeds for the family pilot, and only 18 capture files. The family-level bootstrap interval includes zero, so the specified stop rule skips feature-count variants and the new two-level subtype model. No production files or existing reports are modified.
