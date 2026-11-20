# LODO calibration study

Platt scaling and isotonic regression are fitted only on a stratified validation split from the training datasets. The held-out dataset is used only for final metrics and reliability curves. The threshold for raw, Platt, and isotonic scores is selected using benign validation scores to target at most 1% false alarms; finite sample ties can yield a lower observed validation rate.

Reports include Brier score, 10-bin expected calibration error, reliability-curve points, and held-out recall at the validation-selected threshold. Active production calibration is not included: its 77-feature schema differs from the 11-feature LODO schema, and the exact production training capture membership is undocumented, so a validation split cannot be proven disjoint from model training. No values were fabricated and no active model was changed.

Reliability PNGs plot the ideal diagonal in gray, raw output in blue, Platt in green, and isotonic in orange. Axes are 0–1 mean predicted attack probability (horizontal) and observed attack fraction (vertical).

Run `evaluation/lodo_evaluation.py` first to create the LODO candidate models. Calibrated bundles are research candidates under `models/experimental/calibrated/` and do not alter API or CLI model loading.

See `calibration_metrics.csv`, `calibration_results.json`, and the PNG reliability plots for results.
