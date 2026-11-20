"""One-seed XGBoost LOCO check with a 5,000-row per-label sample cap."""
from __future__ import annotations

import json
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from experiments.unseen_capture_20261113 import run_loco

OUT = ROOT / "experiments/unseen_generalization_20261117/cap5000_loco"
BASELINE_DIR = ROOT / "experiments/failing_types_20261113/seed_42/multiclass_77"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--summarize", action="store_true", help="rebuild paired summary from completed LOCO files")
    args = parser.parse_args()
    if not args.summarize:
        run_loco.CAP_PER_RAW_LABEL = 5_000
        run_loco.OUT = OUT
        original_models = run_loco.models

        def only_xgboost(seed: int, n_classes: int):
            return {"xgboost": original_models(seed, n_classes)["xgboost"]}

        run_loco.models = only_xgboost
        run_loco.main()

    import numpy as np
    import pandas as pd

    current = pd.read_csv(OUT / "loco_capture_metrics.csv")
    baseline = pd.read_csv(BASELINE_DIR / "loco_capture_metrics.csv")
    baseline = baseline[baseline.model.eq("xgboost")][
        ["heldout_capture", "attack_recall_at_1pct_cal_fpr", "pooled_fpr", "pr_auc_attack",
         "end_to_end_correct_type_recall", "benign_rows"]
    ].rename(columns={
        "attack_recall_at_1pct_cal_fpr": "baseline_recall",
        "pooled_fpr": "baseline_fpr",
        "pr_auc_attack": "baseline_pr_auc",
        "end_to_end_correct_type_recall": "baseline_correct_type_recall",
    })
    baseline = baseline.rename(columns={"benign_rows": "baseline_benign_rows"})
    current["capture_key"] = current.heldout_capture.str.removesuffix(".parquet")
    baseline["capture_key"] = baseline.heldout_capture.str.split("__", n=1).str[-1]
    baseline["capture_key"] = baseline.capture_key.str.removesuffix(".parquet")
    paired = current.merge(baseline.drop(columns="heldout_capture"), on="capture_key", validate="one_to_one")
    if len(paired) != 18:
        raise RuntimeError(f"Expected 18 matched captures; got {len(paired)}")
    paired["recall_difference"] = paired.attack_recall_at_1pct_cal_fpr - paired.baseline_recall
    paired.to_csv(OUT / "cap5000_vs_cap1000_capture.csv", index=False)
    positive = paired[paired.attack_rows.gt(0) & paired.baseline_recall.notna()]
    rng = np.random.default_rng(20261117)
    d = positive.recall_difference.to_numpy()
    if len(d) != 16:
        raise RuntimeError(f"Expected 16 paired attack-bearing captures; got {len(d)}")
    samples = rng.integers(0, len(d), size=(20_000, len(d)))
    boot = d[samples].mean(axis=1)
    current_types = pd.read_csv(OUT / "loco_per_type.csv")
    base_types = pd.read_csv(BASELINE_DIR / "loco_per_type.csv")
    current_types = current_types[current_types.model.eq("xgboost")].copy()
    base_types = base_types[base_types.model.eq("xgboost")].copy()
    current_types["capture_key"] = current_types.heldout_capture.str.removesuffix(".parquet")
    base_types["capture_key"] = base_types.heldout_capture.str.split("__", n=1).str[-1]
    base_types["capture_key"] = base_types.capture_key.str.removesuffix(".parquet")
    type_rows = []
    for attack_type in sorted(set(current_types.attack_type) | set(base_types.attack_type)):
        cur = current_types[current_types.attack_type.eq(attack_type)]
        bas = base_types[base_types.attack_type.eq(attack_type)]
        type_rows.append({
            "attack_type": attack_type,
            "cap1000_positive_captures": int(bas.heldout_capture.nunique()),
            "cap1000_mean_detected_recall": float(bas.detected_recall.mean()) if len(bas) else None,
            "cap1000_mean_correct_type_recall": float(bas.correct_type_recall.mean()) if len(bas) else None,
            "cap5000_positive_captures": int(cur.heldout_capture.nunique()),
            "cap5000_mean_detected_recall": float(cur.detected_recall.mean()) if len(cur) else None,
            "cap5000_mean_correct_type_recall": float(cur.correct_type_recall.mean()) if len(cur) else None,
        })
    pd.DataFrame(type_rows).to_csv(OUT / "cap5000_per_type_comparison.csv", index=False)
    baseline_pooled_fpr = float((paired.baseline_fpr * paired.baseline_benign_rows).sum() / paired.baseline_benign_rows.sum())
    cap5000_pooled_fpr = float((paired.pooled_fpr * paired.benign_rows).sum() / paired.benign_rows.sum())
    summary = {
        "cap_per_raw_label": 5000,
        "seed": 42,
        "capture_count": int(len(paired)),
        "attack_bearing_capture_count": int(len(positive)),
        "baseline_cap1000_mean_attack_recall": float(positive.baseline_recall.mean()),
        "cap5000_mean_attack_recall": float(positive.attack_recall_at_1pct_cal_fpr.mean()),
        "mean_capture_recall_difference": float(d.mean()),
        "paired_capture_bootstrap_95ci": [float(np.quantile(boot, .025)), float(np.quantile(boot, .975))],
        "baseline_cap1000_mean_capture_fpr": float(paired.baseline_fpr.mean()),
        "cap5000_mean_capture_fpr": float(paired.pooled_fpr.mean()),
        "baseline_cap1000_pooled_fpr": baseline_pooled_fpr,
        "cap5000_pooled_fpr": cap5000_pooled_fpr,
        "baseline_cap1000_worst_capture_fpr": float(paired.baseline_fpr.max()),
        "cap5000_worst_capture_fpr": float(paired.pooled_fpr.max()),
        "baseline_cap1000_mean_capture_pr_auc": float(positive.baseline_pr_auc.mean()),
        "cap5000_mean_capture_pr_auc": float(positive.pr_auc_attack.mean()),
        "method": "Same 18-capture XGBoost LOCO harness and separate benign calibration capture rule; only per-raw-label sample cap changes from 1,000 to 5,000. One seed, exploratory.",
        "interpretation": "The paired bootstrap resamples capture identities. More rows from the same captures do not provide independent capture environments.",
    }
    (OUT / "cap5000_comparison.json").write_text(json.dumps(summary, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
