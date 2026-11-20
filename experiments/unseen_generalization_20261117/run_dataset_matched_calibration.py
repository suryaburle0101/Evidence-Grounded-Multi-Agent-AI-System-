"""Test dataset-matched benign calibration on the exact seed-42 18-capture sample."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from experiments.unseen_capture_20261113 import run_loco
from experiments.family_design_20261116.evaluate_families import read_seed
from pipeline.data_pipeline import FEATURES

OUT = ROOT / "experiments/unseen_generalization_20261117/dataset_matched_calibration"
BASELINE_DIR = ROOT / "experiments/failing_types_20261113/seed_42/multiclass_77"


def load_seed42():
    frames = read_seed(42)
    manifest = []
    for name, frame in frames.items():
        manifest.append({"capture": name, "dataset": str(frame["__dataset"].iloc[0]),
                         "sampled_rows": len(frame), "type_counts": frame["__type"].value_counts().to_dict(),
                         "quality": {"source": "existing seed-42 sampled capture partition"}})
    return frames, manifest


def dataset_matched_calibration(captures, heldout):
    dataset = str(captures[heldout]["__dataset"].iloc[0])
    options = []
    for name, frame in captures.items():
        if name == heldout or str(frame["__dataset"].iloc[0]) != dataset:
            continue
        benign_rows = frame.loc[frame["__type"].eq("Benign")]
        if len(benign_rows) >= 100:
            options.append(name)
    if len(options) < 4:
        raise RuntimeError(f"Need four separate benign calibration captures in {dataset}; found {len(options)} for {heldout}")
    # Greedy farthest-point selection of benign feature medians. This sees only
    # non-held-out capture rows and reserves the selected captures from fitting.
    medians = np.vstack([
        captures[name].loc[captures[name]["__type"].eq("Benign"), FEATURES].median().to_numpy(dtype=float)
        for name in options
    ])
    center = np.nanmedian(medians, axis=0)
    scale = np.nanmedian(np.abs(medians - center), axis=0)
    scale[~np.isfinite(scale) | (scale == 0)] = 1.0
    z = np.nan_to_num((medians - center) / scale, nan=0.0, posinf=10.0, neginf=-10.0)
    z = np.clip(z, -10, 10)
    selected = [int(np.argmax(np.linalg.norm(z, axis=1)))]
    while len(selected) < 4:
        distance = np.min(np.linalg.norm(z[:, None, :] - z[np.asarray(selected)][None, :, :], axis=2), axis=1)
        distance[selected] = -1
        selected.append(int(np.argmax(distance)))
    return [options[i] for i in selected]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--summarize", action="store_true")
    parser.add_argument("--cap", type=int, default=1000, help="rows per raw label per capture; 1000 reuses the saved seed-42 sample")
    args = parser.parse_args()
    global OUT
    if args.cap != 1000:
        OUT = ROOT / f"experiments/unseen_generalization_20261117/dataset_matched_calibration_cap{args.cap}"
    if not args.summarize:
        run_loco.CAP_PER_RAW_LABEL = args.cap
        run_loco.OUT = OUT
        if args.cap == 1000:
            run_loco.load_captures = load_seed42
        run_loco.build_calibration_pool = dataset_matched_calibration
        original_models = run_loco.models
        run_loco.models = lambda seed, n_classes: {"xgboost": original_models(seed, n_classes)["xgboost"]}
        run_loco.main()

    import numpy as np
    import pandas as pd

    current = pd.read_csv(OUT / "loco_capture_metrics.csv")
    baseline = pd.read_csv(BASELINE_DIR / "loco_capture_metrics.csv")
    current = current[current.model.eq("xgboost")].copy()
    baseline = baseline[baseline.model.eq("xgboost")].copy()
    current["capture_key"] = current.heldout_capture.str.split("__", n=1).str[-1].str.removesuffix(".parquet")
    baseline["dataset"] = baseline.heldout_capture.str.split("__", n=1).str[0]
    baseline["capture_key"] = baseline.heldout_capture.str.split("__", n=1).str[-1]
    baseline = baseline[["capture_key", "dataset", "attack_recall_at_1pct_cal_fpr", "pooled_fpr", "pr_auc_attack",
                         "end_to_end_correct_type_recall", "benign_rows"]].rename(columns={
        "attack_recall_at_1pct_cal_fpr": "baseline_recall",
        "pooled_fpr": "baseline_capture_fpr",
        "pr_auc_attack": "baseline_pr_auc",
        "end_to_end_correct_type_recall": "baseline_correct_type_recall",
        "benign_rows": "baseline_benign_rows",
    })
    paired = current.merge(baseline, on="capture_key", validate="one_to_one")
    if len(paired) != 18:
        raise RuntimeError(f"Expected 18 paired captures; got {len(paired)}")
    positive = paired[paired.attack_rows.gt(0) & paired.baseline_recall.notna()]
    by_dataset = {}
    for dataset, group in paired.groupby("dataset"):
        atk = group[group.attack_rows.gt(0) & group.baseline_recall.notna()]
        by_dataset[dataset] = {
            "captures": int(len(group)),
            "baseline_mean_recall": float(atk.baseline_recall.mean()) if len(atk) else None,
            "candidate_mean_recall": float(atk.attack_recall_at_1pct_cal_fpr.mean()) if len(atk) else None,
            "baseline_mean_capture_fpr": float(group.baseline_capture_fpr.mean()),
            "candidate_mean_capture_fpr": float(group.pooled_fpr.mean()),
            "baseline_worst_capture_fpr": float(group.baseline_capture_fpr.max()),
            "candidate_worst_capture_fpr": float(group.pooled_fpr.max()),
        }
    diff = positive.attack_recall_at_1pct_cal_fpr.to_numpy() - positive.baseline_recall.to_numpy()
    rng = np.random.default_rng(20261118)
    idx = rng.integers(0, len(diff), size=(20_000, len(diff)))
    bootstrap = diff[idx].mean(axis=1)
    paired.to_csv(OUT / "dataset_matched_vs_baseline_capture.csv", index=False)
    current_types = pd.read_csv(OUT / "loco_per_type.csv")
    base_types = pd.read_csv(BASELINE_DIR / "loco_per_type.csv")
    current_types = current_types[current_types.model.eq("xgboost")].copy()
    base_types = base_types[base_types.model.eq("xgboost")].copy()
    type_rows = []
    for attack_type in sorted(set(current_types.attack_type) | set(base_types.attack_type)):
        cur = current_types[current_types.attack_type.eq(attack_type)]
        bas = base_types[base_types.attack_type.eq(attack_type)]
        type_rows.append({
            "attack_type": attack_type,
            "baseline_positive_captures": int(bas.heldout_capture.nunique()),
            "baseline_mean_detected_recall": float(bas.detected_recall.mean()) if len(bas) else None,
            "baseline_mean_correct_type_recall": float(bas.correct_type_recall.mean()) if len(bas) else None,
            "candidate_positive_captures": int(cur.heldout_capture.nunique()),
            "candidate_mean_detected_recall": float(cur.detected_recall.mean()) if len(cur) else None,
            "candidate_mean_correct_type_recall": float(cur.correct_type_recall.mean()) if len(cur) else None,
        })
    pd.DataFrame(type_rows).to_csv(OUT / "dataset_matched_per_type_comparison.csv", index=False)
    summary = {
        "captures": int(len(paired)), "attack_bearing_captures": int(len(positive)),
        "sample_cap_per_raw_label": args.cap,
        "calibration_policy": "For each held-out capture, reserve four same-dataset benign captures chosen by greedy farthest-point coverage of benign feature medians; selection excludes the test capture and uses no test rows. Exclude calibration captures from training; take the maximum per-capture 99th percentile threshold.",
        "baseline_cross_dataset_calibration": {
            "mean_attack_recall": float(positive.baseline_recall.mean()),
            "mean_capture_fpr": float(paired.baseline_capture_fpr.mean()),
            "pooled_fpr": float((paired.baseline_capture_fpr * paired.baseline_benign_rows).sum() / paired.baseline_benign_rows.sum()),
            "worst_capture_fpr": float(paired.baseline_capture_fpr.max()),
            "mean_attack_pr_auc": float(positive.baseline_pr_auc.mean()),
            "mean_correct_type_recall": float(positive.baseline_correct_type_recall.mean()),
        },
        "dataset_matched_calibration_candidate": {
            "mean_attack_recall": float(positive.attack_recall_at_1pct_cal_fpr.mean()),
            "mean_capture_fpr": float(paired.pooled_fpr.mean()),
            "pooled_fpr": float((paired.pooled_fpr * paired.benign_rows).sum() / paired.benign_rows.sum()),
            "worst_capture_fpr": float(paired.pooled_fpr.max()),
            "mean_attack_pr_auc": float(positive.pr_auc_attack.mean()),
            "mean_correct_type_recall": float(positive.end_to_end_correct_type_recall.mean()),
        },
        "paired_recall_difference": {
            "mean": float(diff.mean()), "capture_bootstrap_95ci": [float(np.quantile(bootstrap, .025)), float(np.quantile(bootstrap, .975))],
        },
        "by_dataset": by_dataset,
        "limitations": [f"One seed, {args.cap}-row cap, and the same 18 captures; exploratory only.",
                        "This calibration-pool selection was formulated after observing dataset-specific FPR drift; treat it as a follow-up exploratory candidate, not a preregistered confirmatory result.",
                        "Dataset identity is known for offline evaluation; this does not calibrate an unknown future dataset.",
                        "No production model, decision threshold, or existing report was changed."],
    }
    (OUT / "dataset_matched_calibration_comparison.json").write_text(json.dumps(summary, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
