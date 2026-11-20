"""Research-only 12-class one-vs-rest candidate on existing capture samples.

Each class detector gets a Bonferroni calibration budget (1% / 12) using only
separate benign capture(s). Test captures are never used to fit thresholds or
models. Outputs are written beside this script, never to production folders.
"""
from __future__ import annotations

import json
import math
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
SEED = 42
TARGET_UNION_FPR = 0.01
CALIBRATION_FPR_PER_CLASS = TARGET_UNION_FPR / 12
ATTACKS = [
    "Botnet", "DDoS", "DoS-GoldenEye", "DoS-Hulk", "DoS-SlowHTTPTest",
    "DoS-Slowloris", "FTP-BruteForce", "Infiltration", "SQL-Injection",
    "SSH-BruteForce", "Web-BruteForce", "Web-XSS",
]

from evaluation import ten_type_candidate as project  # noqa: E402
from experiments.family_design_20261116.evaluate_families import (  # noqa: E402
    choose_calibration,
    read_seed,
)
from pipeline.data_pipeline import FEATURES  # noqa: E402


def hashes(frame: pd.DataFrame) -> pd.Series:
    return pd.util.hash_pandas_object(frame[FEATURES], index=False)


def without_cross_split_duplicates(train, cal, test):
    test_hashes = set(hashes(test))
    cal_hashes = set(hashes(cal))
    train_hashes = hashes(train)
    train_keep = ~train_hashes.isin(test_hashes | cal_hashes)
    cal_keep = ~hashes(cal).isin(test_hashes)
    removed_train = int((~train_keep).sum())
    removed_cal = int((~cal_keep).sum())
    return (train.loc[train_keep].reset_index(drop=True),
            cal.loc[cal_keep].reset_index(drop=True), removed_train, removed_cal)


def new_model(seed: int, pos: int, neg: int) -> XGBClassifier:
    return XGBClassifier(
        objective="binary:logistic", eval_metric="logloss", n_estimators=60,
        max_depth=4, learning_rate=0.08, min_child_weight=3,
        subsample=0.85, colsample_bytree=0.85, tree_method="hist",
        scale_pos_weight=max(1.0, neg / max(1, pos)), random_state=seed, n_jobs=1,
    )


def summarize_existing() -> None:
    metrics = pd.read_csv(OUT / "ovr_loco_capture_metrics.csv")
    types = pd.read_csv(OUT / "ovr_loco_per_type.csv")
    base_dir = ROOT / "experiments/failing_types_20261113/seed_42/multiclass_77"
    baseline = pd.read_csv(base_dir / "loco_capture_metrics.csv").query("model == 'xgboost'")
    baseline_types = pd.read_csv(base_dir / "loco_per_type.csv").query("model == 'xgboost'")
    positive = metrics[metrics.attack_rows.gt(0)]
    base_positive = baseline[baseline.attack_rows.gt(0)]
    paired = positive.merge(
        base_positive[["heldout_capture", "attack_recall_at_1pct_cal_fpr"]],
        on="heldout_capture", how="inner",
    )
    differences = (paired.attack_recall - paired.attack_recall_at_1pct_cal_fpr).to_numpy()
    rng = np.random.default_rng(20261117)
    indices = rng.integers(0, len(differences), size=(20_000, len(differences)))
    bootstrap = differences[indices].mean(axis=1)
    base_correct_mean = float(base_positive.end_to_end_correct_type_recall.mean())
    type_macro_ovr = float(types.groupby("attack_type").correct_type_recall.mean().mean())
    type_macro_base = float(baseline_types.groupby("attack_type").correct_type_recall.mean().mean())
    result = {
        "baseline_matched_seed42": {
            "attack_recall_mean_capture": float(base_positive.attack_recall_at_1pct_cal_fpr.mean()),
            "attack_recall_pooled_rows": float(np.average(base_positive.attack_recall_at_1pct_cal_fpr, weights=base_positive.attack_rows)),
            "correct_type_recall_mean_capture": base_correct_mean,
            "correct_type_recall_macro_12_types": type_macro_base,
            "mean_capture_fpr": float(baseline.pooled_fpr.mean()),
            "pooled_fpr": float(np.average(baseline.pooled_fpr, weights=baseline.benign_rows)),
            "worst_capture_fpr": float(baseline.pooled_fpr.max()),
            "attack_pr_auc_mean_capture": float(base_positive.pr_auc_attack.mean()),
        },
        "one_vs_rest_candidate": {
            "attack_recall_mean_capture": float(positive.attack_recall.mean()),
            "attack_recall_pooled_rows": float(np.average(positive.attack_recall, weights=positive.attack_rows)),
            "correct_type_recall_mean_capture": float(positive.correct_type_recall.mean()),
            "correct_type_recall_macro_12_types": type_macro_ovr,
            "mean_capture_fpr": float(metrics.capture_fpr.mean()),
            "pooled_fpr": float(np.average(metrics.capture_fpr, weights=metrics.benign_rows)),
            "worst_capture_fpr": float(metrics.capture_fpr.max()),
            "attack_pr_auc_mean_capture": float(positive.attack_pr_auc.mean()),
        },
        "paired_capture_bootstrap_attack_recall_difference": {
            "candidate_minus_baseline_mean": float(differences.mean()),
            "ci95_low": float(np.quantile(bootstrap, 0.025)),
            "ci95_high": float(np.quantile(bootstrap, 0.975)),
            "attack_bearing_captures": int(len(differences)),
            "bootstrap_replicates": 20_000,
            "seed": 20261117,
            "interpretation": "Exploratory single-seed capture bootstrap; interval includes zero.",
        },
    }
    (OUT / "ovr_loco_comparison.json").write_text(
        json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, indent=2), flush=True)


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--summarize", action="store_true", help="Rebuild matched comparison from completed CSV outputs without refitting models")
    if parser.parse_args().summarize:
        summarize_existing()
        return
    captures = read_seed(SEED)
    capture_rows, type_rows, confusion_rows, calibration_rows = [], [], [], []
    for fold, heldout in enumerate(captures, 1):
        print(f"[{fold}/18] {heldout}: load fold", flush=True)
        cal_names = choose_calibration(captures, heldout)
        train_names = [n for n in captures if n not in {heldout, *cal_names}]
        train = pd.concat([captures[n] for n in train_names], ignore_index=True)
        cal = pd.concat([
            captures[n].loc[captures[n]["__type"].eq("Benign")].copy()
            for n in cal_names
        ], ignore_index=True)
        test = captures[heldout].copy()
        train, cal, removed_train, removed_cal = without_cross_split_duplicates(train, cal, test)
        y_train = train["__type"].to_numpy()
        y_test = test["__type"].to_numpy()
        benign_cal = cal["__type"].eq("Benign").to_numpy()
        if not benign_cal.any():
            raise RuntimeError(f"No benign calibration rows for {heldout}")

        probabilities = np.full((len(test), len(ATTACKS)), np.nan, dtype=np.float32)
        thresholds = np.full(len(ATTACKS), np.inf, dtype=float)
        for j, attack in enumerate(ATTACKS):
            positive = y_train == attack
            pos = int(positive.sum())
            neg = int(len(positive) - pos)
            if not pos or not neg:
                continue
            model = new_model(SEED, pos, neg)
            model.fit(train[FEATURES], positive.astype(np.uint8))
            cal_scores = model.predict_proba(cal.loc[benign_cal, FEATURES])[:, 1]
            by_capture = {}
            limits = []
            benign_cal_frame = cal.loc[benign_cal]
            for cal_name in cal_names:
                mask = benign_cal_frame["__capture"].eq(cal_name).to_numpy()
                vals = cal_scores[mask]
                q = float(np.quantile(vals, 1 - CALIBRATION_FPR_PER_CLASS, method="higher"))
                threshold = float(np.nextafter(q, math.inf))
                limits.append(threshold)
                by_capture[cal_name] = {
                    "benign_rows": int(len(vals)), "threshold": threshold,
                    "observed_fpr": float(np.mean(vals >= threshold)),
                }
            thresholds[j] = max(limits)
            probabilities[:, j] = model.predict_proba(test[FEATURES])[:, 1]
            calibration_rows.append({
                "heldout_capture": heldout, "class": attack,
                "calibration_threshold": thresholds[j],
                "calibration_by_capture": json.dumps(by_capture, sort_keys=True),
            })
            del model

        valid = np.isfinite(probabilities).all(axis=1)
        if not valid.all():
            raise RuntimeError(f"Missing trained class detector in fold {heldout}")
        fired = probabilities >= thresholds.reshape(1, -1)
        flagged = fired.any(axis=1)
        scaled_probabilities = probabilities / np.maximum(thresholds.reshape(1, -1), 1e-12)
        normalized = scaled_probabilities.copy()
        normalized[~fired] = -np.inf
        predicted = np.asarray(ATTACKS, dtype=object)[np.argmax(normalized, axis=1)]
        is_attack = np.isin(y_test, ATTACKS)
        benign = y_test == "Benign"
        attack_score = scaled_probabilities.max(axis=1)
        capture_rows.append({
            "heldout_capture": heldout, "calibration_captures": ";".join(cal_names),
            "train_rows": int(len(train)), "test_rows": int(len(test)),
            "train_test_or_cal_duplicate_vectors_removed": removed_train,
            "cal_test_duplicate_vectors_removed": removed_cal,
            "attack_rows": int(is_attack.sum()), "benign_rows": int(benign.sum()),
            "attack_recall": float(flagged[is_attack].mean()) if is_attack.any() else None,
            "correct_type_recall": float(((predicted == y_test) & flagged & is_attack).sum() / is_attack.sum()) if is_attack.any() else None,
            "capture_fpr": float(flagged[benign].mean()) if benign.any() else None,
            "attack_pr_auc": float(average_precision_score(is_attack.astype(int), attack_score)) if is_attack.any() and benign.any() else None,
            "calibration_fpr_target_per_detector": CALIBRATION_FPR_PER_CLASS,
        })
        output = np.where(flagged, predicted, "NOT_FLAGGED")
        matrix = pd.crosstab(pd.Series(y_test, name="actual"), pd.Series(output, name="output"))
        for actual, row in matrix.iterrows():
            for out, count in row.items():
                if count:
                    confusion_rows.append({"heldout_capture": heldout, "actual": actual, "output": out, "count": int(count)})
        for j, attack in enumerate(ATTACKS):
            mask = y_test == attack
            if not mask.any():
                continue
            type_rows.append({
                "heldout_capture": heldout, "attack_type": attack,
                "support": int(mask.sum()),
                "detected_recall_any_label": float(flagged[mask].mean()),
                "correct_type_recall": float(((predicted[mask] == attack) & flagged[mask]).mean()),
                "one_vs_rest_detector_recall": float(fired[mask, j].mean()),
                "one_vs_rest_pr_auc": float(average_precision_score(mask.astype(int), probabilities[:, j])),
            })
        recall_text = (f"{capture_rows[-1]['attack_recall']:.3f}"
                       if capture_rows[-1]["attack_recall"] is not None else "n/a")
        print(f"[{fold}/18] {heldout}: recall={recall_text}, FPR={capture_rows[-1]['capture_fpr']}", flush=True)

    metrics = pd.DataFrame(capture_rows)
    types = pd.DataFrame(type_rows)
    metrics.to_csv(OUT / "ovr_loco_capture_metrics.csv", index=False)
    types.to_csv(OUT / "ovr_loco_per_type.csv", index=False)
    pd.DataFrame(confusion_rows).to_csv(OUT / "ovr_loco_confusion.csv", index=False)
    pd.DataFrame(calibration_rows).to_csv(OUT / "ovr_loco_thresholds.csv", index=False)

    positive = metrics[metrics.attack_rows.gt(0)]
    baseline = pd.read_csv(ROOT / "experiments/failing_types_20261113/seed_42/multiclass_77/loco_capture_metrics.csv")
    baseline = baseline[baseline.model.eq("xgboost")].set_index("heldout_capture")
    paired = metrics.set_index("heldout_capture").join(
        baseline[["attack_recall_at_1pct_cal_fpr", "pooled_fpr"]].rename(columns={
            "attack_recall_at_1pct_cal_fpr": "baseline_attack_recall",
            "pooled_fpr": "baseline_fpr",
        }), how="left"
    ).reset_index()
    paired.to_csv(OUT / "ovr_loco_vs_multiclass.csv", index=False)
    summary = {
        "task": "12 one-vs-rest XGBoost detectors, capture-held-out evaluation",
        "seed": SEED, "sample_source": "Existing seed-42 capture samples capped at 1,000 rows per raw label per capture",
        "capture_count": int(len(metrics)), "attack_bearing_captures": int(len(positive)),
        "calibration_target_union_fpr": TARGET_UNION_FPR,
        "per_detector_bonferroni_calibration_target": CALIBRATION_FPR_PER_CLASS,
        "attack_recall_mean_capture": float(positive.attack_recall.mean()) if len(positive) else None,
        "attack_recall_sd_capture": float(positive.attack_recall.std(ddof=1)) if len(positive) > 1 else None,
        "attack_recall_pooled_rows": float(positive.attack_rows.mul(positive.attack_recall).sum() / positive.attack_rows.sum()) if positive.attack_rows.sum() else None,
        "correct_type_recall_mean_capture": float(positive.correct_type_recall.mean()) if len(positive) else None,
        "mean_capture_fpr": float(metrics.capture_fpr.dropna().mean()),
        "pooled_fpr": float(metrics.loc[metrics.capture_fpr.notna(), "capture_fpr"].mul(metrics.loc[metrics.capture_fpr.notna(), "benign_rows"]).sum() / metrics.benign_rows.sum()),
        "worst_capture_fpr": float(metrics.capture_fpr.max()),
        "attack_pr_auc_mean_capture": float(positive.attack_pr_auc.mean()) if len(positive) else None,
        "baseline_attack_recall_mean_capture": float(baseline.loc[positive.heldout_capture, "attack_recall_at_1pct_cal_fpr"].mean()),
        "baseline_worst_capture_fpr": float(baseline.pooled_fpr.max()),
        "ovr_worst_capture_fpr": float(metrics.capture_fpr.max()),
        "interpretation": "One-seed reduced-sample exploratory result. Calibration thresholds use separate benign capture(s) only. No model artifact was promoted.",
        "summary_by_type": types.groupby("attack_type").agg(
            captures=("heldout_capture", "nunique"),
            mean_detected_recall=("detected_recall_any_label", "mean"),
            mean_correct_type_recall=("correct_type_recall", "mean"),
            mean_one_vs_rest_pr_auc=("one_vs_rest_pr_auc", "mean"),
        ).reset_index().to_dict(orient="records"),
        "limitations": [
            "Only one seed was run to fit within the machine's current memory headroom.",
            "The existing capture inventory has only two or three positive capture files for most requested types.",
            "Threshold quantiles for each detector use a small calibration sample and are noisy.",
            "This candidate does not change or replace active production models.",
        ],
    }
    (OUT / "ovr_loco_report.json").write_text(json.dumps(summary, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    summarize_existing()
    print(json.dumps({k: summary[k] for k in (
        "attack_recall_mean_capture", "correct_type_recall_mean_capture", "mean_capture_fpr",
        "pooled_fpr", "worst_capture_fpr", "attack_pr_auc_mean_capture",
        "baseline_attack_recall_mean_capture", "baseline_worst_capture_fpr",
    )}, indent=2), flush=True)


if __name__ == "__main__":
    main()
