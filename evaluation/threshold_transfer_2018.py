"""Capture-held-out benign-only threshold transfer on CSE-CIC-IDS2018.

No model is fitted or modified. Each fold chooses a threshold from benign
scores in five whole captures and evaluates the other five captures, then
swaps the folds. Scores are raw classifier outputs; the 99th benign percentile
targets about 1% calibration FPR. Test FPR is reported, never tuned.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (average_precision_score, confusion_matrix,
                             f1_score, precision_score, recall_score,
                             roc_auc_score)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from evaluation.production_model_validation import sample_capture, canonical_family
from detection import model_predictor

DATA = ROOT / "data" / "raw" / "CSE_CIC_IDS2018"
OUT = ROOT / "reports" / "threshold_transfer_2018" / "threshold_transfer.json"
CAP = 5000
SEED = 20261011
TARGET_FPR = 0.01
FOLD_A = {
    "Botnet-Friday-02-03-2018_TrafficForML_CICFlowMeter.parquet",
    "DDoS1-Tuesday-20-02-2018_TrafficForML_CICFlowMeter.parquet",
    "DoS1-Thursday-15-02-2018_TrafficForML_CICFlowMeter.parquet",
    "Infil1-Wednesday-28-02-2018_TrafficForML_CICFlowMeter.parquet",
    "Web1-Thursday-22-02-2018_TrafficForML_CICFlowMeter.parquet",
}


def _threshold_at_fpr(benign_scores: np.ndarray, target_fpr: float) -> float:
    """Choose the lowest empirical threshold whose tied-score FPR is <= target."""
    ordered = np.sort(np.asarray(benign_scores, dtype=float))
    if not len(ordered):
        raise ValueError("Cannot calibrate a threshold without benign scores")
    allowed_false_positives = int(np.floor(target_fpr * len(ordered)))
    boundary_index = len(ordered) - allowed_false_positives - 1
    # Strictly step above the boundary value so ties cannot push calibration
    # false positives over budget. Scores are classified with >= threshold.
    return float(np.nextafter(ordered[boundary_index], np.inf))


def _predict_scores(frame: pd.DataFrame, model) -> np.ndarray:
    x = model_predictor.prepare_input(frame[model_predictor.FEATURE_NAMES])
    positive = list(model.classes_).index(1)
    return np.asarray(model.predict_proba(x)[:, positive], dtype=float)


def _metrics(frame: pd.DataFrame, scores: np.ndarray, threshold: float) -> dict:
    y = (frame["__raw_label"].map(canonical_family) != "Benign").to_numpy(dtype=int)
    pred = (scores >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "rows": int(len(y)), "attack_rows": int(y.sum()), "threshold": float(threshold),
        "recall_attack": float(recall_score(y, pred, zero_division=0)),
        "precision_attack": float(precision_score(y, pred, zero_division=0)),
        "f1_attack": float(f1_score(y, pred, zero_division=0)),
        "false_positive_rate": float(fp / max(1, fp + tn)),
        "roc_auc": float(roc_auc_score(y, scores)) if len(np.unique(y)) == 2 else None,
        "average_precision": float(average_precision_score(y, scores)) if y.sum() else None,
        "confusion_matrix_tn_fp_fn_tp": [int(tn), int(fp), int(fn), int(tp)],
        "family_recall": {
            family: float(recall_score((frame["__raw_label"].map(canonical_family) == family).to_numpy(), pred,
                                       zero_division=0))
            for family in sorted(set(frame["__raw_label"].map(canonical_family)) - {"Benign"})
        },
    }


def _pool_family_metrics(rows: list[tuple[str, pd.DataFrame, np.ndarray]]) -> dict:
    combined = pd.concat([part[1] for part in rows], ignore_index=True)
    predictions = np.concatenate([part[2] for part in rows])
    labels = combined["__raw_label"].map(canonical_family)
    output = {}
    for family in sorted(set(labels) - {"Benign"}):
        mask = (labels == family).to_numpy()
        output[family] = {"attack_rows": int(mask.sum()),
                          "recall": float(recall_score(np.ones(mask.sum()), predictions[mask], zero_division=0)),
                          "captures": sorted({name for name, frame, _ in rows
                                              if (frame["__raw_label"].map(canonical_family) == family).any()})}
    benign = labels.eq("Benign").to_numpy()
    output["Benign"] = {"rows": int(benign.sum()),
                        "false_positive_rate": float(predictions[benign].mean()) if benign.any() else None}
    return output


def main() -> int:
    files = sorted(DATA.glob("*.parquet"))
    if len(files) != 10:
        raise ValueError(f"Expected 10 CSE-CIC-IDS2018 captures, found {len(files)}")
    names = {path.name for path in files}
    if FOLD_A - names or len(FOLD_A) != 5:
        raise ValueError("Fold A manifest does not match the available captures")
    fold_files = {"A": [p for p in files if p.name in FOLD_A],
                  "B": [p for p in files if p.name not in FOLD_A]}
    samples = {}
    sample_audit = {}
    for index, path in enumerate(files):
        frame, audit = sample_capture(path, CAP, 20000, SEED + index)
        if frame.empty or not (frame["__raw_label"].map(canonical_family) == "Benign").any():
            raise ValueError(f"Capture is missing usable benign or labeled rows: {path.name}")
        samples[path.name] = frame
        sample_audit[path.name] = audit
        print(f"Sampled {path.name}: {len(frame)} rows")

    models = {"random_forest": model_predictor.rf_binary,
              "xgboost": model_predictor.xgb_binary}
    scores = {model: {name: _predict_scores(frame, estimator) for name, frame in samples.items()}
              for model, estimator in models.items()}
    report = {
        "schema": "benign-only-capture-heldout-threshold-transfer-v1",
        "dataset": "CSE-CIC-IDS2018",
        "production_model_version": model_predictor.MODEL_ARTIFACT_VERSION,
        "production_artifacts_modified": False,
        "threshold_method": "99th percentile of raw scores for benign calibration flows only",
        "target_calibration_fpr": TARGET_FPR,
        "test_threshold_tuning": False,
        "sampling_cap_per_raw_label_per_capture": CAP,
        "folds": {},
        "out_of_fold_by_capture": {},
        "out_of_fold_per_family": {},
        "limitations": [
            "This is a fixed two-fold capture split, not a guarantee of performance on future networks.",
            "The 1% target is for pooled calibration benign samples; test FPR may differ and is reported without adjustment.",
            "Rows are sampled by raw label, so precision and alert volume do not estimate deployment prevalence.",
            "Per-family metrics are descriptive; some families occur in only one capture and have no replication across captures.",
        ],
    }

    pooled = {model: [] for model in models}
    for fold, calibration_files in fold_files.items():
        test_fold = "B" if fold == "A" else "A"
        testing_files = fold_files[test_fold]
        report["folds"][fold] = {
            "calibration_captures": [p.name for p in calibration_files],
            "test_captures": [p.name for p in testing_files],
            "models": {},
        }
        for model_name, estimator in models.items():
            cal_benign_scores = np.concatenate([
                scores[model_name][p.name][
                    samples[p.name]["__raw_label"].map(canonical_family).to_numpy() == "Benign"
                ] for p in calibration_files
            ])
            threshold = _threshold_at_fpr(cal_benign_scores, TARGET_FPR)
            actual_cal_fpr = float(np.mean(cal_benign_scores >= threshold))
            if actual_cal_fpr > TARGET_FPR:
                raise AssertionError("Calibrated threshold exceeded the requested benign FPR")
            fold_result = {"threshold": threshold,
                           "calibration_benign_rows": int(len(cal_benign_scores)),
                           "calibration_fpr": actual_cal_fpr,
                           "test": {"existing_0_5_threshold": {}, "benign_calibrated_threshold": {}}}
            for path in testing_files:
                frame = samples[path.name]
                flow_scores = scores[model_name][path.name]
                existing = _metrics(frame, flow_scores, 0.5)
                calibrated = _metrics(frame, flow_scores, threshold)
                fold_result["test"]["existing_0_5_threshold"][path.name] = existing
                fold_result["test"]["benign_calibrated_threshold"][path.name] = calibrated
                pred = (flow_scores >= threshold).astype(int)
                pooled[model_name].append((path.name, frame, pred))
                report["out_of_fold_by_capture"].setdefault(path.name, {})[model_name] = calibrated
            report["folds"][fold]["models"][model_name] = fold_result

    for model_name, rows in pooled.items():
        report["out_of_fold_per_family"][model_name] = _pool_family_metrics(rows)
    report["sampling_audit"] = sample_audit
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Report: {OUT}")
    for model_name, families in report["out_of_fold_per_family"].items():
        print(model_name, json.dumps(families, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
