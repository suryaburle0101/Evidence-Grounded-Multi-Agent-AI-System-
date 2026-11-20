"""Research-only RF feature ablation for CICIDS2017 -> CSE-CIC-IDS2018.

Trains matched Random Forest candidates on capture-group-separated CICIDS2017
files, calibrates on the held-out Infiltration capture, and evaluates on all
2018 captures. Production artifacts are only read and are never overwritten.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (average_precision_score, brier_score_loss,
                             confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from evaluation.production_model_validation import sample_capture, canonical_family
from detection import model_predictor

DATA = ROOT / "data" / "raw"
OUT = ROOT / "reports" / "feature_ablation_2018" / "feature_ablation.json"
CALIBRATION_FILE = "Infiltration-Thursday-no-metadata.parquet"
TEST_FILES = {"Portscan-Friday-no-metadata.parquet", "WebAttacks-Thursday-no-metadata.parquet"}
SUSPECTS = ["ECE Flag Count", "RST Flag Count", "Fwd Seg Size Min", "Fwd Header Length"]
CAP = 3000
SEED = 20261011


def attack_target(frame: pd.DataFrame) -> np.ndarray:
    return (frame["__raw_label"].map(canonical_family) != "Benign").to_numpy(dtype=int)


def calibrate(model, x: pd.DataFrame, y: np.ndarray):
    raw = model.predict_proba(x)[:, list(model.classes_).index(1)]
    clipped = np.clip(raw, 1e-6, 1 - 1e-6)
    logits = np.log(clipped / (1 - clipped)).reshape(-1, 1)
    calibrator = LogisticRegression(C=1e6, solver="lbfgs", random_state=SEED).fit(logits, y)
    calibrated = calibrator.predict_proba(logits)[:, 1]
    benign = calibrated[y == 0]
    threshold = float(np.quantile(benign, 0.99, method="higher")) if len(benign) else 1.0
    return calibrator, threshold, int(len(benign))


def score(model, calibrator, threshold, frame, features):
    x = frame[features]
    raw = model.predict_proba(x)[:, list(model.classes_).index(1)]
    logits = np.log(np.clip(raw, 1e-6, 1 - 1e-6) / np.clip(1 - raw, 1e-6, 1))
    prob = calibrator.predict_proba(logits.reshape(-1, 1))[:, 1]
    y = attack_target(frame)
    pred = (prob >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "rows": int(len(y)), "attack_rows": int(y.sum()), "threshold": threshold,
        "recall_attack": float(recall_score(y, pred, zero_division=0)),
        "precision_attack": float(precision_score(y, pred, zero_division=0)),
        "f1_attack": float(f1_score(y, pred, zero_division=0)),
        "false_positive_rate": float(fp / max(1, fp + tn)),
        "roc_auc": float(roc_auc_score(y, prob)) if len(np.unique(y)) == 2 else None,
        "average_precision": float(average_precision_score(y, prob)) if y.sum() else None,
        "brier_score": float(brier_score_loss(y, prob)),
        "confusion_matrix_tn_fp_fn_tp": [int(tn), int(fp), int(fn), int(tp)],
    }


def read_sample(path: Path, seed: int) -> pd.DataFrame:
    frame, _ = sample_capture(path, CAP, 20000, seed)
    return frame


def main() -> int:
    names = model_predictor.FEATURE_NAMES
    absent = [feature for feature in SUSPECTS if feature not in names]
    if absent:
        raise ValueError(f"Suspect features not found in active schema: {absent}")
    files = sorted((DATA / "CICIDS2017").glob("*.parquet"))
    calibration_path = DATA / "CICIDS2017" / CALIBRATION_FILE
    train_paths = [p for p in files if p.name not in TEST_FILES | {CALIBRATION_FILE}]
    if not train_paths or not calibration_path.exists():
        raise FileNotFoundError("Expected capture-group files are missing from CICIDS2017")

    train_parts = [read_sample(path, SEED + i) for i, path in enumerate(train_paths)]
    train = pd.concat(train_parts, ignore_index=True).drop_duplicates(
        subset=names + ["__raw_label"]
    )
    calibration = read_sample(calibration_path, SEED + 100)
    y_train, y_cal = attack_target(train), attack_target(calibration)
    if len(np.unique(y_train)) != 2 or len(np.unique(y_cal)) != 2:
        raise ValueError("Training and calibration partitions must contain benign and attack flows")

    results = {"schema": "cicids2017-feature-ablation-external-v1",
               "production_artifacts_modified": False,
               "split": {"train_capture_files": [p.name for p in train_paths],
                         "calibration_capture_file": CALIBRATION_FILE,
                         "external_test": "all CSE-CIC-IDS2018 capture files"},
               "sampling_cap_per_raw_label_per_file": CAP,
               "suspect_features_removed": SUSPECTS,
               "training_rows": int(len(train)), "calibration_rows": int(len(calibration)),
               "calibration_benign_rows": int((y_cal == 0).sum()),
               "models": {}, "heldout_cicids2017": [], "captures": []}

    model_params = model_predictor.rf_binary.get_params(deep=False)
    model_params["n_jobs"] = 1
    candidates = {"all_77_features": names,
                  "without_four_suspects": [n for n in names if n not in SUSPECTS]}
    fitted = {}
    for candidate, features in candidates.items():
        model = type(model_predictor.rf_binary)(**model_params)
        model.fit(train[features], y_train)
        calibrator, threshold, benign_n = calibrate(model, calibration[features], y_cal)
        fitted[candidate] = (model, calibrator, threshold, features)
        results["models"][candidate] = {"feature_count": len(features),
            "calibration_method": "Platt scaling; held-out CICIDS2017 capture",
            "calibration_benign_rows": benign_n,
            "threshold_at_1pct_calibration_benign_fpr": threshold}

    # Keep the calibration capture separate from these within-dataset checks.
    # They show whether its operating threshold transfers across capture days.
    for index, path in enumerate(sorted((DATA / "CICIDS2017").glob("*.parquet"))):
        if path.name not in TEST_FILES:
            continue
        frame = read_sample(path, SEED + 150 + index)
        row = {"capture": path.name, "sample_rows": len(frame)}
        for candidate, (model, calibrator, threshold, features) in fitted.items():
            row[candidate] = score(model, calibrator, threshold, frame, features)
        results["heldout_cicids2017"].append(row)

    external_files = sorted((DATA / "CSE_CIC_IDS2018").glob("*.parquet"))
    if not external_files:
        raise FileNotFoundError("No CSE-CIC-IDS2018 capture files found")
    pooled = {key: [] for key in candidates}
    for index, path in enumerate(external_files):
        frame = read_sample(path, SEED + 200 + index)
        if frame.empty:
            continue
        row = {"capture": path.name, "sample_rows": len(frame)}
        for candidate, (model, calibrator, threshold, features) in fitted.items():
            row[candidate] = score(model, calibrator, threshold, frame, features)
            pooled[candidate].append((frame, model, calibrator, threshold, features))
        results["captures"].append(row)

    results["overall_external"] = {}
    for candidate, parts in pooled.items():
        if parts:
            all_frames = pd.concat([part[0] for part in parts], ignore_index=True)
            model, calibrator, threshold, features = fitted[candidate]
            results["overall_external"][candidate] = score(
                model, calibrator, threshold, all_frames, features)
    results["limitations"] = [
        "Research ablation only; a single CICIDS2017 calibration capture sets the threshold.",
        "External rows are capped per raw label and capture; these are not field prevalence estimates.",
        "Ablation scores do not establish a production fix; independent capture and extractor validation remains necessary.",
    ]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Saved {OUT}")
    for candidate, metrics in results["overall_external"].items():
        print(f"{candidate}: recall={metrics['recall_attack']:.3f}, "
              f"FPR={metrics['false_positive_rate']:.4f}, AUC={metrics['roc_auc']:.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
