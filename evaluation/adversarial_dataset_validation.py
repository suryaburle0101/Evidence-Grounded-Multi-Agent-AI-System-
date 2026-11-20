"""Grouped adversarial validation: distinguish benign 2017 vs 2018 flows.

This is a dataset-shift diagnostic only. It does not train or update an attack
detector and feature importance does not establish why two datasets differ.
Each fold holds out complete capture files from both datasets.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from evaluation.production_model_validation import sample_capture, canonical_family
from detection import model_predictor

RAW = ROOT / "data" / "raw"
OUT = ROOT / "reports" / "adversarial_validation" / "benign_dataset_shift.json"
CAP = 3000
SEED = 20261011
FOLDS = 5


def main() -> int:
    groups = []
    frames = []
    audit = []
    for dataset, folder, domain in (
        ("CICIDS2017", RAW / "CICIDS2017", 0),
        ("CSE-CIC-IDS2018", RAW / "CSE_CIC_IDS2018", 1),
    ):
        paths = sorted(folder.glob("*.parquet"))
        if not paths:
            raise FileNotFoundError(f"No parquet captures found in {folder}")
        for index, path in enumerate(paths):
            sampled, info = sample_capture(path, CAP, 20000, SEED + domain * 100 + index)
            benign = sampled.loc[sampled["__raw_label"].map(canonical_family) == "Benign"].copy()
            if benign.empty:
                raise ValueError(f"No benign flows sampled from {path.name}")
            benign["__dataset"] = domain
            benign["__capture"] = f"{dataset}/{path.name}"
            frames.append(benign)
            audit.append({"dataset": dataset, "capture": path.name,
                          "benign_rows": int(len(benign)),
                          "rows_scanned": info.get("rows_scanned"),
                          "sampling_method": info.get("sampling")})
            print(f"Sampled {dataset}/{path.name}: {len(benign)} benign flows")

    data = pd.concat(frames, ignore_index=True)
    features = model_predictor.FEATURE_NAMES
    x = data[features].astype(float)
    y = data["__dataset"].to_numpy(dtype=int)
    group = data["__capture"].to_numpy(dtype=str)
    cv = StratifiedGroupKFold(n_splits=FOLDS, shuffle=True, random_state=SEED)
    oof = np.full(len(data), np.nan, dtype=float)
    fold_results = []
    importances = []
    for fold, (train_idx, test_idx) in enumerate(cv.split(x, y, group), start=1):
        estimator = RandomForestClassifier(
            n_estimators=250, max_features="sqrt", min_samples_leaf=3,
            class_weight="balanced_subsample", n_jobs=1, random_state=SEED + fold,
        )
        estimator.fit(x.iloc[train_idx], y[train_idx])
        probabilities = estimator.predict_proba(x.iloc[test_idx])[:, list(estimator.classes_).index(1)]
        oof[test_idx] = probabilities
        importances.append(estimator.feature_importances_)
        fold_groups = sorted(set(group[test_idx]))
        fold_results.append({
            "fold": fold,
            "heldout_capture_groups": fold_groups,
            "heldout_rows": int(len(test_idx)),
            "heldout_cicids2017_rows": int((y[test_idx] == 0).sum()),
            "heldout_cse_cic_ids2018_rows": int((y[test_idx] == 1).sum()),
            "roc_auc": float(roc_auc_score(y[test_idx], probabilities)),
            "accuracy_at_0_5": float(accuracy_score(y[test_idx], probabilities >= 0.5)),
        })
    if np.isnan(oof).any():
        raise RuntimeError("Grouped cross-validation did not score every sampled row")

    # Univariate AUCs are computed on the out-of-fold benign sample and show
    # direction/strength of each feature's dataset association.
    univariate = []
    for feature in features:
        auc = float(roc_auc_score(y, x[feature]))
        univariate.append({"feature": feature, "dataset_auc": auc,
                           "separation_from_chance": abs(auc - 0.5)})
    univariate.sort(key=lambda item: item["separation_from_chance"], reverse=True)
    mean_importance = np.mean(np.vstack(importances), axis=0)
    rf_ranked = sorted(
        ({"feature": feature, "mean_random_forest_importance": float(value)}
         for feature, value in zip(features, mean_importance)),
        key=lambda item: item["mean_random_forest_importance"], reverse=True,
    )
    report = {
        "schema": "grouped-benign-adversarial-validation-v1",
        "purpose": "diagnose whether benign CICIDS2017 and CSE-CIC-IDS2018 flows are distinguishable",
        "production_artifacts_modified": False,
        "sampling_cap_per_raw_label_per_capture": CAP,
        "group_split": "5-fold StratifiedGroupKFold; entire capture files held out together",
        "sampled_rows": int(len(data)),
        "sampled_cicids2017_rows": int((y == 0).sum()),
        "sampled_cse_cic_ids2018_rows": int((y == 1).sum()),
        "out_of_fold_roc_auc": float(roc_auc_score(y, oof)),
        "out_of_fold_accuracy_at_0_5": float(accuracy_score(y, oof >= 0.5)),
        "folds": fold_results,
        "top_univariate_features": univariate[:20],
        "top_random_forest_features": rf_ranked[:20],
        "sampling_audit": audit,
        "limitations": [
            "High dataset-classifier AUC means sampled benign rows differ in these features; it does not establish the cause.",
            "Feature rankings are diagnostic associations, not evidence that dropping or normalizing a feature improves attack detection.",
            "Rows are bounded per capture; capture-level generalization is measured, but this is not live-network validation.",
        ],
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Grouped OOF dataset AUC: {report['out_of_fold_roc_auc']:.3f}")
    print("Top shifted features:")
    for entry in univariate[:10]:
        print(f"  {entry['feature']}: AUC={entry['dataset_auc']:.3f}")
    print(f"Report: {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
