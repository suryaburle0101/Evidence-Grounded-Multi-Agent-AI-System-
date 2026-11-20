"""
Train dedicated Infiltration and Heartbleed detectors.

Run from E:\\Local Disk\\cyber:
    python train_rare_family_models.py

For each family it:
  1. builds a dataset: ALL positive flows + sampled negatives
     (Benign and every other attack class)
  2. runs 5-fold stratified cross-validation (out-of-fold scores)
  3. picks the lowest threshold whose false-positive rate on the
     negatives stays under TARGET_FPR
  4. trains the final model on all data and saves it to models/

READ THE CV NUMBERS SKEPTICALLY: Heartbleed has ~11 near-identical
flows and Infiltration ~36, so results are optimistic. Confirm on
CSE-CIC-IDS2018 / UNSW-NB15 later.
"""

import re
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_predict

warnings.filterwarnings("ignore")

from detection.rare_family_detector import clean_features, model_path, MODEL_DIR

DATA_DIR = Path("data/raw/CICIDS2017")
TARGETS = {"Infiltration": "infiltration", "Heartbleed": "heartbleed"}

BENIGN_CAP = 100_000
OTHER_CAP = 10_000
TARGET_FPR = 0.002        # max 0.2% of negatives flagged
SEED = 42


def normalize(v):
    return " ".join(re.sub(r"[^a-z0-9]+", " ", str(v).lower()).split())


def load_all():
    frames = []
    rng = np.random.RandomState(SEED)
    for path in sorted(DATA_DIR.glob("*.parquet")):
        df = pd.read_parquet(path)
        if "Label" not in df.columns:
            continue
        df["_lab"] = df["Label"].astype(str).map(normalize)
        for lab, grp in df.groupby("_lab"):
            keep_all = lab in TARGETS.values()
            cap = None if keep_all else (
                BENIGN_CAP if lab == "benign" else OTHER_CAP
            )
            if cap is not None and len(grp) > cap:
                grp = grp.sample(n=cap, random_state=rng)
            frames.append(grp)
        print(f"  loaded {path.name}")
    data = pd.concat(frames, ignore_index=True)
    return data


def pick_threshold(y, p, target_fpr):
    neg, pos = p[y == 0], p[y == 1]
    for t in np.arange(0.05, 1.0, 0.01):
        fpr = float((neg >= t).mean())
        if fpr <= target_fpr:
            return round(float(t), 2), fpr, float((pos >= t).mean())
    t = 0.99
    return t, float((neg >= t).mean()), float((pos >= t).mean())


def main():
    MODEL_DIR.mkdir(exist_ok=True)
    print("Loading data ...")
    data = load_all()

    feature_cols = [
        c for c in data.columns
        if c not in ("Label", "_lab")
        and pd.api.types.is_numeric_dtype(data[c])
    ]
    X_all = clean_features(data[feature_cols])
    labels = data["_lab"].values
    print(f"\nDataset: {len(X_all)} rows, {len(feature_cols)} features")

    for family, key in TARGETS.items():
        print("\n" + "=" * 80)
        print(family.upper())
        print("=" * 80)

        y = (labels == key).astype(int)
        n_pos = int(y.sum())
        print(f"positives={n_pos}  negatives={len(y) - n_pos}")
        if n_pos < 5:
            print("Too few positives, skipping.")
            continue

        model = RandomForestClassifier(
            n_estimators=150,
            class_weight="balanced_subsample",
            min_samples_leaf=2,
            n_jobs=-1,
            random_state=SEED
        )

        folds = min(5, n_pos)
        cv = StratifiedKFold(n_splits=folds, shuffle=True, random_state=SEED)
        oof = cross_val_predict(
            model, X_all, y, cv=cv, method="predict_proba"
        )[:, 1]

        print("\nOut-of-fold results:")
        print(f"{'thr':>6}{'recall':>10}{'FPR':>10}{'FP count':>10}")
        for t in (0.3, 0.5, 0.7, 0.8, 0.9):
            rec = (oof[y == 1] >= t).mean()
            fpr = (oof[y == 0] >= t).mean()
            fp = int((oof[y == 0] >= t).sum())
            print(f"{t:>6.2f}{rec:>10.1%}{fpr:>10.3%}{fp:>10}")

        thr, fpr, rec = pick_threshold(y, oof, TARGET_FPR)
        print(f"\nChosen threshold = {thr}  "
              f"(recall={rec:.1%}, FPR={fpr:.3%}, target<={TARGET_FPR:.1%})")

        # Which other classes cause the false positives?
        fp_mask = (y == 0) & (oof >= thr)
        if fp_mask.any():
            fp_labels = pd.Series(labels[fp_mask]).value_counts()
            print("False positives came from:", dict(fp_labels.head(5)))

        model.fit(X_all, y)
        joblib.dump(
            {"model": model, "features": feature_cols,
             "threshold": thr, "family": family,
             "cv_recall": rec, "cv_fpr": fpr},
            model_path(family)
        )
        print(f"Saved -> {model_path(family)}")

    print("\nDone.")


if __name__ == "__main__":
    main()