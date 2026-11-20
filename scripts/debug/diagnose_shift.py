"""
Why does the 2017-trained pipeline fail on 2018?

For 4 matched groups (Benign, Bot, DoS Hulk, Infiltration) this
compares CICIDS2017 vs CSE-CIC-IDS2018:
  1. which features shifted most (median difference / 2017 spread)
  2. what the ML models predict on each set (attack probability)

Run from E:\\Local Disk\\cyber:
    python diagnose_shift.py
"""

import re
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")

from agents.detection_agent import detection_agent
from agents.investigation_agent import investigation_agent
from detection.rare_family_detector import clean_features

D17 = Path("data/raw/CICIDS2017")
D18 = Path("data/raw/CSE_CIC_IDS2018")
FEATURES = joblib.load("models/rare_infiltration.pkl")["features"]
COLMAP = {re.sub(r"[^a-z0-9]+", "", f.lower()): f for f in FEATURES}

N_STATS = 3000     # flows used for feature statistics
N_MODEL = 40       # flows run through the models

GROUPS = [
    ("Benign",
     (D17 / "Benign-Monday-no-metadata.parquet", "benign"),
     (D18 / "Infil2-Thursday-01-03-2018_TrafficForML_CICFlowMeter.parquet",
      "benign")),
    ("Bot",
     (D17 / "Botnet-Friday-no-metadata.parquet", "bot"),
     (D18 / "Botnet-Friday-02-03-2018_TrafficForML_CICFlowMeter.parquet",
      "bot")),
    ("DoS Hulk",
     (D17 / "DoS-Wednesday-no-metadata.parquet", "dos hulk"),
     (D18 / "DoS2-Friday-16-02-2018_TrafficForML_CICFlowMeter.parquet",
      "dos attacks hulk")),
    ("Infiltration",
     (D17 / "Infiltration-Thursday-no-metadata.parquet", "infiltration"),
     (D18 / "Infil2-Thursday-01-03-2018_TrafficForML_CICFlowMeter.parquet",
      "infilteration")),
]


def norm(v):
    return " ".join(re.sub(r"[^a-z0-9]+", " ", str(v).lower()).split())


def load(path, label, year, n):
    df = pd.read_parquet(path)
    lab_col = next(c for c in df.columns
                   if re.sub(r"[^a-z0-9]", "", c.lower()) == "label")
    df = df[df[lab_col].astype(str).map(norm) == label]
    if len(df) > n:
        df = df.sample(n=n, random_state=1)
    if year == 2018:
        df = df.rename(columns={c: COLMAP[re.sub(r"[^a-z0-9]+", "", c.lower())]
                                for c in df.columns
                                if re.sub(r"[^a-z0-9]+", "", c.lower())
                                in COLMAP})
    return df[FEATURES]


def run_models(X):
    probs, fams = [], []
    for i in range(len(X)):
        row = X.iloc[[i]]
        det = detection_agent.analyze(row)
        inv = investigation_agent.analyze(det)
        probs.append(float(inv.get("average_attack_probability", 0.0)))
        fams.append(det.get("predicted_attack"))
    return np.array(probs), pd.Series(fams).value_counts().to_dict()


def main():
    for name, (p17, l17), (p18, l18) in GROUPS:
        print("\n" + "=" * 96)
        print(name.upper())
        print("=" * 96)

        a = load(p17, l17, 2017, N_STATS)
        b = load(p18, l18, 2018, N_STATS)
        print(f"flows: 2017={len(a)}  2018={len(b)}")

        A, B = clean_features(a), clean_features(b)
        med_a, med_b = A.median(), B.median()
        iqr_a = (A.quantile(0.75) - A.quantile(0.25)).abs()
        scale = iqr_a.where(iqr_a > 0, A.std()).replace(0, np.nan)
        shift = ((med_b - med_a) / scale).replace([np.inf, -np.inf], np.nan)
        shift = shift.fillna(0.0)

        big = int((shift.abs() > 1).sum())
        print(f"features with |median shift| > 1 x 2017 spread: "
              f"{big}/{len(FEATURES)}")
        top = shift.abs().sort_values(ascending=False).head(10).index
        print(f"{'feature':<32}{'2017 median':>16}{'2018 median':>16}"
              f"{'shift':>9}")
        for f in top:
            print(f"{f:<32}{med_a[f]:>16.4g}{med_b[f]:>16.4g}"
                  f"{shift[f]:>9.2f}")

        pa, fa = run_models(a.head(N_MODEL))
        pb, fb = run_models(b.head(N_MODEL))
        print(f"\nModel avg attack probability: "
              f"2017={pa.mean():.3f}   2018={pb.mean():.3f}")
        print(f"Predicted family 2017: {fa}")
        print(f"Predicted family 2018: {fb}")

    print("\nDone. Paste this whole output back.")


if __name__ == "__main__":
    main()