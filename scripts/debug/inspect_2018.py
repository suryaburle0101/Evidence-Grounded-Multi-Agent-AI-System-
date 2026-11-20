"""
Inspect the CSE-CIC-IDS2018 files so we can build a held-out test.

Run from E:\\Local Disk\\cyber:
    python inspect_2018.py
"""

import re
import warnings
from pathlib import Path

import joblib
import pandas as pd

warnings.filterwarnings("ignore")

RAW_2018 = Path("data/raw/CSE_CIC_IDS2018")
MODEL = Path("models/rare_infiltration.pkl")


def norm(c):
    return re.sub(r"[^a-z0-9]+", "", str(c).lower())


def read_any(path, nrows=None):
    if path.suffix.lower() == ".parquet":
        df = pd.read_parquet(path)
        return df.head(nrows) if nrows else df
    return pd.read_csv(path, nrows=nrows, low_memory=False)


def main():
    if not RAW_2018.exists():
        print("Folder not found:", RAW_2018.resolve())
        return

    files = sorted(
        p for p in RAW_2018.rglob("*")
        if p.suffix.lower() in (".csv", ".parquet")
    )
    print(f"Found {len(files)} data files in {RAW_2018}\n")

    features = None
    if MODEL.exists():
        features = joblib.load(MODEL)["features"]
        feat_norm = {norm(c): c for c in features}
        print(f"Model expects {len(features)} features (CICIDS2017 names)\n")

    for path in files:
        size_mb = path.stat().st_size / 1e6
        print("=" * 90)
        print(f"{path.name}  ({size_mb:.0f} MB)")
        try:
            df = read_any(path, nrows=200000)
        except Exception as e:
            print("  could not read:", type(e).__name__, e)
            continue

        print(f"  columns: {len(df.columns)}   sampled rows: {len(df)}")

        label_col = next(
            (c for c in df.columns if norm(c) == "label"), None
        )
        if label_col:
            print("  labels (in first 200k rows):")
            for k, v in df[label_col].value_counts().head(12).items():
                print(f"     {v:>8}  {k}")
        else:
            print("  no Label column found")

        if features:
            cols_norm = {norm(c) for c in df.columns}
            matched = [f for f in features if norm(f) in cols_norm]
            print(f"  feature match after name normalisation: "
                  f"{len(matched)}/{len(features)}")
            missing = [f for f in features if norm(f) not in cols_norm]
            if missing:
                print("  missing examples:", missing[:8])
        print("  first columns:", list(df.columns)[:8])

    print("\nDone. Paste this whole output back.")


if __name__ == "__main__":
    main()