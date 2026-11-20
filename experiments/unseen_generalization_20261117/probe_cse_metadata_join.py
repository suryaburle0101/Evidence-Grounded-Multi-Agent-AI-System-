"""Exact 77-feature + canonical-label join probe for one official CSE CSV."""
from __future__ import annotations
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import numpy as np
import pandas as pd
from pipeline.data_pipeline import FEATURES, map_schema
from experiments.family_design_20261116.evaluate_families import read_seed
from experiments.dataset_expansion_20261113.labels import map_label

RAW = ROOT / "experiments/unseen_generalization_20261117/raw_metadata_cse2018/Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv"
OUT = ROOT / "experiments/unseen_generalization_20261117/cse_metadata_join_probe.json"
ALIASES = {
    "Fwd Header Len": "Fwd Header Length",
    "Bwd Header Len": "Bwd Header Length",
    "ECE Flag Cnt": "ECE Flag Count",
}


def prepare(frame: pd.DataFrame) -> pd.DataFrame:
    frame, _ = map_schema(frame)
    frame = frame.rename(columns=ALIASES)
    missing = [col for col in FEATURES + ["Label"] if col not in frame.columns]
    if missing:
        raise ValueError(f"Missing after aliases: {missing}")
    return frame


def digest(frame: pd.DataFrame) -> pd.Series:
    numeric = frame[FEATURES].apply(pd.to_numeric, errors="coerce").astype("float64")
    combo = numeric.copy()
    combo["__canonical_label"] = frame["Label"].astype(str)
    return pd.util.hash_pandas_object(combo, index=False)


def main():
    frames = read_seed(42)
    target = frames["CSE-CIC-IDS2018__Bruteforce-Wednesday-14-02-2018_TrafficForML_CICFlowMeter"].copy()
    target["Label"] = target["__type"].astype(str)
    target_hashes = digest(target).astype("uint64")
    needed = set(target_hashes.tolist())
    source_counts: dict[int, int] = {}
    metadata_examples: dict[int, dict] = {}
    total = 0
    valid = 0
    for chunk in pd.read_csv(RAW, chunksize=50_000, low_memory=False, encoding_errors="replace"):
        mapped = prepare(chunk)
        mapped["Label"] = mapped["Label"].map(map_label)
        values = mapped[FEATURES].apply(pd.to_numeric, errors="coerce").astype("float64")
        keep = np.isfinite(values.to_numpy()).all(axis=1)
        total += len(chunk)
        valid += int(keep.sum())
        sub = mapped.loc[keep].copy()
        h = digest(sub).astype("uint64")
        matched = h.isin(needed)
        if matched.any():
            for key, count in h[matched].value_counts().items():
                source_counts[int(key)] = source_counts.get(int(key), 0) + int(count)
            for idx in np.flatnonzero(matched.to_numpy()):
                key = int(h.iloc[idx])
                if key not in metadata_examples:
                    metadata_examples[key] = {
                        "Timestamp": str(sub.iloc[idx]["Timestamp"]),
                        "Dst Port": str(sub.iloc[idx]["Dst Port"]),
                    }
        print(f"scanned={total:,} rows; matched_hashes={len(source_counts):,}", flush=True)
    target_counts = target_hashes.value_counts()
    unique_rows = ambiguous_rows = unmatched_rows = 0
    for key, count in target_counts.items():
        found = source_counts.get(int(key), 0)
        if found == 1:
            unique_rows += int(count)
        elif found > 1:
            ambiguous_rows += int(count)
        else:
            unmatched_rows += int(count)
    result = {
        "source_file": RAW.name,
        "source_rows": total,
        "finite_feature_rows": valid,
        "target_seed42_rows": int(len(target)),
        "unique_exact_feature_and_label_matched_rows": unique_rows,
        "ambiguous_exact_match_rows": ambiguous_rows,
        "unmatched_rows": unmatched_rows,
        "metadata_fields_present": ["Timestamp", "Dst Port"],
        "source_ip_present": bool("Source IP" in pd.read_csv(RAW, nrows=0).columns or "Src IP" in pd.read_csv(RAW, nrows=0).columns),
        "interpretation": "Only unique rows may be assigned metadata. This flow file has timestamp and destination port, but not source/destination IP; it cannot support source-host behavior aggregates.",
    }
    OUT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    main()
