"""Check exact feature/label joins between downloaded metadata flows and seed-42 rows."""
from __future__ import annotations

import glob
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import pandas as pd
import pyarrow.parquet as pq

from pipeline.data_pipeline import FEATURES, map_schema
from experiments.family_design_20261116.evaluate_families import read_seed
from experiments.dataset_expansion_20261113.labels import map_label

RAW = ROOT / "experiments/unseen_generalization_20261117/raw_metadata_2017"
OUT = ROOT / "experiments/unseen_generalization_20261117"
ALIASES = {
    "Total Length of Fwd Packets": "Fwd Packets Length Total",
    "Total Length of Bwd Packets": "Bwd Packets Length Total",
    "Min Packet Length": "Packet Length Min",
    "Max Packet Length": "Packet Length Max",
    "Average Packet Size": "Avg Packet Size",
    "Init_Win_bytes_forward": "Init Fwd Win Bytes",
    "Init_Win_bytes_backward": "Init Bwd Win Bytes",
    "act_data_pkt_fwd": "Fwd Act Data Packets",
    "min_seg_size_forward": "Fwd Seg Size Min",
}


def prep(df: pd.DataFrame) -> pd.DataFrame:
    df, _ = map_schema(df)
    df = df.rename(columns=ALIASES)
    if "Label" in df:
        df["Label"] = df["Label"].map(map_label)
    missing = [c for c in FEATURES + ["Label"] if c not in df]
    if missing:
        raise ValueError(f"missing canonical fields: {missing}")
    return df


def digest(df: pd.DataFrame) -> pd.Series:
    numeric = df[FEATURES].apply(pd.to_numeric, errors="coerce")
    return pd.util.hash_pandas_object(pd.concat([numeric, df[["Label"]]], axis=1), index=False)


def main() -> None:
    captures = read_seed(42)
    targets = {name: frame.copy() for name, frame in captures.items() if name.startswith("CICIDS2017__")}
    # In the labelled-flow archive, each weekday/scenario source corresponds to one local capture file.
    file_map = {
        "Monday-WorkingHours.pcap_ISCX.csv.parquet": "Benign-Monday-no-metadata",
        "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv.parquet": "DDoS-Friday-no-metadata",
        "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv.parquet": "Portscan-Friday-no-metadata",
        "Friday-WorkingHours-Morning.pcap_ISCX.csv.parquet": "Botnet-Friday-no-metadata",
        "Tuesday-WorkingHours.pcap_ISCX.csv.parquet": "Bruteforce-Tuesday-no-metadata",
        "Wednesday-workingHours.pcap_ISCX.csv.parquet": "DoS-Wednesday-no-metadata",
        "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv.parquet": "Infiltration-Thursday-no-metadata",
        "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv.parquet": "WebAttacks-Thursday-no-metadata",
    }
    results = []
    for fname, local_name in file_map.items():
        fpath = RAW / fname
        target = targets[f"CICIDS2017__{local_name}"].copy()
        target["Label"] = target["__type"].astype(str)
        target_hash = digest(target)
        # Store multiplicities, because duplicate vectors with metadata cannot be assigned arbitrarily.
        needed = set(target_hash.astype("uint64"))
        source_hash_counts: dict[int, int] = {}
        source_rows = 0
        for batch in pq.ParquetFile(fpath).iter_batches(batch_size=50_000):
            src = prep(batch.to_pandas())
            h = digest(src).astype("uint64")
            source_rows += len(src)
            for value, count in h[h.isin(needed)].value_counts().items():
                source_hash_counts[int(value)] = source_hash_counts.get(int(value), 0) + int(count)
        target_counts = target_hash.astype("uint64").value_counts()
        unique = ambiguous = missed = 0
        for value, count in target_counts.items():
            found = source_hash_counts.get(int(value), 0)
            if found == 1:
                unique += int(count == 1)
            elif found > 1:
                ambiguous += int(count)
            else:
                missed += int(count)
        results.append({"metadata_file": fname, "local_capture": local_name,
                        "metadata_rows": source_rows, "sample_rows": len(target),
                        "sample_vectors_with_one_exact_source_match": unique,
                        "sample_rows_ambiguous_metadata_match": ambiguous,
                        "sample_rows_without_exact_match": missed,
                        "metadata_source_unique_hashes_for_sample": sum(n == 1 for n in source_hash_counts.values())})
        print(results[-1], flush=True)
    (OUT / "metadata_join_probe.json").write_text(json.dumps(results, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
