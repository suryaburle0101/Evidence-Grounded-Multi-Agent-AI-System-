"""Build the input-drift baseline used by the live drift check.

Per-feature 0.5th/99.5th percentile bounds come from CICIDS2017 rows (the
production training source). Held-out CICIDS2017 rows set the per-flow
threshold; sampled CSE-CIC-IDS2018 rows are scored only as a reference.
This is a coarse input-range screen, not a measure of model accuracy.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pipeline.data_pipeline import FEATURES, map_schema

RAW_2017 = ROOT / "data" / "raw" / "CICIDS2017"
RAW_2018 = ROOT / "data" / "raw" / "CSE_CIC_IDS2018"
OUT = ROOT / "models" / "drift_baseline.json"
SEED = 20261009
PER_CHUNK = 2000
PER_FILE = 20000


def _chunks(path: Path):
    if path.suffix.lower() == ".parquet":
        for batch in pq.ParquetFile(path).iter_batches(batch_size=50000):
            yield batch.to_pandas()
    else:
        yield from pd.read_csv(path, chunksize=50000, low_memory=False, encoding="latin1")


def sample_file(path: Path, rng, per_file: int = PER_FILE) -> pd.DataFrame:
    parts = []
    for chunk in _chunks(path):
        mapped, _ = map_schema(chunk)
        missing = [f for f in FEATURES if f not in mapped.columns]
        if missing:
            raise ValueError(f"{path.name} is missing {len(missing)} features, e.g. {missing[:5]}")
        num = mapped[list(FEATURES)].apply(pd.to_numeric, errors="coerce")
        ok = num.notna().all(axis=1) & np.isfinite(num.to_numpy(dtype=float)).all(axis=1)
        num = num.loc[ok]
        if len(num) > PER_CHUNK:
            num = num.sample(PER_CHUNK, random_state=int(rng.integers(0, 2**31 - 1)))
        parts.append(num)
    if not parts:
        return pd.DataFrame(columns=list(FEATURES))
    frame = pd.concat(parts, ignore_index=True)
    if len(frame) > per_file:
        frame = frame.sample(per_file, random_state=int(rng.integers(0, 2**31 - 1)))
    return frame.reset_index(drop=True)


def per_flow_fraction(values: np.ndarray, lo: np.ndarray, hi: np.ndarray) -> np.ndarray:
    return ((values < lo) | (values > hi)).mean(axis=1)


def summarize(fraction: np.ndarray, threshold: float) -> dict:
    return {
        "rows": int(len(fraction)),
        "median_fraction": round(float(np.median(fraction)), 4),
        "p95_fraction": round(float(np.quantile(fraction, 0.95)), 4),
        "share_over_threshold": round(float((fraction > threshold).mean()), 4),
    }


def main() -> int:
    rng = np.random.default_rng(SEED)
    files = sorted(p for p in RAW_2017.rglob("*") if p.suffix.lower() in {".csv", ".parquet"})
    if not files:
        raise SystemExit(f"No CSV/parquet files found under {RAW_2017}")
    pool = []
    for path in files:
        frame = sample_file(path, rng)
        print(f"CICIDS2017 {path.name}: {len(frame)} rows sampled")
        pool.append(frame)
    pool = (pd.concat(pool, ignore_index=True).drop_duplicates()
            .sample(frac=1.0, random_state=SEED).reset_index(drop=True))
    cut = int(len(pool) * 0.7)
    base, held = pool.iloc[:cut], pool.iloc[cut:]

    lo = base.quantile(0.005).to_numpy(dtype=float)
    hi = base.quantile(0.995).to_numpy(dtype=float)
    held_fraction = per_flow_fraction(held.to_numpy(dtype=float), lo, hi)
    threshold = float(np.quantile(held_fraction, 0.99))

    reference = {"CICIDS2017 held-out": summarize(held_fraction, threshold)}
    for path in sorted(RAW_2018.rglob("*.parquet")):
        frame = sample_file(path, rng, per_file=3000)
        if frame.empty:
            continue
        fraction = per_flow_fraction(frame.to_numpy(dtype=float), lo, hi)
        reference[path.name[:40]] = summarize(fraction, threshold)

    payload = {
        "schema": "input-range-drift-baseline-v1",
        "features": list(FEATURES),
        "lo": [float(x) for x in lo],
        "hi": [float(x) for x in hi],
        "per_flow_threshold": threshold,
        "caution_share": 0.25,
        "warning_share": 0.5,
        "baseline_rows": int(len(base)),
        "source": "CICIDS2017 files: " + ", ".join(p.name for p in files),
        "reference_check": reference,
        "note": "Coarse input-range screen against CICIDS2017; not a measure of model accuracy.",
    }
    OUT.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print(f"\nper-flow threshold (99th pct of held-out CICIDS2017): {threshold:.4f}")
    print(f"{'dataset':42s} {'rows':>6s} {'median':>8s} {'p95':>8s} {'share>thr':>10s}")
    for name, s in reference.items():
        print(f"{name:42s} {s['rows']:6d} {s['median_fraction']:8.3f} {s['p95_fraction']:8.3f} {s['share_over_threshold']:10.3f}")
    print(f"\nSaved {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
