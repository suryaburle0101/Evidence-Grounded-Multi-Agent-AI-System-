import sys, json
from pathlib import Path
import numpy as np, pandas as pd
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "evaluation"))
import build_drift_baseline as b
from sklearn.ensemble import IsolationForest

rng = np.random.default_rng(20261010)
files17 = sorted(p for p in b.RAW_2017.rglob("*") if p.suffix.lower() in {".csv", ".parquet"})
pool = pd.concat([b.sample_file(p, rng) for p in files17], ignore_index=True).drop_duplicates()
pool = pool.sample(frac=1.0, random_state=1).reset_index(drop=True)
cut = int(len(pool) * 0.7)
base, held = pool.iloc[:cut], pool.iloc[cut:]
iso = IsolationForest(n_estimators=200, max_samples=4096, random_state=1, n_jobs=-1).fit(base)
score = lambda df: -iso.score_samples(df)
thr = float(np.quantile(score(held), 0.99))

cfg = json.load(open(ROOT / "models" / "drift_baseline.json"))
lo, hi, feats = np.array(cfg["lo"]), np.array(cfg["hi"]), cfg["features"]
print(f"\n{'dataset':38s} novelty share above 2017 99th pct (expect ~0.01 for held-out 2017)")
print(f"{'CICIDS2017 held-out':38s} {(score(held) > thr).mean():.3f}")
outs = []
for p in sorted(b.RAW_2018.rglob("*.parquet")):
    f = b.sample_file(p, rng, per_file=3000)
    if f.empty:
        continue
    outs.append((f[feats].to_numpy(float) < lo) | (f[feats].to_numpy(float) > hi))
    print(f"{p.name[:36]:38s} {(score(f) > thr).mean():.3f}")
allout = np.vstack(outs).mean(axis=0)
print("\nFeatures most often outside the CICIDS2017 range in CSE-CIC-IDS2018:")
for i in np.argsort(allout)[::-1][:8]:
    print(f"  {feats[i]:42s} {allout[i]:.3f}")
