"""
Diagnose Infiltration and Heartbleed detection.

Uses ALL available flows of each class (Infiltration ~36,
Heartbleed ~11) and shows, per class:
  - what RF / XGBoost each predicted
  - their attack probabilities
  - the investigation finding
  - the final pipeline decision + label

Usage (from E:\\Local Disk\\cyber):
    python diagnose_stealth.py
"""

import re
import warnings
from collections import Counter
from pathlib import Path

import pandas as pd

warnings.filterwarnings("ignore")

from agents.orchestrator import orchestrator

DATA_DIR = Path("data/raw/CICIDS2017")
TARGETS = ["infiltration", "heartbleed"]


def normalize(v):
    return " ".join(re.sub(r"[^a-z0-9]+", " ", str(v).lower()).split())


def load_class(target):
    """Search every parquet file for rows whose label matches target."""
    frames = []
    for path in sorted(DATA_DIR.glob("*.parquet")):
        df = pd.read_parquet(path)
        if "Label" not in df.columns:
            continue
        mask = df["Label"].astype(str).map(normalize) == target
        if mask.any():
            print(f"  found {int(mask.sum())} '{target}' rows in {path.name}")
            frames.append(df[mask])
    if not frames:
        return None
    return pd.concat(frames)


def fmt(x, nd=3):
    try:
        return f"{float(x):.{nd}f}"
    except Exception:
        return str(x)


def run(target):
    print("\n" + "=" * 100)
    print(target.upper())
    print("=" * 100)

    df = load_class(target)
    if df is None or df.empty:
        print(f"  No rows found for '{target}' in {DATA_DIR}")
        return

    X_all = df.drop(columns=["Label"])
    print(f"  total flows: {len(X_all)}\n")

    rows = []
    for i in range(len(X_all)):
        r = orchestrator.analyze(X_all.iloc[[i]])
        if not r.get("pipeline_completed"):
            err = r.get("error", {})
            print(f"  flow {i}: PIPELINE ERROR at {err.get('step')}: "
                  f"{err.get('message')}")
            continue

        det = r["detection"]
        inv = r["investigation"]
        dec = r["decision"]
        ev = r["evidence"]

        rows.append({
            "i": i,
            "RF": det.get("random_forest", {}).get("attack_family"),
            "XGB": det.get("xgboost", {}).get("attack_family"),
            "RF_atk_p": inv.get("random_forest_attack_probability"),
            "XGB_atk_p": inv.get("xgboost_attack_probability"),
            "finding": str(inv.get("finding")),
            "flow_ev": ev.get("flow_evidence_score"),
            "decision": dec.get("final_decision"),
            "final_attack": dec.get("final_attack"),
        })

    R = pd.DataFrame(rows)
    if R.empty:
        return

    # ---- Per-flow table ----
    show = R.copy()
    for c in ["RF_atk_p", "XGB_atk_p", "flow_ev"]:
        show[c] = show[c].map(fmt)
    print(show.to_string(index=False))

    # ---- Aggregates ----
    n = len(R)
    print("\n--- SUMMARY ---")
    print("Final decisions      :", dict(Counter(R["decision"])))
    print("Final attack labels  :", dict(Counter(R["final_attack"])))
    print("RF raw predictions   :", dict(Counter(R["RF"])))
    print("XGB raw predictions  :", dict(Counter(R["XGB"])))
    print("Investigation finding:", dict(Counter(R["finding"])))

    rf_p = pd.to_numeric(R["RF_atk_p"], errors="coerce")
    xg_p = pd.to_numeric(R["XGB_atk_p"], errors="coerce")
    fe = pd.to_numeric(R["flow_ev"], errors="coerce")
    print(f"\nAvg attack prob  RF={rf_p.mean():.3f}  XGB={xg_p.mean():.3f}"
          f"   (max RF={rf_p.max():.3f}, max XGB={xg_p.max():.3f})")
    print(f"Avg flow evidence score = {fe.mean():.3f} "
          f"(max {fe.max():.3f})")

    correct_label = sum(
        1 for a in R["final_attack"] if target in normalize(a)
    )
    detected = int((R["decision"] != "BENIGN").sum())
    print(f"\nFlagged (ATTACK or REVIEW): {detected}/{n}")
    print(f"Correct family label      : {correct_label}/{n}")


def main():
    for t in TARGETS:
        run(t)
    print("\nDone. Paste the full output back.")


if __name__ == "__main__":
    main()