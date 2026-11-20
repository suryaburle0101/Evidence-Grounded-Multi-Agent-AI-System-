"""
Diagnose WHY benign flows are flagged and WHY Infiltration gets the
wrong family label.

Usage (from E:\\Local Disk\\cyber):
    python diagnose_false_positives.py
    python diagnose_false_positives.py --n 200
"""

import argparse
import re
import warnings
from collections import Counter
from pathlib import Path

import pandas as pd

warnings.filterwarnings("ignore")

from agents.orchestrator import orchestrator

DATA_DIR = Path("data/raw/CICIDS2017")

SETS = [
    ("BENIGN (should be BENIGN)",
     "Benign-Monday-no-metadata.parquet", "Benign"),
    ("INFILTRATION (should be ATTACK)",
     "Infiltration-Thursday-no-metadata.parquet", "Infiltration"),
]


def normalize(v):
    return " ".join(re.sub(r"[^a-z0-9]+", " ", str(v).lower()).split())


def case_of(decision):
    """Extract which decision case fired from the reasons text."""
    reasons = decision.get("correlation_reasons", [])
    for r in reversed(reasons):
        if r.startswith("Final decision"):
            return r[:110]
    return "unknown"


def avg(values):
    values = [v for v in values if v is not None]
    return sum(values) / len(values) if values else 0.0


def run(title, filename, label, n):
    path = DATA_DIR / filename
    df = pd.read_parquet(path)
    df = df[df["Label"].astype(str).map(normalize) == normalize(label)]
    if len(df) > n:
        df = df.sample(n=n, random_state=7)
    X_all = df.drop(columns=["Label"])

    print("\n" + "=" * 90)
    print(title, f"- {len(X_all)} flows")
    print("=" * 90)

    decisions = Counter()
    cases = Counter()
    attack_labels = Counter()
    rows = []

    for i in range(len(X_all)):
        result = orchestrator.analyze(X_all.iloc[[i]])
        if not result.get("pipeline_completed"):
            err = result.get("error", {})
            print("PIPELINE ERROR:", err.get("step"), err.get("message"))
            continue

        d = result["decision"]
        inv = result["investigation"]
        ev = result["evidence"]

        decisions[d["final_decision"]] += 1

        if d["final_decision"] != "BENIGN":
            cases[case_of(d)] += 1
            attack_labels[d["final_attack"]] += 1

        rows.append({
            "decision": d["final_decision"],
            "final_attack": d["final_attack"],
            "predicted_attack": d.get("predicted_attack"),
            "rf": d.get("random_forest_attack"),
            "xgb": d.get("xgboost_attack"),
            "agree": d.get("model_agreement"),
            "avg_prob": d.get("average_attack_probability"),
            "flow_ev": d.get("flow_evidence_score"),
            "ev_family": d.get("evidence_attack_family"),
            "finding": str(d.get("investigation_finding")),
            "severity": d.get("investigation_severity"),
            "corr": d.get("correlation_score"),
        })

    R = pd.DataFrame(rows)
    if R.empty:
        return

    print("\nDecisions:", dict(decisions))

    flagged = R[R["decision"] != "BENIGN"]
    clean = R[R["decision"] == "BENIGN"]

    if len(flagged):
        print("\nWhich decision case fired (flagged flows):")
        for k, v in cases.most_common():
            print(f"  {v:>4} x {k}")

        print("\nFinal attack labels assigned:")
        for k, v in attack_labels.most_common():
            print(f"  {v:>4} x {k}")

        print("\nModel raw predictions on flagged flows (RF / XGB):")
        pair = Counter(zip(flagged["rf"], flagged["xgb"]))
        for (a, b), v in pair.most_common(8):
            print(f"  {v:>4} x RF={a} | XGB={b}")

        print("\nInvestigation finding on flagged flows:")
        for k, v in Counter(flagged["finding"]).most_common(5):
            print(f"  {v:>4} x {k}")

        print("\nEvidence-agent family on flagged flows:")
        for k, v in Counter(flagged["ev_family"]).most_common(5):
            print(f"  {v:>4} x {k}")

    print("\nAverages            flagged   |   not flagged")
    for col in ["avg_prob", "flow_ev", "corr"]:
        f = avg(flagged[col].tolist()) if len(flagged) else float("nan")
        c = avg(clean[col].tolist()) if len(clean) else float("nan")
        print(f"  {col:<14}  {f:>8.3f}   |   {c:>8.3f}")

    if len(flagged):
        print("\nFirst 5 flagged flows in detail:")
        print(flagged.head(5).to_string(index=False))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=100)
    args = ap.parse_args()

    for title, filename, label in SETS:
        run(title, filename, label, args.n)

    print("\nDone. Paste this whole output back.")


if __name__ == "__main__":
    main()