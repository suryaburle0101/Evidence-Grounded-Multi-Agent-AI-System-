"""
flow_evidence_diagnostic.py
-----------------------------
Place in: evaluation/flow_evidence_diagnostic.py

Runs the full 397-flow evaluation set (same sampling as agent_evaluation.py)
but captures per-flow flow_evidence_score / level / final_decision so we can
see exactly:
  1. Which Infiltration flows are still missed, and how close their score
     was to the trigger threshold (near-misses vs. genuinely undetectable).
  2. Which Benign flows got falsely escalated, and whether their scores
     are borderline (threshold tuning could help) or clearly high
     (a different problem -- these benign flows genuinely look
     low-and-slow, e.g. large downloads / long-lived sessions).
  3. Whether "correct" Infiltration catches landed as clean THREAT or as
     the vaguer REVIEW/"Infiltration (flow-anomaly)" bucket, for an
     exact-label accuracy view alongside the existing threat-vs-no-threat
     metric.

Run from the project root:
    python evaluation/flow_evidence_diagnostic.py
"""

import sys
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from agents.orchestrator import orchestrator

DATA_DIR = PROJECT_ROOT / "data" / "raw" / "CICIDS2017"
SAMPLES_PER_CLASS = 50

DATASET_FILES = [
    "Benign-Monday-no-metadata.parquet",
    "Botnet-Friday-no-metadata.parquet",
    "Bruteforce-Tuesday-no-metadata.parquet",
    "DDoS-Friday-no-metadata.parquet",
    "DoS-Wednesday-no-metadata.parquet",
    "Infiltration-Thursday-no-metadata.parquet",
    "Portscan-Friday-no-metadata.parquet",
    "WebAttacks-Thursday-no-metadata.parquet",
]


def normalize_label(label):
    label = str(label)
    if label == "Benign":
        return "Benign"
    if label == "Bot":
        return "Botnet"
    if label in ["FTP-Patator", "SSH-Patator"]:
        return "Brute Force"
    if label == "DDoS":
        return "DDoS"
    if label.startswith("DoS "):
        return "DoS"
    if label == "PortScan":
        return "Port Scan"
    if label.startswith("Web Attack"):
        return "Web Attack"
    if label == "Infiltration":
        return "Infiltration"
    if label == "Heartbleed":
        return "Heartbleed"
    return label


print("Loading data...")
frames = []
for filename in DATASET_FILES:
    filepath = DATA_DIR / filename
    if not filepath.exists():
        continue
    df = pd.read_parquet(filepath)
    df["Expected_Family"] = df["Label"].apply(normalize_label)
    frames.append(df)

data = pd.concat(frames, ignore_index=True)

eval_frames = []
for family in sorted(data["Expected_Family"].unique()):
    class_data = data[data["Expected_Family"] == family]
    n = min(SAMPLES_PER_CLASS, len(class_data))
    eval_frames.append(class_data.sample(n=n, random_state=42))

evaluation_data = pd.concat(eval_frames, ignore_index=True)

print(f"Running pipeline on {len(evaluation_data)} flows...\n")

rows = []
for index, row in evaluation_data.iterrows():
    expected_family = row["Expected_Family"]
    X = row.drop(labels=["Label", "Expected_Family"]).to_frame().T

    try:
        result = orchestrator.analyze(X)
        decision = result["decision"]
        evidence = result["evidence"]

        rows.append({
            "expected": expected_family,
            "final_decision": decision.get("final_decision"),
            "final_attack": decision.get("final_attack"),
            "flow_evidence_score": decision.get("flow_evidence_score"),
            "flow_evidence_level": decision.get("flow_evidence_level"),
            "flow_evidence_triggered": decision.get("flow_evidence_triggered"),
            "evidence_state": evidence.get("evidence_state"),
        })
    except Exception as e:
        print(f"ERROR on row {index}: {e}")

diag = pd.DataFrame(rows)

# ============================================================
# 1. INFILTRATION: score distribution, hit vs miss
# ============================================================

print("=" * 75)
print("INFILTRATION FLOWS -- flow_evidence_score for each")
print("=" * 75)

inf = diag[diag["expected"] == "Infiltration"].copy()
inf["caught"] = inf["final_attack"].apply(
    lambda a: a is not None and a != "Benign"
)
inf_sorted = inf.sort_values("flow_evidence_score", ascending=False)
print(inf_sorted[[
    "flow_evidence_score", "flow_evidence_level", "final_decision",
    "final_attack", "caught"
]].to_string(index=False))

print(f"\nCaught: {inf['caught'].sum()}/{len(inf)}")
print(f"Missed (score present but below threshold, or None):")
missed = inf[~inf["caught"]]
print(missed[["flow_evidence_score", "flow_evidence_level"]].to_string(index=False))

# ============================================================
# 2. BENIGN: which ones got escalated, and how strongly
# ============================================================

print("\n")
print("=" * 75)
print("BENIGN FLOWS -- false positives from flow evidence")
print("=" * 75)

ben = diag[diag["expected"] == "Benign"].copy()
ben_escalated = ben[ben["final_decision"] != "BENIGN"]

if ben_escalated.empty:
    print("No benign flows were escalated.")
else:
    print(ben_escalated[[
        "flow_evidence_score", "flow_evidence_level",
        "final_decision", "final_attack"
    ]].to_string(index=False))

print(f"\nBenign flows escalated: {len(ben_escalated)}/{len(ben)}")
print("\nFull benign flow_evidence_score distribution:")
print(ben["flow_evidence_score"].describe().to_string())

# ============================================================
# 3. Exact-label view for Infiltration catches
# ============================================================

print("\n")
print("=" * 75)
print("INFILTRATION CATCHES -- clean THREAT vs. REVIEW/flow-anomaly")
print("=" * 75)

caught = inf[inf["caught"]]
print(caught["final_decision"].value_counts().to_string())
print()
print(caught["final_attack"].value_counts().to_string())
