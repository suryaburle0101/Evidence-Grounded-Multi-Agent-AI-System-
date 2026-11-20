"""
Multi-sample end-to-end pipeline test.

Runs each attack class through the ORCHESTRATOR (detection ->
investigation -> evidence -> decision -> response) and reports:
  - per-class detection rate (ATTACK), review rate (REVIEW), miss rate
  - false-positive rate on Benign traffic
  - family-match rate for flows flagged ATTACK/REVIEW

Run from the project root or by script path:
    python evaluation/legacy_scripts/test_full_pipeline.py  # 100 samples/class
    python evaluation/legacy_scripts/test_full_pipeline.py --n 300
    python evaluation/legacy_scripts/test_full_pipeline.py --only Infiltration
"""

import argparse
import re
from pathlib import Path

import pandas as pd

try:
    from ._paths import project_path
except ImportError:
    from _paths import project_path

from agents.orchestrator import orchestrator

DATA_DIR = project_path("data/raw/CICIDS2017")

# "expect" = what a correct pipeline should output.
# "family" = substrings accepted as a family match (lowercase).
TESTS = [
    {"name": "Benign", "file": "Benign-Monday-no-metadata.parquet",
     "labels": ["Benign"], "expect": "BENIGN", "family": ["benign"]},
    {"name": "Bot", "file": "Botnet-Friday-no-metadata.parquet",
     "labels": ["Bot"], "expect": "ATTACK", "family": ["bot"]},
    {"name": "FTP-Patator", "file": "Bruteforce-Tuesday-no-metadata.parquet",
     "labels": ["FTP-Patator"], "expect": "ATTACK",
     "family": ["ftp", "patator", "brute"]},
    {"name": "DDoS", "file": "DDoS-Friday-no-metadata.parquet",
     "labels": ["DDoS"], "expect": "ATTACK", "family": ["ddos", "dos"]},
    {"name": "DoS Hulk", "file": "DoS-Wednesday-no-metadata.parquet",
     "labels": ["DoS Hulk"], "expect": "ATTACK", "family": ["dos", "hulk"]},
    {"name": "Infiltration", "file": "Infiltration-Thursday-no-metadata.parquet",
     "labels": ["Infiltration"], "expect": "ATTACK",
     "family": ["infiltration"]},
    {"name": "PortScan", "file": "Portscan-Friday-no-metadata.parquet",
     "labels": ["PortScan"], "expect": "ATTACK",
     "family": ["portscan", "port scan", "scan"]},
    {"name": "Web Attack - Brute Force",
     "file": "WebAttacks-Thursday-no-metadata.parquet",
     "labels": ["Web Attack"], "contains": "brute force",
     "expect": "ATTACK", "family": ["web", "brute"]},
    {"name": "Web Attack - XSS",
     "file": "WebAttacks-Thursday-no-metadata.parquet",
     "labels": ["Web Attack"], "contains": "xss",
     "expect": "ATTACK", "family": ["web", "xss"]},
    {"name": "Web Attack - SQL Injection",
     "file": "WebAttacks-Thursday-no-metadata.parquet",
     "labels": ["Web Attack"], "contains": "sql",
     "expect": "ATTACK", "family": ["web", "sql"]},
]


def normalize(value):
    value = str(value).lower()
    value = re.sub(r"[^a-z0-9]+", " ", value)
    return " ".join(value.split())


def find_labels(df, test):
    """Return list of actual label strings in df matching the test."""
    available = df["Label"].dropna().astype(str).unique()
    contains = test.get("contains")

    matches = []
    for label in available:
        norm = normalize(label)
        if contains:
            if "web attack" in norm and normalize(contains) in norm:
                matches.append(label)
        else:
            for wanted in test["labels"]:
                if norm == normalize(wanted):
                    matches.append(label)
    return matches


def load_samples(test, n, seed=42):
    path = DATA_DIR / test["file"]
    if not path.exists():
        raise FileNotFoundError(f"Dataset file not found: {path}")

    df = pd.read_parquet(path)
    if "Label" not in df.columns:
        raise ValueError(f"'Label' column not found in {path.name}")

    labels = find_labels(df, test)
    if not labels:
        raise ValueError(
            f"No matching label for {test['name']}. Available: "
            f"{list(df['Label'].dropna().unique())}"
        )

    rows = df[df["Label"].isin(labels)]
    total = len(rows)
    if total > n:
        rows = rows.sample(n=n, random_state=seed)

    X = rows.drop(columns=["Label"])
    return X, total


def run_test(test, n):
    X_all, total = load_samples(test, n)

    counts = {"ATTACK": 0, "REVIEW": 0, "BENIGN": 0, "ERROR": 0}
    family_hits = 0
    flagged = 0
    first_error = None

    for i in range(len(X_all)):
        X = X_all.iloc[[i]]
        try:
            result = orchestrator.analyze(X)
        except Exception as e:                      # safety net
            counts["ERROR"] += 1
            first_error = first_error or f"{type(e).__name__}: {e}"
            continue

        if not result.get("pipeline_completed"):
            counts["ERROR"] += 1
            err = result.get("error", {})
            first_error = first_error or (
                f"{err.get('step')}: {err.get('error_type')}: "
                f"{err.get('message')}"
            )
            continue

        decision = result.get("final_decision") or "BENIGN"
        counts[decision] = counts.get(decision, 0) + 1

        if decision in ("ATTACK", "REVIEW"):
            flagged += 1
            attack = normalize(result.get("final_attack", ""))
            if any(f in attack for f in test["family"]):
                family_hits += 1

    tested = len(X_all)
    ok = tested - counts["ERROR"]

    return {
        "name": test["name"],
        "expect": test["expect"],
        "available": total,
        "tested": tested,
        "counts": counts,
        "flagged": flagged,
        "family_hits": family_hits,
        "ok": ok,
        "first_error": first_error,
    }


def pct(a, b):
    return f"{(100.0 * a / b):5.1f}%" if b else "  n/a "


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, default=100,
                        help="max samples per class")
    parser.add_argument("--only", type=str, default=None,
                        help="run only tests whose name contains this")
    args = parser.parse_args()

    tests = [t for t in TESTS
             if not args.only or args.only.lower() in t["name"].lower()]

    print("=" * 90)
    print("FULL PIPELINE TEST (orchestrator, multi-sample)")
    print("=" * 90)

    results = []
    for test in tests:
        print(f"\nRunning: {test['name']} ...", flush=True)
        try:
            r = run_test(test, args.n)
        except Exception as e:
            print(f"  SETUP ERROR: {type(e).__name__}: {e}")
            continue
        results.append(r)
        c = r["counts"]
        print(f"  samples={r['tested']} (of {r['available']})  "
              f"ATTACK={c['ATTACK']}  REVIEW={c['REVIEW']}  "
              f"BENIGN={c['BENIGN']}  ERROR={c['ERROR']}")
        if r["first_error"]:
            print(f"  first error: {r['first_error']}")

    # ---------------- Summary ----------------
    print("\n" + "=" * 90)
    print("SUMMARY")
    print("=" * 90)
    print(f"{'Class':<28}{'N':>6}{'ATTACK%':>10}{'REVIEW%':>10}"
          f"{'MISSED%':>10}{'FamilyMatch%':>15}")
    print("-" * 90)

    for r in results:
        c = r["counts"]
        ok = r["ok"]
        if r["expect"] == "BENIGN":
            fp = c["ATTACK"] + c["REVIEW"]
            print(f"{r['name']:<28}{ok:>6}"
                  f"{pct(c['ATTACK'], ok):>10}{pct(c['REVIEW'], ok):>10}"
                  f"{'':>10}{'':>15}   <- false positives: "
                  f"{pct(fp, ok).strip()}")
        else:
            print(f"{r['name']:<28}{ok:>6}"
                  f"{pct(c['ATTACK'], ok):>10}{pct(c['REVIEW'], ok):>10}"
                  f"{pct(c['BENIGN'], ok):>10}"
                  f"{pct(r['family_hits'], r['flagged']):>15}")

    print("\nHow to read this:")
    print("  ATTACK%  = flows the pipeline confidently flagged")
    print("  REVIEW%  = flows escalated to an analyst (partial credit)")
    print("  MISSED%  = attack flows the pipeline called BENIGN (bad)")
    print("  Benign row: ATTACK%+REVIEW% = false-positive rate (bad)")
    print("=" * 90)


if __name__ == "__main__":
    main()
