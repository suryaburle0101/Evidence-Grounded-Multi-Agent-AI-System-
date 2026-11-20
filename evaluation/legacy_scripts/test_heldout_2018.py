"""
Held-out test on CSE-CIC-IDS2018 (data the models never trained on).

Run from the project root or by script path:
    python evaluation/legacy_scripts/test_heldout_2018.py  # 40 flows per label per file
    python evaluation/legacy_scripts/test_heldout_2018.py --n 100
    python evaluation/legacy_scripts/test_heldout_2018.py --only Infil

Reports, per label: ATTACK / REVIEW / BENIGN rates and family match.
Benign row = false-positive rate. Attack rows: BENIGN% = missed.
"""

import argparse
import re
import time
import warnings
from collections import defaultdict
from pathlib import Path

import joblib
import pandas as pd

try:
    from ._paths import project_path
except ImportError:
    from _paths import project_path

warnings.filterwarnings("ignore")

from agents.orchestrator import orchestrator

RAW_2018 = project_path("data/raw/CSE_CIC_IDS2018")
FEATURE_SOURCE = project_path("models/rare_infiltration.pkl")

# label (normalised, substring) -> accepted family substrings in final_attack
FAMILY = {
    "bot": ["bot"],
    "ssh bruteforce": ["ssh", "brute", "patator"],
    "ftp bruteforce": ["ftp", "brute", "patator"],
    "ddos": ["ddos", "dos"],
    "dos": ["dos", "hulk"],
    "infilteration": ["infiltration"],
    "brute force web": ["web", "brute"],
    "brute force xss": ["web", "xss"],
    "sql injection": ["web", "sql"],
}


def norm(v):
    return " ".join(re.sub(r"[^a-z0-9]+", " ", str(v).lower()).split())


def norm_col(c):
    return re.sub(r"[^a-z0-9]+", "", str(c).lower())


def family_words(label):
    n = norm(label)
    for key, words in FAMILY.items():
        if key in n:
            return words
    return []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=40,
                    help="max flows per label per file")
    ap.add_argument("--only", type=str, default=None,
                    help="only files whose name contains this text")
    args = ap.parse_args()

    features = joblib.load(FEATURE_SOURCE)["features"]
    col_map = {norm_col(f): f for f in features}

    files = sorted(RAW_2018.glob("*.parquet"))
    if args.only:
        files = [f for f in files if args.only.lower() in f.name.lower()]

    stats = defaultdict(lambda: {"ATTACK": 0, "REVIEW": 0, "BENIGN": 0,
                                 "ERROR": 0, "fam": 0, "flagged": 0})
    first_error = None
    start = time.time()

    print("=" * 96)
    print("HELD-OUT TEST: CSE-CIC-IDS2018 (unseen data)")
    print("=" * 96)

    for path in files:
        df = pd.read_parquet(path)
        label_col = next(c for c in df.columns if norm_col(c) == "label")
        labels = df[label_col].astype(str)

        # rename columns to the training names; verify full coverage
        rename = {c: col_map[norm_col(c)] for c in df.columns
                  if norm_col(c) in col_map}
        X_all = df.rename(columns=rename)
        missing = [f for f in features if f not in X_all.columns]
        if missing:
            print(f"\n{path.name}: SKIPPED, {len(missing)} features "
                  f"missing after rename, e.g. {missing[:5]}")
            continue
        X_all = X_all[features]

        print(f"\n{path.name}")
        for lab in sorted(labels.unique()):
            idx = labels[labels == lab].index
            if len(idx) > args.n:
                idx = idx.to_series().sample(n=args.n, random_state=42).index
            expected_attack = norm(lab) != "benign"
            words = family_words(lab)
            s = stats[lab]

            for i in idx:
                try:
                    r = orchestrator.analyze(X_all.loc[[i]])
                except Exception as e:
                    s["ERROR"] += 1
                    first_error = first_error or f"{type(e).__name__}: {e}"
                    continue
                if not r.get("pipeline_completed"):
                    s["ERROR"] += 1
                    err = r.get("error", {})
                    first_error = first_error or (
                        f"{err.get('step')}: {err.get('message')}")
                    continue

                d = r.get("final_decision") or "BENIGN"
                s[d] += 1
                if d != "BENIGN" and expected_attack:
                    s["flagged"] += 1
                    fa = norm(r.get("final_attack", ""))
                    if any(w in fa for w in words):
                        s["fam"] += 1
            print(f"   {lab:<28} tested {len(idx)}")

    # ---------------- Summary ----------------
    print("\n" + "=" * 96)
    print("SUMMARY (aggregated across files)")
    print("=" * 96)
    print(f"{'Label':<30}{'N':>6}{'ATTACK%':>10}{'REVIEW%':>10}"
          f"{'BENIGN%':>10}{'FamilyMatch%':>15}")
    print("-" * 96)

    def pct(a, b):
        return f"{100.0 * a / b:5.1f}%" if b else "  n/a "

    for lab in sorted(stats, key=lambda x: (norm(x) != "benign", x)):
        s = stats[lab]
        ok = s["ATTACK"] + s["REVIEW"] + s["BENIGN"]
        tag = "  <- false positives = ATTACK%+REVIEW%" \
            if norm(lab) == "benign" else ""
        fam = pct(s["fam"], s["flagged"]) if norm(lab) != "benign" else ""
        print(f"{lab:<30}{ok:>6}{pct(s['ATTACK'], ok):>10}"
              f"{pct(s['REVIEW'], ok):>10}{pct(s['BENIGN'], ok):>10}"
              f"{fam:>15}{tag}")
        if s["ERROR"]:
            print(f"   ({s['ERROR']} errors)")

    if first_error:
        print("\nFirst error seen:", first_error)
    print(f"\nElapsed: {(time.time() - start) / 60:.1f} min")
    print("BENIGN% on an attack row = MISSED attacks (bad).")
    print("=" * 96)


if __name__ == "__main__":
    main()
