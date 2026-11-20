"""Non-deploying acceptance gate for capture-held-out model evaluation reports."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PRIORITY_FAMILIES = ("DDoS", "DoS", "Botnet", "BruteForce", "Infiltration")
PRIORITY_FAMILY_COUNTS = {
    "DDoS": 1_234_729,
    "DoS": 397_333,
    "Botnet": 145_968,
    "BruteForce": 103_244,
    "Infiltration": 94_857,
}


def evaluate(report: dict, min_family_recall: float = 0.80,
             max_benign_fpr: float = 0.01,
             required_families: tuple[str, ...] | list[str] = DEFAULT_PRIORITY_FAMILIES) -> dict:
    """Gate a declared priority-family scope; retain all other metrics as context."""
    required_families = tuple(dict.fromkeys(str(name) for name in required_families))
    if not required_families:
        raise ValueError("At least one required attack family must be specified")
    models = {}
    for model_name, families in report.get("out_of_fold_per_family", {}).items():
        benign = families.get("Benign", {}).get("false_positive_rate")
        attack_families = {name: float(values.get("recall", 0.0))
                           for name, values in families.items() if name != "Benign"}
        priority_recall = {name: attack_families.get(name) for name in required_families}
        failures = []
        if benign is None or float(benign) > max_benign_fpr:
            failures.append("benign false-positive rate exceeds the limit or is missing")
        failures.extend(f"{name} priority-family recall below {min_family_recall:.0%} or missing"
                        for name, recall in priority_recall.items()
                        if recall is None or recall < min_family_recall)
        out_of_scope = {name: recall for name, recall in attack_families.items()
                        if name not in required_families}
        models[model_name] = {
            "decision": "ACCEPT" if not failures else "IMPROVE",
            "benign_false_positive_rate": benign,
            "priority_families": priority_recall,
            "other_family_recall_best_effort": out_of_scope,
            "failures": failures,
        }
    if not models:
        raise ValueError("Report has no out_of_fold_per_family model metrics")
    return {
        "schema": "non-deploying-model-acceptance-gate-v1",
        "dataset": report.get("dataset"),
        "criteria": {"minimum_recall_each_family": min_family_recall,
                     "maximum_benign_false_positive_rate": max_benign_fpr,
                     "required_priority_families": list(required_families),
                     "scope_note": "Only priority families determine ACCEPT; every other reported family remains visible as best-effort context.",
                     "priority_selection_basis": "Five highest attack-family counts in the included combined CIC-IDS-Collection file; dataset composition is not real-world prevalence.",
                     "priority_family_rows_in_collection": {name: PRIORITY_FAMILY_COUNTS.get(name)
                                                            for name in required_families}},
        "decision": "ACCEPT" if all(item["decision"] == "ACCEPT" for item in models.values()) else "IMPROVE",
        "models": models,
        "promotion": "not_performed",
        "note": "ACCEPT means the supplied evaluation report met these criteria; this gate never changes or deploys model artifacts.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=ROOT / "reports" / "threshold_transfer_2018" / "threshold_transfer.json")
    parser.add_argument("--output", type=Path, default=ROOT / "reports" / "model_acceptance" / "acceptance_gate.json")
    parser.add_argument("--min-family-recall", type=float, default=0.80)
    parser.add_argument("--max-benign-fpr", type=float, default=0.01)
    parser.add_argument("--required-families", nargs="+", default=list(DEFAULT_PRIORITY_FAMILIES),
                        help="families that define the acceptance scope; defaults to the five most frequent families in the included combined collection")
    args = parser.parse_args()
    if not 0 <= args.min_family_recall <= 1 or not 0 <= args.max_benign_fpr <= 1:
        parser.error("metric limits must be in [0, 1]")
    decision = evaluate(json.loads(args.input.read_text(encoding="utf-8")),
                        args.min_family_recall, args.max_benign_fpr, args.required_families)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"decision": decision["decision"], "output": str(args.output),
                      "models": {name: item["decision"] for name, item in decision["models"].items()}}, indent=2))
    return 0 if decision["decision"] == "ACCEPT" else 1


if __name__ == "__main__":
    raise SystemExit(main())
