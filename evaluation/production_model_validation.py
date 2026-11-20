"""Evaluate the active 77-feature models on external CSE-CIC-IDS2018 captures.

This reads flow rows in bounded batches, makes a seeded per-label reservoir
sample from each capture file, and never uses labels as model inputs. The
production models are not fitted or changed by this script.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
from sklearn.metrics import (
    accuracy_score, average_precision_score, brier_score_loss,
    classification_report, confusion_matrix, f1_score,
    precision_score, recall_score, roc_auc_score,
)

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pipeline.data_pipeline import FEATURES, map_schema

DATA_DIR = ROOT / "data" / "raw" / "CSE_CIC_IDS2018"
REPORT_DIR = ROOT / "reports" / "production_model_validation"
RANDOM_SEED = 20261008


def canonical_family(value: object) -> str:
    text = re.sub(r"[^a-z0-9]+", " ", str(value).strip().casefold()).strip()
    if text in {"benign", "normal"}:
        return "Benign"
    if "heartbleed" in text:
        return "Heartbleed"
    if "infil" in text:
        return "Infiltration"
    if "ddos" in text:
        return "DDoS"
    if re.search(r"\bdos\b", text):
        return "DoS"
    if "portscan" in text or "port scan" in text:
        return "PortScan"
    if "bot" in text:
        return "Botnet"
    if any(token in text for token in ("web", "sql", "xss", "injection")):
        return "WebAttack"
    if "brute" in text or "patator" in text:
        return "BruteForce"
    return text.title() or "Unknown"


def _source_columns(original_columns: list[str]) -> tuple[str, dict[str, str]]:
    empty = pd.DataFrame(columns=original_columns)
    mapped, aliases = map_schema(empty)
    label = next((str(c) for c in mapped.columns
                  if str(c).strip().casefold() in {"label", "attack", "class", "target"}), None)
    if label is None:
        raise ValueError("Capture file has no label column")
    reverse_aliases = {target: source for source, target in aliases.items()}
    missing = [feature for feature in FEATURES if feature not in mapped.columns]
    if missing:
        raise ValueError(f"Capture file is missing {len(missing)} production features: {missing[:8]}")
    sources = {feature: reverse_aliases.get(feature, feature) for feature in FEATURES}
    return label, sources


def sample_capture(path: Path, cap_per_label: int, batch_size: int, seed: int) -> tuple[pd.DataFrame, dict]:
    parquet = pq.ParquetFile(path)
    label_column, sources = _source_columns(parquet.schema.names)
    source_label = next((source for source, target in map_schema(
        pd.DataFrame(columns=parquet.schema.names))[1].items() if target == label_column), label_column)
    read_columns = list(dict.fromkeys([*sources.values(), source_label]))
    rng = np.random.default_rng(seed)
    reservoirs: dict[str, pd.DataFrame] = {}
    seen_by_label: dict[str, int] = {}
    rows_seen = 0
    invalid_rows = 0

    for record_batch in parquet.iter_batches(batch_size=batch_size, columns=read_columns):
        chunk = record_batch.to_pandas()
        mapped, _ = map_schema(chunk)
        raw_labels = mapped[label_column].astype(str).str.strip()
        numeric = mapped[FEATURES].apply(pd.to_numeric, errors="coerce")
        valid = numeric.notna().all(axis=1) & np.isfinite(numeric.to_numpy(dtype=float)).all(axis=1)
        rows_seen += len(chunk)
        invalid_rows += int((~valid).sum())
        if not valid.any():
            continue

        clean = numeric.loc[valid].copy()
        clean["__raw_label"] = raw_labels.loc[valid].to_numpy()
        for raw_label, group in clean.groupby("__raw_label", sort=True):
            label = str(raw_label)
            prior_seen = seen_by_label.get(label, 0)
            current_count = len(group)
            prior = reservoirs.get(label)
            if prior is None:
                prior = group.iloc[0:0].copy()
            combined_size = len(prior) + current_count
            seen_total = prior_seen + current_count
            if combined_size <= cap_per_label:
                selected = pd.concat([prior, group], ignore_index=True)
            else:
                old_keep = int(rng.hypergeometric(prior_seen, current_count, cap_per_label))
                new_keep = cap_per_label - old_keep
                selected_parts = []
                if old_keep:
                    selected_parts.append(prior.iloc[rng.choice(len(prior), old_keep, replace=False)])
                if new_keep:
                    selected_parts.append(group.iloc[rng.choice(len(group), new_keep, replace=False)])
                selected = pd.concat(selected_parts, ignore_index=True)
            reservoirs[label] = selected
            seen_by_label[label] = seen_total

    if not reservoirs:
        return pd.DataFrame(), {"rows_scanned": rows_seen, "invalid_rows": invalid_rows,
                                "rows_sampled": 0, "labels": {}}
    sampled = pd.concat(reservoirs.values(), ignore_index=True)
    sampled = sampled.drop_duplicates(subset=FEATURES + ["__raw_label"]).reset_index(drop=True)
    return sampled, {
        "rows_scanned": rows_seen,
        "invalid_rows": invalid_rows,
        "rows_sampled": len(sampled),
        "label_counts": {str(k): int(v) for k, v in
                         sampled["__raw_label"].map(canonical_family).value_counts().items()},
        "raw_label_counts": {str(k): int(v) for k, v in
                             sampled["__raw_label"].value_counts().items()},
        "sample_cap_per_raw_label": cap_per_label,
        "sampling": "seeded per-label reservoir sampling across the complete capture file",
    }


def _ece(y_true: np.ndarray, probabilities: np.ndarray, bins: int = 10) -> float:
    edges = np.linspace(0, 1, bins + 1)
    total = max(1, len(y_true))
    score = 0.0
    for index in range(bins):
        mask = ((probabilities >= edges[index]) &
                (probabilities < edges[index + 1] if index < bins - 1 else probabilities <= edges[index + 1]))
        if mask.any():
            score += float(mask.sum() / total * abs(y_true[mask].mean() - probabilities[mask].mean()))
    return float(score)


def _binary_metrics(y_true: np.ndarray, probabilities: np.ndarray, threshold: float = 0.5) -> dict:
    y_true = np.asarray(y_true, dtype=int)
    probabilities = np.asarray(probabilities, dtype=float)
    predicted = (probabilities >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, predicted, labels=[0, 1]).ravel()
    result = {
        "rows": int(len(y_true)), "threshold": threshold,
        "accuracy": float(accuracy_score(y_true, predicted)),
        "precision_attack": float(precision_score(y_true, predicted, zero_division=0)),
        "recall_attack": float(recall_score(y_true, predicted, zero_division=0)),
        "f1_attack": float(f1_score(y_true, predicted, zero_division=0)),
        "false_positive_rate": float(fp / max(1, fp + tn)),
        "confusion_matrix_tn_fp_fn_tp": [int(tn), int(fp), int(fn), int(tp)],
        "brier_score_raw_uncalibrated": float(brier_score_loss(y_true, probabilities)),
        "ece_10_bins_raw_uncalibrated": _ece(y_true, probabilities),
    }
    if len(np.unique(y_true)) == 2:
        result["roc_auc"] = float(roc_auc_score(y_true, probabilities))
        result["average_precision"] = float(average_precision_score(y_true, probabilities))
    return result


def _model_metrics(features: pd.DataFrame, raw_labels: pd.Series, predictor) -> dict:
    binary = predictor.rf_binary
    multi = predictor.rf_multiclass
    xgb_binary = predictor.xgb_binary
    xgb_multi = predictor.xgb_multiclass
    is_attack = ~raw_labels.map(lambda value: canonical_family(value) == "Benign").to_numpy()
    y_binary = is_attack.astype(int)
    y_family = raw_labels.map(canonical_family).to_numpy()
    outputs = {}
    for name, binary_model, multi_model in (
        ("random_forest", binary, multi),
        ("xgboost", xgb_binary, xgb_multi),
    ):
        positive_index = list(binary_model.classes_).index(1)
        attack_probability = np.asarray(binary_model.predict_proba(features)[:, positive_index], dtype=float)
        predicted_family = np.asarray([
            predictor.decode_label(value) for value in multi_model.predict(features)
        ], dtype=object)
        expected_canonical = np.asarray([canonical_family(value) for value in y_family], dtype=object)
        predicted_canonical = np.asarray([canonical_family(value) for value in predicted_family], dtype=object)
        labels = sorted(set(expected_canonical) | set(predicted_canonical))
        outputs[name] = {
            "binary_attack_detection": _binary_metrics(y_binary, attack_probability),
            "family_classification": {
                "accuracy": float(accuracy_score(expected_canonical, predicted_canonical)),
                "macro_f1": float(f1_score(expected_canonical, predicted_canonical,
                                           labels=labels, average="macro", zero_division=0)),
                "classification_report": classification_report(
                    expected_canonical, predicted_canonical, labels=labels,
                    target_names=labels, zero_division=0, output_dict=True,
                ),
                "confusion_matrix_labels": labels,
                "confusion_matrix": confusion_matrix(
                    expected_canonical, predicted_canonical, labels=labels
                ).tolist(),
            },
        }
    return outputs


def run(max_rows_per_label: int, batch_size: int, seed: int) -> dict:
    files = sorted(DATA_DIR.glob("*.parquet"))
    if not files:
        raise FileNotFoundError(f"No CSE-CIC-IDS2018 Parquet captures found in {DATA_DIR}")
    from detection import model_predictor as predictor

    report = {
        "schema": "active-production-77-feature-external-validation-v1",
        "production_model_version": predictor.MODEL_ARTIFACT_VERSION,
        "feature_schema_version": predictor.FEATURE_SCHEMA_VERSION,
        "external_dataset": "CSE-CIC-IDS2018",
        "split": "all CSE-CIC-IDS2018 capture files; this dataset is external to the CICIDS2017 production artifacts",
        "sampled_rows_per_raw_label_per_capture": max_rows_per_label,
        "probability_semantics": "raw classifier outputs; no production calibration has been fitted",
        "model_artifacts_modified": False,
        "files": [],
        "overall": {},
        "limitations": [
            "This is an external dataset evaluation, not a live-network test.",
            "Sampling is bounded and stratified by each capture's original label; counts are reported per file.",
            "Attack-family normalization groups related labels; inspect per-label reports before using a family score as a guarantee.",
            "The production models were not retrained or recalibrated by this evaluation.",
        ],
    }
    pooled_features = []
    pooled_labels = []
    for index, path in enumerate(files):
        sampled, sample_info = sample_capture(path, max_rows_per_label, batch_size, seed + index)
        if sampled.empty:
            report["files"].append({"file": path.name, "sample": sample_info, "error": "no valid feature rows"})
            continue
        features = predictor.prepare_input(sampled[FEATURES])
        labels = sampled["__raw_label"].astype(str).reset_index(drop=True)
        metrics = _model_metrics(features, labels, predictor)
        report["files"].append({"file": path.name, "sample": sample_info, "models": metrics})
        pooled_features.append(features)
        pooled_labels.append(labels)
        print(f"{path.name}: n={len(features)} RF recall="
              f"{metrics['random_forest']['binary_attack_detection']['recall_attack']:.3f}; "
              f"XGB recall={metrics['xgboost']['binary_attack_detection']['recall_attack']:.3f}")
    if pooled_features:
        features = pd.concat(pooled_features, ignore_index=True)
        labels = pd.concat(pooled_labels, ignore_index=True)
        report["overall"] = _model_metrics(features, labels, predictor)
        report["sample_summary"] = {
            "rows": int(len(features)),
            "label_counts": {canonical_family(label): int(count)
                             for label, count in labels.map(canonical_family).value_counts().items()},
        }
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    target = REPORT_DIR / "production_external_2018.json"
    target.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Report: {target}")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-rows-per-label", type=int, default=5000)
    parser.add_argument("--batch-size", type=int, default=20000)
    parser.add_argument("--seed", type=int, default=RANDOM_SEED)
    args = parser.parse_args(argv)
    if args.max_rows_per_label < 1 or args.batch_size < 1:
        parser.error("sampling cap and batch size must be positive")
    run(args.max_rows_per_label, args.batch_size, args.seed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
