"""Research-only 57-feature candidate study against held-out CIC-IDS attack labels.

Trains fresh RF/XGBoost candidates on CICIDS2017 captures, calibrates using only
benign CICIDS2018 fold-A rows, then evaluates on fold-B captures and novel raw
attack labels from the combined Kaggle collection. It does not save or promote
model artifacts. The collection has no source-capture column, so its attack
recall is diagnostic and cannot establish an independent operational FPR.
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, recall_score
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from evaluation.production_model_validation import canonical_family, sample_capture
from pipeline.data_pipeline import FEATURES, map_schema

COLLECTION = ROOT / "data" / "raw" / "CIC_IDS_Collection" / "cic-collection.parquet"
DATA_2017 = ROOT / "data" / "raw" / "CICIDS2017"
DATA_2018 = ROOT / "data" / "raw" / "CSE_CIC_IDS2018"
OUTPUT = ROOT / "reports" / "cic_collection_candidate" / "candidate_study.json"
CAP_PER_RAW_LABEL = 3000
COLLECTION_CAP_PER_RAW_LABEL = 3000
SEED = 20261011
FOLD_A = {
    "Botnet-Friday-02-03-2018_TrafficForML_CICFlowMeter.parquet",
    "DDoS1-Tuesday-20-02-2018_TrafficForML_CICFlowMeter.parquet",
    "DoS1-Thursday-15-02-2018_TrafficForML_CICFlowMeter.parquet",
    "Infil1-Wednesday-28-02-2018_TrafficForML_CICFlowMeter.parquet",
    "Web1-Thursday-22-02-2018_TrafficForML_CICFlowMeter.parquet",
}


def _threshold_at_fpr(scores: np.ndarray, target_fpr: float = 0.01) -> float:
    ordered = np.sort(np.asarray(scores, dtype=float))
    if not len(ordered):
        raise ValueError("No benign calibration scores")
    allowed = int(np.floor(target_fpr * len(ordered)))
    index = len(ordered) - allowed - 1
    return float(np.nextafter(ordered[index], np.inf))


def _features_and_target(frame: pd.DataFrame, feature_names: list[str]) -> tuple[pd.DataFrame, np.ndarray]:
    x = frame[feature_names].apply(pd.to_numeric, errors="coerce")
    valid = x.notna().all(axis=1) & np.isfinite(x.to_numpy(dtype=float)).all(axis=1)
    x = x.loc[valid]
    raw = frame.loc[valid, "__raw_label"].astype(str)
    y = (raw.map(canonical_family) != "Benign").to_numpy(dtype=np.int8)
    return x.astype("float32"), y


def _sample_collection(path: Path, feature_names: list[str], cap: int) -> tuple[pd.DataFrame, dict]:
    parquet = pq.ParquetFile(path)
    columns = parquet.schema.names
    mapped_schema, _ = map_schema(pd.DataFrame(columns=columns))
    label_col = next((c for c in mapped_schema.columns if str(c).strip().casefold() == "label"), None)
    if label_col is None:
        raise ValueError("CIC-IDS-Collection has no Label column")
    missing = [feature for feature in feature_names if feature not in mapped_schema.columns]
    if missing:
        raise ValueError(f"Collection is missing candidate features: {missing}")
    source_map = {}
    for feature in feature_names:
        source_map[feature] = next((name for name in columns if str(name).strip() == feature), feature)
    source_label = next((name for name in columns if str(name).strip().casefold() == "label"), label_col)
    read_columns = list(dict.fromkeys([*source_map.values(), source_label]))
    rng = np.random.default_rng(SEED)
    reservoirs: dict[str, pd.DataFrame] = {}
    seen: Counter = Counter()
    rows_seen = invalid = 0
    for batch in parquet.iter_batches(batch_size=200_000, columns=read_columns):
        chunk = batch.to_pandas().rename(columns={source: target for target, source in source_map.items() if source != target})
        rows_seen += len(chunk)
        raw = chunk[source_label].astype(str).str.strip()
        numeric = chunk[feature_names].apply(pd.to_numeric, errors="coerce")
        valid = numeric.notna().all(axis=1) & np.isfinite(numeric.to_numpy(dtype=float)).all(axis=1)
        invalid += int((~valid).sum())
        if not valid.any():
            continue
        clean = numeric.loc[valid].copy()
        clean["__raw_label"] = raw.loc[valid].to_numpy()
        for label, group in clean.groupby("__raw_label", sort=True):
            prior_seen = seen[label]
            prior = reservoirs.get(label, group.iloc[0:0].copy())
            combined = len(prior) + len(group)
            if combined <= cap:
                selected = pd.concat([prior, group], ignore_index=True)
            else:
                old_keep = int(rng.hypergeometric(prior_seen, len(group), cap))
                new_keep = cap - old_keep
                parts = []
                if old_keep:
                    parts.append(prior.iloc[rng.choice(len(prior), old_keep, replace=False)])
                if new_keep:
                    parts.append(group.iloc[rng.choice(len(group), new_keep, replace=False)])
                selected = pd.concat(parts, ignore_index=True)
            reservoirs[label] = selected
            seen[label] += len(group)
    if not reservoirs:
        raise ValueError("No valid flow rows found in CIC-IDS-Collection")
    sampled = pd.concat(reservoirs.values(), ignore_index=True)
    return sampled, {"rows_scanned": rows_seen, "invalid_rows": invalid,
                     "rows_sampled": len(sampled), "label_rows_seen": dict(seen),
                     "sample_cap_per_raw_label": cap}


def _scores(model, frame: pd.DataFrame, features: list[str]) -> np.ndarray:
    positive_class = list(model.classes_).index(1)
    return model.predict_proba(frame[features])[:, positive_class]


def _metrics(frame: pd.DataFrame, scores: np.ndarray, threshold: float) -> dict:
    raw = frame["__raw_label"].astype(str)
    y = (raw.map(canonical_family) != "Benign").to_numpy(dtype=np.int8)
    pred = scores >= threshold
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    per_family = {}
    for family in sorted(set(raw.map(canonical_family)) - {"Benign"}):
        mask = raw.map(canonical_family).eq(family).to_numpy()
        per_family[family] = float(recall_score(np.ones(mask.sum()), pred[mask], zero_division=0))
    return {"rows": int(len(frame)), "attack_rows": int(y.sum()), "threshold": threshold,
            "attack_recall": float(tp / max(1, tp + fn)),
            "false_positive_rate": float(fp / max(1, fp + tn)),
            "family_recall": per_family,
            "confusion_matrix_tn_fp_fn_tp": [int(tn), int(fp), int(fn), int(tp)]}


def run() -> dict:
    if not COLLECTION.is_file():
        raise FileNotFoundError(f"Expected downloaded collection at {COLLECTION}")
    collection_columns = set(pq.read_schema(COLLECTION).names)
    # Candidate schema intentionally uses only production features present in the collection.
    features = [feature for feature in FEATURES if feature in collection_columns]
    if not features:
        raise ValueError("No feature names overlap with the production schema")
    train_files = sorted(DATA_2017.glob("*.parquet"))
    if not train_files:
        raise FileNotFoundError(f"No CICIDS2017 parquet files under {DATA_2017}")
    train_parts = []
    for path in train_files:
        frame, _ = sample_capture(path, CAP_PER_RAW_LABEL, 200_000, SEED)
        frame["__raw_label"] = frame["__raw_label"].astype(str)
        train_parts.append(frame[[*features, "__raw_label"]])
    train = pd.concat(train_parts, ignore_index=True).drop_duplicates(
        subset=[*features, "__raw_label"]).reset_index(drop=True)
    x_train, y_train = _features_and_target(train, features)
    train = train.loc[x_train.index].reset_index(drop=True)
    x_train = x_train.reset_index(drop=True)

    calibration_parts, test_parts = [], []
    capture_audit = {"calibration": [], "test": []}
    for path in sorted(DATA_2018.glob("*.parquet")):
        frame, _ = sample_capture(path, 5000, 200_000, SEED)
        frame = frame[[*features, "__raw_label"]]
        if path.name in FOLD_A:
            calibration_parts.append(frame)
            capture_audit["calibration"].append(path.name)
        else:
            test_parts.append(frame)
            capture_audit["test"].append(path.name)
    calibration = pd.concat(calibration_parts, ignore_index=True)
    heldout = pd.concat(test_parts, ignore_index=True)
    benign_calibration = calibration[calibration["__raw_label"].map(canonical_family).eq("Benign")]
    if benign_calibration.empty:
        raise ValueError("No benign CICIDS2018 calibration rows found")
    collection, collection_audit = _sample_collection(COLLECTION, features, COLLECTION_CAP_PER_RAW_LABEL)
    training_labels = {re.sub(r"\s+", " ", label.strip().casefold()) for label in train["__raw_label"].unique()}
    collection_labels = collection["__raw_label"].astype(str).str.strip()
    novel_mask = ~collection_labels.str.casefold().isin(training_labels) & ~collection_labels.map(canonical_family).eq("Benign")
    novel_attacks = collection.loc[novel_mask].copy().reset_index(drop=True)
    if novel_attacks.empty:
        raise ValueError("No attack labels absent from CICIDS2017 training were found")

    models = {
        "random_forest": RandomForestClassifier(
            n_estimators=250, class_weight="balanced_subsample", n_jobs=1, random_state=SEED,
        ),
        "xgboost": XGBClassifier(
            n_estimators=300, max_depth=8, learning_rate=0.08, subsample=0.8,
            colsample_bytree=0.85, tree_method="hist", n_jobs=4,
            eval_metric="logloss", random_state=SEED,
        ),
    }
    output = {"schema": "cic-collection-research-candidate-v1",
              "production_artifacts_modified": False,
              "candidate_features": features,
              "candidate_feature_count": len(features),
              "training_dataset": "CICIDS2017 capture files",
              "training_rows": int(len(x_train)),
              "calibration_test_capture_split": capture_audit,
              "calibration_method": "1% target FPR using benign rows from CICIDS2018 fold A only",
              "collection_profile": collection_audit,
              "novel_collection_raw_labels": sorted(novel_attacks["__raw_label"].astype(str).unique()),
              "novel_collection_attack_rows_sampled": int(len(novel_attacks)),
              "collection_fpr": None,
              "collection_fpr_note": "Not reported: combined dataset has no source-capture field and includes prior CICIDS datasets.",
              "models": {}}
    x_cal, y_cal = _features_and_target(benign_calibration, features)
    # Keep only the aligned valid benign rows for the threshold stage.
    benign_calibration = benign_calibration.loc[x_cal.index]
    x_test, y_test = _features_and_target(heldout, features)
    heldout = heldout.loc[x_test.index].reset_index(drop=True)
    x_test = x_test.reset_index(drop=True)
    x_novel, _ = _features_and_target(novel_attacks, features)
    novel_attacks = novel_attacks.loc[x_novel.index].reset_index(drop=True)
    x_novel = x_novel.reset_index(drop=True)
    for name, model in models.items():
        model.fit(x_train, y_train)
        calibration_scores = _scores(model, x_cal, features)
        threshold = _threshold_at_fpr(calibration_scores)
        test_scores = _scores(model, x_test, features)
        novel_scores = _scores(model, x_novel, features)
        output["models"][name] = {
            "threshold": threshold,
            "calibration_benign_rows": int(len(x_cal)),
            "calibration_fpr": float((calibration_scores >= threshold).mean()),
            "heldout_2018": _metrics(heldout, test_scores, threshold),
            "novel_collection_attacks": _metrics(novel_attacks, novel_scores, threshold),
        }
    output["limitations"] = [
        "Research-only candidate uses 57 common columns; it is not compatible with the production 77-feature artifacts.",
        "Novel collection attack rows are a diagnostic test only; the file contains no source-capture provenance.",
        "Collection benign rows are excluded from FPR claims because the combined file overlaps existing datasets.",
        "No candidate model was saved or promoted.",
    ]
    return output


def main() -> int:
    result = run()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(OUTPUT), "features": result["candidate_feature_count"],
                      "training_rows": result["training_rows"],
                      "novel_collection_labels": result["novel_collection_raw_labels"],
                      "models": {name: {"heldout_recall": item["heldout_2018"]["attack_recall"],
                                        "heldout_fpr": item["heldout_2018"]["false_positive_rate"],
                                        "collection_recall": item["novel_collection_attacks"]["attack_recall"]}
                                 for name, item in result["models"].items()}}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
