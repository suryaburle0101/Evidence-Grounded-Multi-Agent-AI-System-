"""Train and evaluate a focused candidate for the five priority attack families.

The candidate is non-deploying. It uses CICIDS2017 training captures plus
flow-disjoint training/calibration partitions from the 2018 training-fold
captures, and evaluates on separate 2018 captures. The 2017 Botnet
capture is held out because the 2018 test fold has no Botnet capture. Exact
feature-vector overlap is removed across train, calibration, and test splits.

Run with the repository's pinned environment:
    .\\recovery_venv\\Scripts\\python.exe evaluation\\priority_family_candidate.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation.production_model_validation import canonical_family, sample_capture
from pipeline.data_pipeline import FEATURES

DATA_2017 = ROOT / "data" / "raw" / "CICIDS2017"
DATA_2018 = ROOT / "data" / "raw" / "CSE_CIC_IDS2018"
OUTPUT = ROOT / "reports" / "priority_family_candidate" / "priority_family_candidate.json"
PRIORITY = ("DDoS", "DoS", "Botnet", "BruteForce", "Infiltration")
FOLD_A = {
    "Botnet-Friday-02-03-2018_TrafficForML_CICFlowMeter.parquet",
    "DDoS1-Tuesday-20-02-2018_TrafficForML_CICFlowMeter.parquet",
    "DoS1-Thursday-15-02-2018_TrafficForML_CICFlowMeter.parquet",
    "Infil1-Wednesday-28-02-2018_TrafficForML_CICFlowMeter.parquet",
    "Web1-Thursday-22-02-2018_TrafficForML_CICFlowMeter.parquet",
}
BOTNET_HOLDOUT = "Botnet-Friday-no-metadata.parquet"
CAP_PER_LABEL = 5000
TARGET_FPR = 0.01
SEED = 20261011


def _load_capture(path: Path, seed: int) -> pd.DataFrame:
    frame, _audit = sample_capture(path, CAP_PER_LABEL, 200_000, seed)
    if frame.empty:
        raise ValueError(f"No valid flow rows in {path}")
    frame["__family"] = frame["__raw_label"].map(canonical_family)
    frame["__capture"] = path.name
    return frame[[*FEATURES, "__raw_label", "__family", "__capture"]]


def _remove_feature_overlap(frame: pd.DataFrame, references: list[pd.DataFrame]) -> tuple[pd.DataFrame, int]:
    seen: set[int] = set()
    for ref in references:
        if not ref.empty:
            seen.update(pd.util.hash_pandas_object(ref[FEATURES], index=False).astype("uint64").tolist())
    hashes = pd.util.hash_pandas_object(frame[FEATURES], index=False).astype("uint64")
    keep = ~hashes.isin(seen)
    return frame.loc[keep].copy().reset_index(drop=True), int((~keep).sum())


def _threshold(scores: np.ndarray, target_fpr: float) -> float:
    raw_scores = np.asarray(scores)
    benign = np.sort(raw_scores)
    if not len(benign):
        raise ValueError("Cannot calibrate without benign flows")
    allowed = int(np.floor(target_fpr * len(benign)))
    boundary = benign[len(benign) - allowed - 1]
    # Advance in the score array's own dtype so tied float32 probabilities are
    # excluded correctly, rather than advancing by an invisible float64 ULP.
    infinity = np.asarray(np.inf, dtype=raw_scores.dtype)
    return float(np.nextafter(np.asarray(boundary, dtype=raw_scores.dtype), infinity))


def _balanced_weights(y: np.ndarray) -> np.ndarray:
    classes, counts = np.unique(y, return_counts=True)
    weights = {label: len(y) / (len(classes) * count) for label, count in zip(classes, counts)}
    return np.asarray([weights[label] for label in y], dtype=float)


def _scores(model, encoder: LabelEncoder, frame: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    probabilities = model.predict_proba(frame[FEATURES])
    priority_indices = [int(np.flatnonzero(encoder.classes_ == family)[0]) for family in PRIORITY]
    priority_probabilities = probabilities[:, priority_indices]
    best = np.argmax(priority_probabilities, axis=1)
    return priority_probabilities.max(axis=1), np.asarray(PRIORITY, dtype=object)[best]


def _metrics(frame: pd.DataFrame, scores: np.ndarray, family_guess: np.ndarray,
             threshold: float) -> dict:
    family = frame["__family"].to_numpy(dtype=object)
    benign = family == "Benign"
    in_scope = np.isin(family, PRIORITY)
    flagged = scores >= threshold
    tn, fp, fn, tp = confusion_matrix(in_scope[benign | in_scope].astype(int),
                                      flagged[benign | in_scope].astype(int), labels=[0, 1]).ravel()
    per_family = {}
    for name in PRIORITY:
        mask = family == name
        per_family[name] = {
            "rows": int(mask.sum()),
            "detection_recall": float(flagged[mask].mean()) if mask.any() else None,
            "correct_family_recall": float((flagged[mask] & (family_guess[mask] == name)).mean()) if mask.any() else None,
            "family_prediction_accuracy_when_flagged": (
                float((family_guess[mask & flagged] == name).mean()) if (mask & flagged).any() else None
            ),
        }
    return {
        "rows": int(len(frame)),
        "priority_attack_rows": int(in_scope.sum()),
        "benign_rows": int(benign.sum()),
        "out_of_scope_attack_rows": int((~benign & ~in_scope).sum()),
        "threshold": threshold,
        "priority_detection_recall": float(tp / max(1, tp + fn)),
        "benign_false_positive_rate": float(fp / max(1, fp + tn)),
        "precision_among_priority_and_benign": float(tp / max(1, tp + fp)),
        "confusion_matrix_tn_fp_fn_tp_priority_vs_benign": [int(tn), int(fp), int(fn), int(tp)],
        "priority_family_recall": per_family,
        "out_of_scope_attack_flag_rate": (
            float(flagged[~benign & ~in_scope].mean()) if (~benign & ~in_scope).any() else None
        ),
    }


def _ovr_metrics(frame: pd.DataFrame, scores: np.ndarray, thresholds: np.ndarray) -> dict:
    actual = frame["__family"].to_numpy(dtype=object)
    benign = actual == "Benign"
    in_scope = np.isin(actual, PRIORITY)
    flags_by_family = scores >= thresholds.reshape(1, -1)
    flagged = flags_by_family.any(axis=1)
    # If multiple family-specific detectors fire, assign the highest score
    # relative to its own calibrated threshold.
    scaled = scores / np.maximum(thresholds.reshape(1, -1), 1e-12)
    guesses = np.asarray(PRIORITY, dtype=object)[np.argmax(scaled, axis=1)]
    eligible = benign | in_scope
    tn, fp, fn, tp = confusion_matrix(in_scope[eligible].astype(int),
                                      flagged[eligible].astype(int), labels=[0, 1]).ravel()
    per_family = {}
    for index, family in enumerate(PRIORITY):
        mask = actual == family
        per_family[family] = {
            "rows": int(mask.sum()),
            "detection_recall": float(flags_by_family[mask, index].mean()) if mask.any() else None,
            "correct_family_recall": float((flags_by_family[mask, index] & (guesses[mask] == family)).mean()) if mask.any() else None,
        }
    return {
        "rows": int(len(frame)),
        "priority_attack_rows": int(in_scope.sum()),
        "benign_rows": int(benign.sum()),
        "thresholds_by_family": {family: float(thresholds[index]) for index, family in enumerate(PRIORITY)},
        "priority_detection_recall": float(tp / max(1, tp + fn)),
        "benign_false_positive_rate": float(fp / max(1, fp + tn)),
        "precision_among_priority_and_benign": float(tp / max(1, tp + fp)),
        "confusion_matrix_tn_fp_fn_tp_priority_vs_benign": [int(tn), int(fp), int(fn), int(tp)],
        "priority_family_recall": per_family,
        "out_of_scope_attack_flag_rate": (
            float(flagged[~benign & ~in_scope].mean()) if (~benign & ~in_scope).any() else None
        ),
    }


def run() -> dict:
    files17 = sorted(DATA_2017.glob("*.parquet"))
    files18 = sorted(DATA_2018.glob("*.parquet"))
    if not files17 or len(files18) != 10:
        raise FileNotFoundError("Expected CICIDS2017 Parquet files and ten CSE-CIC-IDS2018 captures")
    if BOTNET_HOLDOUT not in {path.name for path in files17}:
        raise ValueError(f"Missing Botnet holdout capture {BOTNET_HOLDOUT}")
    if FOLD_A - {path.name for path in files18}:
        raise ValueError("2018 split manifest does not match the available capture files")

    train_parts, calibration_parts, test_parts = [], [], []
    audit = {"train_captures": [], "calibration_benign_captures": [], "test_captures": [],
             "2017_botnet_holdout": BOTNET_HOLDOUT}
    for index, path in enumerate(files17):
        rows = _load_capture(path, SEED + index)
        if path.name == BOTNET_HOLDOUT:
            test_parts.append(rows)
            audit["test_captures"].append(path.name)
        else:
            train_parts.append(rows)
            audit["train_captures"].append(path.name)

    for index, path in enumerate(files18, start=len(files17)):
        rows = _load_capture(path, SEED + index)
        if path.name in FOLD_A:
            attacks = rows[rows["__family"] != "Benign"]
            benign = rows[rows["__family"] == "Benign"]
            # Use a flow-disjoint sample from each training capture for benign
            # threshold calibration; train on the remaining benign rows and all
            # labeled attacks in those captures.
            if not benign.empty:
                calibration = benign.sample(frac=0.25, random_state=SEED + index)
                benign_train = benign.drop(index=calibration.index)
                calibration_parts.append(calibration)
                train_parts.append(pd.concat([attacks, benign_train], ignore_index=True))
                audit["train_captures"].append(f"{path.name} (remaining rows)")
                audit["calibration_benign_captures"].append(path.name)
        else:
            test_parts.append(rows)
            audit["test_captures"].append(path.name)

    train = pd.concat(train_parts, ignore_index=True)
    calibration = pd.concat(calibration_parts, ignore_index=True)
    test = pd.concat(test_parts, ignore_index=True)
    # Remove exact feature-only duplicates before fitting, calibration, or test.
    train_hash = pd.util.hash_pandas_object(train[FEATURES], index=False)
    train = train.loc[~train_hash.duplicated()].reset_index(drop=True)
    calibration, calibration_overlap = _remove_feature_overlap(calibration, [train])
    test, test_overlap = _remove_feature_overlap(test, [train, calibration])
    if not (calibration["__family"] == "Benign").any():
        raise ValueError("No benign calibration rows remain after overlap removal")

    # The candidate is trained to classify benign, the five priority families,
    # and a catch-all for other attacks; only priority classes trigger its score.
    train["__target"] = np.where(train["__family"].isin(PRIORITY), train["__family"],
                                  np.where(train["__family"] == "Benign", "Benign", "OtherAttack"))
    calibration["__target"] = np.where(calibration["__family"].isin(PRIORITY), calibration["__family"],
                                        np.where(calibration["__family"] == "Benign", "Benign", "OtherAttack"))
    test["__target"] = np.where(test["__family"].isin(PRIORITY), test["__family"],
                                np.where(test["__family"] == "Benign", "Benign", "OtherAttack"))
    encoder = LabelEncoder().fit(train["__target"])
    y_train = encoder.transform(train["__target"])
    n_classes = len(encoder.classes_)
    if n_classes < len(PRIORITY) + 2:
        raise ValueError(f"Training data lacks required classes: {encoder.classes_.tolist()}")

    models = {
        "random_forest": RandomForestClassifier(
            n_estimators=300, min_samples_leaf=2, class_weight="balanced_subsample",
            n_jobs=1, random_state=SEED,
        ),
        "xgboost": XGBClassifier(
            n_estimators=350, max_depth=8, learning_rate=0.07, subsample=0.8,
            colsample_bytree=0.85, tree_method="hist", n_jobs=4,
            objective="multi:softprob", num_class=n_classes, eval_metric="mlogloss",
            random_state=SEED,
        ),
    }
    benign_cal = calibration[calibration["__family"] == "Benign"]
    output = {
        "schema": "priority-family-candidate-v1",
        "production_artifacts_modified": False,
        "priority_families": list(PRIORITY),
        "acceptance_criteria": {"minimum_correct_family_recall_each": 0.80,
                                 "maximum_benign_false_positive_rate": TARGET_FPR},
        "feature_count": len(FEATURES),
        "split_audit": audit,
        "exact_duplicate_rows_removed": {"calibration_vs_training": calibration_overlap,
                                          "test_vs_training_and_calibration": test_overlap},
        "rows": {"train": int(len(train)), "calibration_benign": int(len(benign_cal)),
                 "test": int(len(test))},
        "calibration_method": "benign-only threshold calibrated on 2018 fold-A benign flows; target empirical FPR <= 1%",
        "models": {},
        "limitations": [
            "The test set is a fixed public-dataset capture holdout, not live network traffic.",
            "The 2017 Botnet capture is tested separately because no Botnet capture exists in the 2018 test fold.",
            "No candidate artifacts are saved or promoted.",
            "Dataset row frequencies are not estimates of real-world prevalence.",
        ],
    }

    for name, model in models.items():
        fit_args = {}
        if name == "xgboost":
            fit_args["sample_weight"] = _balanced_weights(y_train)
        model.fit(train[FEATURES], y_train, **fit_args)
        calibration_scores, _ = _scores(model, encoder, benign_cal)
        threshold = _threshold(calibration_scores, TARGET_FPR)
        cal_fpr = float(np.mean(calibration_scores >= threshold))
        if cal_fpr > TARGET_FPR:
            raise AssertionError(f"Calibrated FPR {cal_fpr:.4%} exceeded {TARGET_FPR:.2%}")
        test_scores, test_guesses = _scores(model, encoder, test)
        pooled = _metrics(test, test_scores, test_guesses, threshold)
        per_capture = {}
        for capture_name, capture in test.groupby("__capture", sort=True):
            positions = test.index.get_indexer(capture.index)
            per_capture[str(capture_name)] = _metrics(
                capture, test_scores[positions], test_guesses[positions], threshold
            )
        acceptance_families = pooled["priority_family_recall"]
        failures = [f"{family} correct-family recall below 80% or not testable"
                    for family in PRIORITY
                    if acceptance_families[family]["correct_family_recall"] is None
                    or acceptance_families[family]["correct_family_recall"] < 0.80]
        if pooled["benign_false_positive_rate"] > TARGET_FPR:
            failures.append("benign false-positive rate above 1%")
        output["models"][name] = {
            "threshold": threshold,
            "calibration_benign_fpr": cal_fpr,
            "heldout": pooled,
            "per_capture": per_capture,
            "acceptance": {"decision": "ACCEPT" if not failures else "IMPROVE", "failures": failures},
        }

    # One-vs-rest classifiers give each priority family its own score and
    # allocate a fifth of the overall benign alert budget to each detector.
    # The union is evaluated independently because test captures can differ
    # from calibration captures and the individual rates need not add neatly.
    output["one_vs_rest"] = {}
    family_budget = TARGET_FPR / len(PRIORITY)
    for model_name in ("random_forest", "xgboost"):
        family_models = {}
        thresholds = []
        test_score_columns = []
        cal_fprs = {}
        for family in PRIORITY:
            y_binary = train["__family"].eq(family).astype("int8").to_numpy()
            if model_name == "random_forest":
                detector = RandomForestClassifier(
                    n_estimators=160, min_samples_leaf=2, class_weight="balanced_subsample",
                    n_jobs=1, random_state=SEED,
                )
            else:
                detector = XGBClassifier(
                    n_estimators=180, max_depth=6, learning_rate=0.08, subsample=0.8,
                    colsample_bytree=0.9, tree_method="hist", n_jobs=4,
                    eval_metric="logloss", random_state=SEED,
                )
            if model_name == "xgboost":
                detector.fit(train[FEATURES], y_binary, sample_weight=_balanced_weights(y_binary))
            else:
                detector.fit(train[FEATURES], y_binary)
            positive_index = list(detector.classes_).index(1)
            cal_scores = detector.predict_proba(benign_cal[FEATURES])[:, positive_index]
            threshold = _threshold(cal_scores, family_budget)
            cal_fpr = float(np.mean(cal_scores >= threshold))
            if cal_fpr > family_budget:
                raise AssertionError(f"{family} calibration FPR {cal_fpr:.4%} exceeded {family_budget:.4%}")
            test_scores = detector.predict_proba(test[FEATURES])[:, positive_index]
            family_models[family] = {"threshold": threshold, "calibration_fpr": cal_fpr}
            thresholds.append(threshold)
            test_score_columns.append(test_scores)
            cal_fprs[family] = cal_fpr
        score_matrix = np.column_stack(test_score_columns)
        thresholds_array = np.asarray(thresholds, dtype=float)
        pooled = _ovr_metrics(test, score_matrix, thresholds_array)
        per_capture = {}
        for capture_name, capture in test.groupby("__capture", sort=True):
            positions = test.index.get_indexer(capture.index)
            per_capture[str(capture_name)] = _ovr_metrics(capture, score_matrix[positions], thresholds_array)
        families = pooled["priority_family_recall"]
        failures = [f"{family} recall below 80% or not testable"
                    for family in PRIORITY
                    if families[family]["detection_recall"] is None or families[family]["detection_recall"] < 0.80]
        if pooled["benign_false_positive_rate"] > TARGET_FPR:
            failures.append("combined benign false-positive rate above 1%")
        output["one_vs_rest"][model_name] = {
            "family_detectors": family_models,
            "per_detector_calibration_fpr": cal_fprs,
            "heldout": pooled,
            "per_capture": per_capture,
            "acceptance": {"decision": "ACCEPT" if not failures else "IMPROVE", "failures": failures},
        }
    return output


def main() -> int:
    result = run()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(OUTPUT), "training_rows": result["rows"]["train"],
                      "test_rows": result["rows"]["test"],
                      "models": {name: {"decision": model["acceptance"]["decision"],
                                        "failures": model["acceptance"]["failures"],
                                        "benign_fpr": model["heldout"]["benign_false_positive_rate"],
                                        "family_recall": {family: values["correct_family_recall"]
                                                         for family, values in model["heldout"]["priority_family_recall"].items()}}
                                 for name, model in result["models"].items()},
                      "one_vs_rest": {name: {"decision": model["acceptance"]["decision"],
                                              "failures": model["acceptance"]["failures"],
                                              "benign_fpr": model["heldout"]["benign_false_positive_rate"],
                                              "family_recall": {family: values["detection_recall"]
                                                                for family, values in model["heldout"]["priority_family_recall"].items()}}
                                      for name, model in result["one_vs_rest"].items()}}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
