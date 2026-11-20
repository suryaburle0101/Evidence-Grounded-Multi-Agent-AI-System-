"""Research-only multi-class candidate for 12 CICFlowMeter attack types.

Training uses complete capture files from CICIDS2017 and CSE-CIC-IDS2018.
Complete files from both datasets are held out for testing, while benign flows
from a separate complete capture are used for threshold calibration. No model
artifacts are promoted.

Run from the repository root:
    .\\recovery_venv\\Scripts\\python.exe evaluation\\ten_type_candidate.py
"""
from __future__ import annotations

import json
import math
import re
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation.production_model_validation import sample_capture
from pipeline.data_pipeline import FEATURES

DATA = ROOT / "data" / "raw"
OUT = ROOT / "reports" / "ten_type_candidate" / "ten_type_candidate.json"
SEED = 42
TRAIN_CAP = 15_000
EVAL_CAP = 8_000
BENIGN_FPR_LIMIT = 0.01

# CICIDS2017 labels are retained at attack-type granularity and CICIDS2018
# spelling/tool variants map into the same semantic type where appropriate.
ATTACK_TYPES = (
    "Botnet", "FTP-BruteForce", "SSH-BruteForce", "DDoS",
    "DoS-Hulk", "DoS-GoldenEye", "DoS-Slowloris", "DoS-SlowHTTPTest",
    "Infiltration", "Web-BruteForce", "Web-XSS", "SQL-Injection",
)
CLASSES = ("Benign", *ATTACK_TYPES)
CALIBRATION_CAPTURE_NAMES = {
    "Benign-Monday-no-metadata.parquet",
    "DDoS1-Tuesday-20-02-2018_TrafficForML_CICFlowMeter.parquet",
}
TEST_CAPTURE_NAMES = {
    "DoS-Wednesday-no-metadata.parquet",
    "Botnet-Friday-02-03-2018_TrafficForML_CICFlowMeter.parquet",
    "Bruteforce-Wednesday-14-02-2018_TrafficForML_CICFlowMeter.parquet",
    "DDoS2-Wednesday-21-02-2018_TrafficForML_CICFlowMeter.parquet",
    "Infil2-Thursday-01-03-2018_TrafficForML_CICFlowMeter.parquet",
    "Web1-Thursday-22-02-2018_TrafficForML_CICFlowMeter.parquet",
}


def canonical_type(raw: object) -> str:
    text = re.sub(r"[^a-z0-9]+", " ", str(raw).strip().casefold()).strip()
    if text in {"benign", "normal"}:
        return "Benign"
    if "heartbleed" in text:
        return "Heartbleed"  # deliberately out of the 12-type candidate
    if "infil" in text:
        return "Infiltration"
    if "ddos" in text:
        return "DDoS"
    if "hulk" in text:
        return "DoS-Hulk"
    if "goldeneye" in text:
        return "DoS-GoldenEye"
    if "slowloris" in text:
        return "DoS-Slowloris"
    if "slowhttptest" in text or "slow http test" in text:
        return "DoS-SlowHTTPTest"
    if "ftp" in text and ("patator" in text or "brute" in text):
        return "FTP-BruteForce"
    if "ssh" in text and ("patator" in text or "brute" in text):
        return "SSH-BruteForce"
    if "bot" in text:
        return "Botnet"
    if "xss" in text:
        return "Web-XSS"
    if "sql" in text or "injection" in text:
        return "SQL-Injection"
    if "web" in text and "brute" in text:
        return "Web-BruteForce"
    return "OutOfScope"


def load_capture(path: Path, cap: int) -> tuple[pd.DataFrame, dict]:
    frame, quality = sample_capture(path, cap, batch_size=100_000, seed=SEED)
    if frame.empty:
        return frame, quality
    frame["__type"] = frame["__raw_label"].map(canonical_type)
    frame["__capture"] = path.name
    return frame, quality


def row_hashes(frame: pd.DataFrame) -> pd.Series:
    return pd.util.hash_pandas_object(frame[FEATURES], index=False)


def threshold_for_fpr(benign_scores: np.ndarray, target: float) -> tuple[float, float]:
    scores = np.asarray(benign_scores, dtype=float)
    if not len(scores):
        raise ValueError("No benign calibration scores")
    threshold = float(np.quantile(scores, 1.0 - target, method="higher"))
    threshold = float(np.nextafter(threshold, math.inf))
    observed = float(np.mean(scores >= threshold))
    return threshold, observed


def score_model(model, encoder: LabelEncoder, X: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    probs = np.asarray(model.predict_proba(X), dtype=float)
    labels = [str(x) for x in encoder.classes_]
    attack_idx = [i for i, name in enumerate(labels) if name != "Benign"]
    attack_probs = probs[:, attack_idx]
    choices = np.argmax(attack_probs, axis=1)
    predicted = np.asarray([labels[attack_idx[i]] for i in choices], dtype=object)
    score = attack_probs.max(axis=1)
    return predicted, score


def per_type_thresholds(model, encoder: LabelEncoder, X: pd.DataFrame,
                        benign_mask: np.ndarray) -> tuple[dict[str, float], float]:
    probs = np.asarray(model.predict_proba(X), dtype=float)
    budget = BENIGN_FPR_LIMIT / len(ATTACK_TYPES)
    thresholds = {}
    for idx, name in enumerate(encoder.classes_):
        if name == "Benign":
            continue
        thresholds[str(name)], _ = threshold_for_fpr(probs[benign_mask, idx], budget)
    cal_fire = np.zeros((len(X), len(ATTACK_TYPES)), dtype=bool)
    for j, name in enumerate(ATTACK_TYPES):
        class_idx = int(np.flatnonzero(encoder.classes_ == name)[0])
        cal_fire[:, j] = probs[:, class_idx] >= thresholds[name]
    union_fpr = float(cal_fire[benign_mask].any(axis=1).mean())
    return thresholds, union_fpr


def per_type_metrics(frame: pd.DataFrame, probs: np.ndarray, encoder: LabelEncoder,
                     thresholds: dict[str, float]) -> dict:
    attack_indices = [int(np.flatnonzero(encoder.classes_ == name)[0]) for name in ATTACK_TYPES]
    attack_probs = probs[:, attack_indices]
    limits = np.asarray([thresholds[name] for name in ATTACK_TYPES], dtype=float)
    fired = attack_probs >= limits.reshape(1, -1)
    flagged = fired.any(axis=1)
    normalized = attack_probs / limits.reshape(1, -1)
    normalized[~fired] = -np.inf
    guess_indices = np.argmax(normalized, axis=1)
    guessed = np.asarray(ATTACK_TYPES, dtype=object)[guess_indices]
    actual = frame["__type"].to_numpy(dtype=object)
    benign = actual == "Benign"
    attack = np.isin(actual, ATTACK_TYPES)
    per_type = {}
    for j, name in enumerate(ATTACK_TYPES):
        mask = actual == name
        per_type[name] = {
            "support": int(mask.sum()),
            "detected_recall": float(flagged[mask].mean()) if mask.any() else None,
            "correct_type_recall": float((flagged[mask] & (guessed[mask] == name)).mean()) if mask.any() else None,
            "class_detector_recall": float(fired[mask, j].mean()) if mask.any() else None,
        }
    observed_classes = [v["correct_type_recall"] for v in per_type.values()
                        if v["correct_type_recall"] is not None]
    return {
        "rows": int(len(frame)),
        "benign_rows": int(benign.sum()),
        "attack_rows_in_scope": int(attack.sum()),
        "benign_false_positive_rate": float(flagged[benign].mean()) if benign.any() else None,
        "attack_detection_recall": float(flagged[attack].mean()) if attack.any() else None,
        "correct_type_recall_macro": float(np.mean(observed_classes)) if observed_classes else None,
        "per_attack_type": per_type,
    }


def metrics(frame: pd.DataFrame, predicted: np.ndarray, score: np.ndarray,
            threshold: float) -> dict:
    actual = frame["__type"].to_numpy(dtype=object)
    benign = actual == "Benign"
    attack = np.isin(actual, ATTACK_TYPES)
    flagged = score >= threshold
    per_type = {}
    for name in ATTACK_TYPES:
        mask = actual == name
        per_type[name] = {
            "support": int(mask.sum()),
            "detected_recall": float(flagged[mask].mean()) if mask.any() else None,
            "correct_type_recall": float((flagged[mask] & (predicted[mask] == name)).mean()) if mask.any() else None,
            "top_type_accuracy": float((predicted[mask] == name).mean()) if mask.any() else None,
        }
    return {
        "rows": int(len(frame)),
        "benign_rows": int(benign.sum()),
        "attack_rows_in_scope": int(attack.sum()),
        "benign_false_positive_rate": float(flagged[benign].mean()) if benign.any() else None,
        "attack_detection_recall": float(flagged[attack].mean()) if attack.any() else None,
        "correct_type_recall_macro": float(np.mean([
            x["correct_type_recall"] for x in per_type.values()
            if x["correct_type_recall"] is not None
        ])) if any(x["correct_type_recall"] is not None for x in per_type.values()) else None,
        "per_attack_type": per_type,
    }


def main() -> int:
    all_paths = sorted([* (DATA / "CICIDS2017").glob("*.parquet"),
                        * (DATA / "CSE_CIC_IDS2018").glob("*.parquet")])
    train_paths = [p for p in all_paths
                   if p.name not in TEST_CAPTURE_NAMES and p.name not in CALIBRATION_CAPTURE_NAMES]
    test_paths = [p for p in all_paths if p.name in TEST_CAPTURE_NAMES]
    cal_paths = [p for p in all_paths if p.name in CALIBRATION_CAPTURE_NAMES]
    if (not train_paths or len(test_paths) != len(TEST_CAPTURE_NAMES)
            or len(cal_paths) != len(CALIBRATION_CAPTURE_NAMES)):
        raise FileNotFoundError("Required CICIDS2017/CSE-CIC-IDS2018 capture files are missing")

    train_parts, train_quality = [], {}
    for path in train_paths:
        frame, quality = load_capture(path, TRAIN_CAP)
        if not frame.empty:
            train_parts.append(frame[frame["__type"].isin(CLASSES)])
        train_quality[path.name] = quality
    train = pd.concat(train_parts, ignore_index=True)
    train = train.drop_duplicates(subset=FEATURES + ["__type"]).reset_index(drop=True)
    absent_train = [name for name in ATTACK_TYPES if not (train["__type"] == name).any()]
    if absent_train:
        raise ValueError(f"Training labels absent for required attack types: {absent_train}")

    cal_parts, cal_quality = [], {}
    for path in cal_paths:
        frame, quality = load_capture(path, EVAL_CAP)
        cal_parts.append(frame[frame["__type"] == "Benign"].copy())
        cal_quality[path.name] = quality
    cal = pd.concat(cal_parts, ignore_index=True)
    if cal.empty:
        raise ValueError("Chosen calibration capture has no benign rows")

    test_parts, test_quality = [], {}
    for path in test_paths:
        frame, quality = load_capture(path, EVAL_CAP)
        if not frame.empty:
            test_parts.append(frame[frame["__type"].isin(CLASSES)])
        test_quality[path.name] = quality
    test = pd.concat(test_parts, ignore_index=True)

    # Exclude feature-identical rows that cross the capture split boundary.
    train_hash = set(row_hashes(train))
    cal_hash = set(row_hashes(cal))
    cal_overlap = row_hashes(cal).isin(train_hash)
    cal = cal.loc[~cal_overlap].reset_index(drop=True)
    cal_hash = set(row_hashes(cal))
    test_hash = row_hashes(test)
    test_overlap = test_hash.isin(train_hash | cal_hash)
    test = test.loc[~test_overlap].reset_index(drop=True)

    encoder = LabelEncoder().fit(CLASSES)
    y = encoder.transform(train["__type"])
    counts = np.bincount(y, minlength=len(encoder.classes_))
    weights = {i: len(y) / (len(counts) * max(1, count)) for i, count in enumerate(counts)}
    sample_weights = np.asarray([weights[int(i)] for i in y], dtype=float)
    X_train, X_cal, X_test = train[FEATURES], cal[FEATURES], test[FEATURES]
    cal_benign = cal["__type"].eq("Benign").to_numpy()
    if not cal_benign.any():
        raise ValueError("No non-overlapping benign calibration examples remain")

    candidates = {
        "random_forest": RandomForestClassifier(
            n_estimators=300, max_features="sqrt", min_samples_leaf=2,
            class_weight="balanced_subsample", random_state=SEED, n_jobs=-1,
        ),
        "xgboost": XGBClassifier(
            objective="multi:softprob", num_class=len(encoder.classes_),
            eval_metric="mlogloss", n_estimators=240, max_depth=6,
            learning_rate=0.08, subsample=0.85, colsample_bytree=0.85,
            tree_method="hist", random_state=SEED, n_jobs=-1,
        ),
    }
    models_out = {}
    for name, model in candidates.items():
        if name == "xgboost":
            model.fit(X_train, y, sample_weight=sample_weights, verbose=False)
        else:
            model.fit(X_train, y)
        cal_pred, cal_score = score_model(model, encoder, X_cal)
        threshold, observed_cal_fpr = threshold_for_fpr(cal_score[cal_benign], BENIGN_FPR_LIMIT)
        test_pred, test_score = score_model(model, encoder, X_test)
        overall = metrics(test, test_pred, test_score, threshold)
        class_thresholds, observed_classwise_cal_fpr = per_type_thresholds(
            model, encoder, X_cal, cal_benign)
        classwise_test_probs = np.asarray(model.predict_proba(X_test), dtype=float)
        classwise = per_type_metrics(test, classwise_test_probs, encoder, class_thresholds)
        by_capture = {}
        for capture in sorted(test["__capture"].unique()):
            mask = test["__capture"].eq(capture).to_numpy()
            subframe = test.loc[mask].reset_index(drop=True)
            by_capture[capture] = {
                "shared_threshold": metrics(subframe, test_pred[mask], test_score[mask], threshold),
                "per_type_thresholds": per_type_metrics(subframe, classwise_test_probs[mask], encoder,
                                                        class_thresholds),
            }
        supported = [k for k, v in classwise["per_attack_type"].items() if v["support"] > 0]
        failures = []
        if classwise["benign_false_positive_rate"] is None or classwise["benign_false_positive_rate"] > BENIGN_FPR_LIMIT:
            failures.append("held-out benign false-positive rate exceeds 1%")
        if len(supported) < 10:
            failures.append("fewer than 10 attack types have held-out examples")
        failures.extend(f"{k} correct-type recall below 80% or unobserved"
                        for k, v in classwise["per_attack_type"].items()
                        if v["correct_type_recall"] is None or v["correct_type_recall"] < 0.80)
        models_out[name] = {
            "shared_threshold_baseline": {
                "threshold": threshold,
                "calibration_benign_fpr": observed_cal_fpr,
                "heldout": overall,
            },
            "per_type_threshold_candidate": {
                "thresholds": class_thresholds,
                "calibration_benign_fpr_union": observed_classwise_cal_fpr,
                "heldout": classwise,
            },
            "calibration_rows": int(len(cal)),
            "per_capture": by_capture,
            "decision": "ACCEPT" if not failures else "IMPROVE",
            "failures": failures,
        }

    result = {
        "schema": "capture-heldout-12-attack-type-candidate-v1",
        "scope": {
            "attack_types": list(ATTACK_TYPES),
            "excluded": {"PortScan": "not present in the CSE-CIC-IDS2018 test captures",
                         "Heartbleed": "only 11 CICIDS2017 training rows; absent from the 2018 test source"},
            "label_mapping": "CICIDS2017 and CSE-CIC-IDS2018 tool/name variants normalized to 12 attack types; attack subtypes kept separate where both datasets label them",
        },
        "split": {
            "training": "complete CICIDS2017 and CSE-CIC-IDS2018 capture files except named calibration/test captures",
            "calibration": "benign rows only from separate complete CICIDS2017 and CSE-CIC-IDS2018 capture files",
            "calibration_capture_files": sorted(CALIBRATION_CAPTURE_NAMES),
            "test": "complete named capture files from both CICIDS2017 and CSE-CIC-IDS2018",
            "test_capture_files": sorted(TEST_CAPTURE_NAMES),
            "target_benign_fpr": BENIGN_FPR_LIMIT,
            "duplicate_policy": "feature-identical rows across train/calibration/test capture groups removed from later groups",
        },
        "training_rows": int(len(train)),
        "training_counts": {str(k): int(v) for k, v in train["__type"].value_counts().items()},
        "calibration_capture_quality": cal_quality,
        "training_capture_quality": train_quality,
        "test_capture_quality": test_quality,
        "removed_overlap_rows": {"calibration": int(cal_overlap.sum()), "test": int(test_overlap.sum())},
        "acceptance_criteria": {
            "minimum_attack_types_with_heldout_examples": 10,
            "minimum_correct_type_recall_each": 0.80,
            "maximum_benign_false_positive_rate": BENIGN_FPR_LIMIT,
            "promotion": "never; research candidate only",
        },
        "promotion": "not_performed",
        "models": models_out,
        "limitations": [
            "This is cross-dataset evaluation: CICIDS2017 training and CSE-CIC-IDS2018 calibration/test captures.",
            "The evaluation can show whether these 12 labels transfer; it cannot guarantee detection of every real-world attack.",
            "PortScan and Heartbleed are not counted toward the 12-type target because there is no adequate held-out 2018 support.",
            "Models are in-memory research candidates only and do not replace active production artifacts.",
        ],
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(OUT), "training_rows": len(train),
                      "heldout_rows": len(test), "attack_types": list(ATTACK_TYPES),
                      "models": {name: {"decision": v["decision"],
                                        "attack_recall": v["per_type_threshold_candidate"]["heldout"]["attack_detection_recall"],
                                        "correct_type_recall_macro": v["per_type_threshold_candidate"]["heldout"]["correct_type_recall_macro"],
                                        "benign_fpr": v["per_type_threshold_candidate"]["heldout"]["benign_false_positive_rate"],
                                        "failures": len(v["failures"])}
                                 for name, v in models_out.items()}}, indent=2))
    return 0 if any(v["decision"] == "ACCEPT" for v in models_out.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
