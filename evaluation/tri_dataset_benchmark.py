"""Group-held-out binary IDS benchmark across CICIDS2017, CSE-CIC-IDS2018, and UNSW-NB15.

This is a research/evaluation workflow. It does not replace the production
77-feature models. CICFlowMeter and UNSW-NB15 use different feature schemas,
so this benchmark maps only a small set of semantically shared flow features
and reports the limitations of cross-dataset results.

Run from the project root with the pinned environment:
    .\recovery_venv\Scripts\python.exe evaluation\tri_dataset_benchmark.py
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "raw"
REPORT_DIR = ROOT / "reports" / "tri_dataset_benchmark"
UNSW_FEATURES_FILE = DATA / "UNSW_NB15" / "NUSW-NB15_features.csv"
FEATURES = [
    "duration_s", "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes",
    "fwd_mean_bytes", "bwd_mean_bytes", "packets_per_second",
    "protocol_tcp", "protocol_udp", "protocol_icmp",
]
RANDOM_STATE = 42
DEFAULT_ROWS_PER_FILE = 20_000
SPLIT_MANIFEST = {
    "CICIDS2017": {
        "calibration": ["Infiltration-Thursday-no-metadata.parquet"],
        "test": ["Portscan-Friday-no-metadata.parquet", "WebAttacks-Thursday-no-metadata.parquet"],
    },
    "CSE-CIC-IDS2018": {
        "calibration": ["Infil2-Thursday-01-03-2018_TrafficForML_CICFlowMeter.parquet"],
        "test": ["Web1-Thursday-22-02-2018_TrafficForML_CICFlowMeter.parquet",
                 "Web2-Friday-23-02-2018_TrafficForML_CICFlowMeter.parquet"],
    },
    "UNSW-NB15": {
        "calibration": ["UNSW-NB15_3.csv"],
        "test": ["UNSW-NB15_4.csv"],
    },
}


def _clean_label(value: object) -> str:
    return re.sub(r"\s+", " ", str(value).replace("\ufeff", "").strip()).casefold()


def _first_column(frame: pd.DataFrame, candidates: tuple[str, ...]) -> str:
    names = {str(col).strip().casefold(): str(col) for col in frame.columns}
    for candidate in candidates:
        if candidate.casefold() in names:
            return names[candidate.casefold()]
    raise ValueError(f"Missing expected data field; tried {candidates}")


def _protocol_flags(values: pd.Series) -> pd.DataFrame:
    numeric = pd.to_numeric(values, errors="coerce")
    text = values.astype(str).str.strip().str.lower()
    tcp = numeric.eq(6) | text.eq("tcp")
    udp = numeric.eq(17) | text.eq("udp")
    icmp = numeric.isin([1, 58]) | text.isin(["icmp", "icmpv6", "ipv6-icmp"])
    return pd.DataFrame({
        "protocol_tcp": tcp.astype("float32"),
        "protocol_udp": udp.astype("float32"),
        "protocol_icmp": icmp.astype("float32"),
    }, index=values.index)


def _build_shared_features(
    frame: pd.DataFrame,
    *,
    protocol: str,
    duration: str,
    duration_scale: float,
    fwd_packets: str,
    bwd_packets: str,
    fwd_bytes: str,
    bwd_bytes: str,
) -> pd.DataFrame:
    """Convert each source schema into common, unit-normalized flow features."""
    duration_s = pd.to_numeric(frame[duration], errors="coerce") / duration_scale
    fwd_pkts = pd.to_numeric(frame[fwd_packets], errors="coerce").clip(lower=0)
    bwd_pkts = pd.to_numeric(frame[bwd_packets], errors="coerce").clip(lower=0)
    fwd_octets = pd.to_numeric(frame[fwd_bytes], errors="coerce").clip(lower=0)
    bwd_octets = pd.to_numeric(frame[bwd_bytes], errors="coerce").clip(lower=0)
    safe_duration = duration_s.where(duration_s > 0)
    result = pd.DataFrame({
        "duration_s": duration_s,
        "fwd_packets": fwd_pkts,
        "bwd_packets": bwd_pkts,
        "fwd_bytes": fwd_octets,
        "bwd_bytes": bwd_octets,
        "fwd_mean_bytes": fwd_octets / fwd_pkts.replace(0, np.nan),
        "bwd_mean_bytes": bwd_octets / bwd_pkts.replace(0, np.nan),
        "packets_per_second": (fwd_pkts + bwd_pkts) / safe_duration,
    }, index=frame.index)
    result = pd.concat([result, _protocol_flags(frame[protocol])], axis=1)
    # Rates and means can be undefined for zero-duration/zero-packet rows;
    # use zero only after marking those cases so the data-quality report sees them.
    return result.replace([np.inf, -np.inf], np.nan)


def _sample_file(frame: pd.DataFrame, label_column: str, max_rows: int) -> pd.DataFrame:
    if len(frame) <= max_rows:
        return frame
    labels = frame[label_column].astype(str)
    groups = []
    # Keep every rare labeled example when possible, then allocate the remaining
    # sample proportionally. This avoids dropping all Heartbleed/Infiltration rows.
    rare = labels.value_counts()
    rare_names = set(rare[rare <= max(500, int(max_rows * 0.05))].index)
    for label, group in frame.groupby(label_column, dropna=False, sort=True):
        if str(label) in rare_names:
            groups.append(group)
    budget = max(0, max_rows - sum(len(group) for group in groups))
    common = frame[~labels.isin(rare_names)]
    if budget and not common.empty:
        sample = common.sample(n=min(budget, len(common)), random_state=RANDOM_STATE)
        groups.append(sample)
    sampled = pd.concat(groups, ignore_index=True) if groups else frame.sample(max_rows, random_state=RANDOM_STATE)
    if len(sampled) > max_rows:
        # Rare rows have priority; trim the largest class first, deterministically.
        counts = sampled[label_column].astype(str).value_counts()
        trim_label = counts.index[0]
        keep = sampled[sampled[label_column].astype(str) != trim_label]
        trim = sampled[sampled[label_column].astype(str) == trim_label]
        sampled = pd.concat([keep, trim.sample(max(0, max_rows - len(keep)), random_state=RANDOM_STATE)])
    return sampled.reset_index(drop=True)


def _read_cicflow_file(path: Path, dataset: str, max_rows: int) -> pd.DataFrame:
    import pyarrow.parquet as pq

    schema_cols = [str(c).strip() for c in pq.read_schema(path).names]
    schema = pd.DataFrame(columns=schema_cols)
    label_col = _first_column(schema, ("Label",))
    protocol = _first_column(schema, ("Protocol",))
    duration = _first_column(schema, ("Flow Duration",))
    fp = _first_column(schema, ("Total Fwd Packets", "Tot Fwd Pkts"))
    bp = _first_column(schema, ("Total Backward Packets", "Tot Bwd Pkts"))
    fb = _first_column(schema, ("Fwd Packets Length Total", "Total Length of Fwd Packets", "TotLen Fwd Pkts"))
    bb = _first_column(schema, ("Bwd Packets Length Total", "Total Length of Bwd Packets", "TotLen Bwd Pkts"))
    selected = list(dict.fromkeys([label_col, protocol, duration, fp, bp, fb, bb]))
    source = pd.read_parquet(path, columns=selected)
    source = source[[label_col, protocol, duration, fp, bp, fb, bb]].copy()
    source = source[~source[label_col].astype(str).str.strip().str.casefold().eq("label")]
    source = _sample_file(source, label_col, max_rows)
    features = _build_shared_features(
        source, protocol=protocol, duration=duration, duration_scale=1_000_000.0,
        fwd_packets=fp, bwd_packets=bp, fwd_bytes=fb, bwd_bytes=bb,
    )
    labels = source[label_col].map(lambda x: 0 if _clean_label(x) in {"benign", "normal"} else 1)
    return _finalize_rows(features, labels, dataset, path.name)


def _read_unsw_file(path: Path, names: list[str], max_rows: int) -> pd.DataFrame:
    normalized = [str(name).strip() for name in names]
    name_map = {name.casefold(): name for name in normalized}
    required = [name_map[key] for key in (
        "proto", "dur", "spkts", "dpkts", "sbytes", "dbytes", "label"
    )]
    # Headerless UNSW parts are read with the official feature list; load only
    # the columns used by this benchmark, preserving the original fields.
    frame = pd.read_csv(path, header=None, names=normalized, usecols=required, low_memory=False)
    label_col = name_map["label"]
    frame = frame[pd.to_numeric(frame[label_col], errors="coerce").isin([0, 1])]
    frame = _sample_file(frame, label_col, max_rows)
    features = _build_shared_features(
        frame,
        protocol=name_map["proto"],
        duration=name_map["dur"],
        duration_scale=1.0,
        fwd_packets=name_map["spkts"],
        bwd_packets=name_map["dpkts"],
        fwd_bytes=name_map["sbytes"],
        bwd_bytes=name_map["dbytes"],
    )
    labels = pd.to_numeric(frame[label_col], errors="coerce").astype(int)
    return _finalize_rows(features, labels, "UNSW-NB15", path.name)


def _finalize_rows(features: pd.DataFrame, labels: pd.Series, dataset: str, group: str) -> pd.DataFrame:
    frame = features.copy()
    frame["target"] = labels.to_numpy()
    frame["dataset"] = dataset
    frame["capture_group"] = group
    numeric = frame[FEATURES].replace([np.inf, -np.inf], np.nan)
    valid = numeric.notna().all(axis=1) & numeric.ge(0).all(axis=1)
    frame = frame.loc[valid].copy()
    frame[FEATURES] = np.log1p(numeric.loc[valid]).astype("float32")
    frame["target"] = frame["target"].astype("int8")
    return frame.drop_duplicates(subset=FEATURES + ["target"]).reset_index(drop=True)


def load_all(max_rows_per_file: int) -> tuple[pd.DataFrame, dict]:
    records = []
    source_summary = {}
    sources = [
        ("CICIDS2017", sorted((DATA / "CICIDS2017").glob("*.parquet"))),
        ("CSE-CIC-IDS2018", sorted((DATA / "CSE_CIC_IDS2018").glob("*.parquet"))),
    ]
    for dataset, files in sources:
        if not files:
            raise FileNotFoundError(f"No Parquet source files for {dataset}")
        source_summary[dataset] = []
        for path in files:
            rows = _read_cicflow_file(path, dataset, max_rows_per_file)
            source_summary[dataset].append({"file": path.name, "rows_used": len(rows), "attacks": int(rows.target.sum())})
            records.append(rows)
    if not UNSW_FEATURES_FILE.is_file():
        raise FileNotFoundError(f"Missing UNSW feature-name file: {UNSW_FEATURES_FILE}")
    names_frame = pd.read_csv(UNSW_FEATURES_FILE, encoding="latin1")
    names = [str(x).strip() for x in names_frame["Name"].tolist()]
    unsw_files = sorted((DATA / "UNSW_NB15").glob("UNSW-NB15_[1-4].csv"))
    if len(unsw_files) < 4:
        raise FileNotFoundError("Expected UNSW-NB15_1.csv through UNSW-NB15_4.csv")
    source_summary["UNSW-NB15"] = []
    for path in unsw_files:
        rows = _read_unsw_file(path, names, max_rows_per_file)
        source_summary["UNSW-NB15"].append({"file": path.name, "rows_used": len(rows), "attacks": int(rows.target.sum())})
        records.append(rows)
    combined = pd.concat(records, ignore_index=True)
    # Per-file exact duplicates are removed in _finalize_rows. Keep matching
    # records across capture files so held-out groups remain intact; audit them
    # because duplicated capture contents can inflate group-held-out metrics.
    cross_group_duplicate_rows = int(combined.duplicated(subset=FEATURES + ["target"], keep=False).sum())
    source_summary["quality"] = {
        "rows_after_per_file_validation_and_deduplication": int(len(combined)),
        "rows_in_exact_duplicate_sets_across_capture_groups": cross_group_duplicate_rows,
        "rows_retained_to_preserve_capture_group_splits": int(len(combined)),
        "nonfinite_or_negative_feature_rows_removed": "counted during per-file normalization; invalid rows are excluded",
    }
    return combined, source_summary


def _logit(probabilities: np.ndarray) -> np.ndarray:
    clipped = np.clip(np.asarray(probabilities, dtype=float), 1e-6, 1 - 1e-6)
    return np.log(clipped / (1 - clipped)).reshape(-1, 1)


def _choose_threshold(y_true: np.ndarray, probabilities: np.ndarray, target_fpr: float) -> float:
    y_true = np.asarray(y_true, dtype=int)
    probabilities = np.asarray(probabilities, dtype=float)
    benign = probabilities[y_true == 0]
    if not len(benign):
        return 0.5
    threshold = float(np.quantile(benign, 1.0 - target_fpr, method="higher"))
    return float(np.clip(threshold, 1e-6, 1.0))


def _ece(y_true: np.ndarray, probabilities: np.ndarray, bins: int = 10) -> float:
    y_true = np.asarray(y_true, dtype=int)
    probabilities = np.asarray(probabilities, dtype=float)
    edges = np.linspace(0.0, 1.0, bins + 1)
    total = max(1, len(y_true))
    score = 0.0
    for i in range(bins):
        mask = (probabilities >= edges[i]) & (probabilities < edges[i + 1] if i < bins - 1 else probabilities <= edges[i + 1])
        if mask.any():
            score += mask.sum() / total * abs(float(y_true[mask].mean()) - float(probabilities[mask].mean()))
    return float(score)


def _metrics(y_true: np.ndarray, probabilities: np.ndarray, threshold: float, anomaly_flags: np.ndarray | None = None) -> dict:
    y_true = np.asarray(y_true, dtype=int)
    predictions = (np.asarray(probabilities) >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, predictions, labels=[0, 1]).ravel()
    result = {
        "rows": int(len(y_true)),
        "threshold": round(float(threshold), 6),
        "accuracy": round(float(accuracy_score(y_true, predictions)), 6),
        "precision_attack": round(float(precision_score(y_true, predictions, zero_division=0)), 6),
        "recall_attack": round(float(recall_score(y_true, predictions, zero_division=0)), 6),
        "f1_attack": round(float(f1_score(y_true, predictions, zero_division=0)), 6),
        "false_positive_rate": round(float(fp / max(1, fp + tn)), 6),
        "confusion_matrix_tn_fp_fn_tp": [int(tn), int(fp), int(fn), int(tp)],
        "brier_score": round(float(brier_score_loss(y_true, probabilities)), 6),
        "expected_calibration_error_10_bins": round(_ece(y_true, probabilities), 6),
    }
    if len(np.unique(y_true)) == 2:
        result["roc_auc"] = round(float(roc_auc_score(y_true, probabilities)), 6)
        result["average_precision"] = round(float(average_precision_score(y_true, probabilities)), 6)
    if anomaly_flags is not None:
        anomaly_flags = np.asarray(anomaly_flags, dtype=bool)
        benign_mask = y_true == 0
        attack_mask = y_true == 1
        result["novelty_attack_recall"] = round(float(anomaly_flags[attack_mask].mean()), 6) if attack_mask.any() else None
        result["novelty_benign_false_positive_rate"] = round(float(anomaly_flags[benign_mask].mean()), 6) if benign_mask.any() else None
        # Treat either signal as a request for analyst review. This is an
        # evaluation-only policy: it does not turn an anomaly into a confirmed
        # attack and does not change the deployed detector.
        review_predictions = (predictions == 1) | anomaly_flags
        review_tn, review_fp, review_fn, review_tp = confusion_matrix(
            y_true, review_predictions.astype(int), labels=[0, 1]
        ).ravel()
        result["ml_or_novelty_review"] = {
            "recall_attack": round(float(review_tp / max(1, review_tp + review_fn)), 6),
            "false_positive_rate": round(float(review_fp / max(1, review_fp + review_tn)), 6),
            "precision_review": round(float(precision_score(y_true, review_predictions, zero_division=0)), 6),
            "confusion_matrix_tn_fp_fn_tp": [int(review_tn), int(review_fp), int(review_fn), int(review_tp)],
            "interpretation": "candidate analyst-review union; not a confirmed attack verdict",
        }
    return result


def _acceptance(recall: float, fpr: float, minimum_recall: float, maximum_fpr: float) -> dict:
    failures = []
    if recall < minimum_recall:
        failures.append(f"attack recall below {minimum_recall:.0%}")
    if fpr > maximum_fpr:
        failures.append(f"false-positive rate above {maximum_fpr:.2%}")
    return {"decision": "ACCEPT" if not failures else "IMPROVE", "failures": failures}


def _feature_drift(train: pd.DataFrame, test: pd.DataFrame, bins: int = 10) -> dict:
    """Population Stability Index by feature using train quantile boundaries."""
    epsilon = 1e-6
    rows = []
    for feature in FEATURES:
        reference = pd.to_numeric(train[feature], errors="coerce").dropna().to_numpy()
        observed = pd.to_numeric(test[feature], errors="coerce").dropna().to_numpy()
        if not len(reference) or not len(observed):
            continue
        edges = np.unique(np.quantile(reference, np.linspace(0, 1, bins + 1)))
        if len(edges) < 2:
            # A constant training feature still needs a useful out-of-range bin.
            edges = np.array([-np.inf, np.inf])
        else:
            edges[0], edges[-1] = -np.inf, np.inf
        ref_counts = np.histogram(reference, bins=edges)[0].astype(float)
        test_counts = np.histogram(observed, bins=edges)[0].astype(float)
        ref_share = np.clip(ref_counts / max(1, ref_counts.sum()), epsilon, 1)
        test_share = np.clip(test_counts / max(1, test_counts.sum()), epsilon, 1)
        psi = float(np.sum((test_share - ref_share) * np.log(test_share / ref_share)))
        rows.append({"feature": feature, "psi": round(psi, 6)})
    rows.sort(key=lambda row: row["psi"], reverse=True)
    return {
        "method": "population stability index, test distribution against train quantile bins",
        "mean_psi": round(float(np.mean([row["psi"] for row in rows])), 6) if rows else None,
        "max_psi": rows[0]["psi"] if rows else None,
        "top_shifted_features": rows[:5],
        "interpretation": "screening signal only; thresholds are not universal and this does not establish model failure",
    }


def _exclude_feature_overlap(frame: pd.DataFrame, *references: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    """Keep only feature vectors not already present in an earlier split."""
    seen = set()
    for reference in references:
        if not reference.empty:
            seen.update(pd.util.hash_pandas_object(reference[FEATURES], index=False).tolist())
    if not seen or frame.empty:
        return frame.copy(), 0
    row_hashes = pd.util.hash_pandas_object(frame[FEATURES], index=False)
    keep = ~row_hashes.isin(seen)
    return frame.loc[keep].copy(), int((~keep).sum())


def _fit_bundle(train: pd.DataFrame, calibration: pd.DataFrame, model_name: str, target_fpr: float) -> dict:
    calibration, calibration_overlap_removed = _exclude_feature_overlap(calibration, train)
    x_train, y_train = train[FEATURES], train.target.to_numpy(dtype=int)
    x_cal, y_cal = calibration[FEATURES], calibration.target.to_numpy(dtype=int)
    if len(np.unique(y_train)) < 2 or len(np.unique(y_cal)) < 2:
        raise ValueError("Train and calibration partitions must each contain benign and attack rows")
    if model_name == "RandomForest":
        model = RandomForestClassifier(
            n_estimators=160, min_samples_leaf=2, class_weight="balanced_subsample",
            n_jobs=1, random_state=RANDOM_STATE,
        )
    else:
        model = XGBClassifier(
            n_estimators=180, max_depth=6, learning_rate=0.08, subsample=0.8,
            colsample_bytree=0.9, tree_method="hist", n_jobs=1,
            eval_metric="logloss", random_state=RANDOM_STATE,
        )
    model.fit(x_train, y_train)
    raw_cal = model.predict_proba(x_cal)[:, list(model.classes_).index(1)]
    platt = LogisticRegression(C=1e6, solver="lbfgs", random_state=RANDOM_STATE)
    platt.fit(_logit(raw_cal), y_cal)
    calibrated = platt.predict_proba(_logit(raw_cal))[:, list(platt.classes_).index(1)]
    threshold = _choose_threshold(y_cal, calibrated, target_fpr)

    benign = train.loc[train.target == 0, FEATURES]
    iforest = IsolationForest(n_estimators=150, contamination="auto", n_jobs=1, random_state=RANDOM_STATE)
    iforest.fit(benign)
    cal_benign = calibration.loc[calibration.target == 0, FEATURES]
    benign_scores = iforest.score_samples(cal_benign)
    novelty_threshold = float(np.quantile(benign_scores, target_fpr, method="lower")) if len(benign_scores) else float("-inf")
    top_features = []
    if hasattr(model, "feature_importances_"):
        order = np.argsort(model.feature_importances_)[::-1][:8]
        top_features = [{"feature": FEATURES[int(i)], "importance": round(float(model.feature_importances_[i]), 6)} for i in order]
    return {"model": model, "calibrator": platt, "threshold": threshold, "novelty_model": iforest,
            "novelty_threshold": novelty_threshold, "top_global_features": top_features,
            "calibration": {"method": "Platt scaling on held-out capture groups", "target_benign_fpr": target_fpr,
                            "chosen_threshold": threshold, "calibration_rows": int(len(calibration)),
                            "overlapping_feature_rows_removed": calibration_overlap_removed}}


def _predict(bundle: dict, frame: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    raw = bundle["model"].predict_proba(frame[FEATURES])[:, list(bundle["model"].classes_).index(1)]
    calibrated = bundle["calibrator"].predict_proba(_logit(raw))[:, list(bundle["calibrator"].classes_).index(1)]
    novelty = bundle["novelty_model"].score_samples(frame[FEATURES]) <= bundle["novelty_threshold"]
    return calibrated, novelty


def _group_partitions(frame: pd.DataFrame, dataset: str, test_fraction: float = 0.25) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    groups = sorted(frame.loc[frame.dataset == dataset, "capture_group"].unique())
    if len(groups) < 4:
        raise ValueError(f"Need >=4 capture groups for {dataset} group-held-out train/calibration/test")
    manifest = SPLIT_MANIFEST[dataset]
    test_groups = set(manifest["test"])
    calibration_groups = set(manifest["calibration"])
    if not test_groups.issubset(groups) or not calibration_groups.issubset(groups):
        raise ValueError(f"The capture split manifest for {dataset} does not match the files found")
    train_groups = set(groups) - test_groups - calibration_groups
    subset = frame[frame.dataset == dataset]
    return (
        subset[subset.capture_group.isin(train_groups)].copy(),
        subset[subset.capture_group.isin(calibration_groups)].copy(),
        subset[subset.capture_group.isin(test_groups)].copy(),
    )


def run(max_rows_per_file: int, target_fpr: float, minimum_recall: float) -> dict:
    frame, source_summary = load_all(max_rows_per_file)
    cic_train, cic_cal, cic_test = [], [], []
    split_summary = {}
    for dataset in ("CICIDS2017", "CSE-CIC-IDS2018"):
        train, calibration, test = _group_partitions(frame, dataset)
        cic_train.append(train)
        cic_cal.append(calibration)
        cic_test.append(test)
        split_summary[dataset] = {
            "train_groups": sorted(train.capture_group.unique().tolist()),
            "calibration_groups": sorted(calibration.capture_group.unique().tolist()),
            "test_groups": sorted(test.capture_group.unique().tolist()),
            "rows_train": len(train), "rows_calibration": len(calibration), "rows_test": len(test),
        }
    cic_train_frame = pd.concat(cic_train, ignore_index=True)
    cic_cal_frame = pd.concat(cic_cal, ignore_index=True)
    cicflow_tests = pd.concat(cic_test, ignore_index=True)
    unsw_train, unsw_cal, unsw_test = _group_partitions(frame, "UNSW-NB15", test_fraction=0.25)
    split_summary["UNSW-NB15"] = {
        "train_groups": sorted(unsw_train.capture_group.unique().tolist()),
        "calibration_groups": sorted(unsw_cal.capture_group.unique().tolist()),
        "test_groups": sorted(unsw_test.capture_group.unique().tolist()),
        "rows_train": len(unsw_train), "rows_calibration": len(unsw_cal), "rows_test": len(unsw_test),
    }
    output = {
        "schema": "tri-dataset-common-flow-binary-v1",
        "datasets": ["CICIDS2017", "CSE-CIC-IDS2018", "UNSW-NB15"],
        "features": FEATURES,
        "feature_transform": "duration normalized to seconds; log1p nonnegative numeric features; protocol TCP/UDP/ICMP flags",
        "split_method": "explicit whole-capture file manifest; separate calibration and test captures; exact duplicates removed only within each capture file",
        "split_manifest": SPLIT_MANIFEST,
        "target": "binary attack vs benign; family labels are not merged across incompatible taxonomies",
        "target_benign_fpr": target_fpr,
        "acceptance_criteria": {"minimum_attack_recall": minimum_recall,
                                "maximum_false_positive_rate": target_fpr,
                                "promotion": "never; this benchmark writes research reports only"},
        "source_files": source_summary,
        "splits": split_summary,
        "results": [],
        "limitations": [
            "These three datasets are laboratory benchmarks, not live enterprise traffic.",
            "UNSW-NB15 has a different native flow schema; this evaluation uses only the documented shared semantic subset and does not pretend it has all 77 CICFlowMeter features.",
            "Family-level accuracy across datasets is intentionally not reported because their label taxonomies do not match.",
            "Thresholds and calibration are derived from held-out capture groups; the final held-out capture groups remain untouched until scoring.",
            "Exact rows repeated across capture files are audited; feature-identical rows in calibration/test splits are excluded when that vector appeared in an earlier split.",
            "This research candidate does not replace production models automatically.",
        ],
    }
    experiments = [
        ("RF_2017_2018_to_heldout_2017_2018", "RandomForest", cic_train_frame, cic_cal_frame, {
            "CICIDS2017 held-out groups": cicflow_tests[cicflow_tests.dataset == "CICIDS2017"],
            "CSE-CIC-IDS2018 held-out groups": cicflow_tests[cicflow_tests.dataset == "CSE-CIC-IDS2018"],
            "UNSW-NB15 external test group": unsw_test,
        }),
        ("XGB_2017_2018_to_heldout_2017_2018", "XGBoost", cic_train_frame, cic_cal_frame, {
            "CICIDS2017 held-out groups": cicflow_tests[cicflow_tests.dataset == "CICIDS2017"],
            "CSE-CIC-IDS2018 held-out groups": cicflow_tests[cicflow_tests.dataset == "CSE-CIC-IDS2018"],
            "UNSW-NB15 external test group": unsw_test,
        }),
        ("RF_UNSW_group_holdout", "RandomForest", unsw_train, unsw_cal, {"UNSW-NB15 held-out group": unsw_test}),
        ("XGB_UNSW_group_holdout", "XGBoost", unsw_train, unsw_cal, {"UNSW-NB15 held-out group": unsw_test}),
    ]
    for experiment, model_name, train, calibration, tests in experiments:
        bundle = _fit_bundle(train, calibration, model_name, target_fpr)
        calibration_unique, _ = _exclude_feature_overlap(calibration, train)
        for test_name, test in tests.items():
            if test.empty:
                continue
            test, test_overlap_removed = _exclude_feature_overlap(test, train, calibration_unique)
            if test.empty:
                print(f"{experiment} | {test_name}: skipped; no unique test rows remain after overlap removal")
                continue
            probs, novelty = _predict(bundle, test)
            metrics = _metrics(test.target.to_numpy(), probs, bundle["threshold"], novelty)
            metrics["candidate_acceptance"] = {
                "binary_classifier": _acceptance(metrics["recall_attack"], metrics["false_positive_rate"],
                                                  minimum_recall, target_fpr),
                "ml_or_novelty_review": _acceptance(
                    metrics["ml_or_novelty_review"]["recall_attack"],
                    metrics["ml_or_novelty_review"]["false_positive_rate"],
                    minimum_recall, target_fpr,
                ),
            }
            metrics["feature_drift"] = _feature_drift(train[FEATURES], test[FEATURES])
            # Pooled results can hide a detector that only works on one capture.
            # Keep the same calibration threshold and break the held-out result
            # back out by capture so transfer variability is visible.
            metrics["per_capture"] = {}
            for capture_name, capture in test.groupby("capture_group", sort=True):
                positions = test.index.get_indexer(capture.index)
                metrics["per_capture"][str(capture_name)] = _metrics(
                    capture.target.to_numpy(), probs[positions], bundle["threshold"], novelty[positions]
                )
            output["results"].append({
                "experiment": experiment,
                "model": model_name,
                "test": test_name,
                "metrics": metrics,
                "calibration": bundle["calibration"],
                "test_rows_removed_for_prior_split_overlap": test_overlap_removed,
                "top_global_features": bundle["top_global_features"],
            })
            print(f"{experiment} | {test_name}: recall={metrics['recall_attack']:.3f} "
                  f"FPR={metrics['false_positive_rate']:.3f} F1={metrics['f1_attack']:.3f} "
                  f"Brier={metrics['brier_score']:.3f} novelty-recall={metrics['novelty_attack_recall']:.3f}")
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    (REPORT_DIR / "benchmark.json").write_text(json.dumps(output, indent=2), encoding="utf-8")
    rows = []
    for result in output["results"]:
        rows.append({"experiment": result["experiment"], "model": result["model"], "test": result["test"], **result["metrics"]})
    pd.DataFrame(rows).to_csv(REPORT_DIR / "metrics.csv", index=False)
    print(f"\nReport: {REPORT_DIR / 'benchmark.json'}")
    print(f"Metrics: {REPORT_DIR / 'metrics.csv'}")
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows-per-file", type=int, default=DEFAULT_ROWS_PER_FILE,
                        help=f"deterministic stratified sample cap per capture file (default {DEFAULT_ROWS_PER_FILE})")
    parser.add_argument("--target-fpr", type=float, default=0.01,
                        help="calibration target false-positive rate on benign calibration rows")
    parser.add_argument("--minimum-recall", type=float, default=0.80,
                        help="minimum held-out attack recall required to accept a candidate")
    args = parser.parse_args(argv)
    if args.rows_per_file < 100:
        parser.error("--rows-per-file must be at least 100")
    if not 0 < args.target_fpr < 0.5:
        parser.error("--target-fpr must be between 0 and 0.5")
    if not 0 < args.minimum_recall <= 1:
        parser.error("--minimum-recall must be greater than 0 and at most 1")
    run(args.rows_per_file, args.target_fpr, args.minimum_recall)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
