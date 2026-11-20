"""Capture-held-out test of past-flow-rate features on metadata-bearing originals.

Inputs are a CICIDS2017 metadata mirror and official CSE-CIC-IDS2018 processed
flow CSVs. Samples are built per whole capture after computing causal,
timestamp-ordered behavior features over that capture's valid flows. IPs, ports,
timestamps, and identifiers are never model inputs.
"""
from __future__ import annotations

import gc
import json
import math
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
from sklearn.metrics import average_precision_score
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from evaluation.ten_type_candidate import ATTACK_TYPES
from pipeline.data_pipeline import FEATURES, map_schema
from experiments.dataset_expansion_20261113.labels import map_label

OUT = ROOT / "experiments/unseen_generalization_20261117/metadata_behavior_loco"
RAW_2017 = ROOT / "experiments/unseen_generalization_20261117/raw_metadata_2017"
RAW_2018 = ROOT / "experiments/unseen_generalization_20261117/raw_metadata_cse2018"
CAP = 1_000
SEED = 42
WINDOWS = (60, 300)
BEHAVIOR = [
    f"behavior_prior_flows_{w}s" for w in WINDOWS
] + [f"behavior_prior_same_dst_port_flows_{w}s" for w in WINDOWS]
LABELS = ["Benign", *ATTACK_TYPES]
TARGETS = set(LABELS)
ALIASES_2017 = {
    "Total Length of Fwd Packets": "Fwd Packets Length Total",
    "Total Length of Bwd Packets": "Bwd Packets Length Total",
    "Min Packet Length": "Packet Length Min",
    "Max Packet Length": "Packet Length Max",
    "Average Packet Size": "Avg Packet Size",
    "Init_Win_bytes_forward": "Init Fwd Win Bytes",
    "Init_Win_bytes_backward": "Init Bwd Win Bytes",
    "act_data_pkt_fwd": "Fwd Act Data Packets",
    "min_seg_size_forward": "Fwd Seg Size Min",
}
ALIASES_2018 = {
    "Fwd Header Len": "Fwd Header Length",
    "Bwd Header Len": "Bwd Header Length",
    "ECE Flag Cnt": "ECE Flag Count",
}


def _feature_frame(raw: pd.DataFrame, aliases: dict[str, str]) -> tuple[pd.DataFrame, pd.Series]:
    mapped, _ = map_schema(raw)
    mapped = mapped.rename(columns=aliases)
    missing = [name for name in [*FEATURES, "Label", "Timestamp"] if name not in mapped.columns]
    if missing:
        raise ValueError(f"Missing source fields after header mapping: {missing}")
    port_col = "Destination Port" if "Destination Port" in mapped.columns else "Dst Port"
    if port_col not in mapped:
        raise ValueError("Destination port required to build history features")
    X = pd.DataFrame({name: pd.to_numeric(mapped[name], errors="coerce").astype("float32") for name in FEATURES})
    labels = mapped["Label"].astype("string").str.strip()
    return X, pd.DataFrame({"raw_label": labels, "timestamp": mapped["Timestamp"],
                            "dst_port": pd.to_numeric(mapped[port_col], errors="coerce")})


def add_causal_history(X: pd.DataFrame, meta: pd.DataFrame, dataset: str) -> tuple[pd.DataFrame, dict]:
    if dataset == "CSE-CIC-IDS2018":
        ts = pd.to_datetime(meta.timestamp, format="%d/%m/%Y %H:%M:%S", errors="coerce")
    else:
        ts = pd.to_datetime(meta.timestamp, errors="coerce", utc=True)
    labels = meta.raw_label.map(map_label)
    port = pd.to_numeric(meta.dst_port, errors="coerce").fillna(-1).to_numpy(dtype=np.int32)
    finite_x = np.isfinite(X.to_numpy(copy=False)).all(axis=1)
    valid = finite_x & ts.notna().to_numpy()
    for name in ("Flow Duration", "Fwd Header Length", "Bwd Header Length"):
        valid &= X[name].to_numpy() >= 0
    valid &= labels.isin(TARGETS).to_numpy()
    invalid = int((~valid).sum())
    X = X.loc[valid].reset_index(drop=True)
    labels = labels.loc[valid].reset_index(drop=True)
    raw_labels = meta.raw_label.loc[valid].astype(str).reset_index(drop=True)
    port = port[valid]
    ts_ns = ts.loc[valid].astype("int64").to_numpy()
    order = np.argsort(ts_ns, kind="stable")
    X = X.iloc[order].reset_index(drop=True)
    labels = labels.iloc[order].reset_index(drop=True)
    raw_labels = raw_labels.iloc[order].reset_index(drop=True)
    port = port[order]
    ts_ns = ts_ns[order]

    behavior = {}
    first_at_time = np.searchsorted(ts_ns, ts_ns, side="left")
    for window in WINDOWS:
        left = np.searchsorted(ts_ns, ts_ns - window * 1_000_000_000, side="left")
        behavior[f"behavior_prior_flows_{window}s"] = (first_at_time - left).astype("float32")

    same_port = {window: np.zeros(len(X), dtype=np.float32) for window in WINDOWS}
    port_order = np.argsort(port, kind="stable")
    sorted_ports = port[port_order]
    cuts = np.r_[0, np.flatnonzero(sorted_ports[1:] != sorted_ports[:-1]) + 1, len(sorted_ports)]
    for start, end in zip(cuts[:-1], cuts[1:]):
        p = int(sorted_ports[start])
        if p < 0:
            continue
        ix = port_order[start:end]
        times = ts_ns[ix]  # stable port sort preserves the global time order
        first_same_time = np.searchsorted(times, times, side="left")
        for window in WINDOWS:
            lower = np.searchsorted(times, times - window * 1_000_000_000, side="left")
            same_port[window][ix] = first_same_time - lower
    for window in WINDOWS:
        behavior[f"behavior_prior_same_dst_port_flows_{window}s"] = same_port[window]
    for name, values in behavior.items():
        X[name] = values
    X["__type"] = labels.to_numpy()
    X["__raw_label"] = raw_labels.to_numpy()
    metadata = {"invalid_or_out_of_scope_rows_removed": invalid,
                "valid_target_rows": int(len(X)),
                "timestamps_sorted_for_features": True,
                "features_use_strictly_earlier_timestamps": True}
    return X, metadata


def input_files():
    sources = []
    for path in sorted(RAW_2017.glob("*.parquet")):
        sources.append(("CICIDS2017", path, ALIASES_2017))
    for path in sorted(RAW_2018.glob("*.csv")):
        # The 4.05 GB 20-Feb DDoS object is excluded from this first bounded run.
        if path.name.startswith("Thuesday-20-02-2018"):
            continue
        sources.append(("CSE-CIC-IDS2018", path, ALIASES_2018))
    return sources


def prepare_samples() -> list[dict]:
    out_dir = OUT / f"samples_{CAP}"
    out_dir.mkdir(parents=True, exist_ok=True)
    manifests = []
    for ordinal, (dataset, path, aliases) in enumerate(input_files()):
        source_name = path.stem
        capture_id = f"{dataset}__{source_name}"
        target_path = out_dir / f"{dataset}__{source_name}.parquet"
        if target_path.exists():
            sample = pd.read_parquet(target_path)
            manifests.append({"source_dataset": dataset, "capture_id": capture_id,
                              "source_file": str(path), "source_rows": None,
                              "valid_target_rows": None,
                              "invalid_or_out_of_scope_rows_removed": None,
                              "sampled_rows": int(len(sample)),
                              "sampled_label_counts": sample["__type"].value_counts().to_dict(),
                              "metadata_fields_used_only_for_features": ["Timestamp", "Destination Port/Dst Port"],
                              "metadata_not_model_inputs": True,
                              "reused_from_interrupted_preparation": True})
            print(f"Reusing prepared capture {capture_id}", flush=True)
            del sample
            continue
        print(f"Preparing {dataset}/{path.name}", flush=True)
        if path.suffix.casefold() == ".parquet":
            raw = pq.read_table(path).to_pandas()
        else:
            raw = pd.read_csv(path, low_memory=False, encoding_errors="replace")
        rows_read = len(raw)
        X, meta = _feature_frame(raw, aliases)
        del raw
        capture, quality = add_causal_history(X, meta, dataset)
        del X, meta
        # Retain true repeated flows as events; sample independently within each raw label.
        rng = np.random.default_rng(SEED + ordinal)
        selected = []
        for raw_label, group in capture.groupby("__raw_label", sort=True):
            if not group["__type"].isin(TARGETS).all():
                continue
            take = min(CAP, len(group))
            selected.extend(rng.choice(group.index.to_numpy(), size=take, replace=False).tolist())
        sample = capture.loc[selected].copy().reset_index(drop=True)
        sample["capture"] = capture_id
        sample["source_dataset"] = dataset
        sample.to_parquet(target_path, index=False, compression="zstd")
        manifests.append({"source_dataset": dataset, "capture_id": capture_id,
                          "source_file": str(path), "source_rows": rows_read,
                          **quality, "sampled_rows": int(len(sample)),
                          "sampled_label_counts": sample["__type"].value_counts().to_dict(),
                          "metadata_fields_used_only_for_features": ["Timestamp", "Destination Port/Dst Port"],
                          "metadata_not_model_inputs": True})
        print(f"  sampled {len(sample):,} / {len(capture):,} valid target rows", flush=True)
        del capture, sample
        gc.collect()
    pd.DataFrame(manifests).to_csv(OUT / "capture_manifest.csv", index=False)
    (OUT / "prepare_report.json").write_text(json.dumps({
        "task": "CICIDS2017 metadata mirror plus official CSE-CIC-IDS2018 flow CSVs",
        "cap_per_raw_label_per_capture": CAP, "seed": SEED,
        "capture_count": len(manifests), "windows_seconds": list(WINDOWS),
        "behavior_feature_names": BEHAVIOR,
        "important_limitations": ["The official CSE processed CSVs expose timestamp and destination port but omit source/destination IP.",
                                   "The large 20-Feb CSE DDoS CSV (4.05 GB) was excluded from this bounded run.",
                                   "CICIDS2017 files came from a third-party mirror; exact joining to local samples was not possible.",
                                   "Behavior features are causal past-window counts computed after timestamp sorting, per capture, over valid target rows; no labels are used in their calculation."],
    }, indent=2) + "\n", encoding="utf-8")
    return manifests


def choose_calibration(frames: dict[str, pd.DataFrame], heldout: str) -> list[str]:
    dataset = str(frames[heldout]["source_dataset"].iloc[0])
    candidates = []
    for name, frame in frames.items():
        if name == heldout or str(frame["source_dataset"].iloc[0]) != dataset:
            continue
        if int(frame["__type"].eq("Benign").sum()) >= 100:
            candidates.append(name)
    if len(candidates) < 2:
        raise RuntimeError(f"Need two separate same-dataset benign captures for {heldout}, found {len(candidates)}")
    return candidates[:2]


def fit_score(train, cal, test, feature_cols):
    encoder = LabelEncoder().fit(train["__type"])
    model = XGBClassifier(objective="multi:softprob", num_class=len(encoder.classes_), eval_metric="mlogloss",
        n_estimators=80, max_depth=6, learning_rate=.08, subsample=.85,
        colsample_bytree=.85, tree_method="hist", random_state=SEED, n_jobs=1)
    model.fit(train[feature_cols], encoder.transform(train["__type"]))
    classes = list(encoder.classes_)
    attack_idx = [i for i, label in enumerate(classes) if label != "Benign"]
    pcal = model.predict_proba(cal[feature_cols])
    thresholds = []
    for capture in cal["capture"].unique():
        mask = cal["capture"].eq(capture).to_numpy()
        scores = pcal[mask][:, attack_idx].max(axis=1)
        q = float(np.quantile(scores, .99, method="higher"))
        thresholds.append(float(np.nextafter(q, math.inf)))
    threshold = max(thresholds)
    ptest = model.predict_proba(test[feature_cols])
    score = ptest[:, attack_idx].max(axis=1)
    prediction = np.asarray(classes, dtype=object)[ptest.argmax(axis=1)]
    return score, prediction, threshold, sorted(set(ATTACK_TYPES) - set(classes))


def eval_variant(frames, feature_cols, variant):
    metrics, per_type, confusion, coverage = [], [], [], []
    names = list(frames)
    for heldout in names:
        print(f"Evaluating {variant}: {heldout}", flush=True)
        cals = choose_calibration(frames, heldout)
        train_names = [n for n in names if n not in {heldout, *cals}]
        train = pd.concat([frames[n] for n in train_names], ignore_index=True)
        cal_parts = [frames[n].loc[frames[n]["__type"].eq("Benign")].copy() for n in cals]
        cal = pd.concat(cal_parts, ignore_index=True)
        test = frames[heldout].copy()
        # Remove exact 77-feature vectors that cross the train/calibration/test boundaries.
        test_hash = pd.util.hash_pandas_object(test[FEATURES], index=False)
        test_hash_set = set(test_hash.tolist())
        cal_hash = pd.util.hash_pandas_object(cal[FEATURES], index=False)
        cal_hash_set = set(cal_hash.tolist())
        keep_test = ~test_hash.isin(cal_hash_set)
        test = test.loc[keep_test].reset_index(drop=True)
        test_hash = pd.util.hash_pandas_object(test[FEATURES], index=False)
        test_hash_set = set(test_hash.tolist())
        keep_cal = ~cal_hash.isin(test_hash_set)
        cal = cal.loc[keep_cal].reset_index(drop=True)
        overlap = test_hash_set | set(pd.util.hash_pandas_object(cal[FEATURES], index=False).tolist())
        train_hash = pd.util.hash_pandas_object(train[FEATURES], index=False)
        keep_train = ~train_hash.isin(overlap)
        removed_train = int((~keep_train).sum())
        train = train.loc[keep_train].reset_index(drop=True)
        score, prediction, threshold, absent = fit_score(train, cal, test, feature_cols)
        y = test["__type"].to_numpy(dtype=object)
        attack = y != "Benign"
        detected = score >= threshold
        fpr = float(detected[~attack].mean()) if (~attack).any() else np.nan
        recall = float(detected[attack].mean()) if attack.any() else np.nan
        ap = float(average_precision_score(attack.astype(int), score)) if attack.any() and (~attack).any() else np.nan
        correct = ((prediction == y) & detected & attack)
        e2e = float(correct[attack].mean()) if attack.any() else np.nan
        row = {"variant": variant, "heldout_capture": heldout,
               "dataset": str(frames[heldout]["source_dataset"].iloc[0]),
               "training_captures": len(train_names), "calibration_captures": ";".join(cals),
               "test_rows": len(test), "benign_rows": int((~attack).sum()), "attack_rows": int(attack.sum()),
               "threshold": threshold, "attack_recall": recall, "pr_auc": ap, "capture_fpr": fpr,
               "correct_type_recall": e2e, "train_test_or_cal_duplicate_vectors_removed": removed_train,
               "attack_types_absent_from_training": ";".join(absent)}
        metrics.append(row)
        output = np.where(detected, prediction, "NOT_FLAGGED")
        table = pd.crosstab(pd.Series(y, name="actual"), pd.Series(output, name="output"))
        for actual, values in table.iterrows():
            for out_name, count in values.items():
                if count:
                    confusion.append({"variant": variant, "heldout_capture": heldout,
                                      "actual": actual, "output": out_name, "count": int(count)})
        for label in ATTACK_TYPES:
            m = y == label
            if m.any():
                per_type.append({"variant": variant, "heldout_capture": heldout, "attack_type": label,
                    "support": int(m.sum()), "detected_recall": float(detected[m].mean()),
                    "correct_type_recall": float(correct[m].mean())})
        coverage.append({"variant": variant, "heldout_capture": heldout,
                         "absent_training_types": ";".join(absent), "training_rows": len(train),
                         "training_captures": len(train_names), "calibration_captures": ";".join(cals)})
    return pd.DataFrame(metrics), pd.DataFrame(per_type), pd.DataFrame(confusion), pd.DataFrame(coverage)


def evaluate():
    sample_dir = OUT / f"samples_{CAP}"
    files = sorted(sample_dir.glob("*.parquet"))
    if len(files) < 10:
        raise FileNotFoundError(f"Expected prepared samples in {sample_dir}; run preparation first")
    frames = {}
    for path in files:
        frame = pd.read_parquet(path)
        name = str(frame["capture"].iloc[0])
        frames[name] = frame
    variants = []
    specs = [("raw_77", FEATURES), ("raw_77_plus_history", [*FEATURES, *BEHAVIOR])]
    for variant, cols in specs:
        metrics, types, conf, coverage = eval_variant(frames, cols, variant)
        metrics.to_csv(OUT / f"{variant}_capture_metrics.csv", index=False)
        types.to_csv(OUT / f"{variant}_per_type.csv", index=False)
        conf.to_csv(OUT / f"{variant}_confusion.csv", index=False)
        coverage.to_csv(OUT / f"{variant}_coverage.csv", index=False)
        variants.append(metrics)
    raw, hist = variants
    paired = raw.merge(hist, on="heldout_capture", suffixes=("_raw", "_history"), validate="one_to_one")
    positive = paired[paired.attack_rows_raw.gt(0)]
    diff = positive.attack_recall_history - positive.attack_recall_raw
    rng = np.random.default_rng(20261118)
    sample_idx = rng.integers(0, len(diff), size=(20_000, len(diff)))
    boot = diff.to_numpy()[sample_idx].mean(axis=1)
    paired.to_csv(OUT / "history_vs_raw_capture.csv", index=False)
    summaries = {}
    for variant, data in [("raw_77", raw), ("raw_77_plus_history", hist)]:
        pos = data[data.attack_rows.gt(0)]
        summaries[variant] = {
            "capture_count": int(data.heldout_capture.nunique()),
            "attack_bearing_captures": int(len(pos)),
            "mean_capture_attack_recall": float(pos.attack_recall.mean()),
            "pooled_attack_recall": float(pos.attack_rows.mul(pos.attack_recall).sum() / pos.attack_rows.sum()),
            "mean_capture_pr_auc": float(pos.pr_auc.mean()),
            "mean_capture_fpr": float(data.capture_fpr.mean()),
            "pooled_fpr": float(data.capture_fpr.mul(data.benign_rows).sum() / data.benign_rows.sum()),
            "worst_capture_fpr": float(data.capture_fpr.max()),
            "mean_correct_type_recall": float(pos.correct_type_recall.mean()),
        }
    report = {
        "method": "One-seed XGBoost LOCO on original metadata-bearing capture files. Same rows and folds are used for 77 raw features and 77+4 causal past-history features. Per-fold thresholds use the maximum 99th percentile across two separate benign calibration captures from the held-out dataset. Test captures are never used for model fitting or threshold selection.",
        "inputs": {"CICIDS2017": "Third-party Hugging Face metadata mirror", "CSE-CIC-IDS2018": "Official S3 processed flow CSVs; nine of ten files, excluding the 4.05 GB 20-Feb DDoS capture"},
        "sampling": {"cap_per_raw_label_per_capture": CAP, "seed": SEED},
        "history_features": BEHAVIOR,
        "history_rule": "Flows are sorted by timestamp within each capture. For equal timestamps, rows do not count one another as prior flows. Features count all valid earlier target flows and earlier flows to the same destination port in trailing 60s/300s windows. Timestamps, ports, IPs, and IDs are not model inputs.",
        "summary": summaries,
        "paired_capture_recall_difference_history_minus_raw": {
            "mean": float(diff.mean()), "capture_bootstrap_95ci": [float(np.quantile(boot, .025)), float(np.quantile(boot, .975))],
            "positive_captures": int(len(diff)), "replicates": 20_000,
        },
        "limitations": ["Exploratory one-seed capped evaluation; no independent networks beyond these public laboratory captures.",
                        "The official CSE CSV omits source and destination IP, so source-host brute-force features could not be built.",
                        "CSE 20-Feb DDoS file was excluded; no conclusion about that capture's history features.",
                        "The CSE source CSV and local CSE Parquet do not exact-join sufficiently to restore metadata onto local rows; these results use the original CSVs end to end.",
                        "No production model, logic, thresholds, data, or existing reports were modified."],
    }
    (OUT / "metadata_behavior_loco_report.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    (OUT / "RESULTS.md").write_text(render_report(summaries, report), encoding="utf-8")
    print(json.dumps(report, indent=2), flush=True)


def evaluate_port_only():
    """Ablate out capture-wide activity counts; retain only prior same-port counts."""
    sample_dir = OUT / f"samples_{CAP}"
    frames = {}
    for path in sorted(sample_dir.glob("*.parquet")):
        frame = pd.read_parquet(path)
        frames[str(frame["capture"].iloc[0])] = frame
    if len(frames) < 10:
        raise FileNotFoundError(f"Prepared capture samples missing in {sample_dir}")
    cols = [*FEATURES, *BEHAVIOR[-2:]]
    metrics, types, conf, coverage = eval_variant(frames, cols, "raw_77_plus_same_port_history")
    metrics.to_csv(OUT / "same_port_history_capture_metrics.csv", index=False)
    types.to_csv(OUT / "same_port_history_per_type.csv", index=False)
    conf.to_csv(OUT / "same_port_history_confusion.csv", index=False)
    coverage.to_csv(OUT / "same_port_history_coverage.csv", index=False)
    raw = pd.read_csv(OUT / "raw_77_capture_metrics.csv")
    paired = raw.merge(metrics, on="heldout_capture", suffixes=("_raw", "_port"), validate="one_to_one")
    positive = paired[paired.attack_rows_raw.gt(0)]
    diff = positive.attack_recall_port - positive.attack_recall_raw
    rng = np.random.default_rng(20261119)
    ids = rng.integers(0, len(diff), size=(20_000, len(diff)))
    boot = diff.to_numpy()[ids].mean(axis=1)
    paired.to_csv(OUT / "same_port_history_vs_raw_capture.csv", index=False)
    raw_types = pd.read_csv(OUT / "raw_77_per_type.csv")
    type_rows = []
    for label in ATTACK_TYPES:
        a = raw_types[raw_types.attack_type.eq(label)]
        b = types[types.attack_type.eq(label)]
        if len(a) or len(b):
            type_rows.append({"attack_type": label, "captures": int(len(b)),
                              "raw_correct_type_recall": float(a.correct_type_recall.mean()) if len(a) else None,
                              "same_port_correct_type_recall": float(b.correct_type_recall.mean()) if len(b) else None,
                              "raw_detected_recall": float(a.detected_recall.mean()) if len(a) else None,
                              "same_port_detected_recall": float(b.detected_recall.mean()) if len(b) else None})
    pd.DataFrame(type_rows).to_csv(OUT / "same_port_history_per_type_comparison.csv", index=False)
    pos_raw = raw[raw.attack_rows.gt(0)]
    pos_new = metrics[metrics.attack_rows.gt(0)]
    summary = {
        "history_features": BEHAVIOR[-2:], "capture_count": int(metrics.heldout_capture.nunique()),
        "attack_bearing_captures": int(len(positive)),
        "raw_77": {"mean_attack_recall": float(pos_raw.attack_recall.mean()),
                   "pooled_attack_recall": float(pos_raw.attack_rows.mul(pos_raw.attack_recall).sum()/pos_raw.attack_rows.sum()),
                   "mean_capture_fpr": float(raw.capture_fpr.mean()), "pooled_fpr": float(raw.capture_fpr.mul(raw.benign_rows).sum()/raw.benign_rows.sum()),
                   "worst_capture_fpr": float(raw.capture_fpr.max()), "mean_pr_auc": float(pos_raw.pr_auc.mean()),
                   "mean_correct_type_recall": float(pos_raw.correct_type_recall.mean())},
        "same_port_history": {"mean_attack_recall": float(pos_new.attack_recall.mean()),
                   "pooled_attack_recall": float(pos_new.attack_rows.mul(pos_new.attack_recall).sum()/pos_new.attack_rows.sum()),
                   "mean_capture_fpr": float(metrics.capture_fpr.mean()), "pooled_fpr": float(metrics.capture_fpr.mul(metrics.benign_rows).sum()/metrics.benign_rows.sum()),
                   "worst_capture_fpr": float(metrics.capture_fpr.max()), "mean_pr_auc": float(pos_new.pr_auc.mean()),
                   "mean_correct_type_recall": float(pos_new.correct_type_recall.mean())},
        "paired_recall_difference": {"mean": float(diff.mean()), "capture_bootstrap_95ci": [float(np.quantile(boot,.025)),float(np.quantile(boot,.975))]},
        "limitations": ["One seed and 1,000-row cap; exploratory only.", "No source IP fields are present in official CSE processed CSVs.",
                        "No production models or thresholds were changed."],
    }
    (OUT / "same_port_history_report.json").write_text(json.dumps(summary, indent=2, allow_nan=False)+"\n", encoding="utf-8")
    print(json.dumps(summary, indent=2), flush=True)


def render_report(summaries, report):
    raw = summaries["raw_77"]
    hist = summaries["raw_77_plus_history"]
    ci = report["paired_capture_recall_difference_history_minus_raw"]["capture_bootstrap_95ci"]
    type_raw = pd.read_csv(OUT / "raw_77_per_type.csv")
    type_hist = pd.read_csv(OUT / "raw_77_plus_history_per_type.csv")
    type_rows = []
    for label in ATTACK_TYPES:
        a = type_raw[type_raw.attack_type.eq(label)]
        b = type_hist[type_hist.attack_type.eq(label)]
        if not len(a) and not len(b):
            continue
        type_rows.append(f"| {label} | {int(len(a))} | {a.correct_type_recall.mean():.1%} | {a.detected_recall.mean():.1%} | {b.correct_type_recall.mean():.1%} | {b.detected_recall.mean():.1%} |")
    type_table = "\n".join(type_rows)
    cap_raw = pd.read_csv(OUT / "raw_77_capture_metrics.csv")
    cap_hist = pd.read_csv(OUT / "raw_77_plus_history_capture_metrics.csv")
    dataset_rows = []
    for dataset in sorted(cap_raw.dataset.unique()):
        for variant, frame in [("Raw 77", cap_raw), ("+ history", cap_hist)]:
            g = frame[frame.dataset.eq(dataset)]
            pos = g[g.attack_rows.gt(0)]
            dataset_rows.append(f"| {dataset} | {variant} | {pos.attack_recall.mean():.1%} | {g.capture_fpr.mean():.2%} | {g.capture_fpr.max():.2%} |")
    dataset_table = "\n".join(dataset_rows)
    return f'''# Metadata-based temporal feature candidate

This is a research-only, one-seed capture-held-out comparison on original metadata-bearing source files. It uses {raw['capture_count']} capture files and caps each raw label at {CAP:,} sampled rows per capture after calculating causal history over valid source flows. The candidate adds four features counting preceding flows in the previous 60/300 seconds and preceding flows to the same destination port in those windows. IPs, ports, timestamps, and flow IDs are excluded from model inputs.

| Metric | Raw 77 features | Raw 77 + past-history features |
|---|---:|---:|
| Mean attack recall over attack-bearing captures | {raw['mean_capture_attack_recall']:.1%} | {hist['mean_capture_attack_recall']:.1%} |
| Pooled attack recall | {raw['pooled_attack_recall']:.1%} | {hist['pooled_attack_recall']:.1%} |
| Mean capture PR-AUC | {raw['mean_capture_pr_auc']:.3f} | {hist['mean_capture_pr_auc']:.3f} |
| Mean capture FPR | {raw['mean_capture_fpr']:.2%} | {hist['mean_capture_fpr']:.2%} |
| Pooled FPR | {raw['pooled_fpr']:.2%} | {hist['pooled_fpr']:.2%} |
| Worst-capture FPR | {raw['worst_capture_fpr']:.2%} | {hist['worst_capture_fpr']:.2%} |
| Mean correct-type recall | {raw['mean_correct_type_recall']:.1%} | {hist['mean_correct_type_recall']:.1%} |

The paired recall difference is {report['paired_capture_recall_difference_history_minus_raw']['mean']:+.1%} (capture-bootstrap 95% interval {ci[0]:+.1%} to {ci[1]:+.1%}). Per-type and confusion tables are in the adjacent CSV files. This is not evidence of all-12 unseen-network performance: it is one seed, a reduced sample, and public lab captures only.

## Per-type outcomes

“Detected recall” counts an attack as detected even if it receives the wrong type; “correct-type recall” requires the exact label. Captures indicates the number of positive held-out capture files represented.

| Attack type | Captures | Raw correct-type recall | Raw detected recall | History correct-type recall | History detected recall |
|---|---:|---:|---:|---:|---:|
{type_table}

## Dataset-level outcomes

| Source dataset | Features | Mean attack recall | Mean capture FPR | Worst capture FPR |
|---|---|---:|---:|---:|
{dataset_table}

Thresholds are selected from two separate benign captures within the known held-out dataset; the held-out capture is excluded from model fitting and threshold selection. The CSE-CIC-IDS2018 source files lack source/destination IPs, and the very large 20-Feb DDoS source file was excluded. No candidate was promoted to production.

Reproduce the preparation and evaluation:

```powershell
.\\.venv\\Scripts\\python.exe experiments\\unseen_generalization_20261117\\metadata_behavior_loco.py --prepare
.\\.venv\\Scripts\\python.exe experiments\\unseen_generalization_20261117\\metadata_behavior_loco.py --evaluate
```
'''


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--evaluate", action="store_true")
    parser.add_argument("--summarize", action="store_true", help="rebuild RESULTS.md from saved outputs without refitting")
    parser.add_argument("--port-only", action="store_true", help="evaluate same-destination-port history ablation")
    args = parser.parse_args()
    if args.port_only:
        evaluate_port_only()
        return
    if args.summarize:
        report = json.loads((OUT / "metadata_behavior_loco_report.json").read_text(encoding="utf-8"))
        (OUT / "RESULTS.md").write_text(render_report(report["summary"], report), encoding="utf-8")
        print(f"Updated {OUT / 'RESULTS.md'}", flush=True)
        return
    if args.prepare or not args.evaluate:
        prepare_samples()
    if args.evaluate or not args.prepare:
        evaluate()


if __name__ == "__main__":
    main()
