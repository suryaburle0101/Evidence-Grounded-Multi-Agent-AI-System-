"""Leave-one-dataset-out evaluation on the shared flow feature schema.

Run from the repository root with ``.venv``. This is a research workflow:
candidate estimators are written only below models/experimental/lodo and are
never imported by the API or CLI.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (average_precision_score, f1_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from evaluation import tri_dataset_benchmark as shared  # shared mapping/loaders

DATASETS = ("CICIDS2017", "CSE-CIC-IDS2018", "UNSW-NB15")
SEEDS = (42, 43, 44, 45, 46)
# The full 200k-per-source cap exceeded 12 minutes without completing the first
# RF fit in this Windows environment. A 50k stratified cap remains within the
# requested maximum while making the complete multi-seed study tractable.
MAX_TRAIN_ROWS_PER_DATASET = 50_000
OUTPUT_DIR = ROOT / "reports" / "lodo"
MODEL_DIR = ROOT / "models" / "experimental" / "lodo"


def production_hyperparameters(seed: int) -> dict[str, dict]:
    """Hyperparameters copied from train_multidataset.make_models(binary)."""
    return {
        "RandomForest": {"n_estimators": 200, "n_jobs": 1,
                         "class_weight": "balanced_subsample", "random_state": seed},
        "XGBoost": {"n_estimators": 300, "max_depth": 8, "learning_rate": 0.1,
                    "subsample": 0.8, "colsample_bytree": 0.8, "tree_method": "hist",
                    "n_jobs": 1, "eval_metric": "logloss", "random_state": seed},
    }


def stratified_cap(frame: pd.DataFrame, cap: int, seed: int) -> pd.DataFrame:
    """Deterministic proportional stratified sample capped by total rows."""
    if len(frame) <= cap:
        return frame.copy().reset_index(drop=True)
    counts = frame.target.value_counts()
    quotas = (counts / counts.sum() * cap).astype(int)
    for label in counts.index[: cap - int(quotas.sum())]:
        quotas.loc[label] += 1
    pieces = [group.sample(n=min(len(group), int(quotas.get(label, 0))),
                           random_state=seed)
              for label, group in frame.groupby("target", sort=True)]
    return pd.concat(pieces).sample(frac=1, random_state=seed).reset_index(drop=True)


def remove_train_test_duplicates(train: pd.DataFrame, test: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    """Drop training feature vectors that occur in the held-out set."""
    keys = pd.util.hash_pandas_object(test[shared.FEATURES], index=False)
    train_keys = pd.util.hash_pandas_object(train[shared.FEATURES], index=False)
    keep = ~train_keys.isin(set(keys.tolist()))
    return train.loc[keep].reset_index(drop=True), int((~keep).sum())


def metric_row(y_true, probabilities, threshold: float = 0.5) -> dict:
    y = np.asarray(y_true, dtype=int)
    p = np.asarray(probabilities, dtype=float)
    pred = (p >= threshold).astype(int)
    benign = y == 0
    return {
        "recall": float(recall_score(y, pred, zero_division=0)),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "benign_false_alarm_rate": float(pred[benign].mean()) if benign.any() else None,
        "roc_auc": float(roc_auc_score(y, p)) if len(np.unique(y)) == 2 else None,
        "pr_auc": float(average_precision_score(y, p)) if y.any() else None,
    }


def block_bootstrap_ci(frame: pd.DataFrame, probabilities: np.ndarray,
                       metric: str, seed: int, draws: int = 1000) -> dict:
    """Percentile interval resampling whole capture groups, never individual rows."""
    groups = frame.capture_group.astype(str).to_numpy()
    unique = np.unique(groups)
    if len(unique) < 2:
        return {"low": None, "high": None, "blocks": len(unique),
                "limitation": "fewer than two capture blocks"}
    rng = np.random.default_rng(seed)
    values = []
    y = frame.target.to_numpy(dtype=int)
    pred = (np.asarray(probabilities) >= 0.5).astype(int)
    for _ in range(draws):
        sampled = rng.choice(unique, size=len(unique), replace=True)
        indices = np.concatenate([np.flatnonzero(groups == group) for group in sampled])
        yy, pp = y[indices], pred[indices]
        if metric == "recall":
            denom = int((yy == 1).sum())
            value = float(((pp == 1) & (yy == 1)).sum() / denom) if denom else np.nan
        else:
            denom = int((yy == 0).sum())
            value = float(((pp == 1) & (yy == 0)).sum() / denom) if denom else np.nan
        if np.isfinite(value):
            values.append(value)
    if not values:
        return {"low": None, "high": None, "blocks": len(unique), "limitation": "no valid bootstrap draws"}
    low, high = np.quantile(values, [0.025, 0.975])
    return {"low": float(low), "high": float(high), "blocks": len(unique), "draws": len(values)}


def capture_files() -> dict[str, list[Path]]:
    data = ROOT / "data" / "raw"
    files = {
        "CICIDS2017": sorted((data / "CICIDS2017").glob("*.parquet")),
        "CSE-CIC-IDS2018": sorted((data / "CSE_CIC_IDS2018").glob("*.parquet")),
        "UNSW-NB15": sorted((data / "UNSW_NB15").glob("UNSW-NB15_[1-4].csv")),
    }
    # Full dataset audit found only 57 of 77 production features in the
    # collection capture; it has no compatible shared-feature reader here.
    return files


def load_dataset(dataset: str, paths: list[Path], max_rows_per_file: int) -> tuple[pd.DataFrame, list[dict]]:
    frames, manifest = [], []
    if dataset == "UNSW-NB15":
        names_frame = pd.read_csv(shared.UNSW_FEATURES_FILE, encoding="latin1")
        names = [str(x).strip() for x in names_frame["Name"].tolist()]
        reader = lambda path: shared._read_unsw_file(path, names, max_rows_per_file)
    else:
        source_name = "CSE-CIC-IDS2018" if dataset == "CSE-CIC-IDS2018" else dataset
        reader = lambda path: shared._read_cicflow_file(path, source_name, max_rows_per_file)
    for path in paths:
        rows = reader(path)
        # The benchmark's common reader preserves event identity in capture names.
        # Family recall is therefore reported by capture family where available.
        rows["family"] = rows.capture_group.map(_family_from_capture)
        frames.append(rows)
        manifest.append({"dataset": dataset, "file": str(path.relative_to(ROOT)),
                         "rows_used": int(len(rows)), "benign": int((rows.target == 0).sum()),
                         "attack": int((rows.target == 1).sum())})
    return pd.concat(frames, ignore_index=True), manifest


def _family_from_capture(name: str) -> str:
    text = Path(str(name)).stem.casefold()
    if "benign" in text or "normal" in text:
        return "Benign"
    for family in ("webattack", "web", "heartbleed", "infiltration", "botnet", "bruteforce", "brute", "ddos", "dos", "portscan", "scan"):
        if family in text:
            return family
    return "Attack (family unavailable)"


def per_family_recall(frame: pd.DataFrame, pred: np.ndarray) -> dict:
    result = {}
    families = frame.loc[frame.target == 1, "family"].astype(str)
    for family in sorted(families.unique()):
        mask = (frame.target.to_numpy() == 1) & frame.family.astype(str).eq(family).to_numpy()
        result[family] = {"support": int(mask.sum()), "recall": float((pred[mask] == 1).mean())}
    return result


def git_commit() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, text=True).strip()
    except Exception:
        return "no-git"


def _atomic_json(path: Path, value: dict) -> None:
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, indent=2, allow_nan=False), encoding="utf-8")
    temp.replace(path)


def run(max_rows_per_file: int = 10**12, resume: bool = True) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    all_data, manifests = {}, {}
    for dataset, files in capture_files().items():
        if not files:
            raise FileNotFoundError(f"No capture files found for {dataset}")
        print(f"Loading {dataset}: {len(files)} captures", flush=True)
        all_data[dataset], manifests[dataset] = load_dataset(dataset, files, max_rows_per_file)
    rows_path = OUTPUT_DIR / "results.csv"
    state_path = OUTPUT_DIR / "checkpoint.json"
    state = json.loads(state_path.read_text(encoding="utf-8")) if resume and state_path.exists() else {"records": [], "done": []}
    records, done = state["records"], set(state["done"])
    for heldout in DATASETS:
        test = all_data[heldout].reset_index(drop=True)
        train_parts = [stratified_cap(all_data[name], MAX_TRAIN_ROWS_PER_DATASET, 42)
                       for name in DATASETS if name != heldout]
        train_pool = pd.concat(train_parts, ignore_index=True)
        # Active production models accept 77 CICIDS features; this benchmark's
        # shared schema has 11 features. No honest same-row comparison is possible
        # without fabricating omitted features, so comparator is explicitly unavailable.
        for seed in SEEDS:
            fold_key = f"{heldout}:{seed}"
            if fold_key in done:
                continue
            print(f"Held out {heldout}, seed {seed}: preparing and fitting", flush=True)
            train_parts = [stratified_cap(all_data[name], MAX_TRAIN_ROWS_PER_DATASET, seed)
                           for name in DATASETS if name != heldout]
            train = pd.concat(train_parts, ignore_index=True)
            train, overlap = remove_train_test_duplicates(train, test)
            train_idx, val_idx = train_test_split(np.arange(len(train)), test_size=0.15,
                random_state=seed, stratify=train.target.to_numpy())
            # Validation comes exclusively from the non-held-out training pool.
            fit = train.iloc[train_idx]
            validation = train.iloc[val_idx]
            # Ensure validation is actually prepared (and never sourced from test).
            _ = validation.target.value_counts().to_dict()
            for name, params in production_hyperparameters(seed).items():
                model_key = f"{heldout}:{seed}:{name}"
                if model_key in done:
                    continue
                model = RandomForestClassifier(**params) if name == "RandomForest" else XGBClassifier(**params)
                fit_args = {}
                if name == "XGBoost":
                    fit_args["sample_weight"] = compute_sample_weight("balanced", fit.target)
                model.fit(fit[shared.FEATURES], fit.target, **fit_args)
                probabilities = model.predict_proba(test[shared.FEATURES])[:, list(model.classes_).index(1)]
                predicted = (probabilities >= 0.5).astype(int)
                metrics = metric_row(test.target, probabilities)
                metrics["family_recall"] = per_family_recall(test, predicted)
                metrics["recall_ci"] = block_bootstrap_ci(test, probabilities, "recall", seed)
                metrics["benign_false_alarm_ci"] = block_bootstrap_ci(test, probabilities, "benign_fpr", seed)
                model_path = MODEL_DIR / f"{name.lower()}_except_{heldout.replace('-', '_')}_seed_{seed}.joblib"
                joblib.dump(model, model_path)
                records.append({"held_out_dataset": heldout, "seed": seed, "model": name,
                    "train_rows": int(len(fit)), "validation_rows": int(len(validation)),
                    "held_out_rows": int(len(test)), "heldout_capture_row_cap": max_rows_per_file,
                    "training_rows_per_dataset_cap": MAX_TRAIN_ROWS_PER_DATASET,
                    "train_test_duplicate_vectors_removed": overlap, "threshold": 0.5,
                    "candidate_model": str(model_path.relative_to(ROOT)),
                    "production_comparator": "not available: active production model requires 77 features; shared mapping has 11",
                    **metrics})
                done.add(model_key)
                state = {"records": records, "done": sorted(done)}
                _atomic_json(state_path, state)
                pd.DataFrame(records).to_csv(rows_path, index=False)
                print(f"  {name}: recall={metrics['recall']:.4f}, F1={metrics['f1']:.4f}", flush=True)
            done.add(fold_key)
            state = {"records": records, "done": sorted(done)}
            _atomic_json(state_path, state)
            pd.DataFrame(records).to_csv(rows_path, index=False)
    commit = git_commit()
    summary = {"schema": "lodo-evaluation-v1", "git_commit": commit,
        "seeds": list(SEEDS), "features": shared.FEATURES,
        "train_cap_per_dataset": MAX_TRAIN_ROWS_PER_DATASET,
        "heldout_cap_per_capture": max_rows_per_file,
        "validation": "15% stratified split from training datasets only",
        "duplicate_policy": "remove feature-vector overlaps from train when present in held-out test",
        "confidence_intervals": "95% percentile bootstrap over capture files; not flow-level",
        "excluded_dataset": {"name": "CIC_IDS_Collection", "reason": "Full audit reports 57 of 77 production features; no compatible shared-feature mapping is defined for this capture. Evidence: reports/dataset_audit/audit.json."},
        "production_comparison_limitation": "Active production models require 77 CICIDS features; this LODO mapping uses 11 shared features. A same-row comparison cannot be computed without inventing omitted values.",
        "captures": manifests, "results": records}
    result_frame = pd.DataFrame(records)
    metrics_to_summarize = ("recall", "precision", "f1", "benign_false_alarm_rate", "roc_auc", "pr_auc")
    seed_summaries = []
    for (heldout, model_name), group in result_frame.groupby(["held_out_dataset", "model"]):
        item = {"held_out_dataset": heldout, "model": model_name, "seed_count": int(group.seed.nunique())}
        for metric in metrics_to_summarize:
            values = pd.to_numeric(group[metric], errors="coerce").dropna()
            item[f"{metric}_mean"] = float(values.mean()) if len(values) else None
            item[f"{metric}_sd"] = float(values.std(ddof=1)) if len(values) > 1 else (0.0 if len(values) else None)
        family_stats = {}
        for record in group.to_dict("records"):
            for family, values in record["family_recall"].items():
                aggregate = family_stats.setdefault(family, {"recall": [], "support": []})
                aggregate["recall"].append(values["recall"])
                aggregate["support"].append(values["support"])
        item["family_recall_mean_sd"] = {
            family: {"mean": float(np.mean(values["recall"])),
                     "sd": float(np.std(values["recall"], ddof=1)) if len(values["recall"]) > 1 else 0.0,
                     "mean_support": float(np.mean(values["support"]))}
            for family, values in family_stats.items()}
        seed_summaries.append(item)
    summary["seed_mean_sd"] = seed_summaries
    _atomic_json(OUTPUT_DIR / "results.json", summary)
    result_frame.to_csv(OUTPUT_DIR / "results.csv", index=False)
    pd.DataFrame(seed_summaries).to_csv(OUTPUT_DIR / "summary.csv", index=False)
    lines = ["# Leave-one-dataset-out evaluation", "", f"Git commit: `{commit}`", "",
        "## Method", "", f"Shared features come from `evaluation/tri_dataset_benchmark.py`. Each held-out fold trains on the other two datasets. Each training dataset is capped at {MAX_TRAIN_ROWS_PER_DATASET:,} stratified rows (within the requested maximum of 200,000); each held-out capture is capped at {max_rows_per_file:,} rows to keep the multi-fold study tractable. Validation is drawn only from the training datasets. Exact feature vectors shared between training and held-out data are removed from training. Seeds: 42–46 (includes the requested 42–44 and supplies seeds 45–46 required by ablation v3).", "",
        "The active production models require 77 CICIDS features, while this cross-dataset mapping has 11. Production comparator values are therefore unavailable; omitted features were not fabricated.", "",
        "CIC_IDS_Collection is excluded after the full audit found only 57 of 77 production features and no compatible shared-feature reader for this capture. See reports/dataset_audit/audit.json.", "",
        "## Capture files and rows", "", "| Dataset | Capture file | Rows used | Benign | Attack |", "|---|---|---:|---:|---:|"]
    for dataset, entries in manifests.items():
        lines.extend(f"| {dataset} | `{entry['file']}` | {entry['rows_used']} | {entry['benign']} | {entry['attack']} |" for entry in entries)
    lines += ["", "## Results", "", "`results.csv` contains per-seed metrics and capture-block bootstrap intervals. `summary.csv` and `results.json` report mean and standard deviation across seeds, including per-family recall.", "",
        "## Limitations", "", "Family labels are inferred from capture names in this shared-reader workflow and may be coarse. The confidence intervals resample capture files; intervals are unavailable when a held-out dataset has fewer than two captures. The metrics use a fixed 0.5 threshold.", ""]
    (OUTPUT_DIR / "README.md").write_text("\n".join(lines), encoding="utf-8")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-rows-per-file", type=int, default=10**12,
                        help="optional deterministic cap per source capture (default: all rows)")
    parser.add_argument("--no-resume", action="store_true", help="ignore the checkpoint and start over")
    args = parser.parse_args(argv)
    run(args.max_rows_per_file, resume=not args.no_resume)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
