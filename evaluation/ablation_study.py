"""Evaluate staged pipeline ablations on existing held-out 2018 captures.

Run from the project root with:
    .\\.venv\\Scripts\\python.exe evaluation\\ablation_study.py

This study reads the existing production models and held-out capture files; it
does not fit or write model artifacts.
"""
from __future__ import annotations

import argparse
import csv
import math
import pickle
import subprocess
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.orchestrator import orchestrator
from evaluation.production_model_validation import canonical_family, sample_capture
from evaluation.model_acceptance_gate import evaluate as evaluate_model_acceptance
from evaluation import tri_dataset_benchmark as shared_features
from pipeline.build_info import GIT_COMMIT_HASH, PIPELINE_VERSION

SEEDS = (42, 43, 44, 45, 46)
MAX_ROWS = 1000
SAMPLE_CAP_PER_RAW_LABEL = 1000
TEST_CAPTURE_NAMES = (
    "DoS-Wednesday-no-metadata.parquet",
    "Botnet-Friday-02-03-2018_TrafficForML_CICFlowMeter.parquet",
    "Bruteforce-Wednesday-14-02-2018_TrafficForML_CICFlowMeter.parquet",
    "DDoS2-Wednesday-21-02-2018_TrafficForML_CICFlowMeter.parquet",
    "Infil2-Thursday-01-03-2018_TrafficForML_CICFlowMeter.parquet",
    "Web1-Thursday-22-02-2018_TrafficForML_CICFlowMeter.parquet",
)
DATASET_NAME = "Existing capture-held-out CICIDS2017/CSE-CIC-IDS2018 test captures"
OUTPUT_V3_DIR = ROOT / "reports" / "ablation_study_v3"
BOOTSTRAP_RESAMPLES = 10_000
BOOTSTRAP_SEED = 20261026
TRAINING_STATUS = {
    "DoS-Wednesday-no-metadata.parquet": (
        "unknown — CICIDS2017 is the active models' training source, but exact capture membership is undocumented"
    ),
    "Botnet-Friday-02-03-2018_TrafficForML_CICFlowMeter.parquet": "no — CSE-CIC-IDS2018 is documented as external to active CICIDS2017 artifacts",
    "Bruteforce-Wednesday-14-02-2018_TrafficForML_CICFlowMeter.parquet": "no — CSE-CIC-IDS2018 is documented as external to active CICIDS2017 artifacts",
    "DDoS2-Wednesday-21-02-2018_TrafficForML_CICFlowMeter.parquet": "no — CSE-CIC-IDS2018 is documented as external to active CICIDS2017 artifacts",
    "Infil2-Thursday-01-03-2018_TrafficForML_CICFlowMeter.parquet": "no — CSE-CIC-IDS2018 is documented as external to active CICIDS2017 artifacts",
    "Web1-Thursday-22-02-2018_TrafficForML_CICFlowMeter.parquet": "no — CSE-CIC-IDS2018 is documented as external to active CICIDS2017 artifacts",
}
TRAINING_PROVENANCE_BASIS = (
    "detection/model_predictor.py loads active artifacts named *_cicids2017; README identifies CICIDS2017 as their training source; "
    "reports/production_model_validation/production_2017_source_check.json says capture-level split membership is unknown; "
    "the repository has no per-capture training manifest for these artifacts; train_multidataset.py writes separate candidates under models/multidataset/ and does not write active artifacts."
)

CONFIGURATIONS = (
    ("RF only", {"models": ("random_forest",), "rare_family": False,
                 "investigation": False, "evidence": False, "threat_intel": False}),
    ("XGB only", {"models": ("xgboost",), "rare_family": False,
                  "investigation": False, "evidence": False, "threat_intel": False}),
    ("RF+XGB", {"models": ("random_forest", "xgboost"), "rare_family": False,
                "investigation": False, "evidence": False, "threat_intel": False}),
    ("+rare_family", {"models": ("random_forest", "xgboost"), "rare_family": True,
                      "investigation": False, "evidence": False, "threat_intel": False}),
    ("+investigation", {"models": ("random_forest", "xgboost"), "rare_family": True,
                       "investigation": True, "evidence": False, "threat_intel": False}),
    ("+evidence/flow-evidence", {"models": ("random_forest", "xgboost"), "rare_family": True,
                                 "investigation": True, "evidence": True, "threat_intel": False}),
    ("+threat_intel (full)", {"models": ("random_forest", "xgboost"), "rare_family": True,
                               "investigation": True, "evidence": True, "threat_intel": True}),
)


def _stratified_sample(frame: pd.DataFrame, limit: int, seed: int) -> pd.DataFrame:
    """Proportionally sample every known family with a deterministic seed."""
    if len(frame) <= limit:
        return frame.sample(frac=1, random_state=seed).reset_index(drop=True)
    counts = frame["family"].value_counts().sort_index()
    exact = counts / counts.sum() * limit
    quotas = exact.map(math.floor).astype(int)
    # Preserve each represented stratum when the requested sample can include it.
    if len(counts) <= limit:
        quotas = quotas.clip(lower=1)
    while int(quotas.sum()) > limit:
        choices = quotas[quotas > 1] if len(counts) <= limit else quotas[quotas > 0]
        quotas.loc[choices.index[-1]] -= 1
    remainder = limit - int(quotas.sum())
    fractions = (exact - exact.map(math.floor)).sort_values(ascending=False, kind="stable")
    for family in fractions.index:
        if remainder <= 0:
            break
        if quotas[family] < counts[family]:
            quotas[family] += 1
            remainder -= 1
    parts = [group.sample(n=int(quotas[family]), random_state=seed + i)
             for i, (family, group) in enumerate(frame.groupby("family", sort=True))
             if quotas[family] > 0]
    return pd.concat(parts, ignore_index=True).sample(frac=1, random_state=seed).reset_index(drop=True)


def load_heldout_data(seed: int, limit: int, candidate_mode: bool = False) -> tuple[pd.DataFrame, list[str]]:
    data_dirs = (ROOT / "data" / "raw" / "CICIDS2017",
                 ROOT / "data" / "raw" / "CSE_CIC_IDS2018")
    paths = {path.name: path for folder in data_dirs for path in folder.glob("*.parquet")}
    missing = [name for name in TEST_CAPTURE_NAMES if name not in paths]
    if missing:
        raise FileNotFoundError(f"Held-out captures are missing: {missing}")
    capture_frames = []
    for name in TEST_CAPTURE_NAMES:
        sampled, _ = sample_capture(paths[name], SAMPLE_CAP_PER_RAW_LABEL,
                                    batch_size=100_000, seed=seed)
        if sampled.empty:
            continue
        sampled["family"] = sampled["__raw_label"].map(canonical_family)
        sampled["capture"] = name
        sampled = sampled[sampled["family"].ne("Unknown")]
        if candidate_mode and not sampled.empty:
            feature_columns = [column for column in sampled.columns
                               if column not in {"__raw_label", "family", "capture"}]
            shared_rows = _shared_candidate_features(sampled, feature_columns)
            sampled = sampled.loc[shared_rows.index]
        capture_frames.append(sampled)
    if not capture_frames:
        raise ValueError("No labelled rows were found in the named held-out captures")
    data = pd.concat(capture_frames, ignore_index=True)
    data = _stratified_sample(data, limit, seed)
    return data, list(TEST_CAPTURE_NAMES)


def _prediction_for_configuration(config_name: str, result: dict) -> tuple[str, str | None]:
    detection = result["detection"]
    decision = result.get("decision") or {}
    if config_name == "RF only":
        prediction = detection["random_forest"]
        return ("ATTACK" if int(prediction["binary_prediction"]) == 1 else "BENIGN",
                prediction.get("attack_family"))
    if config_name == "XGB only":
        prediction = detection["xgboost"]
        return ("ATTACK" if int(prediction["binary_prediction"]) == 1 else "BENIGN",
                prediction.get("attack_family"))
    if config_name == "RF+XGB":
        rf = detection["random_forest"]
        xgb = detection["xgboost"]
        rf_attack, xgb_attack = int(rf["binary_prediction"]) == 1, int(xgb["binary_prediction"]) == 1
        if rf_attack != xgb_attack:
            return "REVIEW", None
        family = rf.get("attack_family") if rf_attack else "Benign"
        return ("ATTACK" if rf_attack else "BENIGN", family)
    return str(decision.get("final_decision", "REVIEW")), decision.get("final_attack")


def _bootstrap_binary_ci(values: np.ndarray, seed: int,
                         capture_groups: np.ndarray) -> tuple[float | None, float | None]:
    values = np.asarray(values, dtype=bool)
    capture_groups = np.asarray(capture_groups, dtype=str)
    if values.size == 0:
        return None, None
    unique_groups = np.unique(capture_groups)
    if len(unique_groups) < 2:
        return None, None
    group_rows = {group: np.flatnonzero(capture_groups == group) for group in unique_groups}
    rng = np.random.default_rng(seed)
    samples = np.empty(BOOTSTRAP_RESAMPLES, dtype=float)
    for index in range(BOOTSTRAP_RESAMPLES):
        sampled_groups = rng.choice(unique_groups, size=len(unique_groups), replace=True)
        sampled_rows = np.concatenate([group_rows[group] for group in sampled_groups])
        samples[index] = float(values[sampled_rows].mean())
    low, high = np.quantile(samples, [0.025, 0.975])
    return float(low), float(high)


def _summarize_predictions(truth: np.ndarray, decisions: np.ndarray, seed: int,
                           capture_groups: np.ndarray) -> dict:
    attack_truth = truth != "Benign"
    benign_truth = ~attack_truth
    flagged = decisions != "BENIGN"
    strict_attack = decisions == "ATTACK"
    precision = float(np.sum(attack_truth & flagged) / np.sum(flagged)) if np.sum(flagged) else 0.0
    families = sorted(set(truth) - {"Benign"})
    family_metrics = {}
    for family in families:
        mask = truth == family
        family_metrics[family] = {
            "support": int(mask.sum()),
            "attack_recall": float(flagged[mask].mean()),
            "strict_attack_recall": float(strict_attack[mask].mean()),
        }
    capture_groups = np.asarray(capture_groups, dtype=str)
    recall_ci = _bootstrap_binary_ci(flagged[attack_truth], seed, capture_groups[attack_truth])
    fpr_ci = _bootstrap_binary_ci(flagged[benign_truth], seed + 1, capture_groups[benign_truth])
    return {
        "rows": int(len(truth)),
        "attack_support": int(attack_truth.sum()),
        "benign_support": int(benign_truth.sum()),
        "attack_recall": float(flagged[attack_truth].mean()) if attack_truth.any() else None,
        "strict_attack_recall": float(strict_attack[attack_truth].mean()) if attack_truth.any() else None,
        "benign_false_alarm_rate": float(flagged[benign_truth].mean()) if benign_truth.any() else None,
        "review_rate": float((decisions == "REVIEW").mean()),
        "precision": precision,
        "attack_recall_ci95_low": recall_ci[0],
        "attack_recall_ci95_high": recall_ci[1],
        "benign_false_alarm_ci95_low": fpr_ci[0],
        "benign_false_alarm_ci95_high": fpr_ci[1],
        "family_metrics": family_metrics,
    }


def _shared_candidate_features(data: pd.DataFrame, feature_columns: list[str]) -> pd.DataFrame:
    """Apply the LODO study's shared 11-feature mapping and transform."""
    common = shared_features._build_shared_features(
        data[feature_columns], protocol="Protocol", duration="Flow Duration",
        duration_scale=1_000_000.0, fwd_packets="Total Fwd Packets",
        bwd_packets="Total Backward Packets",
        fwd_bytes="Fwd Packets Length Total",
        bwd_bytes="Bwd Packets Length Total",
    )
    values = common[shared_features.FEATURES].replace([np.inf, -np.inf], np.nan)
    valid = values.notna().all(axis=1) & values.ge(0).all(axis=1)
    return np.log1p(values.loc[valid]).astype("float32")


def _candidate_prediction(model, features: pd.DataFrame, model_name: str) -> list[dict]:
    probabilities = np.asarray(model.predict_proba(features), dtype=float)
    classes = list(model.classes_)
    attack_index, benign_index = classes.index(1), classes.index(0)
    predictions = np.asarray(classes, dtype=object)[np.argmax(probabilities, axis=1)]
    results = []
    for index, predicted in enumerate(predictions):
        p = probabilities[index]
        is_attack = int(predicted)
        results.append({
            "model": model_name, "model_version": "lodo-shared-feature-candidate",
            "feature_schema_version": "tri-dataset-common-flow-binary-v1",
            "calibration_status": "uncalibrated",
            "probability_semantics": "raw candidate classifier probability",
            "attack_family": "Attack" if is_attack else "Benign",
            "confidence": float(p.max()), "binary_prediction": is_attack,
            "binary_attack_probability": float(p[attack_index]),
            "binary_benign_probability": float(p[benign_index]),
            "binary_probabilities": {str(classes[i]): float(p[i]) for i in range(len(classes))},
            "multiclass_prediction": None, "multiclass_probabilities": None,
            "attack_probability_explanation": {
                "status": "unavailable", "reason": "Binary LODO candidate has no multiclass explanation."},
        })
    return results


def _candidate_results_for_rows(data: pd.DataFrame, seed: int, models_dir: Path,
                                feature_columns: list[str]) -> list[dict]:
    shared = _shared_candidate_features(data, feature_columns)
    if len(shared) != len(data):
        raise ValueError("Candidate evaluation data must exclude invalid shared-feature rows before prediction")
    result: list[dict | None] = [None] * len(data)
    datasets = data["capture"].map(
        lambda name: "CICIDS2017" if str(name).endswith("no-metadata.parquet") else "CSE-CIC-IDS2018"
    ).to_numpy()
    file_datasets = {"CICIDS2017": "CICIDS2017", "CSE-CIC-IDS2018": "CSE_CIC_IDS2018"}
    for dataset, filename_dataset in file_datasets.items():
        positions = np.flatnonzero(datasets == dataset)
        if not len(positions):
            continue
        models = {}
        for model_name, stem in (("random_forest", "randomforest"), ("xgboost", "xgboost")):
            path = _candidate_model_path(models_dir, stem, filename_dataset, seed)
            if not path.is_file():
                raise FileNotFoundError(f"Missing LODO candidate model: {path}")
            models[model_name] = joblib.load(path)
        subset = shared.iloc[positions]
        outputs = {name: _candidate_prediction(model, subset, name) for name, model in models.items()}
        for offset, position in enumerate(positions):
            result[int(position)] = {name: values[offset] for name, values in outputs.items()}
    return result  # type: ignore[return-value]


def _candidate_model_path(models_dir: Path, stem: str, heldout_dataset: str,
                          seed: int) -> Path:
    """Resolve candidate names using the same normalized dataset names as LODO."""
    normalized_dataset = heldout_dataset.replace("-", "_")
    return models_dir / f"{stem}_except_{normalized_dataset}_seed_{seed}.joblib"


def evaluate(data: pd.DataFrame, seed: int, candidate_models_dir: Path | None = None) -> dict[str, dict]:
    rows = {}
    feature_columns = [column for column in data.columns if column not in {"__raw_label", "family", "capture"}]
    candidate_results = (_candidate_results_for_rows(data, seed, candidate_models_dir, feature_columns)
                         if candidate_models_dir is not None else None)
    for config_name, config in CONFIGURATIONS:
        predicted_decisions = []
        for index, (_, row) in enumerate(data.iterrows()):
            result = orchestrator.analyze(
                row[feature_columns].to_dict(), generate_llm=False,
                config={**config, "stop_after_decision": True},
                **({"precomputed_detection_results": candidate_results[index]}
                   if candidate_results is not None else {}),
            )
            decision, _family = _prediction_for_configuration(config_name, result)
            predicted_decisions.append(decision)
        truth = data["family"].astype(str).to_numpy()
        decisions = np.asarray(predicted_decisions, dtype=object)
        rows[config_name] = {
            "decisions": decisions,
            "metrics": _summarize_predictions(
                truth, decisions, BOOTSTRAP_SEED + seed, data["capture"].astype(str).to_numpy()
            ),
        }
    return rows


def _mean_std(values: list[float]) -> tuple[float | None, float | None]:
    if not values:
        return None, None
    return float(np.mean(values)), (float(np.std(values, ddof=1)) if len(values) > 1 else 0.0)


def _aggregate_seed_results(seed_runs: list[dict]) -> tuple[list[dict], dict[str, dict]]:
    records = []
    summaries = {}
    metric_names = ("attack_recall", "strict_attack_recall", "benign_false_alarm_rate", "review_rate", "precision")
    for config_name, _ in CONFIGURATIONS:
        per_seed = [run["results"][config_name]["metrics"] for run in seed_runs]
        decisions = np.concatenate([run["results"][config_name]["decisions"] for run in seed_runs])
        truths = np.concatenate([run["data"]["family"].astype(str).to_numpy() for run in seed_runs])
        capture_groups = np.concatenate([
            run["data"]["capture"].astype(str).to_numpy() for run in seed_runs
        ])
        pooled = _summarize_predictions(truths, decisions, BOOTSTRAP_SEED + 999, capture_groups)
        summary = {"configuration": config_name, "pooled": pooled, "per_seed": {}}
        summary_metrics = {}
        for metric in metric_names:
            mean, std = _mean_std([float(item[metric]) for item in per_seed if item[metric] is not None])
            summary_metrics[f"{metric}_mean"] = mean
            summary_metrics[f"{metric}_std"] = std
        summary["metrics"] = summary_metrics
        for run, item in zip(seed_runs, per_seed):
            scalar_metrics = {key: value for key, value in item.items() if key != "family_metrics"}
            records.append({"record_type": "seed_overall", "seed": run["seed"],
                            "configuration": config_name, "family": "ALL", **scalar_metrics})
        records.append({"record_type": "summary_overall", "seed": "ALL",
                        "configuration": config_name, "family": "ALL",
                        **summary_metrics, **{key: pooled[key] for key in metric_names},
                        "attack_support": pooled["attack_support"], "benign_support": pooled["benign_support"],
                        "attack_recall_ci95_low": pooled["attack_recall_ci95_low"],
                        "attack_recall_ci95_high": pooled["attack_recall_ci95_high"],
                        "benign_false_alarm_ci95_low": pooled["benign_false_alarm_ci95_low"],
                        "benign_false_alarm_ci95_high": pooled["benign_false_alarm_ci95_high"],
                        "rows": pooled["rows"]})
        families = sorted(set().union(*(set(item["family_metrics"]) for item in per_seed)))
        summary["families"] = {}
        for family in families:
            family_seed_values = [item["family_metrics"].get(family) for item in per_seed]
            family_seed_values = [value for value in family_seed_values if value is not None]
            family_summary = {"support_mean": float(np.mean([value["support"] for value in family_seed_values]))}
            for metric in ("attack_recall", "strict_attack_recall"):
                mean, std = _mean_std([value[metric] for value in family_seed_values])
                family_summary[f"{metric}_mean"] = mean
                family_summary[f"{metric}_std"] = std
            summary["families"][family] = family_summary
            for run, item in zip(seed_runs, per_seed):
                value = item["family_metrics"].get(family)
                if value:
                    records.append({"record_type": "seed_family", "seed": run["seed"],
                                    "configuration": config_name, "family": family, **value})
            records.append({"record_type": "summary_family", "seed": "ALL",
                            "configuration": config_name, "family": family, **family_summary})
        summaries[config_name] = summary
    return records, summaries


def _capture_metadata(captures: list[str]) -> list[dict[str, str]]:
    return [{"file": name, "active_production_training": TRAINING_STATUS.get(name, "unknown"),
             "capture_group": "CICIDS2017" if name.endswith("no-metadata.parquet") else "CSE-CIC-IDS2018"}
            for name in captures]


def _git_tree_clean() -> bool:
    try:
        return not subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip()
    except (OSError, subprocess.SubprocessError):
        return False


def _candidate_acceptance(seed_runs: list[dict]) -> dict:
    out_of_fold = {}
    for model_name, config_name in (("LODO Random Forest", "RF only"), ("LODO XGBoost", "XGB only")):
        truth = np.concatenate([run["data"]["family"].astype(str).to_numpy() for run in seed_runs])
        decisions = np.concatenate([run["results"][config_name]["decisions"] for run in seed_runs])
        flagged = decisions != "BENIGN"
        benign = truth == "Benign"
        families = {"Benign": {"false_positive_rate": float(flagged[benign].mean()) if benign.any() else None}}
        for family in sorted(set(truth) - {"Benign"}):
            mask = truth == family
            families[family] = {"recall": float(flagged[mask].mean())}
        out_of_fold[model_name] = families
    return evaluate_model_acceptance({"dataset": DATASET_NAME, "out_of_fold_per_family": out_of_fold})


def write_reports(seed_runs: list[dict], models_dir: Path, acceptance_gate: dict | None,
                  *, overwrite: bool = False) -> None:
    report_files = (OUTPUT_V3_DIR / "ablation_metrics.csv", OUTPUT_V3_DIR / "README.md")
    if not overwrite and any(path.exists() for path in report_files):
        raise FileExistsError(f"Refusing to overwrite existing report files in {OUTPUT_V3_DIR}")
    OUTPUT_V3_DIR.mkdir(parents=True, exist_ok=True)
    records, summaries = _aggregate_seed_results(seed_runs)
    captures_by_seed = {str(run["seed"]): ";".join(run["captures"]) for run in seed_runs}
    capture_names = sorted(set(name for run in seed_runs for name in run["captures"]))
    capture_metadata = _capture_metadata(capture_names)
    seed_size = {str(run["seed"]): len(run["data"]) for run in seed_runs}
    capture_seed_info = "; ".join(f"{seed}: {files}" for seed, files in captures_by_seed.items())
    capture_status = "; ".join(f"{item['file']} [{item['active_production_training']}]" for item in capture_metadata)
    fields = ["record_type", "dataset", "seed", "seed_sample_size", "captures_in_sample",
              "capture_training_status", "training_provenance_basis", "pipeline_version", "git_commit_hash",
              "git_tree_clean", "models_dir",
              "configuration", "family", "support", "support_mean", "rows", "attack_support", "benign_support",
              "attack_recall", "attack_recall_mean", "attack_recall_std", "strict_attack_recall",
              "strict_attack_recall_mean", "strict_attack_recall_std", "benign_false_alarm_rate",
              "benign_false_alarm_rate_mean", "benign_false_alarm_rate_std", "review_rate", "review_rate_mean",
              "review_rate_std", "precision", "precision_mean", "precision_std", "attack_recall_ci95_low",
              "attack_recall_ci95_high", "benign_false_alarm_ci95_low", "benign_false_alarm_ci95_high"]
    csv_path = OUTPUT_V3_DIR / "ablation_metrics.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for record in records:
            seed = str(record["seed"])
            writer.writerow({
                "dataset": DATASET_NAME,
                "seed_sample_size": seed_size.get(seed, ""),
                "captures_in_sample": captures_by_seed.get(seed, capture_seed_info),
                "capture_training_status": capture_status,
                "training_provenance_basis": TRAINING_PROVENANCE_BASIS,
                "pipeline_version": PIPELINE_VERSION,
                "git_commit_hash": GIT_COMMIT_HASH,
                "git_tree_clean": _git_tree_clean(),
                "models_dir": str(models_dir),
                **record,
            })

    lines = [
        "# Pipeline ablation study v3", "",
        f"- Dataset: {DATASET_NAME}",
        f"- Seeds: {', '.join(str(seed) for seed in SEEDS)}",
        "- Maximum sample size per seed: 1000; actual sample sizes and files are shown below.",
        f"- Pipeline version: {PIPELINE_VERSION}", f"- Git commit: {GIT_COMMIT_HASH}",
        f"- Git tree clean at report writing: {'yes' if _git_tree_clean() else 'no'}",
        f"- Models directory: `{models_dir}`",
        f"- Model mode: {'LODO candidate models; not promoted' if acceptance_gate is not None else 'current production models'}",
        "- Metric definitions: overall recall counts ATTACK or REVIEW on attack flows; strict recall counts ATTACK only; benign false-alarm rate counts ATTACK or REVIEW on benign flows; precision is the attack share of non-BENIGN verdicts.",
        "- Confidence intervals: 95% percentile intervals from 10,000 bootstrap draws resampling whole capture files, not individual flows, across all five seeds.",
        "", "## Capture files and production-model training provenance", "",
        "The active detector loads the CICIDS2017-named artifacts in `detection/model_predictor.py`. `train_multidataset.py` trains separate candidates under `models/multidataset/`; it does not establish training membership for the active artifacts. The existing source check reports that exact CICIDS2017 capture-level membership is unknown. LODO candidates use the shared 11-feature mapping; their binary-only predictions feed the existing downstream decision stages.",
        "", "| Capture file | Dataset | Used to train active production models? |",
        "|---|---|---|",
    ]
    for item in capture_metadata:
        lines.append(f"| `{item['file']}` | {item['capture_group']} | {item['active_production_training']} |")
    lines.extend(["", "### Files present in each seed's sample", "",
                  "| Seed | Sample size | Exact capture files represented |",
                  "|---:|---:|---|"])
    for run in seed_runs:
        lines.append(f"| {run['seed']} | {len(run['data'])} | {', '.join(f'`{name}`' for name in run['captures'])} |")
    lines.extend(["", "## Overall results across seeds", "",
                  "Mean and sample standard deviation are calculated over the five seed-level metrics. The 95% confidence intervals resample whole capture files to account for flow correlation within a capture.",
                  "", "| Configuration | Recall mean ± SD | Strict recall mean ± SD | Benign FPR mean ± SD | Recall 95% CI | Benign FPR 95% CI | REVIEW mean ± SD | Precision mean ± SD |",
                  "|---|---:|---:|---:|---:|---:|---:|---:|"])
    for config_name, _ in CONFIGURATIONS:
        item = summaries[config_name]
        m, pooled = item["metrics"], item["pooled"]
        fmt = lambda mean, std: "n/a" if mean is None else f"{mean:.4f} ± {std:.4f}"
        lines.append(
            f"| {config_name} | {fmt(m['attack_recall_mean'],m['attack_recall_std'])} | "
            f"{fmt(m['strict_attack_recall_mean'],m['strict_attack_recall_std'])} | "
            f"{fmt(m['benign_false_alarm_rate_mean'],m['benign_false_alarm_rate_std'])} | "
            f"[{pooled['attack_recall_ci95_low']:.4f}, {pooled['attack_recall_ci95_high']:.4f}] | "
            f"[{pooled['benign_false_alarm_ci95_low']:.4f}, {pooled['benign_false_alarm_ci95_high']:.4f}] | "
            f"{fmt(m['review_rate_mean'],m['review_rate_std'])} | {fmt(m['precision_mean'],m['precision_std'])} |"
        )
    lines.extend(["", "## Family recall across seeds", "",
                  "Values are mean ± sample standard deviation across seeds; support_mean is the average per-seed family support.",
                  "", "| Configuration | Family | Mean support | Recall mean ± SD | Strict recall mean ± SD |",
                  "|---|---|---:|---:|---:|"])
    for config_name, _ in CONFIGURATIONS:
        for family, values in summaries[config_name]["families"].items():
            lines.append(f"| {config_name} | {family} | {values['support_mean']:.1f} | "
                         f"{values['attack_recall_mean']:.4f} ± {values['attack_recall_std']:.4f} | "
                         f"{values['strict_attack_recall_mean']:.4f} ± {values['strict_attack_recall_std']:.4f} |")
    if acceptance_gate is not None:
        import json
        (OUTPUT_V3_DIR / "model_acceptance_gate.json").write_text(
            json.dumps(acceptance_gate, indent=2) + "\n", encoding="utf-8")
        lines.extend(["", "## Candidate model acceptance gate", "",
                      f"Overall gate: **{acceptance_gate['decision']}** (no model was promoted)."])
        for name, outcome in acceptance_gate["models"].items():
            details = "; ".join(outcome["failures"]) or "all configured criteria met"
            lines.append(f"- {name}: **{outcome['decision']}** — {details}")
    (OUTPUT_V3_DIR / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {csv_path}")
    print(f"Wrote {OUTPUT_V3_DIR / 'README.md'}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-rows", type=int, default=MAX_ROWS)
    parser.add_argument("--models-dir", type=Path, default=ROOT / "models",
                        help="active production models (default) or the LODO candidate model folder")
    args = parser.parse_args()
    if not 1 <= args.max_rows <= MAX_ROWS:
        parser.error("--max-rows must be from 1 to 1000")
    models_dir = args.models_dir.resolve()
    candidate_mode = models_dir != (ROOT / "models").resolve()
    if candidate_mode:
        required = []
        for heldout_name in ("CICIDS2017", "CSE_CIC_IDS2018"):
            for seed in SEEDS:
                for stem in ("randomforest", "xgboost"):
                    path = _candidate_model_path(models_dir, stem, heldout_name, seed)
                    if not path.is_file():
                        required.append(str(path))
        if required:
            raise FileNotFoundError(
                "Candidate mode requires LODO RF and XGBoost files for held-out CICIDS2017 and "
                "CSE-CIC-IDS2018 for seeds 42-46. Missing: " + ", ".join(required[:8])
            )
    if (OUTPUT_V3_DIR / "ablation_metrics.csv").exists() or (OUTPUT_V3_DIR / "README.md").exists():
        raise FileExistsError(f"Refusing to overwrite v3 report files in {OUTPUT_V3_DIR}")
    seed_runs = []
    checkpoint_tag = models_dir.name if candidate_mode else "production"
    checkpoint_dir = OUTPUT_V3_DIR / "checkpoints" / checkpoint_tag
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    for seed in SEEDS:
        checkpoint_path = checkpoint_dir / f"seed_{seed}.pkl"
        if checkpoint_path.exists():
            print(f"Loading completed checkpoint for seed {seed}...", flush=True)
            with checkpoint_path.open("rb") as handle:
                seed_runs.append(pickle.load(handle))
            continue
        print(f"Loading held-out sample for seed {seed}...", flush=True)
        data, _ = load_heldout_data(seed, args.max_rows, candidate_mode=candidate_mode)
        captures = sorted(data["capture"].astype(str).unique().tolist())
        print(f"Evaluating {len(data)} flows for seed {seed} across {len(CONFIGURATIONS)} configurations...", flush=True)
        results = evaluate(data, seed, models_dir if candidate_mode else None)
        run = {"seed": seed, "data": data, "captures": captures, "results": results}
        with checkpoint_path.open("wb") as handle:
            pickle.dump(run, handle, protocol=pickle.HIGHEST_PROTOCOL)
        seed_runs.append(run)
        print(f"Finished seed {seed}.", flush=True)
    acceptance_gate = _candidate_acceptance(seed_runs) if candidate_mode else None
    write_reports(seed_runs, models_dir, acceptance_gate)
    print(f"Seeds: {', '.join(map(str, SEEDS))}; maximum sample size per seed: {args.max_rows}; pipeline={PIPELINE_VERSION}; git={GIT_COMMIT_HASH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
