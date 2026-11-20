"""Calibrate LODO candidates and report held-out calibration quality.

Run after ``evaluation/lodo_evaluation.py``. Candidate calibrators are saved
only below models/experimental/calibrated and are never loaded by production.
"""
from __future__ import annotations

import argparse
import binascii
import json
import struct
import sys
import zlib
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import brier_score_loss, recall_score
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from evaluation import lodo_evaluation as lodo
from evaluation.tri_dataset_benchmark import FEATURES

REPORT_DIR = ROOT / "reports" / "calibration"
MODEL_DIR = ROOT / "models" / "experimental" / "calibrated"
TARGET_FPR = 0.01


def _logit(probabilities: np.ndarray) -> np.ndarray:
    p = np.clip(np.asarray(probabilities, dtype=float), 1e-6, 1 - 1e-6)
    return np.log(p / (1 - p)).reshape(-1, 1)


def expected_calibration_error(y_true, probabilities, bins: int = 10) -> float:
    y = np.asarray(y_true, dtype=int)
    p = np.asarray(probabilities, dtype=float)
    edges = np.linspace(0.0, 1.0, bins + 1)
    total = max(1, len(y))
    error = 0.0
    for index in range(bins):
        selected = (p >= edges[index]) & (p < edges[index + 1] if index < bins - 1 else p <= edges[index + 1])
        if selected.any():
            error += float(selected.sum() / total * abs(y[selected].mean() - p[selected].mean()))
    return error


def reliability_curve_data(y_true, probabilities, bins: int = 10) -> list[dict]:
    y = np.asarray(y_true, dtype=int)
    p = np.asarray(probabilities, dtype=float)
    edges = np.linspace(0.0, 1.0, bins + 1)
    output = []
    for index in range(bins):
        selected = (p >= edges[index]) & (p < edges[index + 1] if index < bins - 1 else p <= edges[index + 1])
        output.append({"bin": index + 1, "lower": float(edges[index]), "upper": float(edges[index + 1]),
                       "count": int(selected.sum()),
                       "mean_predicted": float(p[selected].mean()) if selected.any() else None,
                       "fraction_positive": float(y[selected].mean()) if selected.any() else None})
    return output


def fit_calibrators(y_validation, raw_validation) -> dict:
    y = np.asarray(y_validation, dtype=int)
    raw = np.asarray(raw_validation, dtype=float)
    if len(np.unique(y)) != 2:
        raise ValueError("Calibration validation split must contain benign and attack rows")
    platt = LogisticRegression(C=1e6, solver="lbfgs", random_state=42)
    platt.fit(_logit(raw), y)
    isotonic = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
    isotonic.fit(raw, y)
    return {"platt": platt, "isotonic": isotonic}


def apply_calibrator(calibrator, method: str, raw_probabilities) -> np.ndarray:
    raw = np.asarray(raw_probabilities, dtype=float)
    if method == "raw":
        return raw.copy()
    if method == "platt":
        return calibrator.predict_proba(_logit(raw))[:, list(calibrator.classes_).index(1)]
    if method == "isotonic":
        return np.asarray(calibrator.predict(raw), dtype=float)
    raise ValueError(f"Unknown calibration method: {method}")


def threshold_for_benign_fpr(y_validation, probabilities, target_fpr: float = TARGET_FPR) -> tuple[float, float]:
    y = np.asarray(y_validation, dtype=int)
    p = np.asarray(probabilities, dtype=float)
    benign = p[y == 0]
    if not len(benign):
        raise ValueError("Cannot choose a benign false-alarm threshold without benign validation rows")
    candidates = np.unique(benign)
    acceptable = [float(value) for value in candidates if float(np.mean(benign >= value)) <= target_fpr]
    threshold = min(acceptable) if acceptable else float(np.nextafter(benign.max(), np.inf))
    return threshold, float(np.mean(benign >= threshold))


def score_probabilities(y_true, probabilities, threshold: float) -> dict:
    y = np.asarray(y_true, dtype=int)
    p = np.asarray(probabilities, dtype=float)
    pred = p >= threshold
    benign = y == 0
    return {"brier_score": float(brier_score_loss(y, p)),
            "ece_10_bins": expected_calibration_error(y, p, 10),
            "recall_at_validation_threshold": float(recall_score(y, pred, zero_division=0)),
            "heldout_benign_false_alarm_rate": float(pred[benign].mean()) if benign.any() else None,
            "threshold": float(threshold)}


def _candidate_path(model_name: str, heldout: str, seed: int) -> Path:
    return lodo.MODEL_DIR / f"{model_name.lower()}_except_{heldout.replace('-', '_')}_seed_{seed}.joblib"


def _atomic_json(path: Path, value: dict) -> None:
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, indent=2, allow_nan=False), encoding="utf-8")
    temp.replace(path)


def _plot_reliability(curves: dict[str, list[dict]], destination: Path, title: str) -> None:
    # Small dependency-free RGB plot: raw=blue, Platt=green, isotonic=orange.
    width, height = 640, 480
    pixels = bytearray([255, 255, 255] * width * height)
    left, right, top, bottom = 56, 612, 28, 424

    def point(x, y, color):
        if 0 <= x < width and 0 <= y < height:
            offset = (y * width + x) * 3
            pixels[offset:offset + 3] = bytes(color)

    def line(x0, y0, x1, y1, color):
        steps = max(abs(x1 - x0), abs(y1 - y0), 1)
        for step in range(steps + 1):
            x = round(x0 + (x1 - x0) * step / steps)
            y = round(y0 + (y1 - y0) * step / steps)
            point(x, y, color)

    def xy(probability, fraction):
        return (round(left + float(probability) * (right - left)),
                round(bottom - float(fraction) * (bottom - top)))

    gray = (220, 225, 230)
    for tick in range(11):
        gx = left + round((right - left) * tick / 10)
        gy = bottom - round((bottom - top) * tick / 10)
        line(gx, top, gx, bottom, gray)
        line(left, gy, right, gy, gray)
    line(left, bottom, right, bottom, (40, 45, 50))
    line(left, top, left, bottom, (40, 45, 50))
    # Ideal calibration reference is dashed gray.
    for index in range(0, 101, 4):
        a = xy(index / 100, index / 100)
        b = xy(min(1, (index + 2) / 100), min(1, (index + 2) / 100))
        line(*a, *b, (110, 115, 120))
    colors = {"raw": (40, 105, 200), "platt": (30, 150, 95), "isotonic": (225, 125, 30)}
    for name, bins in curves.items():
        points = [(row["mean_predicted"], row["fraction_positive"])
                  for row in bins if row["mean_predicted"] is not None]
        scaled = [xy(x, y) for x, y in points]
        for first, second in zip(scaled, scaled[1:]):
            line(*first, *second, colors[name])
        for x, y in scaled:
            for dx in range(-3, 4):
                for dy in range(-3, 4):
                    if dx * dx + dy * dy <= 9:
                        point(x + dx, y + dy, colors[name])

    raw = bytearray()
    stride = width * 3
    for row in range(height):
        raw.append(0)  # PNG filter: None
        raw.extend(pixels[row * stride:(row + 1) * stride])

    def chunk(kind: bytes, data: bytes) -> bytes:
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", binascii.crc32(body) & 0xffffffff)

    png = (b"\x89PNG\r\n\x1a\n" +
           chunk(b"IHDR", struct.pack(">2I5B", width, height, 8, 2, 0, 0, 0)) +
           chunk(b"IDAT", zlib.compress(bytes(raw), level=6)) + chunk(b"IEND", b""))
    destination.write_bytes(png)


def run(max_rows_per_file: int = 10**12, resume: bool = True) -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    # Reuse the exact dataset mapping and sample/cap rules used by LODO.
    data = {}
    for dataset, paths in lodo.capture_files().items():
        print(f"Loading {dataset} for calibration", flush=True)
        data[dataset], _ = lodo.load_dataset(dataset, paths, max_rows_per_file)

    checkpoint_path = REPORT_DIR / "checkpoint.json"
    state = json.loads(checkpoint_path.read_text(encoding="utf-8")) if resume and checkpoint_path.exists() else {"done": [], "records": []}
    done, records = set(state["done"]), state["records"]
    for heldout in lodo.DATASETS:
        test = data[heldout].reset_index(drop=True)
        for seed in lodo.SEEDS:
            training = pd.concat([
                lodo.stratified_cap(data[name], lodo.MAX_TRAIN_ROWS_PER_DATASET, seed)
                for name in lodo.DATASETS if name != heldout
            ], ignore_index=True)
            training, _ = lodo.remove_train_test_duplicates(training, test)
            fit_index, validation_index = train_test_split(
                np.arange(len(training)), test_size=0.15, random_state=seed,
                stratify=training.target.to_numpy())
            validation = training.iloc[validation_index]
            for model_name in ("RandomForest", "XGBoost"):
                key = f"{heldout}:{seed}:{model_name}"
                if key in done:
                    continue
                model_path = _candidate_path(model_name, heldout, seed)
                if not model_path.exists():
                    raise FileNotFoundError(f"Missing LODO candidate {model_path}; run evaluation/lodo_evaluation.py first")
                model = joblib.load(model_path)
                raw_val = model.predict_proba(validation[FEATURES])[:, list(model.classes_).index(1)]
                raw_test = model.predict_proba(test[FEATURES])[:, list(model.classes_).index(1)]
                fitted = fit_calibrators(validation.target, raw_val)
                calibrated_val = {name: apply_calibrator(calibrator, name, raw_val)
                                  for name, calibrator in fitted.items()}
                calibrated_test = {name: apply_calibrator(calibrator, name, raw_test)
                                   for name, calibrator in fitted.items()}
                validation_scores = {"raw": raw_val, **calibrated_val}
                test_scores = {"raw": raw_test, **calibrated_test}
                metrics, curves = {}, {}
                for method, scores in test_scores.items():
                    threshold, validation_fpr = threshold_for_benign_fpr(
                        validation.target, validation_scores[method], TARGET_FPR)
                    metrics[method] = score_probabilities(test.target, scores, threshold)
                    metrics[method]["validation_benign_false_alarm_rate"] = validation_fpr
                    metrics[method]["validation_rows"] = int(len(validation))
                    metrics[method]["heldout_rows"] = int(len(test))
                    curves[method] = reliability_curve_data(test.target, scores, 10)
                figure = REPORT_DIR / f"{heldout.replace('-', '_')}_{model_name.lower()}_seed_{seed}.png"
                _plot_reliability(curves, figure, f"{heldout} · {model_name} · seed {seed}")
                for method, calibrator in fitted.items():
                    calibrated_path = MODEL_DIR / f"{model_name.lower()}_{method}_except_{heldout.replace('-', '_')}_seed_{seed}.joblib"
                    joblib.dump({"base_model": model, "calibrator": calibrator,
                                 "method": method, "features": FEATURES,
                                 "threshold": metrics[method]["threshold"],
                                 "target_validation_benign_fpr": TARGET_FPR}, calibrated_path)
                records.append({"held_out_dataset": heldout, "seed": seed, "model": model_name,
                                "capture_groups": sorted(test.capture_group.astype(str).unique().tolist()),
                                "metrics": metrics, "reliability_curves": curves,
                                "plot": str(figure.relative_to(ROOT)),
                                "production_model_status": "not comparable: active production models require 77 features; LODO schema has 11"})
                done.add(key)
                state = {"done": sorted(done), "records": records}
                _atomic_json(checkpoint_path, state)
                pd.DataFrame([{"held_out_dataset": record["held_out_dataset"],
                    "seed": record["seed"], "model": record["model"], "method": method,
                    **values} for record in records for method, values in record["metrics"].items()]
                ).to_csv(REPORT_DIR / "calibration_metrics.csv", index=False)
                _atomic_json(REPORT_DIR / "calibration_results.json", {
                    "schema": "lodo-calibration-study-v1", "target_benign_fpr": TARGET_FPR,
                    "seeds": list(lodo.SEEDS), "features": FEATURES,
                    "calibration_split": "stratified 15% validation from training datasets only",
                    "heldout_data_used_for_fit_or_threshold": False,
                    "records": records,
                    "production_model_limitation": "The shared LODO mapping has 11 features while active models require 77; no values were fabricated. In addition, exact active-model training capture membership is undocumented, so a validation split cannot be proven disjoint from production training data."})
                print(f"Calibrated {heldout} / {model_name} / seed {seed}", flush=True)
    readme = ["# LODO calibration study", "",
        "Platt scaling and isotonic regression are fitted only on a stratified validation split from the training datasets. The held-out dataset is used only for final metrics and reliability curves. The threshold for raw, Platt, and isotonic scores is selected using benign validation scores to target at most 1% false alarms; finite sample ties can yield a lower observed validation rate.", "",
        "Reports include Brier score, 10-bin expected calibration error, reliability-curve points, and held-out recall at the validation-selected threshold. Active production calibration is not included: its 77-feature schema differs from the 11-feature LODO schema, and the exact production training capture membership is undocumented, so a validation split cannot be proven disjoint from model training. No values were fabricated and no active model was changed.", "",
        "Reliability PNGs plot the ideal diagonal in gray, raw output in blue, Platt in green, and isotonic in orange. Axes are 0–1 mean predicted attack probability (horizontal) and observed attack fraction (vertical).", "",
        "Run `evaluation/lodo_evaluation.py` first to create the LODO candidate models. Calibrated bundles are research candidates under `models/experimental/calibrated/` and do not alter API or CLI model loading.", "",
        "See `calibration_metrics.csv`, `calibration_results.json`, and the PNG reliability plots for results.", ""]
    (REPORT_DIR / "README.md").write_text("\n".join(readme), encoding="utf-8")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-rows-per-file", type=int, default=10**12,
                        help="optional input cap per capture; default is all rows")
    parser.add_argument("--no-resume", action="store_true")
    args = parser.parse_args(argv)
    run(args.max_rows_per_file, resume=not args.no_resume)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
