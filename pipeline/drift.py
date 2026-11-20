"""Coarse input-range check against the training data (not a model-accuracy test)."""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

import numpy as np
import pandas as pd

from pipeline.data_pipeline import FEATURES, map_schema

BASELINE_PATH = Path(__file__).resolve().parents[1] / "models" / "drift_baseline.json"

MESSAGES = {
    "ok": "Input is within the value ranges seen in the CICIDS2017 training data. "
          "This is a coarse range check and does not confirm that a verdict is correct.",
    "caution": "Some flows in this batch fall outside the value ranges of the CICIDS2017 "
               "training data. Treat Benign verdicts for them with caution.",
    "warning": "Most flows in this batch look unlike the CICIDS2017 data the detector was "
               "trained on. A Benign verdict is not reliable for this input.",
}


@lru_cache(maxsize=1)
def _default_baseline() -> dict:
    with open(BASELINE_PATH, encoding="utf-8") as handle:
        return json.load(handle)


def _unavailable(reason: str) -> dict:
    return {"status": "unavailable", "message": f"Input drift check unavailable: {reason}"}


def assess_batch_drift(flows: list, baseline: dict | None = None) -> dict:
    try:
        base = baseline if baseline is not None else _default_baseline()
        features = list(FEATURES)
        if list(base["features"]) != features:
            return _unavailable("baseline was built for a different feature list")
        lo = np.asarray(base["lo"], dtype=float)
        hi = np.asarray(base["hi"], dtype=float)
        mapped, _ = map_schema(pd.DataFrame(flows))
        missing = [f for f in features if f not in mapped.columns]
        if missing:
            return _unavailable(f"{len(missing)} model features are missing from the input")
        values = mapped[features].apply(pd.to_numeric, errors="coerce").to_numpy(dtype=float)
        threshold = float(base["per_flow_threshold"])
        caution_share = float(base["caution_share"])
        warning_share = float(base["warning_share"])
    except (OSError, KeyError, ValueError, TypeError) as exc:
        return _unavailable(str(exc)[:120])

    with np.errstate(invalid="ignore"):
        out = ~np.isfinite(values) | (values < lo) | (values > hi)
    fraction = out.mean(axis=1)
    share = float((fraction > threshold).mean())
    status = "warning" if share >= warning_share else "caution" if share >= caution_share else "ok"
    per_feature = out.mean(axis=0)
    order = np.argsort(per_feature)[::-1][:5]
    return {
        "status": status,
        "flows_checked": int(len(fraction)),
        "unfamiliar_flow_share": round(share, 3),
        "median_out_of_range_fraction": round(float(np.median(fraction)), 3),
        "top_out_of_range_features": [
            {"feature": features[int(i)], "share_of_flows": round(float(per_feature[i]), 3)}
            for i in order if per_feature[i] > 0
        ],
        "message": MESSAGES[status],
    }
