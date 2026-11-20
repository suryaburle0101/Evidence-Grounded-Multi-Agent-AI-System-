"""
Rare-family detector (Infiltration, Heartbleed)

The multiclass RF/XGBoost models never learned these two classes
(too few samples), so this module adds one small dedicated binary
detector per family. Models are created by train_rare_family_models.py
and stored in  models/rare_infiltration.pkl / rare_heartbleed.pkl.

If the model files do not exist yet, the detector reports
available=False and the pipeline keeps working without it.
"""

from pathlib import Path

import joblib
import numpy as np
import pandas as pd

MODEL_DIR = Path(__file__).resolve().parent.parent / "models"

FAMILIES = ["Infiltration", "Heartbleed"]


def model_path(family):
    return MODEL_DIR / f"rare_{family.lower()}.pkl"


def clean_features(df):
    """Shared by training and inference so both see identical data."""
    df = df.copy()
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.apply(pd.to_numeric, errors="coerce")
    df = df.fillna(0.0)
    df = df.clip(lower=-1e12, upper=1e12)
    return df.astype("float32")


class RareFamilyDetector:

    def __init__(self):
        self.name = "Rare Family Detector"
        self._bundles = None

    def _load(self):
        if self._bundles is not None:
            return
        self._bundles = {}
        for family in FAMILIES:
            path = model_path(family)
            if path.exists():
                try:
                    bundle = joblib.load(path)
                    model = bundle.get("model") if isinstance(bundle, dict) else None
                    if model is not None and hasattr(model, "set_params"):
                        try:
                            model.set_params(n_jobs=1)
                        except ValueError:
                            pass
                    self._bundles[family] = bundle
                except Exception:
                    pass

    def analyze(self, X):
        self._load()

        if not self._bundles:
            return {
                "agent": self.name,
                "available": False,
                "any_triggered": False,
                "top_family": None,
                "top_probability": 0.0,
                "scores": {},
                "message": "No rare-family models found. Run "
                           "train_rare_family_models.py first."
            }

        if isinstance(X, dict):
            X = pd.DataFrame([X])
        elif isinstance(X, pd.Series):
            X = X.to_frame().T
        X = X.iloc[[0]]

        scores = {}
        triggered = {}
        thresholds = {}

        for family, bundle in self._bundles.items():
            features = bundle["features"]
            row = clean_features(X.reindex(columns=features))
            classes = list(bundle["model"].classes_)
            prob = float(
                bundle["model"].predict_proba(row)[0][classes.index(1)]
            )
            scores[family] = round(prob, 6)
            thresholds[family] = bundle["threshold"]
            triggered[family] = prob >= bundle["threshold"]

        hits = {f: p for f, p in scores.items() if triggered[f]}
        if hits:
            top_family = max(hits, key=hits.get)
            top_prob = hits[top_family]
        else:
            top_family = None
            top_prob = max(scores.values()) if scores else 0.0

        return {
            "agent": self.name,
            "available": True,
            "any_triggered": bool(hits),
            "top_family": top_family,
            "top_probability": round(top_prob, 6),
            "scores": scores,
            "thresholds": thresholds,
            "triggered": triggered
        }


rare_family_detector = RareFamilyDetector()
