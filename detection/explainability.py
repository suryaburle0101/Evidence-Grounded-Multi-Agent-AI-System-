"""Optional, additivity-checked per-flow SHAP explanations."""
from __future__ import annotations

from functools import lru_cache

import numpy as np


@lru_cache(maxsize=1)
def _tree_explainer(model):
    import shap

    # Path-dependent Tree SHAP uses training-path counts stored in the forest;
    # no arbitrary background rows or labels are introduced at inference time.
    return shap.TreeExplainer(
        model,
        feature_perturbation="tree_path_dependent",
        model_output="raw",
    )


def explain_attack_probability(
    row,
    top_k: int = 8,
    attack_probability: float | None = None,
) -> dict:
    """Explain the RF binary attack score; return no claim if SHAP is unavailable."""
    try:
        import shap  # noqa: F401 - provide a clean optional-dependency status
    except ImportError:
        return {
            "status": "unavailable",
            "reason": "Optional SHAP dependency is not installed.",
        }

    try:
        from detection import model_predictor

        model = model_predictor.rf_binary
        explanation = _tree_explainer(model)(row)
        values = np.asarray(explanation.values, dtype=float)
        base = np.asarray(explanation.base_values, dtype=float)
        classes = list(model_predictor.rf_binary.classes_)
        attack_index = classes.index(1)
        if values.ndim == 3:
            contributions = values[0, :, attack_index]
        elif values.ndim == 2:
            contributions = values[0]
        else:
            raise ValueError(f"Unexpected SHAP output shape: {values.shape}")
        if base.ndim > 1:
            expected = float(base.reshape(-1, base.shape[-1])[0, attack_index])
        elif base.ndim == 1 and len(base) == len(classes):
            expected = float(base[attack_index])
        else:
            expected = float(base.reshape(-1)[0])

        predicted = (
            float(attack_probability)
            if attack_probability is not None
            else float(model_predictor.rf_binary.predict_proba(row)[0][attack_index])
        )
        reconstructed = expected + float(contributions.sum())
        error = abs(reconstructed - predicted)
        if error > 1e-4:
            raise ValueError(f"SHAP additivity check failed (absolute error {error:.6g})")

        ordered = np.argsort(np.abs(contributions))[::-1][:max(1, int(top_k))]
        return {
            "status": "available",
            "explained_output": "Random Forest binary attack probability (raw, uncalibrated)",
            "baseline_value": round(expected, 8),
            "model_output": round(predicted, 8),
            "additivity_absolute_error": round(error, 10),
            "method": "Tree SHAP; tree-path-dependent background",
            "top_features": [
                {
                    "feature": str(model_predictor.FEATURE_NAMES[int(index)]),
                    "value": float(row.iloc[0, int(index)]),
                    "contribution": round(float(contributions[index]), 8),
                    "direction": "raises attack score" if contributions[index] > 0 else "lowers attack score",
                }
                for index in ordered
            ],
            "caveat": "Feature attribution explains this model output; it is not causal proof or confirmation of compromise.",
        }
    except Exception as exc:
        return {
            "status": "error",
            "reason": f"SHAP explanation failed validation ({type(exc).__name__}).",
        }
