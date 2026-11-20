from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb
from detection.explainability import explain_attack_probability


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODELS_DIR = PROJECT_ROOT / "models"


# ============================================================
# MODEL FILES
# ============================================================

RF_BINARY_PATH = MODELS_DIR / "random_forest_binary_cicids2017.pkl"
RF_MULTICLASS_PATH = MODELS_DIR / "random_forest_multiclass_cicids2017.pkl"

XGB_BINARY_PATH = MODELS_DIR / "xgboost_binary_cicids2017.ubj"
XGB_MULTICLASS_PATH = MODELS_DIR / "xgboost_multiclass_cicids2017.ubj"

LABEL_ENCODER_PATH = MODELS_DIR / "multiclass_label_encoder.pkl"


# ============================================================
# LOAD MODELS
# ============================================================

rf_binary = joblib.load(RF_BINARY_PATH)
rf_multiclass = joblib.load(RF_MULTICLASS_PATH)

# Keep inference portable in restricted Windows environments where joblib's
# process pool cannot be created. A single worker is sufficient for flow-level
# predictions and avoids multiprocessing permission failures.
for _model in (rf_binary, rf_multiclass):
    if hasattr(_model, "set_params"):
        try:
            _model.set_params(n_jobs=1)
        except ValueError:
            # Estimators without an n_jobs parameter need no adjustment.
            pass

label_encoder = joblib.load(LABEL_ENCODER_PATH)


class XGBoostBoosterModel:
    """Small sklearn-compatible prediction adapter for stable UBJSON models."""

    def __init__(self, path, classes):
        self._booster = xgb.Booster()
        self._booster.load_model(path)
        self.classes_ = np.asarray(classes)

    def predict_proba(self, X):
        feature_names = list(X.columns) if hasattr(X, "columns") else None
        scores = self._booster.predict(
            xgb.DMatrix(X, feature_names=feature_names)
        )
        if scores.ndim == 1:
            scores = np.column_stack((1.0 - scores, scores))
        return scores

    def predict(self, X):
        probabilities = self.predict_proba(X)
        return self.classes_[np.argmax(probabilities, axis=1)]


xgb_binary = XGBoostBoosterModel(
    XGB_BINARY_PATH,
    classes=(0, 1)
)
xgb_multiclass = XGBoostBoosterModel(
    XGB_MULTICLASS_PATH,
    classes=range(len(label_encoder.classes_))
)


# ============================================================
# FEATURE SCHEMA
# ============================================================

FEATURE_NAMES = list(rf_multiclass.feature_names_in_)

EXPECTED_FEATURE_COUNT = 77
FEATURE_SCHEMA_VERSION = "cicids2017-77-v1"
MODEL_ARTIFACT_VERSION = "cicids2017-production-artifacts-v1"
PROBABILITY_SEMANTICS = "raw classifier probability; not calibrated"


# ============================================================
# VALIDATE FEATURE SCHEMA
# ============================================================

if len(FEATURE_NAMES) != EXPECTED_FEATURE_COUNT:
    raise RuntimeError(
        f"Expected {EXPECTED_FEATURE_COUNT} features, "
        f"but model contains {len(FEATURE_NAMES)}."
    )


# ============================================================
# PREPARE INPUT
# ============================================================

def prepare_input(X):
    """
    Prepare one or more CICIDS2017 network flows
    for model prediction.
    """

    if isinstance(X, dict):
        X = pd.DataFrame([X])

    elif isinstance(X, pd.Series):
        X = X.to_frame().T

    elif not isinstance(X, pd.DataFrame):
        X = pd.DataFrame(X)

    missing = [
        feature
        for feature in FEATURE_NAMES
        if feature not in X.columns
    ]

    if missing:
        raise ValueError(
            "Missing required features:\n"
            + "\n".join(missing)
        )

    # Keep exactly the model's feature order
    X = X[FEATURE_NAMES].copy()

    # Convert values to numeric
    X = X.apply(
        pd.to_numeric,
        errors="coerce"
    )

    if X.isna().any().any():
        invalid_columns = X.columns[
            X.isna().any()
        ].tolist()

        raise ValueError(
            "Input contains invalid or missing "
            f"numeric values in: {invalid_columns}"
        )

    return X


# ============================================================
# DECODE MULTICLASS LABEL
# ============================================================

def decode_label(encoded_label):
    """
    Convert a multiclass prediction into the original
    CICIDS2017 attack-family label.

    Handles:
    - already-decoded string labels
    - numeric labels
    - numeric labels represented as strings
    """

    # Already a known class label
    if isinstance(encoded_label, str):
        if encoded_label in label_encoder.classes_:
            return encoded_label

        # Numeric value stored as a string
        try:
            encoded_label = int(encoded_label)
        except ValueError:
            return encoded_label

    decoded = label_encoder.inverse_transform(
        [int(encoded_label)]
    )[0]

    return str(decoded)# ============================================================
def predict_attack_family(
    X,
    model_type="random_forest",
    _precomputed=None,
):
    """
    Predict the attack family for network flow(s).

    Also exposes the actual model probability outputs
    for downstream investigation and correlation agents.
    """

    X = prepare_input(X)

    # --------------------------------------------------------
    # Select models
    # --------------------------------------------------------

    if model_type == "random_forest":

        binary_model = rf_binary
        multiclass_model = rf_multiclass

    elif model_type == "xgboost":

        binary_model = xgb_binary
        multiclass_model = xgb_multiclass

    else:

        raise ValueError(
            "model_type must be "
            "'random_forest' or 'xgboost'"
        )

    # --------------------------------------------------------
    # Binary prediction
    # --------------------------------------------------------

    binary_classes = list(
        binary_model.classes_
    )
    binary_probability = (
        np.asarray(_precomputed["binary_probability"], dtype=float)
        if _precomputed is not None
        else binary_model.predict_proba(X)[0]
    )
    binary_prediction = binary_classes[int(np.argmax(binary_probability))]

    # --------------------------------------------------------
    # Actual attack probability
    #
    # CICIDS2017 binary models:
    # 0 = Benign
    # 1 = Attack
    # --------------------------------------------------------

    if 1 in binary_classes:

        attack_index = binary_classes.index(1)

        binary_attack_probability = float(
            binary_probability[attack_index]
        )

    else:

        binary_attack_probability = 0.0

    # --------------------------------------------------------
    # Actual benign probability
    # --------------------------------------------------------

    if 0 in binary_classes:

        benign_index = binary_classes.index(0)

        binary_benign_probability = float(
            binary_probability[benign_index]
        )

    else:

        binary_benign_probability = 0.0

    # --------------------------------------------------------
    # Binary confidence
    # --------------------------------------------------------

    binary_confidence = float(
        binary_probability.max()
    )

    # --------------------------------------------------------
    # Store complete binary probabilities
    # --------------------------------------------------------

    binary_probabilities = {
        str(binary_classes[i]):
        float(binary_probability[i])
        for i in range(
            len(binary_classes)
        )
    }

    # --------------------------------------------------------
    # BENIGN
    # --------------------------------------------------------

    if binary_prediction == 0:
        result = {

            "model":
                model_type,

            "model_version": MODEL_ARTIFACT_VERSION,
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "calibration_status": "uncalibrated",
            "probability_semantics": PROBABILITY_SEMANTICS,

            "attack_family":
                "Benign",

            "confidence":
                binary_confidence,

            "binary_prediction":
                int(binary_prediction),

            "binary_attack_probability":
                binary_attack_probability,

            "binary_benign_probability":
                binary_benign_probability,

            "binary_probabilities":
                binary_probabilities,

            "multiclass_prediction":
                None,

            "multiclass_probabilities":
                None
        }
        if model_type == "random_forest":
            result["attack_probability_explanation"] = explain_attack_probability(
                X, attack_probability=binary_attack_probability
            )
        return result

    # --------------------------------------------------------
    # Multiclass prediction
    # --------------------------------------------------------

    multiclass_classes = list(
        multiclass_model.classes_
    )
    multiclass_probability = (
        np.asarray(_precomputed["multiclass_probability"], dtype=float)
        if _precomputed is not None
        else multiclass_model.predict_proba(X)[0]
    )
    multiclass_prediction = multiclass_classes[
        int(np.argmax(multiclass_probability))
    ]

    multiclass_confidence = float(
        multiclass_probability.max()
    )

    attack_family = decode_label(
        multiclass_prediction
    )

    # --------------------------------------------------------
    # Multiclass probability mapping
    # --------------------------------------------------------

    multiclass_probabilities = {}

    for i, class_value in enumerate(
        multiclass_classes
    ):

        class_name = decode_label(
            class_value
        )

        multiclass_probabilities[
            class_name
        ] = float(
            multiclass_probability[i]
        )

    # --------------------------------------------------------
    # Return complete model evidence
    # --------------------------------------------------------

    result = {

        "model":
            model_type,

        "model_version": MODEL_ARTIFACT_VERSION,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "calibration_status": "uncalibrated",
        "probability_semantics": PROBABILITY_SEMANTICS,

        "attack_family":
            attack_family,

        "confidence":
            multiclass_confidence,

        "binary_prediction":
            int(binary_prediction),

        "binary_attack_probability":
            binary_attack_probability,

        "binary_benign_probability":
            binary_benign_probability,

        "binary_probabilities":
            binary_probabilities,

        "multiclass_prediction":
            str(multiclass_prediction),

        "multiclass_probabilities":
            multiclass_probabilities
    }
    if model_type == "random_forest":
        result["attack_probability_explanation"] = explain_attack_probability(
            X, attack_probability=binary_attack_probability
        )
    return result


def predict_attack_family_batch(X, model_type="random_forest"):
    """Predict a batch using vectorized model calls, preserving row results."""
    X = prepare_input(X)
    if model_type == "random_forest":
        binary_model, multiclass_model = rf_binary, rf_multiclass
    elif model_type == "xgboost":
        binary_model, multiclass_model = xgb_binary, xgb_multiclass
    else:
        raise ValueError("model_type must be 'random_forest' or 'xgboost'")

    binary_matrix = np.asarray(binary_model.predict_proba(X))
    binary_classes = list(binary_model.classes_)
    predicted = np.asarray(binary_classes, dtype=object)[np.argmax(binary_matrix, axis=1)]
    attack_rows = np.flatnonzero(predicted == 1)
    multiclass_matrix = None
    if len(attack_rows):
        multiclass_matrix = np.asarray(
            multiclass_model.predict_proba(X.iloc[attack_rows])
        )
    attack_positions = {int(row): position for position, row in enumerate(attack_rows)}
    outputs = []
    for index in range(len(X)):
        precomputed = {"binary_probability": binary_matrix[index]}
        if index in attack_positions:
            precomputed["multiclass_probability"] = multiclass_matrix[attack_positions[index]]
        outputs.append(predict_attack_family(
            X.iloc[[index]], model_type=model_type, _precomputed=precomputed
        ))
    return outputs
# ============================================================
# MODEL COMPARISON
# ============================================================

def compare_models(X):
    """
    Compare Random Forest and XGBoost predictions.
    """

    rf_result = predict_attack_family(
        X,
        model_type="random_forest"
    )

    xgb_result = predict_attack_family(
        X,
        model_type="xgboost"
    )

    rf_attack = rf_result["attack_family"]
    xgb_attack = xgb_result["attack_family"]

    agreement = (
        rf_attack == xgb_attack
    )

    if agreement:

        final_attack = rf_attack

        final_confidence = min(
            rf_result["confidence"],
            xgb_result["confidence"]
        )

        decision = "AGREEMENT"

    else:

        final_attack = None
        final_confidence = None
        decision = "MODEL_DISAGREEMENT"

    return {
        "random_forest": rf_result,
        "xgboost": xgb_result,
        "agreement": agreement,
        "decision": decision,
        "final_attack": final_attack,
        "final_confidence": final_confidence
    }
