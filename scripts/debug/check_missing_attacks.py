import pandas as pd
import joblib
from pathlib import Path


DATA_DIR = Path("data/raw/CICIDS2017")
MODEL_DIR = Path("models")


# ============================================================
# LOAD MODELS
# ============================================================

rf = joblib.load(
    MODEL_DIR / "random_forest_multiclass_cicids2017.pkl"
)

xgb = joblib.load(
    MODEL_DIR / "xgboost_multiclass_cicids2017.pkl"
)

encoder = joblib.load(
    MODEL_DIR / "multiclass_label_encoder.pkl"
)


print("=" * 80)
print("MISSING ATTACK FAMILY MODEL TEST")
print("=" * 80)

print()
print("MODEL CLASSES:")
print(encoder.classes_)

print()
print("MODEL FEATURES:", rf.n_features_in__)


# ============================================================
# TEST DEFINITIONS
# ============================================================

TESTS = [
    (
        "Infiltration",
        "Infiltration-Thursday-no-metadata.parquet",
        "Infiltration"
    ),
    (
        "Heartbleed",
        "DoS-Wednesday-no-metadata.parquet",
        "Heartbleed"
    ),
]


# ============================================================
# RUN TESTS
# ============================================================

for name, filename, label in TESTS:

    print()
    print("-" * 80)
    print("TEST:", name)

    path = DATA_DIR / filename

    if not path.exists():
        print("FILE NOT FOUND:", path)
        continue

    df = pd.read_parquet(path)

    rows = df[df["Label"] == label]

    print("Actual label:", label)
    print("Available samples:", len(rows))

    if len(rows) == 0:
        print("NO SAMPLES FOUND")
        continue

    # Use up to 10 samples
    sample = rows.head(10).copy()

    X = sample.drop(columns=["Label"])

    # Ensure exact feature order expected by model
    X = X[rf.feature_names_in_]

    # --------------------------------------------------------
    # RANDOM FOREST
    # --------------------------------------------------------

    print()
    print("RANDOM FOREST PREDICTIONS:")

    rf_pred = rf.predict(X)

    for i, prediction in enumerate(rf_pred):
        print(
            f"Sample {i + 1}: {prediction}"
        )

    # --------------------------------------------------------
    # XGBOOST
    # --------------------------------------------------------

    print()
    print("XGBOOST PREDICTIONS:")

    xgb_pred_encoded = xgb.predict(X)

    xgb_pred = encoder.inverse_transform(
        xgb_pred_encoded.astype(int)
    )

    for i, prediction in enumerate(xgb_pred):
        print(
            f"Sample {i + 1}: {prediction}"
        )

    # --------------------------------------------------------
    # RANDOM FOREST PROBABILITIES
    # --------------------------------------------------------

    print()
    print("RANDOM FOREST TOP PROBABILITIES:")

    rf_probs = rf.predict_proba(X)

    for i, probs in enumerate(rf_probs):

        top = probs.argmax()

        print(
            f"Sample {i + 1}: "
            f"{rf.classes_[top]} = {probs[top]:.4f}"
        )

    # --------------------------------------------------------
    # XGBOOST PROBABILITIES
    # --------------------------------------------------------

    print()
    print("XGBOOST TOP PROBABILITIES:")

    xgb_probs = xgb.predict_proba(X)

    for i, probs in enumerate(xgb_probs):

        top = probs.argmax()

        print(
            f"Sample {i + 1}: "
            f"{encoder.classes_[top]} = {probs[top]:.4f}"
        )


print()
print("=" * 80)
print("TEST FINISHED")
print("=" * 80)