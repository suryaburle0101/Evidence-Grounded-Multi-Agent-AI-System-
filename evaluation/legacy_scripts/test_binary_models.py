import pandas as pd

try:
    from ._paths import project_path
except ImportError:
    from _paths import project_path

from detection.model_predictor import rf_binary, xgb_binary


print("=" * 70)
print("BINARY MODEL CHECK")
print("=" * 70)


tests = [
    (
        "Infiltration-Thursday-no-metadata.parquet",
        "Infiltration"
    ),
    (
        "DoS-Wednesday-no-metadata.parquet",
        "Heartbleed"
    )
]


for filename, label in tests:

    print()
    print("-" * 70)
    print("Dataset:", filename)
    print("Label:", label)

    path = project_path("data/raw/CICIDS2017/" + filename)

    df = pd.read_parquet(path)

    rows = df[df["Label"] == label]

    print("Samples available:", len(rows))

    if len(rows) == 0:
        print("NO DATA")
        continue

    # Test first sample
    row = rows.iloc[[0]]

    X = row.drop(columns=["Label"])

    # --------------------------------------------------
    # Random Forest Binary
    # --------------------------------------------------

    rf_prediction = rf_binary.predict(X)[0]
    rf_probability = rf_binary.predict_proba(X)[0]
    rf_confidence = float(rf_probability.max())

    # --------------------------------------------------
    # XGBoost Binary
    # --------------------------------------------------

    xgb_prediction = xgb_binary.predict(X)[0]
    xgb_probability = xgb_binary.predict_proba(X)[0]
    xgb_confidence = float(xgb_probability.max())

    # --------------------------------------------------
    # Results
    # --------------------------------------------------

    print()
    print("Random Forest:")
    print("  Prediction :", rf_prediction)
    print("  Confidence :", round(rf_confidence, 6))

    print()
    print("XGBoost:")
    print("  Prediction :", xgb_prediction)
    print("  Confidence :", round(xgb_confidence, 6))


print()
print("=" * 70)
print("BINARY MODEL CHECK FINISHED")
print("=" * 70)
