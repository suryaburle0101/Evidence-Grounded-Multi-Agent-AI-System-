import pandas as pd

try:
    from ._paths import project_path
except ImportError:
    from _paths import project_path

from detection.model_predictor import predict_attack_family


# ============================================================
# CONFIGURATION
# ============================================================

DATASET = project_path("data/raw/CICIDS2017/WebAttacks-Thursday-no-metadata.parquet")


# ============================================================
# LOAD DATASET
# ============================================================

df = pd.read_parquet(DATASET)


print("=" * 70)
print("WEB ATTACK MODEL TEST")
print("=" * 70)


# ============================================================
# DISPLAY ACTUAL LABELS
# ============================================================

print("\nActual dataset labels:")

for label in df["Label"].unique():
    print(repr(label))


# ============================================================
# FIND WEB ATTACK LABELS AUTOMATICALLY
# ============================================================

web_attack_labels = [
    label
    for label in df["Label"].unique()
    if isinstance(label, str)
    and label.startswith("Web Attack")
]


print("\nWeb attack labels found:", len(web_attack_labels))


# ============================================================
# TEST WEB ATTACKS
# ============================================================

for dataset_label in web_attack_labels:

    expected_attack = "Web Attack"

    print("\n" + "-" * 70)
    print(f"Dataset label: {repr(dataset_label)}")

    rows = df[df["Label"] == dataset_label]

    print(f"Samples available: {len(rows)}")

    if len(rows) == 0:
        print("NO DATA")
        continue

    # Test maximum 20 samples
    samples = rows.sample(
        n=min(20, len(rows)),
        random_state=42
    )

    rf_correct = 0
    xgb_correct = 0

    print(f"Testing samples: {len(samples)}")
    print(f"Expected attack family: {expected_attack}")

    # --------------------------------------------------------
    # RANDOM FOREST
    # --------------------------------------------------------

    for i in range(len(samples)):

        row = samples.iloc[[i]]

        X = row.drop(columns=["Label"])

        result = predict_attack_family(
            X,
            model_type="random_forest"
        )

        if result["attack_family"] == expected_attack:
            rf_correct += 1

    # --------------------------------------------------------
    # XGBOOST
    # --------------------------------------------------------

    for i in range(len(samples)):

        row = samples.iloc[[i]]

        X = row.drop(columns=["Label"])

        result = predict_attack_family(
            X,
            model_type="xgboost"
        )

        if result["attack_family"] == expected_attack:
            xgb_correct += 1

    # --------------------------------------------------------
    # RESULTS
    # --------------------------------------------------------

    rf_accuracy = (
        rf_correct / len(samples)
    ) * 100

    xgb_accuracy = (
        xgb_correct / len(samples)
    ) * 100

    print("\nRESULTS")

    print(
        f"Random Forest: {rf_correct} / "
        f"{len(samples)}"
    )

    print(
        f"XGBoost:       {xgb_correct} / "
        f"{len(samples)}"
    )

    print(
        f"RF Accuracy:   {rf_accuracy:.2f}%"
    )

    print(
        f"XGB Accuracy:  {xgb_accuracy:.2f}%"
    )


# ============================================================
# FINISHED
# ============================================================

print("\n" + "=" * 70)
print("WEB ATTACK TEST FINISHED")
print("=" * 70)
