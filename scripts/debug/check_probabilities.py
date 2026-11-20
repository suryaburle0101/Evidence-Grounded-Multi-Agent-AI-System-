import pandas as pd

from detection.model_predictor import predict_attack_family
from response.final_analyzer import detect_rare_attack


DATA_DIR = "data/raw/CICIDS2017"


tests = [
    ("Infiltration-Thursday-no-metadata.parquet", "Infiltration"),
    ("WebAttacks-Thursday-no-metadata.parquet", "Brute Force"),
    ("WebAttacks-Thursday-no-metadata.parquet", "XSS"),
    ("Heartbleed-Thursday-no-metadata.parquet", "Heartbleed"),
]


for filename, attack in tests:

    print()
    print("=" * 80)
    print("TEST:", attack)
    print("=" * 80)

    df = pd.read_parquet(
        f"{DATA_DIR}/{filename}"
    )

    if attack == "Brute Force":
        rows = df[
            df["Label"].astype(str).str.contains(
                "Brute Force",
                na=False
            )
        ]

    elif attack == "XSS":
        rows = df[
            df["Label"].astype(str).str.contains(
                "XSS",
                na=False
            )
        ]

    else:
        rows = df[
            df["Label"] == attack
        ]

    if len(rows) == 0:
        print("NO DATA")
        continue

    X = rows.iloc[[0]].drop(
        columns=["Label"]
    )

    print("Actual label:", rows.iloc[0]["Label"])

    print()
    print("--- RANDOM FOREST ---")

    rf = predict_attack_family(
        X,
        model_type="random_forest"
    )

    print("Attack family:", rf["attack_family"])
    print("Confidence:", rf["confidence"])
    print("Binary attack probability:",
          rf["binary_attack_probability"])
    print("Binary benign probability:",
          rf["binary_benign_probability"])

    print()
    print("--- XGBOOST ---")

    xgb = predict_attack_family(
        X,
        model_type="xgboost"
    )

    print("Attack family:", xgb["attack_family"])
    print("Confidence:", xgb["confidence"])
    print("Binary attack probability:",
          xgb["binary_attack_probability"])
    print("Binary benign probability:",
          xgb["binary_benign_probability"])

    print()
    print("--- BINARY DETECTOR ---")

    binary = detect_rare_attack(X)

    print("RF prediction:",
          binary["random_forest_prediction"])

    print("XGB prediction:",
          binary["xgboost_prediction"])

    print("RF attack probability:",
          binary["random_forest_attack_probability"])

    print("XGB attack probability:",
          binary["xgboost_attack_probability"])

    print("Decision:",
          binary["decision"])