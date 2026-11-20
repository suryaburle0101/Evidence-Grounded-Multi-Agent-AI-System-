import pandas as pd

try:
    from ._paths import project_path
except ImportError:
    from _paths import project_path

from detection.model_predictor import predict_attack_family


tests = [
    ("Botnet-Friday-no-metadata.parquet", "Bot", "Botnet"),
    ("Bruteforce-Tuesday-no-metadata.parquet", "FTP-Patator", "Brute Force"),
    ("Bruteforce-Tuesday-no-metadata.parquet", "SSH-Patator", "Brute Force"),
    ("DDoS-Friday-no-metadata.parquet", "DDoS", "DDoS"),
    ("DoS-Wednesday-no-metadata.parquet", "DoS Hulk", "DoS"),
    ("DoS-Wednesday-no-metadata.parquet", "DoS GoldenEye", "DoS"),
    ("DoS-Wednesday-no-metadata.parquet", "DoS slowloris", "DoS"),
    ("DoS-Wednesday-no-metadata.parquet", "DoS Slowhttptest", "DoS"),
    ("DoS-Wednesday-no-metadata.parquet", "Heartbleed", "DoS"),
    ("Infiltration-Thursday-no-metadata.parquet", "Infiltration", "Infiltration"),
    ("Portscan-Friday-no-metadata.parquet", "PortScan", "Port Scan"),
    ("WebAttacks-Thursday-no-metadata.parquet", "Web Attack   Brute Force", "Web Attack"),
("WebAttacks-Thursday-no-metadata.parquet", "Web Attack   XSS", "Web Attack"),
("WebAttacks-Thursday-no-metadata.parquet", "Web Attack   Sql Injection", "Web Attack"),
]


print()
print("=" * 80)
print("CYBERSECURITY MODEL EVALUATION")
print("=" * 80)


for filename, dataset_label, expected in tests:

    print()
    print("Testing:", dataset_label)
    print("Expected:", expected)

    path = project_path("data/raw/CICIDS2017/" + filename)

    df = pd.read_parquet(path)

    if dataset_label == "Web Attack   Brute Force":
        rows = df[df["Label"].str.contains("Brute Force", na=False)]

    elif dataset_label == "Web Attack   XSS":
        rows = df[df["Label"].str.contains("XSS", na=False)]

    elif dataset_label == "Web Attack   Sql Injection":
        rows = df[df["Label"].str.contains("Sql Injection", na=False)]

    else:
        rows = df[df["Label"] == dataset_label]

    if len(rows) == 0:
        print("RESULT: NO DATA")
        continue

    rows = rows.sample(
        n=min(20, len(rows)),
        random_state=42
    )

    rf_correct = 0
    xgb_correct = 0

    for _, row in rows.iterrows():

        X = row.drop("Label").to_frame().T

        rf = predict_attack_family(
            X,
            model_type="random_forest"
        )

        xgb = predict_attack_family(
            X,
            model_type="xgboost"
        )

        if rf["attack_family"] == expected:
            rf_correct += 1

        if xgb["attack_family"] == expected:
            xgb_correct += 1

    print(
        "Random Forest:",
        rf_correct,
        "/",
        len(rows)
    )

    print(
        "XGBoost:",
        xgb_correct,
        "/",
        len(rows)
    )


print()
print("=" * 80)
print("EVALUATION FINISHED")
print("=" * 80)
