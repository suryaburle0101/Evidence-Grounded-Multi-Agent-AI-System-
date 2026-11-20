import pandas as pd

try:
    from ._paths import project_path
except ImportError:
    from _paths import project_path

from detection.model_predictor import rf_binary, xgb_binary


print("=" * 75)
print("HEARTBLEED BINARY MODEL EVALUATION")
print("=" * 75)

path = project_path("data/raw/CICIDS2017/DoS-Wednesday-no-metadata.parquet")

df = pd.read_parquet(path)

rows = df[df["Label"] == "Heartbleed"]

print("Total Heartbleed samples:", len(rows))
print()

rf_attack = 0
rf_benign = 0

xgb_attack = 0
xgb_benign = 0


for i in range(len(rows)):

    row = rows.iloc[[i]]

    X = row.drop(columns=["Label"])

    rf_prediction = rf_binary.predict(X)[0]
    xgb_prediction = xgb_binary.predict(X)[0]

    if rf_prediction == 1:
        rf_attack += 1
    else:
        rf_benign += 1

    if xgb_prediction == 1:
        xgb_attack += 1
    else:
        xgb_benign += 1


print("-" * 75)

print("RANDOM FOREST")
print("Attack :", rf_attack)
print("Benign :", rf_benign)
print(
    "Accuracy:",
    round((rf_attack / len(rows)) * 100, 2),
    "%"
)

print()

print("XGBOOST")
print("Attack :", xgb_attack)
print("Benign :", xgb_benign)
print(
    "Accuracy:",
    round((xgb_attack / len(rows)) * 100, 2),
    "%"
)

print()

print("=" * 75)
print("HEARTBLEED TEST FINISHED")
print("=" * 75)
