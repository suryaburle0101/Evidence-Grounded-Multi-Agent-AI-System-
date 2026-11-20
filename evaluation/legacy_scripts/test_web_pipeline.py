import pandas as pd

try:
    from ._paths import project_path
except ImportError:
    from _paths import project_path

from detection.model_predictor import compare_models
from response.final_analyzer import final_threat_analysis


DATASET = project_path("data/raw/CICIDS2017/WebAttacks-Thursday-no-metadata.parquet")


df = pd.read_parquet(DATASET)


# Find all Web Attack samples automatically
rows = df[
    df["Label"].astype(str).str.startswith("Web Attack")
]


print("=" * 80)
print("WEB ATTACK FULL PIPELINE INVESTIGATION")
print("=" * 80)

print("\nTotal Web Attack samples:", len(rows))


# Test 20 samples
samples = rows.sample(
    n=min(20, len(rows)),
    random_state=42
)


print("Testing:", len(samples), "samples")


rf_counts = {}
xgb_counts = {}
pipeline_counts = {}


for i in range(len(samples)):

    row = samples.iloc[[i]]

    X = row.drop(columns=["Label"])

    actual = row.iloc[0]["Label"]

    # --------------------------------------------------------
    # MODEL COMPARISON
    # --------------------------------------------------------

    comparison = compare_models(X)

    rf_attack = comparison["random_forest"]["attack_family"]
    xgb_attack = comparison["xgboost"]["attack_family"]

    # --------------------------------------------------------
    # FULL PIPELINE
    # --------------------------------------------------------

    final = final_threat_analysis(X)

    status = final["status"]
    final_attack = final.get("final_attack")

    # --------------------------------------------------------
    # COUNTS
    # --------------------------------------------------------

    rf_counts[rf_attack] = rf_counts.get(rf_attack, 0) + 1
    xgb_counts[xgb_attack] = xgb_counts.get(xgb_attack, 0) + 1

    key = f"{status} -> {final_attack}"

    pipeline_counts[key] = pipeline_counts.get(key, 0) + 1

    # --------------------------------------------------------
    # SHOW RESULT
    # --------------------------------------------------------

    print("\nSample", i + 1)
    print("Dataset label :", repr(actual))
    print("Random Forest :", rf_attack)
    print("XGBoost       :", xgb_attack)
    print("Agreement     :", comparison["agreement"])
    print("Pipeline      :", status)
    print("Final attack  :", final_attack)


# ============================================================
# SUMMARY
# ============================================================

print("\n")
print("=" * 80)
print("MODEL SUMMARY")
print("=" * 80)

print("\nRandom Forest:")
for attack, count in rf_counts.items():
    print(f"  {attack}: {count}")

print("\nXGBoost:")
for attack, count in xgb_counts.items():
    print(f"  {attack}: {count}")


print("\n")
print("=" * 80)
print("FULL PIPELINE SUMMARY")
print("=" * 80)

for result, count in pipeline_counts.items():
    print(f"  {result}: {count}")


print("\n")
print("=" * 80)
print("INVESTIGATION FINISHED")
print("=" * 80)
