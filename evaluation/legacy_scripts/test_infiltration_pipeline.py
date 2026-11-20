import pandas as pd

try:
    from ._paths import project_path
except ImportError:
    from _paths import project_path

from response.final_analyzer import final_threat_analysis


FILE = project_path(
    "data/raw/CICIDS2017/Infiltration-Thursday-no-metadata.parquet"
)


df = pd.read_parquet(FILE)

rows = df[
    df["Label"] == "Infiltration"
].sample(
    n=10,
    random_state=42
)


print("=" * 80)
print("INFILTRATION FINAL PIPELINE TEST")
print("=" * 80)

confirmed = 0
review = 0
benign = 0


for index, (_, row) in enumerate(
    rows.iterrows(),
    start=1
):

    X = row.drop(
        labels=["Label"]
    ).to_frame().T

    result = final_threat_analysis(X)

    print()
    print("-" * 80)
    print(f"Sample {index}")
    print("Dataset label :", row["Label"])

    print(
        "Pipeline      :",
        result["status"]
    )

    print(
        "Final attack  :",
        result["final_attack"]
    )

    print(
        "Reason        :",
        result.get("reason")
    )

    binary = result.get(
        "binary_detection",
        {}
    )

    print(
        "Binary RF     :",
        binary.get(
            "random_forest_prediction"
        )
    )

    print(
        "Binary XGB    :",
        binary.get(
            "xgboost_prediction"
        )
    )

    if result["status"] == "THREAT_CONFIRMED":
        confirmed += 1

    elif result["status"] == "REVIEW_REQUIRED":
        review += 1

    elif result["status"] == "NO_ATTACK_DETECTED":
        benign += 1


print()
print("=" * 80)
print("INFILTRATION PIPELINE SUMMARY")
print("=" * 80)

print(
    "THREAT_CONFIRMED :",
    confirmed
)

print(
    "REVIEW_REQUIRED  :",
    review
)

print(
    "NO_ATTACK        :",
    benign
)

print("=" * 80)
