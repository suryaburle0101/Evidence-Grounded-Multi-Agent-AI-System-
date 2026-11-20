import pandas as pd
import glob
import os

FEATURE_FILE = "data/raw/UNSW_NB15/NUSW-NB15_features.csv"

files = sorted(
    glob.glob("data/raw/UNSW_NB15/UNSW-NB15_*.csv")
)

names = pd.read_csv(
    FEATURE_FILE,
    encoding="cp1252"
)["Name"].tolist()

print("=" * 70)
print("UNSW-NB15 DATASET AUDIT")
print("=" * 70)

print("FEATURE COUNT:", len(names))
print("DATA FILES:", len(files))

overall_label_counts = {}
overall_category_counts = {}

for f in files:

    print("\n" + "=" * 70)
    print(os.path.basename(f))
    print("=" * 70)

    rows = 0
    label_counts = {}
    category_counts = {}

    for chunk in pd.read_csv(
        f,
        header=None,
        names=names,
        usecols=["attack_cat", "Label"],
        chunksize=200000
    ):

        rows += len(chunk)

        for value, count in chunk["Label"].value_counts(
            dropna=False
        ).items():

            label_counts[value] = (
                label_counts.get(value, 0) + int(count)
            )

        for value, count in chunk["attack_cat"].value_counts(
            dropna=False
        ).items():

            category_counts[value] = (
                category_counts.get(value, 0) + int(count)
            )

    print("ROWS:", rows)

    print("\nLABEL DISTRIBUTION:")
    print(
        pd.Series(label_counts)
        .sort_index()
        .to_string()
    )

    print("\nATTACK CATEGORY DISTRIBUTION:")
    print(
        pd.Series(category_counts)
        .to_string()
    )

    for value, count in label_counts.items():
        overall_label_counts[value] = (
            overall_label_counts.get(value, 0) + count
        )

    for value, count in category_counts.items():
        overall_category_counts[value] = (
            overall_category_counts.get(value, 0) + count
        )


print("\n" + "=" * 70)
print("OVERALL UNSW-NB15")
print("=" * 70)

print("\nTOTAL ROWS:")
print(sum(overall_label_counts.values()))

print("\nOVERALL LABEL DISTRIBUTION:")
print(
    pd.Series(overall_label_counts)
    .sort_index()
    .to_string()
)

print("\nOVERALL ATTACK CATEGORY DISTRIBUTION:")
print(
    pd.Series(overall_category_counts)
    .to_string()
)