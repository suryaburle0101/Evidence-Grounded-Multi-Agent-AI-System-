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
print("UNSW-NB15 COMPLETE AUDIT")
print("=" * 70)

print("FEATURES:", len(names))
print("FILES:", len(files))

overall_labels = {}
overall_categories = {}

for file in files:

    print("\n" + "=" * 70)
    print(os.path.basename(file))
    print("=" * 70)

    total_rows = 0
    labels = {}
    categories = {}

    for chunk in pd.read_csv(
        file,
        header=None,
        names=names,
        chunksize=100000,
        encoding="utf-8"
    ):

        total_rows += len(chunk)

        for value, count in chunk["Label"].value_counts(
            dropna=False
        ).items():

            labels[value] = labels.get(value, 0) + int(count)

        for value, count in chunk["attack_cat"].value_counts(
            dropna=False
        ).items():

            categories[value] = categories.get(value, 0) + int(count)

    print("ROWS:", total_rows)

    print("\nLABEL:")
    for value, count in labels.items():
        print(value, "->", count)

    print("\nATTACK CATEGORY:")
    for value, count in categories.items():
        print(value, "->", count)

    for value, count in labels.items():
        overall_labels[value] = (
            overall_labels.get(value, 0) + count
        )

    for value, count in categories.items():
        overall_categories[value] = (
            overall_categories.get(value, 0) + count
        )


print("\n" + "=" * 70)
print("OVERALL")
print("=" * 70)

print("\nTOTAL ROWS:")
print(sum(overall_labels.values()))

print("\nLABEL:")
for value, count in overall_labels.items():
    print(value, "->", count)

print("\nATTACK CATEGORY:")
for value, count in overall_categories.items():
    print(value, "->", count)