import pandas as pd
import glob
import os

folder = "data/raw/CSE_CIC_IDS2018"
files = glob.glob(folder + "/*.parquet")

print("LABEL DISTRIBUTION BY FILE")
print("=" * 80)

for f in files:
    print("\n" + os.path.basename(f))

    labels = pd.read_parquet(
        f,
        columns=["Label"]
    )["Label"]

    print(labels.value_counts(dropna=False).to_string())