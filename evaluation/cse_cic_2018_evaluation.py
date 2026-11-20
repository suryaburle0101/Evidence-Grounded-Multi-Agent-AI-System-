from pathlib import Path
import sys

import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from detection.model_predictor import (
    rf_binary,
    xgb_binary,
    rf_multiclass,
    xgb_multiclass,
    prepare_input,
    decode_label,
    FEATURE_NAMES,
)


# ============================================================
# PATHS
# ============================================================

DATA_DIR = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "CSE_CIC_IDS2018"
)


# ============================================================
# SETTINGS
# ============================================================

SAMPLES_PER_FAMILY_PER_FILE = 50

RANDOM_STATE = 42


# ============================================================
# CSE LABEL -> PROJECT ATTACK FAMILY
# ============================================================

LABEL_MAPPING = {

    "Benign": "Benign",

    "Bot": "Botnet",

    "SSH-Bruteforce": "Brute Force",
    "FTP-BruteForce": "Brute Force",

    "DDoS attacks-LOIC-HTTP": "DDoS",
    "DDOS attack-HOIC": "DDoS",
    "DDOS attack-LOIC-UDP": "DDoS",

    "DoS attacks-GoldenEye": "DoS",
    "DoS attacks-Slowloris": "DoS",
    "DoS attacks-Hulk": "DoS",
    "DoS attacks-SlowHTTPTest": "DoS",

    "Infilteration": "Infiltration",

    "Brute Force -Web": "Web Attack",
    "Brute Force -XSS": "Web Attack",
    "SQL Injection": "Web Attack",
}


# ============================================================
# LOAD ONE FILE
# ============================================================

def load_file(file_path):
    print()
    print("=" * 70)
    print("LOADING")
    print(file_path.name)
    print("=" * 70)

    df = pd.read_parquet(file_path)

    print("Rows:", f"{len(df):,}")
    print("Columns:", len(df.columns))

    if "Label" not in df.columns:
        raise RuntimeError(
            f"Missing Label column in {file_path.name}"
        )

    # Verify exact feature compatibility.
    actual_features = [
        column
        for column in df.columns
        if column != "Label"
    ]

    if actual_features != FEATURE_NAMES:
        raise RuntimeError(
            f"Feature order mismatch in {file_path.name}"
        )

    df["AttackFamily"] = df["Label"].map(
        LABEL_MAPPING
    )

    unknown = df[
        df["AttackFamily"].isna()
    ]["Label"].dropna().unique()

    if len(unknown) > 0:
        print(
            "WARNING - unmapped labels:",
            list(unknown)
        )

    df = df.dropna(
        subset=["AttackFamily"]
    )

    return df


# ============================================================
# CREATE BALANCED EXTERNAL SAMPLE
# ============================================================

def create_sample(data):

    samples = []

    families = sorted(
        data["AttackFamily"].unique()
    )

    print()
    print("=" * 70)
    print("CREATING CSE-CIC-IDS2018 EXTERNAL SAMPLE")
    print("=" * 70)

    for family in families:

        subset = data[
            data["AttackFamily"] == family
        ]

        n = min(
            SAMPLES_PER_FAMILY_PER_FILE,
            len(subset)
        )

        sampled = subset.sample(
            n=n,
            random_state=RANDOM_STATE
        )

        samples.append(sampled)

        print(
            f"{family:20s} -> "
            f"{n} samples"
        )

    return pd.concat(
        samples,
        ignore_index=True
    )


# ============================================================
# EVALUATE
# ============================================================

def evaluate(data):

    X = data.drop(
        columns=[
            "Label",
            "AttackFamily",
        ]
    )

    y_family = data[
        "AttackFamily"
    ].reset_index(drop=True)

    X = prepare_input(X)

    print()
    print("=" * 70)
    print("RUNNING EXISTING CICIDS2017 MODELS")
    print("=" * 70)

    # --------------------------------------------------------
    # Binary
    # --------------------------------------------------------

    rf_binary_pred = rf_binary.predict(X)
    xgb_binary_pred = xgb_binary.predict(X)

    y_binary = (
        y_family != "Benign"
    ).astype(int)

    # --------------------------------------------------------
    # Multiclass
    # --------------------------------------------------------

    rf_multi_encoded = (
        rf_multiclass.predict(X)
    )

    xgb_multi_encoded = (
        xgb_multiclass.predict(X)
    )

    rf_multi_pred = [
        decode_label(value)
        for value in rf_multi_encoded
    ]

    xgb_multi_pred = [
        decode_label(value)
        for value in xgb_multi_encoded
    ]

    # --------------------------------------------------------
    # Binary metrics
    # --------------------------------------------------------

    rf_accuracy = accuracy_score(
        y_binary,
        rf_binary_pred
    )

    xgb_accuracy = accuracy_score(
        y_binary,
        xgb_binary_pred
    )

    rf_precision = precision_score(
        y_binary,
        rf_binary_pred,
        zero_division=0
    )

    xgb_precision = precision_score(
        y_binary,
        xgb_binary_pred,
        zero_division=0
    )

    rf_recall = recall_score(
        y_binary,
        rf_binary_pred,
        zero_division=0
    )

    xgb_recall = recall_score(
        y_binary,
        xgb_binary_pred,
        zero_division=0
    )

    rf_f1 = f1_score(
        y_binary,
        rf_binary_pred,
        zero_division=0
    )

    xgb_f1 = f1_score(
        y_binary,
        xgb_binary_pred,
        zero_division=0
    )

    # --------------------------------------------------------
    # Multiclass
    # --------------------------------------------------------

    rf_multi_accuracy = accuracy_score(
        y_family,
        rf_multi_pred
    )

    xgb_multi_accuracy = accuracy_score(
        y_family,
        xgb_multi_pred
    )

    # --------------------------------------------------------
    # Agreement
    # --------------------------------------------------------

    binary_agreement = (
        rf_binary_pred
        ==
        xgb_binary_pred
    )

    multiclass_agreement = [
        rf_multi_pred[i]
        ==
        xgb_multi_pred[i]
        for i in range(len(y_family))
    ]

    # --------------------------------------------------------
    # Results
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("CSE-CIC-IDS2018 EXTERNAL EVALUATION")
    print("=" * 70)

    print()
    print("Dataset:")
    print("  CSE-CIC-IDS2018")

    print()
    print("Training source:")
    print("  CICIDS2017")

    print()
    print("Training performed on CSE:")
    print("  NO")

    print()
    print("Features:")
    print(f"  {len(FEATURE_NAMES)}")

    print()
    print("Evaluation samples:")
    print(f"  {len(data):,}")

    # --------------------------------------------------------
    # Binary
    # --------------------------------------------------------

    print()
    print("BINARY ATTACK DETECTION")
    print("-" * 70)

    print(
        f"Random Forest"
        f"  Accuracy={rf_accuracy:.4f}"
        f"  Precision={rf_precision:.4f}"
        f"  Recall={rf_recall:.4f}"
        f"  F1={rf_f1:.4f}"
    )

    print(
        f"XGBoost"
        f"         Accuracy={xgb_accuracy:.4f}"
        f"  Precision={xgb_precision:.4f}"
        f"  Recall={xgb_recall:.4f}"
        f"  F1={xgb_f1:.4f}"
    )

    print(
        "Binary model agreement:",
        f"{binary_agreement.mean():.4f}"
    )

    # --------------------------------------------------------
    # Multiclass
    # --------------------------------------------------------

    print()
    print("ATTACK-FAMILY DETECTION")
    print("-" * 70)

    print(
        "Random Forest accuracy:",
        f"{rf_multi_accuracy:.4f}"
    )

    print(
        "XGBoost accuracy:",
        f"{xgb_multi_accuracy:.4f}"
    )

    print(
        "Multiclass model agreement:",
        f"{sum(multiclass_agreement) / len(multiclass_agreement):.4f}"
    )

    # --------------------------------------------------------
    # Per-family
    # --------------------------------------------------------

    print()
    print("PER-FAMILY RESULTS")
    print("-" * 70)

    for family in sorted(
        y_family.unique()
    ):

        mask = (
            y_family == family
        )

        total = int(mask.sum())

        rf_correct = sum(
            rf_multi_pred[i] == family
            for i in range(len(y_family))
            if mask.iloc[i]
        )

        xgb_correct = sum(
            xgb_multi_pred[i] == family
            for i in range(len(y_family))
            if mask.iloc[i]
        )

        rf_binary_correct = sum(
            (
                rf_binary_pred[i] == 0
                if family == "Benign"
                else rf_binary_pred[i] == 1
            )
            for i in range(len(y_family))
            if mask.iloc[i]
        )

        xgb_binary_correct = sum(
            (
                xgb_binary_pred[i] == 0
                if family == "Benign"
                else xgb_binary_pred[i] == 1
            )
            for i in range(len(y_family))
            if mask.iloc[i]
        )

        print(
            f"{family:20s}"
            f" Samples={total:4d}"
            f" RF-family={rf_correct / total:.3f}"
            f" XGB-family={xgb_correct / total:.3f}"
            f" RF-binary={rf_binary_correct / total:.3f}"
            f" XGB-binary={xgb_binary_correct / total:.3f}"
        )

    # --------------------------------------------------------
    # Confusion matrices
    # --------------------------------------------------------

    families = sorted(
        y_family.unique()
    )

    print()
    print("RANDOM FOREST CONFUSION MATRIX")
    print("-" * 70)

    print(
        "Labels:",
        families
    )

    print(
        confusion_matrix(
            y_family,
            rf_multi_pred,
            labels=families
        )
    )

    print()
    print("XGBOOST CONFUSION MATRIX")
    print("-" * 70)

    print(
        "Labels:",
        families
    )

    print(
        confusion_matrix(
            y_family,
            xgb_multi_pred,
            labels=families
        )
    )

    print()
    print("=" * 70)
    print("EXTERNAL EVALUATION COMPLETE")
    print("=" * 70)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print("=" * 70)
    print("CSE-CIC-IDS2018 EXTERNAL EVALUATION")
    print("=" * 70)

    print()
    print("Expected model features:", len(FEATURE_NAMES))

    files = sorted(
        DATA_DIR.glob("*.parquet")
    )

    if not files:
        raise RuntimeError(
            "No CSE-CIC-IDS2018 parquet files found."
        )

    print(
        "CSE files found:",
        len(files)
    )

    all_frames = []

    for file in files:

        df = load_file(file)

        # Sample within each file so that
        # one very large file does not dominate.
        sampled_parts = []

        for family in sorted(
            df["AttackFamily"].unique()
        ):

            subset = df[
                df["AttackFamily"] == family
            ]

            n = min(
                SAMPLES_PER_FAMILY_PER_FILE,
                len(subset)
            )

            sampled_parts.append(
                subset.sample(
                    n=n,
                    random_state=RANDOM_STATE
                )
            )

        if sampled_parts:
            all_frames.append(
                pd.concat(
                    sampled_parts,
                    ignore_index=True
                )
            )

    if not all_frames:
        raise RuntimeError(
            "No evaluation samples created."
        )

    evaluation_data = pd.concat(
        all_frames,
        ignore_index=True
    )

    print()
    print(
        "Total external evaluation rows:",
        len(evaluation_data)
    )

    evaluate(
        evaluation_data
    )