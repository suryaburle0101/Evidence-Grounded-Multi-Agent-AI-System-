import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from pathlib import Path
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data" / "raw" / "CICIDS2017"


# ============================================================
# IMPORT MODELS
# ============================================================

from detection.model_predictor import (
    rf_binary,
    xgb_binary,
    rf_multiclass,
    xgb_multiclass,
    prepare_input,
    decode_label
)


# ============================================================
# RAW LABEL -> ATTACK FAMILY
# ============================================================

LABEL_MAPPING = {

    "Benign": "Benign",

    "Bot": "Botnet",

    "PortScan": "Port Scan",

    "FTP-Patator": "Brute Force",
    "SSH-Patator": "Brute Force",

    "DDoS": "DDoS",

    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS",

    "Web Attack   Brute Force": "Web Attack",
    "Web Attack   XSS": "Web Attack",
    "Web Attack   Sql Injection": "Web Attack",

    "Infiltration": "Infiltration",
    "Heartbleed": "Heartbleed",
}


# ============================================================
# SAMPLE SIZE
# ============================================================

SAMPLES_PER_CLASS = 100


# ============================================================
# LOAD DATA
# ============================================================

def load_evaluation_data():

    frames = []

    for file in DATA_DIR.glob("*.parquet"):

        print(f"Loading: {file.name}")

        df = pd.read_parquet(file)

        if "Label" not in df.columns:
            continue

        df["AttackFamily"] = df["Label"].map(LABEL_MAPPING)

        df = df.dropna(
            subset=["AttackFamily"]
        )

        frames.append(df)

    if not frames:
        raise RuntimeError(
            "No valid CICIDS2017 parquet files found."
        )

    data = pd.concat(
        frames,
        ignore_index=True
    )

    return data


# ============================================================
# SAMPLE DATA
# ============================================================

def create_evaluation_sample(data):

    samples = []

    for label in sorted(
        data["AttackFamily"].unique()
    ):

        subset = data[
            data["AttackFamily"] == label
        ]

        n = min(
            SAMPLES_PER_CLASS,
            len(subset)
        )

        sampled = subset.sample(
            n=n,
            random_state=42
        )

        samples.append(sampled)

        print(
            f"{label:15s} -> "
            f"{n} samples"
        )

    return pd.concat(
        samples,
        ignore_index=True
    )


# ============================================================
# EVALUATE MODELS
# ============================================================

def evaluate(data):

    X = data.drop(
        columns=[
            "Label",
            "AttackFamily"
        ]
    )

    y_true = data["AttackFamily"]

    X = prepare_input(X)

    # --------------------------------------------------------
    # Binary predictions
    # --------------------------------------------------------

    rf_binary_pred = rf_binary.predict(X)

    xgb_binary_pred = xgb_binary.predict(X)

    # --------------------------------------------------------
    # Expected binary labels
    # --------------------------------------------------------

    y_binary = (
        y_true != "Benign"
    ).astype(int)

    # --------------------------------------------------------
    # Multiclass predictions
    # --------------------------------------------------------

    rf_multi_encoded = (
        rf_multiclass.predict(X)
    )

    xgb_multi_encoded = (
        xgb_multiclass.predict(X)
    )

    # --------------------------------------------------------
    # Decode predictions
    # --------------------------------------------------------

    rf_multi_pred = [
        decode_label(x)
        for x in rf_multi_encoded
    ]

    xgb_multi_pred = [
        decode_label(x)
        for x in xgb_multi_encoded
    ]

    # --------------------------------------------------------
    # Binary metrics
    # --------------------------------------------------------

    rf_binary_accuracy = accuracy_score(
        y_binary,
        rf_binary_pred
    )

    xgb_binary_accuracy = accuracy_score(
        y_binary,
        xgb_binary_pred
    )

    # --------------------------------------------------------
    # Multiclass metrics
    #
    # Only evaluate labels represented by the model.
    # Rare raw labels such as Infiltration and Heartbleed
    # are intentionally reported separately.
    # --------------------------------------------------------

    supported_mask = y_true.isin(
        [
            "Benign",
            "Botnet",
            "Brute Force",
            "DDoS",
            "DoS",
            "Port Scan",
            "Web Attack"
        ]
    )

    y_multi_supported = y_true[
        supported_mask
    ]

    rf_multi_supported = [
        rf_multi_pred[i]
        for i in range(len(y_true))
        if supported_mask.iloc[i]
    ]

    xgb_multi_supported = [
        xgb_multi_pred[i]
        for i in range(len(y_true))
        if supported_mask.iloc[i]
    ]

    rf_multi_accuracy = accuracy_score(
        y_multi_supported,
        rf_multi_supported
    )

    xgb_multi_accuracy = accuracy_score(
        y_multi_supported,
        xgb_multi_supported
    )

    # --------------------------------------------------------
    # Model agreement
    # --------------------------------------------------------

    binary_agreement = (
        rf_binary_pred ==
        xgb_binary_pred
    )

    multiclass_agreement = [
        rf_multi_pred[i] ==
        xgb_multi_pred[i]
        for i in range(len(y_true))
    ]

    # --------------------------------------------------------
    # Print summary
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("MODEL EVALUATION RESULTS")
    print("=" * 70)

    print()
    print("BINARY DETECTION")
    print("-" * 70)

    print(
        f"Random Forest accuracy : "
        f"{rf_binary_accuracy:.4f}"
    )

    print(
        f"XGBoost accuracy       : "
        f"{xgb_binary_accuracy:.4f}"
    )

    print(
        f"Binary model agreement : "
        f"{binary_agreement.mean():.4f}"
    )

    print()
    print("MULTICLASS ATTACK-FAMILY DETECTION")
    print("-" * 70)

    print(
        f"Random Forest accuracy : "
        f"{rf_multi_accuracy:.4f}"
    )

    print(
        f"XGBoost accuracy       : "
        f"{xgb_multi_accuracy:.4f}"
    )

    print(
        f"Multiclass agreement   : "
        f"{sum(multiclass_agreement) / len(multiclass_agreement):.4f}"
    )

    # --------------------------------------------------------
    # Per-class results
    # --------------------------------------------------------

    print()
    print("PER-CLASS RESULTS")
    print("-" * 70)

    for attack in sorted(
        y_true.unique()
    ):

        mask = (
            y_true == attack
        )

        total = int(mask.sum())

        rf_correct = sum(
            rf_multi_pred[i] == attack
            for i in range(len(y_true))
            if mask.iloc[i]
        )

        xgb_correct = sum(
            xgb_multi_pred[i] == attack
            for i in range(len(y_true))
            if mask.iloc[i]
        )

        print(
            f"{attack:20s} "
            f"Samples={total:3d} "
            f"RF={rf_correct / total:.3f} "
            f"XGB={xgb_correct / total:.3f}"
        )

    # --------------------------------------------------------
    # Rare attack analysis
    # --------------------------------------------------------

    print()
    print("RARE ATTACK ANALYSIS")
    print("-" * 70)

    rare_attacks = [
        "Infiltration",
        "Heartbleed"
    ]

    for attack in rare_attacks:

        mask = (
            y_true == attack
        )

        total = int(mask.sum())

        if total == 0:
            continue

        rf_attack_detected = sum(
            rf_binary_pred[i] == 1
            for i in range(len(y_true))
            if mask.iloc[i]
        )

        xgb_attack_detected = sum(
            xgb_binary_pred[i] == 1
            for i in range(len(y_true))
            if mask.iloc[i]
        )

        print(
            f"{attack:15s} "
            f"Samples={total:3d} "
            f"RF attack detection="
            f"{rf_attack_detected / total:.3f} "
            f"XGB attack detection="
            f"{xgb_attack_detected / total:.3f}"
        )

    print()
    print("=" * 70)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print("=" * 70)
    print("CICIDS2017 MODEL EVALUATION")
    print("=" * 70)

    data = load_evaluation_data()

    print()
    print(
        f"Total available rows: {len(data):,}"
    )

    print()
    print("Creating balanced evaluation sample...")

    evaluation_data = create_evaluation_sample(
        data
    )

    print()
    print(
        f"Evaluation rows: "
        f"{len(evaluation_data):,}"
    )

    evaluate(
        evaluation_data
    )