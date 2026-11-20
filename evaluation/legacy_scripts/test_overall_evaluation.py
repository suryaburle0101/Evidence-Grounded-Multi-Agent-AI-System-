import pandas as pd
from pathlib import Path

try:
    from ._paths import project_path
except ImportError:
    from _paths import project_path

from detection.model_predictor import predict_attack_family


# ============================================================
# CONFIGURATION
# ============================================================

DATASET_DIR = project_path("data/raw/CICIDS2017")

SAMPLES_PER_LABEL = 20

TESTS = [
    {
        "file": "Benign-Monday-no-metadata.parquet",
        "labels": {
            "Benign": "Benign"
        }
    },
    {
        "file": "Botnet-Friday-no-metadata.parquet",
        "labels": {
            "Bot": "Botnet"
        }
    },
    {
        "file": "Bruteforce-Tuesday-no-metadata.parquet",
        "labels": {
            "FTP-Patator": "Brute Force",
            "SSH-Patator": "Brute Force"
        }
    },
    {
        "file": "DDoS-Friday-no-metadata.parquet",
        "labels": {
            "DDoS": "DDoS"
        }
    },
    {
        "file": "DoS-Wednesday-no-metadata.parquet",
        "labels": {
            "DoS Hulk": "DoS",
            "DoS GoldenEye": "DoS",
            "DoS slowloris": "DoS",
            "DoS Slowhttptest": "DoS",
            "Heartbleed": "DoS"
        }
    },
    {
        "file": "Infiltration-Thursday-no-metadata.parquet",
        "labels": {
            "Infiltration": "Infiltration"
        }
    },
    {
        "file": "Portscan-Friday-no-metadata.parquet",
        "labels": {
            "PortScan": "Port Scan"
        }
    },
    {
        "file": "WebAttacks-Thursday-no-metadata.parquet",
        "labels": {
            "Web Attack   Brute Force": "Web Attack",
            "Web Attack   XSS": "Web Attack",
            "Web Attack   Sql Injection": "Web Attack"
        }
    }
]


# ============================================================
# MAIN EVALUATION
# ============================================================

def main():

    print("=" * 95)
    print("OVERALL CYBERSECURITY MODEL EVALUATION")
    print("=" * 95)

    results = []

    for test in TESTS:

        file_name = test["file"]
        file_path = DATASET_DIR / file_name

        print("\n" + "-" * 95)
        print("FILE:", file_name)
        print("-" * 95)

        if not file_path.exists():
            print("FILE NOT FOUND")
            continue

        # Read complete dataset once
        df = pd.read_parquet(file_path)

        for dataset_label, expected_family in test["labels"].items():

            print(f"\nDataset label : {repr(dataset_label)}")
            print(f"Expected family: {expected_family}")

            rows = df[df["Label"] == dataset_label]

            if len(rows) == 0:
                print("RESULT: NO DATA")
                continue

            sample_count = min(
                SAMPLES_PER_LABEL,
                len(rows)
            )

            rows = rows.sample(
                n=sample_count,
                random_state=42
            )

            rf_correct = 0
            xgb_correct = 0
            agreements = 0

            rf_predictions = {}
            xgb_predictions = {}

            for i in range(len(rows)):

                row = rows.iloc[[i]]

                X = row.drop(
                    columns=["Label"]
                )

                # -------------------------------
                # Random Forest
                # -------------------------------

                rf_result = predict_attack_family(
                    X,
                    model_type="random_forest"
                )

                rf_attack = rf_result["attack_family"]

                if rf_attack == expected_family:
                    rf_correct += 1

                rf_predictions[rf_attack] = (
                    rf_predictions.get(rf_attack, 0) + 1
                )

                # -------------------------------
                # XGBoost
                # -------------------------------

                xgb_result = predict_attack_family(
                    X,
                    model_type="xgboost"
                )

                xgb_attack = xgb_result["attack_family"]

                if xgb_attack == expected_family:
                    xgb_correct += 1

                xgb_predictions[xgb_attack] = (
                    xgb_predictions.get(xgb_attack, 0) + 1
                )

                # -------------------------------
                # Agreement
                # -------------------------------

                if rf_attack == xgb_attack:
                    agreements += 1

            rf_accuracy = (
                rf_correct / sample_count * 100
            )

            xgb_accuracy = (
                xgb_correct / sample_count * 100
            )

            agreement_rate = (
                agreements / sample_count * 100
            )

            print("\nSamples tested :", sample_count)

            print(
                f"Random Forest : "
                f"{rf_correct:2d}/{sample_count} "
                f"({rf_accuracy:6.2f}%)"
            )

            print(
                f"XGBoost       : "
                f"{xgb_correct:2d}/{sample_count} "
                f"({xgb_accuracy:6.2f}%)"
            )

            print(
                f"Agreement     : "
                f"{agreements:2d}/{sample_count} "
                f"({agreement_rate:6.2f}%)"
            )

            print(
                "RF predictions :",
                rf_predictions
            )

            print(
                "XGB predictions:",
                xgb_predictions
            )

            results.append({
                "dataset_label": dataset_label,
                "expected_family": expected_family,
                "samples": sample_count,
                "rf_correct": rf_correct,
                "rf_accuracy": rf_accuracy,
                "xgb_correct": xgb_correct,
                "xgb_accuracy": xgb_accuracy,
                "agreements": agreements,
                "agreement_rate": agreement_rate
            })


    # ========================================================
    # OVERALL SUMMARY
    # ========================================================

    print("\n")
    print("=" * 95)
    print("OVERALL SUMMARY")
    print("=" * 95)

    print(
        f"{'Dataset Label':30} "
        f"{'Expected':15} "
        f"{'RF':12} "
        f"{'XGB':12} "
        f"{'Agreement':12}"
    )

    print("-" * 95)

    for r in results:

        print(
            f"{r['dataset_label'][:30]:30} "
            f"{r['expected_family'][:15]:15} "
            f"{r['rf_accuracy']:6.2f}%      "
            f"{r['xgb_accuracy']:6.2f}%      "
            f"{r['agreement_rate']:6.2f}%"
        )


    # ========================================================
    # GLOBAL METRICS
    # ========================================================

    total_samples = sum(
        r["samples"]
        for r in results
    )

    total_rf_correct = sum(
        r["rf_correct"]
        for r in results
    )

    total_xgb_correct = sum(
        r["xgb_correct"]
        for r in results
    )

    total_agreements = sum(
        r["agreements"]
        for r in results
    )

    if total_samples > 0:

        global_rf_accuracy = (
            total_rf_correct /
            total_samples *
            100
        )

        global_xgb_accuracy = (
            total_xgb_correct /
            total_samples *
            100
        )

        global_agreement = (
            total_agreements /
            total_samples *
            100
        )

        print("\n" + "=" * 95)
        print("GLOBAL METRICS")
        print("=" * 95)

        print(
            f"Total samples tested : {total_samples}"
        )

        print(
            f"Random Forest       : "
            f"{total_rf_correct}/{total_samples} "
            f"({global_rf_accuracy:.2f}%)"
        )

        print(
            f"XGBoost             : "
            f"{total_xgb_correct}/{total_samples} "
            f"({global_xgb_accuracy:.2f}%)"
        )

        print(
            f"Model agreement     : "
            f"{total_agreements}/{total_samples} "
            f"({global_agreement:.2f}%)"
        )


    print("\n")
    print("=" * 95)
    print("EVALUATION FINISHED")
    print("=" * 95)


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    main()
