import sys
from pathlib import Path

import pandas as pd

# ============================================================
# PROJECT PATH
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from agents.orchestrator import orchestrator


# ============================================================
# CONFIGURATION
# ============================================================

DATA_DIR = PROJECT_ROOT / "data" / "raw" / "CICIDS2017"

SAMPLES_PER_CLASS = 50


# ============================================================
# DATASET FILES
# ============================================================

DATASET_FILES = [
    "Benign-Monday-no-metadata.parquet",
    "Botnet-Friday-no-metadata.parquet",
    "Bruteforce-Tuesday-no-metadata.parquet",
    "DDoS-Friday-no-metadata.parquet",
    "DoS-Wednesday-no-metadata.parquet",
    "Infiltration-Thursday-no-metadata.parquet",
    "Portscan-Friday-no-metadata.parquet",
    "WebAttacks-Thursday-no-metadata.parquet",
]


# ============================================================
# CLASS GROUPING
# ============================================================

def normalize_label(label):
    """
    Convert the original CICIDS2017 label into
    the attack family used by our ML system.
    """

    label = str(label)

    if label == "Benign":
        return "Benign"

    if label == "Bot":
        return "Botnet"

    if label in [
        "FTP-Patator",
        "SSH-Patator",
    ]:
        return "Brute Force"

    if label == "DDoS":
        return "DDoS"

    if label.startswith("DoS "):
        return "DoS"

    if label == "PortScan":
        return "Port Scan"

    if label.startswith("Web Attack"):
        return "Web Attack"

    if label == "Infiltration":
        return "Infiltration"

    if label == "Heartbleed":
        return "Heartbleed"

    return label


# ============================================================
# LOAD DATA
# ============================================================

print("=" * 75)
print("CYBERSECURITY MULTI-AGENT SYSTEM EVALUATION")
print("=" * 75)

frames = []

for filename in DATASET_FILES:

    filepath = DATA_DIR / filename

    if not filepath.exists():
        print(f"WARNING: Missing {filename}")
        continue

    print(f"Loading: {filename}")

    df = pd.read_parquet(filepath)

    df["Expected_Family"] = df["Label"].apply(
        normalize_label
    )

    frames.append(df)


if not frames:
    raise RuntimeError(
        "No CICIDS2017 Parquet files were found."
    )


data = pd.concat(
    frames,
    ignore_index=True
)


# ============================================================
# CLASS DISTRIBUTION
# ============================================================

print("\n")
print("=" * 75)
print("AVAILABLE ATTACK FAMILIES")
print("=" * 75)

print(
    data["Expected_Family"]
    .value_counts()
    .to_string()
)


# ============================================================
# BALANCED SAMPLING
# ============================================================

print("\n")
print("=" * 75)
print("CREATING MULTI-SAMPLE EVALUATION SET")
print("=" * 75)

evaluation_frames = []

for family in sorted(
    data["Expected_Family"].unique()
):

    class_data = data[
        data["Expected_Family"] == family
    ]

    sample_count = min(
        SAMPLES_PER_CLASS,
        len(class_data)
    )

    sample = class_data.sample(
        n=sample_count,
        random_state=42
    )

    evaluation_frames.append(sample)

    print(
        f"{family:<20} -> "
        f"{sample_count} samples"
    )


evaluation_data = pd.concat(
    evaluation_frames,
    ignore_index=True
)


print(
    f"\nTotal evaluation flows: "
    f"{len(evaluation_data)}"
)


# ============================================================
# RUN MULTI-AGENT PIPELINE
# ============================================================

results = []

print("\n")
print("=" * 75)
print("RUNNING MULTI-AGENT PIPELINE")
print("=" * 75)


for index, row in evaluation_data.iterrows():

    expected_family = row["Expected_Family"]

    X = row.drop(
        labels=["Label", "Expected_Family"]
    ).to_frame().T

    try:

        result = orchestrator.analyze(X)

        detection = result["detection"]
        investigation = result["investigation"]
        evidence = result["evidence"]
        decision = result["decision"]
        response = result["response"]

        predicted_attack = decision.get(
            "final_attack"
        )

        # ----------------------------------------------------
        # EVALUATE THREAT DECISION
        # ----------------------------------------------------

        if expected_family == "Benign":

            correct = (
                predicted_attack == "Benign"
            )

        else:

            correct = (
                predicted_attack is not None
                and predicted_attack != "Benign"
            )

        # ----------------------------------------------------
        # FALSE BENIGN
        # ----------------------------------------------------

        false_benign = (
            expected_family != "Benign"
            and predicted_attack == "Benign"
        )

        # ----------------------------------------------------
        # STORE RESULT
        # ----------------------------------------------------

        results.append(
            {
                "expected": expected_family,
                "predicted": predicted_attack,

                "detection_state":
                    detection.get(
                        "detection_state"
                    ),

                "investigation":
                    investigation.get(
                        "finding"
                    ),

                "evidence":
                    evidence.get(
                        "evidence_state"
                    ),
                "decision":
                    decision.get(
                        "final_decision"
                    ),

                "decision_confidence":
                    decision.get(
                        "decision_confidence"
                    ),

                "correlation_score":
                    decision.get(
                        "correlation_score"
                    ),

                "decision_reason":
                    decision.get(
                        "decision_reason"
                    ),

                "response":
                    response.get(
                        "response_state"
                    ),

                "severity":
                    response.get(
                        "severity"
                    ),

                "correct":
                    correct,

                "false_benign":
                    false_benign,

                "pipeline_completed":
                    result.get(
                        "pipeline_completed"
                    ),
            }
        )

    except Exception as e:

        print(
            f"ERROR on row {index}: {e}"
        )


# ============================================================
# RESULTS DATAFRAME
# ============================================================

results_df = pd.DataFrame(
    results
)


if results_df.empty:
    raise RuntimeError(
        "No agent evaluation results were generated."
    )


# ============================================================
# OVERALL RESULTS
# ============================================================

print("\n")
print("=" * 75)
print("MULTI-AGENT SYSTEM RESULTS")
print("=" * 75)

total = len(results_df)

correct = int(
    results_df["correct"].sum()
)

false_benign = int(
    results_df["false_benign"].sum()
)

completed = int(
    results_df["pipeline_completed"].sum()
)

accuracy = correct / total

print(
    f"\nTotal flows tested       : {total}"
)

print(
    f"Pipeline completed      : "
    f"{completed}/{total}"
)

print(
    f"Correct threat decisions : "
    f"{correct}/{total}"
)

print(
    f"Threat-decision accuracy : "
    f"{accuracy:.4f}"
)

print(
    f"False benign decisions   : "
    f"{false_benign}"
)


# ============================================================
# FAMILY-LEVEL RESULTS
# ============================================================

print("\n")
print("=" * 75)
print("ATTACK-FAMILY RESULTS")
print("=" * 75)

family_results = (
    results_df
    .groupby("expected")
    .agg(
        samples=("expected", "count"),
        correct=("correct", "sum"),
        false_benign=("false_benign", "sum"),
    )
)

family_results["accuracy"] = (
    family_results["correct"]
    / family_results["samples"]
)

print(
    family_results.to_string()
)


# ============================================================
# DETECTION STATES
# ============================================================

print("\n")
print("=" * 75)
print("DETECTION AGENT STATES")
print("=" * 75)

print(
    results_df[
        "detection_state"
    ].value_counts().to_string()
)


# ============================================================
# INVESTIGATION STATES
# ============================================================

print("\n")
print("=" * 75)
print("INVESTIGATION AGENT FINDINGS")
print("=" * 75)

print(
    results_df[
        "investigation"
    ].value_counts().to_string()
)


# ============================================================
# EVIDENCE STATES
# ============================================================

print("\n")
print("=" * 75)
print("EVIDENCE AGENT RESULTS")
print("=" * 75)

print(
    results_df[
        "evidence"
    ].value_counts().to_string()
)
# ============================================================
# DECISION / CORRELATION RESULTS
# ============================================================

print("\n")
print("=" * 75)
print("DECISION / CORRELATION RESULTS")
print("=" * 75)

print(
    results_df[
        "decision"
    ].value_counts().to_string()
)

print("\nDecision confidence statistics:")

print(
    results_df[
        "decision_confidence"
    ].describe().to_string()
)

print("\nCorrelation score statistics:")

print(
    results_df[
        "correlation_score"
    ].describe().to_string()
)

# ============================================================
# RESPONSE STATES
# ============================================================

print("\n")
print("=" * 75)
print("RESPONSE AGENT STATES")
print("=" * 75)

print(
    results_df[
        "response"
    ].value_counts().to_string()
)


# ============================================================
# SEVERITY DISTRIBUTION
# ============================================================

print("\n")
print("=" * 75)
print("SEVERITY DISTRIBUTION")
print("=" * 75)

print(
    results_df[
        "severity"
    ].value_counts().to_string()
)


# ============================================================
# FALSE-BENIGN ANALYSIS
# ============================================================

print("\n")
print("=" * 75)
print("FALSE-BENIGN ANALYSIS")
print("=" * 75)

false_benign_df = results_df[
    results_df["false_benign"]
]

if false_benign_df.empty:

    print(
        "No false-benign decisions detected."
    )

else:

    print(
        false_benign_df[
            [
                "expected",
                "predicted",
                "detection_state",
                "investigation",
                "evidence",
                "response",
                "severity",
            ]
        ].to_string(index=False)
    )


# ============================================================
# FINAL
# ============================================================

print("\n")
print("=" * 75)
print("MULTI-AGENT EVALUATION COMPLETE")
print("=" * 75)