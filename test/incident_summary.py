# ============================================================
# INCIDENT SUMMARY TEST
# ============================================================

import os
import sys
import warnings

# ------------------------------------------------------------
# ADD PROJECT ROOT TO PYTHON PATH
# ------------------------------------------------------------

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

sys.path.insert(0, PROJECT_ROOT)

# ------------------------------------------------------------
# IMPORTS
# ------------------------------------------------------------

import pandas as pd

from agents.orchestrator import orchestrator


# ------------------------------------------------------------
# IGNORE KNOWN XGBOOST WARNING
# ------------------------------------------------------------

warnings.filterwarnings(
    "ignore",
    message=".*serialized model.*",
    category=UserWarning
)


# ------------------------------------------------------------
# DATASET
# ------------------------------------------------------------

DATASET = os.path.join(
    PROJECT_ROOT,
    "data",
    "raw",
    "CICIDS2017",
    "Infiltration-Thursday-no-metadata.parquet"
)


# ------------------------------------------------------------
# HELPER
# ------------------------------------------------------------

def show(name, value):
    print(f"{name:<35}: {value}")


# ============================================================
# START
# ============================================================

print("=" * 80)
print("AI BASED CYBER-SECURITY THREAT ANALYSIS")
print("INCIDENT SUMMARY TEST")
print("=" * 80)

print()
print("Project root :", PROJECT_ROOT)
print("Dataset      :", DATASET)


# ============================================================
# LOAD DATASET
# ============================================================

if not os.path.exists(DATASET):

    print()
    print("ERROR: Dataset not found.")
    print(DATASET)
    sys.exit(1)


df = pd.read_parquet(DATASET)

print()
print("Dataset loaded successfully.")
print("Rows    :", len(df))
print("Columns :", len(df.columns))


# ============================================================
# LABEL CHECK
# ============================================================

print()
print("Label distribution:")
print(df["Label"].value_counts())


# ============================================================
# SELECT INFILTRATION SAMPLE
# ============================================================

rows = df[
    df["Label"].astype(str).str.strip().str.lower()
    == "infiltration"
]

if len(rows) == 0:

    print()
    print("ERROR: No Infiltration rows found.")
    sys.exit(1)


row = rows.iloc[[0]]

original_label = row.iloc[0]["Label"]

X = row.drop(
    columns=["Label"]
)


print()
print("Selected sample label:", original_label)


# ============================================================
# RUN ORCHESTRATOR
# ============================================================

print()
print("=" * 80)
print("RUNNING COMPLETE PIPELINE")
print("=" * 80)

try:

    result = orchestrator.analyze(X)

except Exception as e:

    print()
    print("PIPELINE ERROR")
    print("Type   :", type(e).__name__)
    print("Message:", str(e))
    raise


# ============================================================
# CHECK PIPELINE
# ============================================================

if not result.get("pipeline_completed", False):

    print()
    print("=" * 80)
    print("PIPELINE FAILED")
    print("=" * 80)

    print(result.get("error"))

    sys.exit(1)


# ============================================================
# GET PIPELINE STAGES
# ============================================================

detection = result.get(
    "detection",
    {}
)

rare = result.get(
    "rare_family",
    {}
)

investigation = result.get(
    "investigation",
    {}
)

evidence = result.get(
    "evidence",
    {}
)

decision = result.get(
    "decision",
    {}
)

response = result.get(
    "response",
    {}
)


# ============================================================
# DETECTION
# ============================================================

rf = detection.get(
    "random_forest",
    {}
)

xgb = detection.get(
    "xgboost",
    {}
)


# ============================================================
# FINAL INCIDENT SUMMARY
# ============================================================

print()
print("=" * 80)
print("FINAL INCIDENT SUMMARY")
print("=" * 80)

show(
    "Original dataset label",
    original_label
)

show(
    "Final decision",
    decision.get("final_decision")
)

show(
    "Detected attack",
    decision.get("final_attack")
)

show(
    "Severity",
    response.get("severity")
)

show(
    "Decision confidence",
    decision.get("decision_confidence")
)

show(
    "Correlation score",
    decision.get("correlation_score")
)


# ============================================================
# ML DETECTION
# ============================================================

print()
print("=" * 80)
print("ML DETECTION")
print("=" * 80)

show(
    "Detection state",
    detection.get("detection_state")
)

show(
    "Random Forest prediction",
    rf.get("attack_family")
)

show(
    "XGBoost prediction",
    xgb.get("attack_family")
)

show(
    "Random Forest confidence",
    rf.get("confidence")
)

show(
    "XGBoost confidence",
    xgb.get("confidence")
)

show(
    "Model agreement",
    detection.get("model_agreement")
)

show(
    "Predicted attack",
    detection.get("predicted_attack")
)


# ============================================================
# BINARY PROBABILITIES
# ============================================================

print()
print("=" * 80)
print("BINARY ATTACK PROBABILITIES")
print("=" * 80)

show(
    "RF attack probability",
    rf.get("binary_attack_probability")
)

show(
    "XGB attack probability",
    xgb.get("binary_attack_probability")
)


# ============================================================
# RARE ATTACK DETECTION
# ============================================================

print()
print("=" * 80)
print("RARE ATTACK DETECTION")
print("=" * 80)

show(
    "Available",
    rare.get("available")
)

show(
    "Triggered",
    rare.get("any_triggered")
)

show(
    "Selected family",
    rare.get("top_family")
)

show(
    "Top probability",
    rare.get("top_probability")
)

if rare.get("scores"):

    print()
    print("Rare-family scores:")

    for family, score in rare["scores"].items():

        print(
            f"  {family:<25}: {score}"
        )


# ============================================================
# INVESTIGATION
# ============================================================

print()
print("=" * 80)
print("INVESTIGATION AGENT")
print("=" * 80)

show(
    "Finding",
    investigation.get("finding")
)

show(
    "Severity",
    investigation.get("severity")
)

show(
    "Investigation required",
    investigation.get("investigation_required")
)

show(
    "Investigation priority",
    investigation.get("investigation_priority")
)

show(
    "Average attack probability",
    investigation.get("average_attack_probability")
)

show(
    "Probability difference",
    investigation.get("probability_difference")
)

show(
    "RF attack probability",
    investigation.get("random_forest_attack_probability")
)

show(
    "XGB attack probability",
    investigation.get("xgboost_attack_probability")
)


# ============================================================
# SUPPORTING EVIDENCE
# ============================================================

print()
print("=" * 80)
print("SUPPORTING EVIDENCE")
print("=" * 80)

show(
    "Evidence state",
    evidence.get("evidence_state")
)

show(
    "Evidence found",
    evidence.get("evidence_found")
)

show(
    "Attack family",
    evidence.get("attack")
)

show(
    "Source",
    evidence.get("source_name")
)

show(
    "Technique ID",
    evidence.get("technique_id")
)

show(
    "Technique name",
    evidence.get("technique_name")
)


# ============================================================
# FLOW EVIDENCE
# ============================================================

print()
print("=" * 80)
print("INDEPENDENT FLOW EVIDENCE")
print("=" * 80)

show(
    "Flow evidence score",
    evidence.get("flow_evidence_score")
)

show(
    "Flow evidence level",
    evidence.get("flow_evidence_level")
)

show(
    "Flow evidence triggered",
    evidence.get("flow_evidence_triggered")
)


# ============================================================
# CORRELATION / DECISION
# ============================================================

print()
print("=" * 80)
print("DECISION / CORRELATION")
print("=" * 80)

show(
    "Final decision",
    decision.get("final_decision")
)

show(
    "Final attack",
    decision.get("final_attack")
)

show(
    "Decision confidence",
    decision.get("decision_confidence")
)

show(
    "Correlation score",
    decision.get("correlation_score")
)

print()

if decision.get("correlation_reasons"):

    print("Correlation reasons:")

    for reason in decision["correlation_reasons"]:

        print(
            "  -",
            reason
        )


# ============================================================
# RESPONSE
# ============================================================

print()
print("=" * 80)
print("RESPONSE AGENT")
print("=" * 80)

show(
    "Response state",
    response.get("response_state")
)

show(
    "Requires action",
    response.get("requires_action")
)

show(
    "Severity",
    response.get("severity")
)

show(
    "Attack",
    response.get("attack")
)

show(
    "Finding",
    response.get("finding")
)

print()

if response.get("recommended_actions"):

    print("Recommended actions:")

    for action in response["recommended_actions"]:

        print(
            "  -",
            action
        )


# ============================================================
# PIPELINE TIMING
# ============================================================

print()
print("=" * 80)
print("PIPELINE")
print("=" * 80)

show(
    "Completed",
    result.get("pipeline_completed")
)

timings = result.get(
    "timings",
    {}
)

print()
print("Stage timings:")

for stage, timing in timings.items():

    print(
        f"  {stage:<15}: {timing} seconds"
    )


# ============================================================
# WHY DETECTED
# ============================================================

print()
print("=" * 80)
print("WHY THIS INCIDENT WAS DETECTED")
print("=" * 80)

if detection.get("model_agreement"):

    print(
        "1. Random Forest and XGBoost agreed on the prediction."
    )

else:

    print(
        "1. Random Forest and XGBoost disagreed."
    )


if rare.get("any_triggered"):

    print(
        "2. The dedicated rare-family detector was triggered."
    )

    if rare.get("top_family"):

        print(
            "   Rare family:",
            rare.get("top_family")
        )


if evidence.get("evidence_found"):

    print(
        "3. Supporting cybersecurity evidence was retrieved."
    )

else:

    print(
        "3. No external attack-family evidence was retrieved."
    )


if evidence.get("flow_evidence_score") is not None:

    print(
        "4. Independent flow-level evidence was evaluated."
    )


if investigation.get("finding"):

    print(
        "5. Investigation finding:",
        investigation.get("finding")
    )


# ============================================================
# COMPLETE
# ============================================================

print()
print("=" * 80)
print("INCIDENT SUMMARY TEST COMPLETED")
print("=" * 80)