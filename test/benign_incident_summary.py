import sys
from pathlib import Path

import pandas as pd

# ------------------------------------------------------------
# PROJECT ROOT
# ------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.orchestrator import orchestrator


# ------------------------------------------------------------
# DATASET
# ------------------------------------------------------------

DATASET = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "CICIDS2017"
    / "Benign-Monday-no-metadata.parquet"
)


print("=" * 80)
print("AI BASED CYBER-SECURITY THREAT ANALYSIS")
print("BENIGN INCIDENT SUMMARY TEST")
print("=" * 80)

print()
print("Project root :", PROJECT_ROOT)
print("Dataset      :", DATASET)


# ------------------------------------------------------------
# LOAD DATA
# ------------------------------------------------------------

df = pd.read_parquet(DATASET)

print()
print("Dataset loaded successfully.")
print("Rows    :", len(df))
print("Columns :", len(df.columns))

print()
print("Label distribution:")
print(df["Label"].value_counts())


# ------------------------------------------------------------
# SELECT ONE BENIGN FLOW
# ------------------------------------------------------------

benign_rows = df[df["Label"].astype(str).str.lower() == "benign"]

if benign_rows.empty:
    raise RuntimeError("No Benign flow found in dataset.")

sample = benign_rows.iloc[[0]].copy()

print()
print("Selected sample label:", sample["Label"].iloc[0])


# ------------------------------------------------------------
# REMOVE LABEL BEFORE ML PIPELINE
# ------------------------------------------------------------

X = sample.drop(columns=["Label"], errors="ignore")


# ------------------------------------------------------------
# RUN COMPLETE PIPELINE
# ------------------------------------------------------------

print()
print("=" * 80)
print("RUNNING COMPLETE PIPELINE")
print("=" * 80)

result = orchestrator.analyze(X)

if not result.get("pipeline_completed", False):
    print()
    print("PIPELINE FAILED")
    print(result.get("error"))
    sys.exit(1)


# ------------------------------------------------------------
# EXTRACT RESULTS
# ------------------------------------------------------------

detection = result.get("detection", {})
rare = result.get("rare_family", {})
investigation = result.get("investigation", {})
evidence = result.get("evidence", {})
decision = result.get("decision", {})
response = result.get("response", {})


# ------------------------------------------------------------
# FINAL INCIDENT SUMMARY
# ------------------------------------------------------------

print()
print("=" * 80)
print("FINAL BENIGN INCIDENT SUMMARY")
print("=" * 80)

print()
print("Original dataset label             :", sample["Label"].iloc[0])
print("Final decision                     :", decision.get("final_decision"))
print("Detected attack                    :", decision.get("final_attack"))
print("Severity                           :", investigation.get("severity"))
print("Decision confidence                :", decision.get("decision_confidence"))
print("Correlation score                  :", decision.get("correlation_score"))


# ------------------------------------------------------------
# ML DETECTION
# ------------------------------------------------------------

print()
print("=" * 80)
print("ML DETECTION")
print("=" * 80)

print()
print("Detection state                    :", detection.get("detection_state"))

rf = detection.get("random_forest", {})
xgb = detection.get("xgboost", {})

print("Random Forest prediction           :", rf.get("attack_family"))
print("XGBoost prediction                 :", xgb.get("attack_family"))
print("Random Forest confidence           :", rf.get("confidence"))
print("XGBoost confidence                 :", xgb.get("confidence"))
print("Model agreement                    :", detection.get("model_agreement"))
print("Predicted attack                   :", detection.get("predicted_attack"))


# ------------------------------------------------------------
# BINARY ATTACK PROBABILITIES
# ------------------------------------------------------------

print()
print("=" * 80)
print("BINARY ATTACK PROBABILITIES")
print("=" * 80)

print()
print(
    "RF attack probability              :",
    detection.get("random_forest", {}).get("attack_probability")
)

print(
    "XGB attack probability             :",
    detection.get("xgboost", {}).get("attack_probability")
)


# ------------------------------------------------------------
# RARE ATTACK DETECTION
# ------------------------------------------------------------

print()
print("=" * 80)
print("RARE ATTACK DETECTION")
print("=" * 80)

print()
print("Available                          :", rare.get("available"))
print("Triggered                          :", rare.get("any_triggered"))
print("Selected family                    :", rare.get("top_family"))
print("Top probability                    :", rare.get("top_probability"))

print()
print("Rare-family scores:")

for family, score in rare.get("scores", {}).items():
    print(f"{family:<28}: {score}")


# ------------------------------------------------------------
# INVESTIGATION
# ------------------------------------------------------------

print()
print("=" * 80)
print("INVESTIGATION AGENT")
print("=" * 80)

print()
print("Finding                            :", investigation.get("finding"))
print("Severity                           :", investigation.get("severity"))
print(
    "Investigation required             :",
    investigation.get("investigation_required")
)
print(
    "Investigation priority             :",
    investigation.get("investigation_priority")
)


# ------------------------------------------------------------
# SUPPORTING EVIDENCE
# ------------------------------------------------------------

print()
print("=" * 80)
print("SUPPORTING EVIDENCE")
print("=" * 80)

print()
print("Evidence state                     :", evidence.get("evidence_state"))
print("Evidence found                     :", evidence.get("evidence_found"))
print("Attack family                      :", evidence.get("attack_family"))
print("Source                             :", evidence.get("source"))
print("Technique ID                       :", evidence.get("technique_id"))
print("Technique name                     :", evidence.get("technique_name"))


# ------------------------------------------------------------
# FLOW EVIDENCE
# ------------------------------------------------------------

print()
print("=" * 80)
print("INDEPENDENT FLOW EVIDENCE")
print("=" * 80)

print()
print("Flow evidence score                :", evidence.get("flow_evidence_score"))
print("Flow evidence level                :", evidence.get("flow_evidence_level"))
print(
    "Flow evidence triggered            :",
    evidence.get("flow_evidence_triggered")
)


# ------------------------------------------------------------
# DECISION
# ------------------------------------------------------------

print()
print("=" * 80)
print("DECISION / CORRELATION")
print("=" * 80)

print()
print("Final decision                     :", decision.get("final_decision"))
print("Final attack                       :", decision.get("final_attack"))
print("Decision confidence                :", decision.get("decision_confidence"))
print("Correlation score                  :", decision.get("correlation_score"))

print()
print("Correlation reasons:")

for reason in decision.get("correlation_reasons", []):
    print("-", reason)


# ------------------------------------------------------------
# RESPONSE
# ------------------------------------------------------------

print()
print("=" * 80)
print("RESPONSE AGENT")
print("=" * 80)

print()
print("Response state                     :", response.get("response_state"))
print("Requires action                    :", response.get("requires_action"))
print("Severity                           :", response.get("severity"))
print("Attack                             :", response.get("attack"))
print("Finding                            :", response.get("finding"))

# ------------------------------------------------------------
# PIPELINE
# ------------------------------------------------------------

print()
print("=" * 80)
print("PIPELINE")
print("=" * 80)

print()
print("Completed                          :", result.get("pipeline_completed"))

print()
print("Stage timings:")

for stage, timing in result.get("timings", {}).items():
    print(f"{stage:<16}: {timing} seconds")


# ------------------------------------------------------------
# FINAL VALIDATION
# ------------------------------------------------------------

print()
print("=" * 80)
print("BENIGN TEST VALIDATION")
print("=" * 80)

final_decision = decision.get("final_decision")
requires_action = response.get("requires_action")

print()
print("Expected final decision            : BENIGN")
print("Actual final decision              :", final_decision)

if final_decision == "BENIGN" and not requires_action:
    print()
    print("RESULT: PASS")
    print("Benign flow was correctly treated as non-malicious.")
else:
    print()
    print("RESULT: REVIEW")
    print("The benign flow was not classified as expected.")

print()
print("=" * 80)
print("BENIGN INCIDENT SUMMARY TEST COMPLETED")
print("=" * 80)