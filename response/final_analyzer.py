from detection.model_predictor import (
    compare_models,
    rf_binary,
    xgb_binary
)

from evidence.evidence_retriever import get_evidence_for_attack


# ============================================================
# DATA PREPARATION
# ============================================================

def prepare_features(X):
    """
    Convert all model input columns to numeric values.

    CICIDS2017 parquet files may contain object/string dtypes
    even though the trained models expect numeric values.
    """

    X = X.copy()

    # Remove label if accidentally supplied
    if "Label" in X.columns:
        X = X.drop(columns=["Label"])

    # Convert every column to numeric
    for column in X.columns:
        X[column] = X[column].astype(str).str.strip()
        X[column] = X[column].replace(
            ["Infinity", "-Infinity", "inf", "-inf", "NaN", "nan"],
            0
        )
        X[column] = X[column].astype(float)

    # Replace remaining invalid values
    X = X.fillna(0)

    return X


# ============================================================
# BINARY RARE-ATTACK DETECTION
# ============================================================

def detect_rare_attack(X):
    """
    Binary models determine whether the flow is an attack.

    Binary model classes:
        0 = Benign
        1 = Attack

    This is especially important for rare attacks such as:
        - Infiltration
        - Heartbleed
    """

    X = prepare_features(X)

    rf_pred = int(rf_binary.predict(X)[0])
    xgb_pred = int(xgb_binary.predict(X)[0])

    rf_probabilities = rf_binary.predict_proba(X)[0]
    xgb_probabilities = xgb_binary.predict_proba(X)[0]

    rf_confidence = float(rf_probabilities.max())
    xgb_confidence = float(xgb_probabilities.max())

    rf_attack_confidence = float(rf_probabilities[1])
    xgb_attack_confidence = float(xgb_probabilities[1])

    # --------------------------------------------------------
    # Binary decision
    # --------------------------------------------------------

    if rf_pred == 1 and xgb_pred == 1:
        decision = "ATTACK"

    elif rf_pred == 1 or xgb_pred == 1:
        decision = "POSSIBLE_ATTACK"

    else:
        decision = "BENIGN"

    return {
        "random_forest_prediction": rf_pred,
        "xgboost_prediction": xgb_pred,

        "random_forest_confidence": rf_confidence,
        "xgboost_confidence": xgb_confidence,

        "random_forest_attack_probability":
            rf_attack_confidence,

        "xgboost_attack_probability":
            xgb_attack_confidence,

        "decision": decision
    }


# ============================================================
# RARE ATTACK IDENTIFICATION
# ============================================================

def identify_rare_attack(X):
    """
    Use binary attack detection to recover rare attacks
    that may be classified as Benign by multiclass models.

    Current rare-attack recovery is based on the binary
    attack detector and evidence mapping.
    """

    binary = detect_rare_attack(X)

    # --------------------------------------------------------
    # Both binary models say benign
    # --------------------------------------------------------

    if binary["decision"] == "BENIGN":
        return None, binary

    # --------------------------------------------------------
    # The binary models detected an attack.
    #
    # We use the multiclass output as supporting information.
    # --------------------------------------------------------

    comparison = compare_models(X)

    rf_attack = comparison["random_forest"]["attack_family"]
    xgb_attack = comparison["xgboost"]["attack_family"]

    # --------------------------------------------------------
    # If multiclass models already identified a known attack,
    # keep that result.
    # --------------------------------------------------------

    if rf_attack != "Benign" and rf_attack == xgb_attack:
        return rf_attack, binary

    # --------------------------------------------------------
    # Rare attack recovery
    #
    # If the multiclass classifier says Benign but the binary
    # classifier detects an attack, investigate rare attacks.
    #
    # Infiltration is one of the known rare CICIDS2017 attacks.
    # --------------------------------------------------------

    if rf_attack == "Benign" and xgb_attack == "Benign":

        # Strong binary evidence
        if (
            binary["random_forest_attack_probability"] >= 0.80
            or
            binary["xgboost_attack_probability"] >= 0.80
        ):
            return "Infiltration", binary

        # Moderate binary evidence from both models
        if (
            binary["random_forest_attack_probability"] >= 0.50
            and
            binary["xgboost_attack_probability"] >= 0.50
        ):
            return "Infiltration", binary

    # --------------------------------------------------------
    # One multiclass model detects an attack
    # --------------------------------------------------------

    if rf_attack != "Benign" and xgb_attack == "Benign":
        return rf_attack, binary

    if xgb_attack != "Benign" and rf_attack == "Benign":
        return xgb_attack, binary

    # --------------------------------------------------------
    # Otherwise require review
    # --------------------------------------------------------

    return None, binary


# ============================================================
# EVIDENCE RETRIEVAL
# ============================================================

def retrieve_evidence(attack):
    """
    Retrieve authoritative evidence for the detected attack.
    """

    if attack is None:
        return None

    try:
        return get_evidence_for_attack(attack)
    except Exception:
        return None


# ============================================================
# FINAL THREAT ANALYSIS
# ============================================================

def final_threat_analysis(X):
    """
    Complete cybersecurity threat-analysis pipeline.

    Pipeline:

        Network Flow
              |
              v
        Multiclass ML
        RF + XGBoost
              |
              v
        Binary ML
        RF + XGBoost
              |
              v
        Rare Attack Recovery
              |
              v
        Evidence Retrieval
              |
              v
        Final Threat Decision
    """

    # ========================================================
    # STEP 1: MULTICLASS MODEL COMPARISON
    # ========================================================

    comparison = compare_models(X)

    rf_result = comparison["random_forest"]
    xgb_result = comparison["xgboost"]

    rf_attack = rf_result["attack_family"]
    xgb_attack = xgb_result["attack_family"]

    # ========================================================
    # STEP 2: MODEL AGREEMENT ON ATTACK
    # ========================================================

    if comparison["agreement"]:

        # ----------------------------------------------------
        # Both models say benign.
        #
        # DO NOT immediately return benign.
        #
        # First run binary detection to catch rare attacks.
        # ----------------------------------------------------

        if rf_attack == "Benign":

            rare_attack, binary_result = identify_rare_attack(X)

            # ------------------------------------------------
            # Rare attack detected
            # ------------------------------------------------

            if rare_attack is not None:

                final_confidence = min(
                    binary_result[
                        "random_forest_attack_probability"
                    ],
                    binary_result[
                        "xgboost_attack_probability"
                    ]
                )

                evidence = retrieve_evidence(rare_attack)

                # --------------------------------------------
                # Evidence found
                # --------------------------------------------

                if evidence is not None:

                    evidence_data = evidence.get(
                        "evidence",
                        {}
                    )

                    return {
                        "status": "THREAT_CONFIRMED",

                        "reason":
                            "RARE_ATTACK_DETECTED_BY_BINARY_MODELS",

                        "final_attack":
                            rare_attack,

                        "final_confidence":
                            final_confidence,

                        "random_forest":
                            rf_result,

                        "xgboost":
                            xgb_result,

                        "binary_detection":
                            binary_result,

                        "source":
                            evidence.get(
                                "source_name",
                                ""
                            ),

                        "source_url":
                            evidence.get(
                                "source_url",
                                ""
                            ),

                        "technique_id":
                            evidence.get(
                                "technique_id",
                                ""
                            ),

                        "technique_name":
                            evidence.get(
                                "technique_name",
                                ""
                            ),

                        "description":
                            evidence_data.get(
                                "description",
                                ""
                            ),

                        "indicators":
                            evidence_data.get(
                                "indicators",
                                []
                            ),

                        "investigation":
                            evidence_data.get(
                                "detection_guidance",
                                evidence_data.get(
                                    "investigation_guidance",
                                    []
                                )
                            ),

                        "mitigation":
                            evidence_data.get(
                                "mitigation_guidance",
                                []
                            ),

                        "message":
                            "Multiclass models classified "
                            "the flow as benign, but binary "
                            "models detected attack activity. "
                            "The flow was investigated as a "
                            "possible rare attack."
                    }

                # --------------------------------------------
                # Attack detected but evidence unavailable
                # --------------------------------------------

                return {
                    "status": "REVIEW_REQUIRED",

                    "reason":
                        "RARE_ATTACK_WITHOUT_EVIDENCE",

                    "final_attack":
                        rare_attack,

                    "final_confidence":
                        final_confidence,

                    "random_forest":
                        rf_result,

                    "xgboost":
                        xgb_result,

                    "binary_detection":
                        binary_result,

                    "message":
                        "Binary models detected attack "
                        "activity, but authoritative evidence "
                        "could not be retrieved."
                }

            # ------------------------------------------------
            # All detection layers say benign
            # ------------------------------------------------

            return {
                "status": "NO_ATTACK_DETECTED",

                "reason":
                    "ALL_MODELS_PREDICT_BENIGN",

                "final_attack":
                    "Benign",

                "final_confidence":
                    min(
                        rf_result["confidence"],
                        xgb_result["confidence"]
                    ),

                "random_forest":
                    rf_result,

                "xgboost":
                    xgb_result,

                "binary_detection":
                    binary_result,

                "message":
                    "Multiclass and binary models "
                    "classified the network flow as benign."
            }

        # ----------------------------------------------------
        # Both multiclass models agree on an attack
        # ----------------------------------------------------

        final_attack = rf_attack

        final_confidence = min(
            rf_result["confidence"],
            xgb_result["confidence"]
        )

        evidence = retrieve_evidence(final_attack)

        # ----------------------------------------------------
        # Evidence not found
        # ----------------------------------------------------

        if evidence is None:

            return {
                "status": "REVIEW_REQUIRED",

                "reason":
                    "EVIDENCE_NOT_FOUND",

                "final_attack":
                    final_attack,

                "final_confidence":
                    final_confidence,

                "random_forest":
                    rf_result,

                "xgboost":
                    xgb_result,

                "message":
                    "The models agreed on an attack, "
                    "but authoritative evidence was not found."
            }

        # ----------------------------------------------------
        # Evidence found
        # ----------------------------------------------------

        evidence_data = evidence.get(
            "evidence",
            {}
        )

        return {
            "status": "THREAT_CONFIRMED",

            "final_attack":
                final_attack,

            "final_confidence":
                final_confidence,

            "random_forest":
                rf_result,

            "xgboost":
                xgb_result,

            "source":
                evidence.get(
                    "source_name",
                    ""
                ),

            "source_url":
                evidence.get(
                    "source_url",
                    ""
                ),

            "technique_id":
                evidence.get(
                    "technique_id",
                    ""
                ),

            "technique_name":
                evidence.get(
                    "technique_name",
                    ""
                ),

            "description":
                evidence_data.get(
                    "description",
                    ""
                ),

            "indicators":
                evidence_data.get(
                    "indicators",
                    []
                ),

            "investigation":
                evidence_data.get(
                    "detection_guidance",
                    evidence_data.get(
                        "investigation_guidance",
                        []
                    )
                ),

            "mitigation":
                evidence_data.get(
                    "mitigation_guidance",
                    []
                ),

            "message":
                "Both machine-learning models agreed "
                "on the detected attack and authoritative "
                "evidence was retrieved."
        }

    # ========================================================
    # STEP 3: MULTICLASS MODEL DISAGREEMENT
    # ========================================================

    rare_attack, binary_result = identify_rare_attack(X)

    # --------------------------------------------------------
    # Binary detector confirms attack
    # --------------------------------------------------------

    if rare_attack is not None:

        final_confidence = min(
            binary_result[
                "random_forest_attack_probability"
            ],
            binary_result[
                "xgboost_attack_probability"
            ]
        )

        evidence = retrieve_evidence(rare_attack)

        if evidence is not None:

            evidence_data = evidence.get(
                "evidence",
                {}
            )

            return {
                "status": "THREAT_CONFIRMED",

                "reason":
                    "BINARY_MODEL_RECOVERY_AFTER_MULTICLASS_DISAGREEMENT",

                "final_attack":
                    rare_attack,

                "final_confidence":
                    final_confidence,

                "random_forest":
                    rf_result,

                "xgboost":
                    xgb_result,

                "binary_detection":
                    binary_result,

                "source":
                    evidence.get(
                        "source_name",
                        ""
                    ),

                "source_url":
                    evidence.get(
                        "source_url",
                        ""
                    ),

                "technique_id":
                    evidence.get(
                        "technique_id",
                        ""
                    ),

                "technique_name":
                    evidence.get(
                        "technique_name",
                        ""
                    ),

                "description":
                    evidence_data.get(
                        "description",
                        ""
                    ),

                "indicators":
                    evidence_data.get(
                        "indicators",
                        []
                    ),

                "investigation":
                    evidence_data.get(
                        "detection_guidance",
                        evidence_data.get(
                            "investigation_guidance",
                            []
                        )
                    ),

                "mitigation":
                    evidence_data.get(
                        "mitigation_guidance",
                        []
                    ),

                "message":
                    "Multiclass models disagreed, but "
                    "binary attack detection provided "
                    "additional evidence of malicious activity."
            }

    # --------------------------------------------------------
    # No reliable recovery
    # --------------------------------------------------------

    return {
        "status":
            "REVIEW_REQUIRED",

        "reason":
            "MODEL_DISAGREEMENT",

        "final_attack":
            None,

        "final_confidence":
            None,

        "random_forest":
            rf_result,

        "xgboost":
            xgb_result,

        "binary_detection":
            binary_result,

        "message":
            "Random Forest and XGBoost produced "
            "different predictions. Binary attack "
            "detection did not provide sufficient "
            "evidence for automatic confirmation. "
            "Further investigation is recommended."
    }