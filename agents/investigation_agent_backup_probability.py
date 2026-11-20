class InvestigationAgent:
    """
    Investigation Agent

    Responsibilities:
    1. Examine Detection Agent results.
    2. Analyze model agreement/disagreement.
    3. Analyze actual binary attack probabilities.
    4. Measure the strength of conflicting evidence.
    5. Determine investigation priority and severity.
    6. Produce a structured investigation result.

    This agent does NOT make the final incident-response
    decision.
    """

    def __init__(self):
        self.name = "Investigation Agent"

    # ========================================================
    # MAIN ANALYSIS
    # ========================================================

    def analyze(self, detection_result):

        rf_result = detection_result["random_forest"]
        xgb_result = detection_result["xgboost"]

        # ----------------------------------------------------
        # Basic model information
        # ----------------------------------------------------

        rf_attack = rf_result["attack_family"]
        xgb_attack = xgb_result["attack_family"]

        rf_binary = int(
            rf_result["binary_prediction"]
        )

        xgb_binary = int(
            xgb_result["binary_prediction"]
        )

        rf_confidence = float(
            rf_result["confidence"]
        )

        xgb_confidence = float(
            xgb_result["confidence"]
        )

        # ----------------------------------------------------
        # Actual binary attack probabilities
        #
        # These values come directly from the model
        # predict_proba() output.
        #
        # Binary classes:
        # 0 = Benign
        # 1 = Attack
        #
        # The fallback preserves compatibility with older
        # detection results that may not contain the new
        # probability fields.
        # ----------------------------------------------------

        rf_attack_probability = float(
            rf_result.get(
                "binary_attack_probability",
                (
                    1.0 - rf_confidence
                    if rf_binary == 0
                    else rf_confidence
                )
            )
        )

        xgb_attack_probability = float(
            xgb_result.get(
                "binary_attack_probability",
                (
                    1.0 - xgb_confidence
                    if xgb_binary == 0
                    else xgb_confidence
                )
            )
        )

        # ----------------------------------------------------
        # Actual binary benign probabilities
        # ----------------------------------------------------

        rf_benign_probability = float(
            rf_result.get(
                "binary_benign_probability",
                1.0 - rf_attack_probability
            )
        )

        xgb_benign_probability = float(
            xgb_result.get(
                "binary_benign_probability",
                1.0 - xgb_attack_probability
            )
        )

        # ----------------------------------------------------
        # Probability disagreement
        # ----------------------------------------------------

        probability_difference = abs(
            rf_attack_probability
            - xgb_attack_probability
        )

        # ----------------------------------------------------
        # Average attack probability
        # ----------------------------------------------------

        average_attack_probability = (
            rf_attack_probability
            + xgb_attack_probability
        ) / 2.0

        # ----------------------------------------------------
        # Binary model relationship
        # ----------------------------------------------------

        both_detect_attack = (
            rf_binary == 1
            and
            xgb_binary == 1
        )

        both_detect_benign = (
            rf_binary == 0
            and
            xgb_binary == 0
        )

        one_detects_attack = (
            rf_binary != xgb_binary
        )

        # ====================================================
        # CASE 1: BOTH MODELS AGREE
        # ====================================================

        if detection_result["model_agreement"]:

            # ------------------------------------------------
            # Both models classify as benign
            # ------------------------------------------------

            if rf_attack == "Benign":

                finding = "NO_ATTACK_INDICATED"
                severity = "LOW"
                investigation_required = False
                investigation_priority = "LOW"

                explanation = (
                    "Random Forest and XGBoost both classified "
                    "the network flow as benign. "
                    f"Random Forest attack probability was "
                    f"{rf_attack_probability:.3f}, while "
                    f"XGBoost attack probability was "
                    f"{xgb_attack_probability:.3f}. "
                    "No significant attack evidence was "
                    "identified by the detection models."
                )

            # ------------------------------------------------
            # Both models classify as the same attack
            # ------------------------------------------------

            else:

                finding = "ATTACK_INDICATED"
                severity = "HIGH"
                investigation_required = True
                investigation_priority = "HIGH"

                explanation = (
                    "Random Forest and XGBoost agreed that "
                    "the network flow belongs to the "
                    f"'{rf_attack}' attack family. "
                    f"Random Forest attack probability was "
                    f"{rf_attack_probability:.3f}, while "
                    f"XGBoost attack probability was "
                    f"{xgb_attack_probability:.3f}. "
                    "The agreement between independent models "
                    "provides strong detection evidence."
                )

        # ====================================================
        # CASE 2: MODELS DISAGREE
        # ====================================================

        else:

            finding = "CONFLICTING_MODEL_EVIDENCE"

            investigation_required = True

            # ------------------------------------------------
            # Determine severity from disagreement strength
            # ------------------------------------------------

            if one_detects_attack:

                if probability_difference >= 0.50:

                    severity = "HIGH"
                    investigation_priority = "HIGH"

                elif probability_difference >= 0.25:

                    severity = "MEDIUM"
                    investigation_priority = "MEDIUM"

                else:

                    severity = "MEDIUM"
                    investigation_priority = "MEDIUM"

            else:

                severity = "MEDIUM"
                investigation_priority = "MEDIUM"

            # ------------------------------------------------
            # Determine likely suspicious model
            # ------------------------------------------------

            if (
                rf_attack != "Benign"
                and
                xgb_attack == "Benign"
            ):

                suspected_attack = rf_attack
                attack_indicating_model = "Random Forest"

            elif (
                xgb_attack != "Benign"
                and
                rf_attack == "Benign"
            ):

                suspected_attack = xgb_attack
                attack_indicating_model = "XGBoost"

            else:

                suspected_attack = None
                attack_indicating_model = "Both models"

            # ------------------------------------------------
            # Explanation
            # ------------------------------------------------

            if suspected_attack:

                explanation = (
                    f"Random Forest identified "
                    f"'{rf_attack}' while XGBoost "
                    f"classified the flow as '{xgb_attack}'. "
                    f"{attack_indicating_model} provided the "
                    "stronger attack indication. "
                    f"Random Forest attack probability was "
                    f"{rf_attack_probability:.3f}, while "
                    f"XGBoost attack probability was "
                    f"{xgb_attack_probability:.3f}. "
                    f"The probability difference was "
                    f"{probability_difference:.3f}. "
                    "Because the models produced conflicting "
                    "evidence, further investigation is required."
                )

            else:

                explanation = (
                    "Random Forest and XGBoost produced "
                    "different attack-family predictions. "
                    f"Random Forest attack probability was "
                    f"{rf_attack_probability:.3f}, while "
                    f"XGBoost attack probability was "
                    f"{xgb_attack_probability:.3f}. "
                    f"Their attack-probability difference was "
                    f"{probability_difference:.3f}. "
                    "Further investigation is required before "
                    "making a final threat decision."
                )

        # ====================================================
        # INVESTIGATION CONCLUSION
        # ====================================================

        if finding == "NO_ATTACK_INDICATED":

            conclusion = (
                "No immediate threat indication was identified."
            )

        elif finding == "ATTACK_INDICATED":

            conclusion = (
                f"Attack activity is strongly indicated as "
                f"'{rf_attack}'."
            )

        else:

            conclusion = (
                "The available model evidence is conflicting. "
                "The suspected attack should be investigated "
                "using additional cybersecurity evidence."
            )

        # ====================================================
        # RETURN STRUCTURED INVESTIGATION RESULT
        # ====================================================

        return {

            "agent":
                self.name,

            "finding":
                finding,

            "severity":
                severity,

            "investigation_required":
                investigation_required,

            "investigation_priority":
                investigation_priority,

            # ------------------------------------------------
            # Model predictions
            # ------------------------------------------------

            "random_forest_attack":
                rf_attack,

            "xgboost_attack":
                xgb_attack,

            "random_forest_binary":
                rf_binary,

            "xgboost_binary":
                xgb_binary,

            # ------------------------------------------------
            # Model confidence
            # ------------------------------------------------

            "random_forest_confidence":
                rf_confidence,

            "xgboost_confidence":
                xgb_confidence,

            # ------------------------------------------------
            # Actual binary probabilities
            # ------------------------------------------------

            "random_forest_attack_probability":
                rf_attack_probability,

            "xgboost_attack_probability":
                xgb_attack_probability,

            "random_forest_benign_probability":
                rf_benign_probability,

            "xgboost_benign_probability":
                xgb_benign_probability,

            "average_attack_probability":
                average_attack_probability,

            "probability_difference":
                probability_difference,

            # ------------------------------------------------
            # Model relationship
            # ------------------------------------------------

            "both_detect_attack":
                both_detect_attack,

            "both_detect_benign":
                both_detect_benign,

            "one_detects_attack":
                one_detects_attack,

            # ------------------------------------------------
            # Suspected attack
            # ------------------------------------------------

            "suspected_attack":
                suspected_attack
                if finding == "CONFLICTING_MODEL_EVIDENCE"
                else (
                    rf_attack
                    if rf_attack != "Benign"
                    else None
                ),

            # ------------------------------------------------
            # Model responsible for suspicious evidence
            # ------------------------------------------------

            "attack_indicating_model":
                attack_indicating_model
                if finding == "CONFLICTING_MODEL_EVIDENCE"
                else (
                    "Random Forest + XGBoost"
                    if rf_attack != "Benign"
                    else None
                ),

            # ------------------------------------------------
            # Investigation explanation
            # ------------------------------------------------

            "explanation":
                explanation,

            "conclusion":
                conclusion
        }


# ============================================================
# CREATE AGENT INSTANCE
# ============================================================

investigation_agent = InvestigationAgent()