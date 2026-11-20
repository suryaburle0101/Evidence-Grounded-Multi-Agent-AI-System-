from detection.model_predictor import (
    predict_attack_family
)


class DetectionAgent:
    """
    Detection Agent

    Responsible for:
    1. Running Random Forest detection
    2. Running XGBoost detection
    3. Comparing their predictions
    4. Reporting model agreement/disagreement

    This agent does NOT make the final incident-response
    decision. That responsibility belongs to later agents.
    """

    def __init__(self):
        self.name = "Detection Agent"

    # ========================================================
    # RUN SINGLE MODEL
    # ========================================================

    def run_model(self, X, model_type):
        """
        Run one ML model against the supplied network flow.
        """

        result = predict_attack_family(
            X,
            model_type=model_type
        )

        return result

    # ========================================================
    # RUN DETECTION
    # ========================================================

    def analyze(self, X, model_types=None, precomputed_results=None):
        """
        Run both Random Forest and XGBoost.

        Returns a structured result that can later be
        consumed by other cybersecurity agents.
        """

        selected = tuple(model_types or ("random_forest", "xgboost"))
        supported = {"random_forest", "xgboost"}
        if not selected or not set(selected).issubset(supported):
            raise ValueError("model_types must contain random_forest and/or xgboost")

        if precomputed_results is not None:
            results = {name: precomputed_results[name] for name in selected}
            rf_result = results.get("random_forest")
            xgb_result = results.get("xgboost")
            if rf_result is not None and xgb_result is not None:
                rf_attack = rf_result["attack_family"]
                xgb_attack = xgb_result["attack_family"]
                agreement = rf_attack == xgb_attack
                detection_state = (
                    "BENIGN" if agreement and rf_attack == "Benign"
                    else "ATTACK_DETECTED" if agreement
                    else "MODEL_DISAGREEMENT"
                )
                combined_confidence = (
                    min(rf_result["confidence"], xgb_result["confidence"])
                    if agreement else None
                )
            else:
                model_result = rf_result or xgb_result
                attack = model_result["attack_family"]
                agreement = True
                detection_state = "BENIGN" if attack == "Benign" else "ATTACK_DETECTED"
                combined_confidence = model_result["confidence"]
        # Keep the established production path unchanged when both models run.
        elif set(selected) == supported:
            # ----------------------------------------------------
            # Random Forest
            # ----------------------------------------------------

            rf_result = self.run_model(X, "random_forest")

        # ----------------------------------------------------
        # XGBoost
        # ----------------------------------------------------

            xgb_result = self.run_model(X, "xgboost")

        # ----------------------------------------------------
        # Extract predictions
        # ----------------------------------------------------

            rf_attack = rf_result["attack_family"]
            xgb_attack = xgb_result["attack_family"]

        # ----------------------------------------------------
        # Model agreement
        # ----------------------------------------------------

            agreement = (
            rf_attack == xgb_attack
        )

        # ----------------------------------------------------
        # Determine detection state
        # ----------------------------------------------------

            if agreement:

                if rf_attack == "Benign":
                    detection_state = "BENIGN"

                else:
                    detection_state = "ATTACK_DETECTED"

            else:

                detection_state = "MODEL_DISAGREEMENT"

        # ----------------------------------------------------
        # Combined confidence
        # ----------------------------------------------------

            if agreement:

                combined_confidence = min(
                    rf_result["confidence"],
                    xgb_result["confidence"]
                )

            else:

                combined_confidence = None

        else:
            results = {name: self.run_model(X, name) for name in selected}
            model_result = next(iter(results.values()))
            attack = model_result["attack_family"]
            agreement = True
            detection_state = "BENIGN" if attack == "Benign" else "ATTACK_DETECTED"
            combined_confidence = model_result["confidence"]
            rf_result = results.get("random_forest")
            xgb_result = results.get("xgboost")

        # ----------------------------------------------------
        # Return agent output
        # ----------------------------------------------------

        return {
            "agent": self.name,

            "detection_state":
                detection_state,

            "model_agreement":
                agreement,

            "predicted_attack": (rf_result or xgb_result)["attack_family"] if agreement else None,

            "combined_confidence":
                combined_confidence,

            **({"random_forest": rf_result} if rf_result is not None else {}),
            **({"xgboost": xgb_result} if xgb_result is not None else {}),

            "requires_investigation":
                not agreement
        }


# ============================================================
# CREATE AGENT INSTANCE
# ============================================================

detection_agent = DetectionAgent()
