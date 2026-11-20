# ============================================================
# DECISION / CORRELATION AGENT  (v5 - exact finding match + rare-family arbitration)
# ============================================================
#
# CHANGES FROM v2
#   1. FIX: fallback label logic treated the string "Benign" as a real
#      attack label, producing REVIEW + final_attack="Benign".
#      All fallbacks now go through _first_real().
#   2. NEW: optional 4th argument rare_result (from
#      detection/rare_family_detector.py). When a dedicated Infiltration
#      or Heartbleed detector fires, it names the family and can
#      escalate the decision. If rare_result is None, behaviour is v2.
#   3. FIX: preserve flow_evidence_level and flow_evidence_triggered
#      from the Evidence Agent in the final Decision Agent result.
# ============================================================

from pipeline.evidence_trail import build_evidence_trail


RARE_ATTACK_PROB = 0.80      # rare detector prob for ATTACK + label override

_NON_LABELS = {"", "benign", "unknown", "suspicious", "none"}


def _real(label):
    """True only for a genuine attack-family label."""
    return label is not None and str(label).strip().lower() not in _NON_LABELS


def _first_real(*labels, default="Suspicious"):
    for label in labels:
        if _real(label):
            return label
    return default


def _clamp(x):
    return max(0.0, min(1.0, float(x)))


def _near_decision_threshold(probability, margin=0.05):
    """A cautious review band around the existing 0.50 rule threshold."""
    return abs(_clamp(probability) - 0.50) <= margin


class DecisionAgent:

    def __init__(self):
        self.name = "Decision / Correlation Agent"

    def analyze(
        self,
        detection_result,
        investigation_result,
        evidence_result,
        rare_result=None,
        threat_intel_result=None
    ):
        # ====================================================
        # DETECTION INFORMATION
        # ====================================================

        detection_state = detection_result.get(
            "detection_state",
            "UNKNOWN"
        )

        model_agreement = detection_result.get(
            "model_agreement",
            False
        )

        predicted_attack = detection_result.get(
            "predicted_attack"
        )

        rf_result = detection_result.get(
            "random_forest",
            {}
        )

        xgb_result = detection_result.get(
            "xgboost",
            {}
        )

        rf_attack = rf_result.get(
            "attack_family",
            "Unknown"
        )

        xgb_attack = xgb_result.get(
            "attack_family",
            "Unknown"
        )

        rf_confidence = float(
            rf_result.get(
                "confidence",
                0.0
            )
        )

        xgb_confidence = float(
            xgb_result.get(
                "confidence",
                0.0
            )
        )

        # ====================================================
        # INVESTIGATION INFORMATION
        # ====================================================

        investigation_severity = investigation_result.get(
            "severity",
            "LOW"
        )

        probability_difference = float(
            investigation_result.get(
                "probability_difference",
                0.0
            )
        )

        investigation_finding = (
            investigation_result.get("finding")
            or investigation_result.get("investigation_finding")
            or "UNKNOWN"
        )

        investigation_required = bool(
            investigation_result.get(
                "investigation_required",
                False
            )
        )

        # EXACT match:
        # "NO_ATTACK_INDICATED" must NOT count as attack
        finding_indicates_attack = (
            str(investigation_finding).strip().upper()
            == "ATTACK_INDICATED"
        )

        rf_attack_probability = float(
            investigation_result.get(
                "random_forest_attack_probability",
                0.0
            )
        )

        xgb_attack_probability = float(
            investigation_result.get(
                "xgboost_attack_probability",
                0.0
            )
        )

        rf_benign_probability = float(
            investigation_result.get(
                "random_forest_benign_probability",
                1.0 - rf_attack_probability
            )
        )

        xgb_benign_probability = float(
            investigation_result.get(
                "xgboost_benign_probability",
                1.0 - xgb_attack_probability
            )
        )

        average_attack_probability = float(
            investigation_result.get(
                "average_attack_probability",
                (
                    rf_attack_probability
                    + xgb_attack_probability
                ) / 2.0
            )
        )

        rf_attack_probability = _clamp(
            rf_attack_probability
        )

        xgb_attack_probability = _clamp(
            xgb_attack_probability
        )

        rf_benign_probability = _clamp(
            rf_benign_probability
        )

        xgb_benign_probability = _clamp(
            xgb_benign_probability
        )

        average_attack_probability = _clamp(
            average_attack_probability
        )

        # ====================================================
        # EVIDENCE INFORMATION
        # ====================================================

        evidence_found = evidence_result.get(
            "evidence_found",
            False
        )

        evidence_attack_family = (
            evidence_result.get("attack_family")
            or evidence_result.get("attack")
        )

        if not _real(evidence_attack_family):
            evidence_attack_family = None

        evidence_confidence = float(
            evidence_result.get(
                "confidence",
                0.0
            )
        )

        threat_intel_result = threat_intel_result or {}
        threat_intel_matched = bool(
            threat_intel_result.get("matched", False)
        )
        threat_intel_confidence = _clamp(
            threat_intel_result.get("max_confidence", 0.0) or 0.0
        )
        threat_intel_family = threat_intel_result.get("family")

        # ----------------------------------------------------
        # FLOW EVIDENCE
        # ----------------------------------------------------

        raw_flow_evidence_score = evidence_result.get(
            "flow_evidence_score"
        )

        flow_evidence_score = _clamp(
            raw_flow_evidence_score
            if raw_flow_evidence_score is not None
            else 0.0
        )

        # FIX:
        # Preserve the qualitative flow-evidence level produced
        # by the Evidence Agent.
        #
        # Possible values from flow_evidence.py include:
        #   very_high
        #   high
        #   moderate
        #   low
        #
        flow_evidence_level = evidence_result.get(
            "flow_evidence_level"
        )

        # FIX:
        # Preserve whether flow evidence independently triggered
        # the Infiltration candidate logic.
        flow_evidence_triggered = bool(
            evidence_result.get(
                "flow_evidence_triggered",
                False
            )
        )

        flow_indicators = evidence_result.get(
            "indicators",
            []
        )

        if not isinstance(flow_indicators, list):
            flow_indicators = []

        # ====================================================
        # RARE-FAMILY DETECTOR (optional)
        # ====================================================

        rare_available = bool(
            isinstance(
                rare_result,
                dict
            )
            and rare_result.get(
                "available"
            )
        )

        rare_triggered = bool(
            rare_available
            and rare_result.get(
                "any_triggered"
            )
        )

        rare_family = (
            rare_result.get(
                "top_family"
            )
            if rare_triggered
            else None
        )

        rare_prob = (
            float(
                rare_result.get(
                    "top_probability",
                    0.0
                )
            )
            if rare_triggered
            else 0.0
        )

        rare_scores = (
            rare_result.get(
                "scores",
                {}
            )
            if rare_available
            else {}
        )

        # Flow evidence names a family the dedicated detector
        # covers, but that detector did NOT confirm it.
        # Evidence alone is not enough in that situation.

        evidence_family_unconfirmed = bool(
            rare_available
            and not rare_triggered
            and evidence_attack_family is not None
            and str(
                evidence_attack_family
            ).lower()
            in {
                str(k).lower()
                for k in rare_scores
            }
        )

        # ====================================================
        # CORRELATION SCORE
        # ====================================================

        correlation_score = 0.0

        reasons = []
        contribution_weights = {}

        if evidence_family_unconfirmed:
            reasons.append(
                f"Flow evidence points to "
                f"{evidence_attack_family}, but the "
                "dedicated detector did not confirm it, "
                "so flow evidence alone is not escalated."
            )

        # ----------------------------------------------------
        # SIGNAL 1: MODEL AGREEMENT
        # ----------------------------------------------------

        if model_agreement:

            correlation_score += 0.30
            contribution_weights["model_agreement"] = 0.30

            reasons.append(
                "Random Forest and XGBoost agree on the predicted "
                "class."
            )

        else:

            reasons.append(
                "Random Forest and XGBoost disagree on the predicted "
                "class"
            )

        # ----------------------------------------------------
        # SIGNAL 2: MODEL CONFIDENCE
        # ----------------------------------------------------

        minimum_model_confidence = min(
            rf_confidence,
            xgb_confidence
        )

        if minimum_model_confidence >= 0.90:

            correlation_score += 0.20
            contribution_weights["model_confidence"] = 0.20

            reasons.append(
                "Both ML models are confident in their predicted class."
            )

        elif minimum_model_confidence >= 0.70:

            correlation_score += 0.10
            contribution_weights["model_confidence"] = 0.10

            reasons.append(
                "The ML models have moderate-to-high prediction "
                "confidence."
            )

        class_says_benign = (
            str(rf_attack).lower() == "benign"
            and str(xgb_attack).lower() == "benign"
        )

        if class_says_benign and average_attack_probability >= 0.80:

            reasons.append(
                "Class prediction (Benign) and binary attack score "
                f"({average_attack_probability:.2f}) disagree; the "
                "class confidence above refers to the Benign class, "
                "not to an attack."
            )

        # ----------------------------------------------------
        # SIGNAL 3: ACTUAL ATTACK PROBABILITY
        # ----------------------------------------------------

        if average_attack_probability >= 0.80:

            correlation_score += 0.15
            contribution_weights["attack_probability"] = 0.15

            reasons.append(
                "The models provide a strong overall attack "
                "probability "
                f"(average={average_attack_probability:.3f})."
            )

        elif average_attack_probability >= 0.50:

            correlation_score += 0.10
            contribution_weights["attack_probability"] = 0.10

            reasons.append(
                "The models provide moderate overall attack "
                "probability "
                f"(average={average_attack_probability:.3f})."
            )

        elif average_attack_probability <= 0.10:

            reasons.append(
                "The models provide a low overall attack probability "
                f"(average={average_attack_probability:.3f})."
            )

        # ----------------------------------------------------
        # SIGNAL 4: PROBABILITY AGREEMENT
        # ----------------------------------------------------

        if probability_difference <= 0.10:

            correlation_score += 0.10
            contribution_weights["probability_alignment"] = 0.10

            reasons.append(
                "RF and XGBoost attack probabilities are closely "
                "aligned."
            )

        elif probability_difference >= 0.40:

            reasons.append(
                "RF and XGBoost attack probabilities show substantial "
                "disagreement."
            )

        # ----------------------------------------------------
        # SIGNAL 5: INVESTIGATION SEVERITY
        # ----------------------------------------------------

        if investigation_severity == "HIGH":

            correlation_score += 0.15
            contribution_weights["investigation_severity"] = 0.15

            reasons.append(
                "Investigation Agent classified the flow as HIGH "
                "severity."
            )

        elif investigation_severity == "MEDIUM":

            correlation_score += 0.10
            contribution_weights["investigation_severity"] = 0.10

            reasons.append(
                "Investigation Agent classified the flow as MEDIUM "
                "severity."
            )

        # ----------------------------------------------------
        # SIGNAL 6: INVESTIGATION FINDING
        # ----------------------------------------------------

        if finding_indicates_attack:

            correlation_score += 0.20
            contribution_weights["investigation_finding"] = 0.20

            reasons.append(
                "Investigation Agent's finding is ATTACK_INDICATED, "
                "independent of the raw ML probability."
            )

        # ----------------------------------------------------
        # SIGNAL 7: AUTHORITATIVE EVIDENCE
        # ----------------------------------------------------

        if evidence_found:

            correlation_score += 0.10
            contribution_weights["reference_doc"] = 0.10

            reasons.append(
                "Authoritative cybersecurity evidence was found "
                "for the predicted attack."
            )

        if threat_intel_matched:
            contribution_weights["threat_intel"] = min(0.20, 0.20 * threat_intel_confidence)
            correlation_score += contribution_weights["threat_intel"]
            reasons.append(
                "A flow indicator matched an imported threat-intelligence feed "
                f"(confidence={threat_intel_confidence:.3f})."
            )

        # ----------------------------------------------------
        # SIGNAL 8: FLOW-LEVEL EVIDENCE
        # ----------------------------------------------------

        if flow_evidence_score >= 0.70:

            correlation_score += 0.15
            contribution_weights["flow_evidence"] = 0.15

            reasons.append(
                "Strong flow-level behavioral evidence supports "
                "the security finding."
            )

        elif flow_evidence_score >= 0.40:

            correlation_score += 0.08
            contribution_weights["flow_evidence"] = 0.08

            reasons.append(
                "Moderate flow-level behavioral evidence supports "
                "the security finding."
            )

        correlation_score = min(
            correlation_score,
            1.0
        )

        # ====================================================
        # FINAL DECISION LOGIC
        # ====================================================

        final_decision = "BENIGN"
        final_attack = "Benign"

        # Production probabilities are currently uncalibrated. Do not make a
        # hard attack/benign call when the correlated score is close to 0.50.
        if model_agreement and _near_decision_threshold(average_attack_probability):
            final_decision = "REVIEW"
            final_attack = _first_real(predicted_attack, rf_attack, xgb_attack)
            reasons.append(
                "Final decision: REVIEW because the raw combined attack probability "
                "is close to the 0.50 decision boundary; this score is not calibrated."
            )

        # ----------------------------------------------------
        # CASE 1: Strong agreed attack
        # ----------------------------------------------------

        elif (
            model_agreement
            and _real(predicted_attack)
            and average_attack_probability >= 0.50
        ):

            final_decision = "ATTACK"

            final_attack = predicted_attack

            reasons.append(
                "Final decision: attack because the models agree on "
                "a non-benign family and provide meaningful attack "
                "probability."
            )

        # ----------------------------------------------------
        # CASE 2: Model disagreement + strong evidence
        # ----------------------------------------------------

        elif (
            not model_agreement
            and average_attack_probability >= 0.50
            and (
                evidence_found
                or flow_evidence_score >= 0.70
                or investigation_severity == "HIGH"
            )
        ):

            final_decision = "ATTACK"

            final_attack = _first_real(
                evidence_attack_family,
                rf_attack,
                xgb_attack
            )

            reasons.append(
                "Final decision: attack because model probabilities "
                "and independent evidence support malicious activity "
                "despite model disagreement."
            )

        # ----------------------------------------------------
        # CASE 3: ML low probability, but investigation says attack
        # ----------------------------------------------------

        elif (
            average_attack_probability < 0.50
            and finding_indicates_attack
            and (
                evidence_found
                or flow_evidence_score >= 0.40
                or investigation_severity in (
                    "HIGH",
                    "MEDIUM"
                )
            )
        ):

            final_decision = (
                "ATTACK"
                if correlation_score >= 0.55
                else "REVIEW"
            )

            final_attack = _first_real(
                evidence_attack_family,
                predicted_attack,
                rf_attack,
                xgb_attack
            )

            reasons.append(
                f"Final decision: {final_decision} because the "
                "Investigation Agent's finding indicates attack "
                "behavior and supporting evidence exists, even "
                "though the raw ML attack probability is low."
            )

        # ----------------------------------------------------
        # CASE 4: Low ML probability but strong flow-level evidence
        # ----------------------------------------------------

        elif (
            average_attack_probability < 0.50
            and not evidence_family_unconfirmed
            and (
                (
                    flow_evidence_score >= 0.80
                    and (
                        finding_indicates_attack
                        or evidence_found
                        or investigation_severity in (
                            "HIGH",
                            "MEDIUM"
                        )
                    )
                )
                or (
                    evidence_found
                    and investigation_severity == "HIGH"
                )
            )
        ):

            final_decision = "REVIEW"

            final_attack = _first_real(
                evidence_attack_family,
                predicted_attack,
                rf_attack,
                xgb_attack
            )

            reasons.append(
                "Final decision: REVIEW because independent evidence "
                "is strong even though ML attack probability is below "
                "the attack threshold."
            )

        # ----------------------------------------------------
        # CASE 5: Model disagreement
        # ----------------------------------------------------

        elif not model_agreement:

            final_decision = "REVIEW"

            final_attack = _first_real(
                rf_attack,
                xgb_attack
            )

            reasons.append(
                "Final decision: REVIEW because the ML models disagree."
            )

        # ----------------------------------------------------
        # CASE 6: Investigation says high severity
        # ----------------------------------------------------

        elif investigation_severity == "HIGH":

            final_decision = "REVIEW"

            final_attack = _first_real(
                predicted_attack,
                evidence_attack_family,
                rf_attack,
                xgb_attack
            )

            reasons.append(
                "Final decision: REVIEW because investigation severity "
                "is HIGH."
            )

        # ----------------------------------------------------
        # CASE 7: Strong flow evidence
        # ----------------------------------------------------

        elif (
            flow_evidence_score >= 0.70
            and average_attack_probability >= 0.20
            and not evidence_family_unconfirmed
        ):

            final_decision = "REVIEW"

            final_attack = _first_real(
                evidence_attack_family,
                predicted_attack,
                rf_attack,
                xgb_attack
            )

            reasons.append(
                "Final decision: REVIEW because strong flow-level "
                "evidence was detected."
            )

        # ----------------------------------------------------
        # CASE 8: Otherwise benign
        # ----------------------------------------------------

        else:

            final_decision = "BENIGN"

            final_attack = "Benign"

            reasons.append(
                "Final decision: BENIGN because no sufficiently strong "
                "correlated attack evidence was found."
            )

        # ====================================================
        # RARE-FAMILY OVERRIDE
        # ====================================================

        # Exact IOC matches from imported feeds are reviewed according to
        # feed confidence. They never execute containment actions.
        if threat_intel_matched:
            if threat_intel_confidence >= 0.90:
                final_decision = "ATTACK"
            elif final_decision == "BENIGN":
                final_decision = "REVIEW"
            if _real(threat_intel_family) and not _real(final_attack):
                final_attack = threat_intel_family
            elif not _real(final_attack):
                final_attack = "Suspicious"
            reasons.append(
                "Threat-intelligence match escalated the flow according to its confidence."
            )

        if rare_triggered and rare_family:

            previous_correlation_score = correlation_score
            correlation_score = min(
                1.0,
                correlation_score + 0.20
            )
            contribution_weights["rare_family"] = (
                correlation_score - previous_correlation_score
            )

            if rare_prob >= RARE_ATTACK_PROB:

                final_decision = "ATTACK"

            elif final_decision == "BENIGN":

                final_decision = "REVIEW"

            if (
                not _real(final_attack)
                or rare_prob >= RARE_ATTACK_PROB
            ):

                final_attack = rare_family

            reasons.append(
                f"Rare-family detector flagged {rare_family} "
                f"(probability={rare_prob:.3f}); the general "
                "RF/XGBoost models cannot recognise this family, "
                "so the dedicated detector names it."
            )

        # ====================================================
        # SAFETY NET
        # ====================================================

        if (
            final_decision in (
                "ATTACK",
                "REVIEW"
            )
            and not _real(final_attack)
        ):

            final_attack = "Suspicious"

        # ====================================================
        # DECISION CONFIDENCE
        # ====================================================

        if final_decision == "ATTACK":

            decision_confidence = min(
                1.0,
                0.50
                + (
                    correlation_score
                    * 0.50
                )
            )

        elif final_decision == "REVIEW":

            decision_confidence = min(
                1.0,
                0.40
                + (
                    correlation_score
                    * 0.40
                )
            )

        else:

            benign_confidence = (
                1.0
                - average_attack_probability
            )

            decision_confidence = min(
                1.0,
                max(
                    0.0,
                    (
                        benign_confidence
                        * 0.70
                    )
                    + (
                        (1.0 - flow_evidence_score)
                        * 0.30
                    )
                )
            )

        # ====================================================
        # RETURN FINAL RESULT
        # ====================================================

        evidence_trail, cited_reasons = build_evidence_trail(
            detection_result,
            investigation_result,
            evidence_result,
            rare_result,
            threat_intel_result,
            contribution_weights,
            reasons,
        )

        return {

            "agent":
                self.name,

            "final_decision":
                final_decision,

            "final_attack":
                final_attack,

            "decision_confidence":
                round(
                    decision_confidence,
                    4
                ),

            "correlation_score":
                round(
                    correlation_score,
                    4
                ),

            "correlation_reasons":
                cited_reasons,

            "evidence_trail":
                evidence_trail,

            # ------------------------------------------------
            # DETECTION
            # ------------------------------------------------

            "detection_state":
                detection_state,

            "model_agreement":
                model_agreement,

            "predicted_attack":
                predicted_attack,

            "random_forest_attack":
                rf_attack,

            "xgboost_attack":
                xgb_attack,

            "random_forest_confidence":
                round(
                    rf_confidence,
                    6
                ),

            "xgboost_confidence":
                round(
                    xgb_confidence,
                    6
                ),

            # ------------------------------------------------
            # MODEL PROBABILITIES
            # ------------------------------------------------

            "random_forest_attack_probability":
                round(
                    rf_attack_probability,
                    6
                ),

            "xgboost_attack_probability":
                round(
                    xgb_attack_probability,
                    6
                ),

            "random_forest_benign_probability":
                round(
                    rf_benign_probability,
                    6
                ),

            "xgboost_benign_probability":
                round(
                    xgb_benign_probability,
                    6
                ),

            "average_attack_probability":
                round(
                    average_attack_probability,
                    6
                ),

            "probability_difference":
                round(
                    probability_difference,
                    6
                ),

            # ------------------------------------------------
            # INVESTIGATION
            # ------------------------------------------------

            "investigation_severity":
                investigation_severity,

            "investigation_finding":
                investigation_finding,

            "investigation_required":
                investigation_required,

            # ------------------------------------------------
            # EVIDENCE
            # ------------------------------------------------

            "evidence_found":
                evidence_found,

            "evidence_attack_family":
                evidence_attack_family,

            "evidence_confidence":
                round(
                    evidence_confidence,
                    6
                ),

            # ------------------------------------------------
            # FLOW EVIDENCE
            # ------------------------------------------------

            "flow_evidence_score":
                round(
                    flow_evidence_score,
                    6
                ),

            "flow_evidence_level":
                flow_evidence_level,

            "flow_evidence_triggered":
                flow_evidence_triggered,

            "flow_indicators":
                flow_indicators,

            # ------------------------------------------------
            # RARE FAMILY
            # ------------------------------------------------

            "rare_family_available":
                rare_available,

            "rare_family_triggered":
                rare_triggered,

            "rare_family":
                rare_family,

            "rare_family_probability":
                round(
                    rare_prob,
                    6
                ),

            "rare_family_scores":
                rare_scores,

            "threat_intel_matched":
                threat_intel_matched,

            "threat_intel_confidence":
                round(threat_intel_confidence, 6),

            "threat_intel_family":
                threat_intel_family,

            # ------------------------------------------------
            # EXPLANATION
            # ------------------------------------------------

            "explanation":
                " ".join(cited_reasons)
        }


# ============================================================
# CREATE AGENT INSTANCE
# ============================================================

decision_agent = DecisionAgent()
