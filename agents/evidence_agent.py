from evidence.evidence_retriever import get_evidence_for_attack
from evidence.flow_evidence_service import score_flow


# ============================================================
# FLOW-EVIDENCE THRESHOLDS
# ============================================================

FLOW_EVIDENCE_TRIGGER_THRESHOLD = 0.90
FLOW_EVIDENCE_REVIEW_THRESHOLD = 0.80


class EvidenceAgent:
    """
    Evidence Agent

    Responsibilities:
    1. Receive Investigation Agent result.
    2. Receive Rare Family Detector result.
    3. Determine suspected attack family.
    4. Independently calculate raw-flow evidence.
    5. Retrieve authoritative cybersecurity evidence.
    6. Return structured evidence for the Decision Agent.
    """

    def __init__(self):
        self.name = "Evidence Agent"

    def analyze(
        self,
        investigation_result,
        flow=None,
        rare_result=None
    ):
        """
        Analyze investigation results and retrieve supporting evidence.

        Parameters
        ----------
        investigation_result : dict
            Result from Investigation Agent.

        flow : pandas Series / dict-like, optional
            Raw network-flow features.

        rare_result : dict, optional
            Result from Rare Family Detector.
        """

        # ====================================================
        # VALIDATE INPUT
        # ====================================================

        if not isinstance(investigation_result, dict):

            return {
                "agent": self.name,
                "evidence_state": "INVALID_INPUT",
                "evidence_found": False,
                "requires_review": True,
                "message":
                    "Investigation result must be a dictionary.",

                "flow_evidence_score": None,
                "flow_evidence_level": None,
                "flow_evidence_triggered": False,

                "rare_family_triggered": False,
                "rare_family": None,
                "rare_probability": None,
            }

        # ====================================================
        # READ RARE-FAMILY DETECTOR RESULT
        # ====================================================

        rare_family_triggered = False
        rare_family = None
        rare_probability = None

        if isinstance(rare_result, dict):

            rare_family_triggered = bool(
                rare_result.get(
                    "any_triggered",
                    False
                )
            )

            rare_family = rare_result.get(
                "top_family"
            )

            rare_probability = rare_result.get(
                "top_probability"
            )

        # ====================================================
        # DETERMINE ATTACK FROM GENERAL ML MODELS
        # ====================================================

        attack = investigation_result.get(
            "random_forest_attack"
        )

        xgb_attack = investigation_result.get(
            "xgboost_attack"
        )

        # If RF says Benign but XGBoost identifies an attack,
        # prefer the non-benign result.

        if (
            attack in [None, "Benign"]
            and xgb_attack not in [None, "Benign"]
        ):

            attack = xgb_attack

        # ====================================================
        # RARE FAMILY OVERRIDE
        # ====================================================

        # Dedicated rare-family models can identify attacks
        # that the general RF/XGBoost multiclass models fail
        # to classify correctly.

        if (
            rare_family_triggered
            and rare_family
        ):

            attack = rare_family

        # ====================================================
        # INDEPENDENT FLOW EVIDENCE
        # ====================================================

        flow_evidence_score = None
        flow_evidence_level = None
        flow_evidence_triggered = False

        # IMPORTANT:
        #
        # Flow evidence is an independent signal.
        # Therefore it is calculated whenever a raw flow is
        # available, regardless of whether ML or the rare
        # detector has already identified an attack.
        #
        # This gives us:
        #
        # ML Detection
        #      +
        # Rare Detector
        #      +
        # Flow Evidence
        #
        # instead of using flow evidence only when ML says Benign.

        if flow is not None:

            try:

                flow_evidence_score, flow_evidence_level = (
                    score_flow(flow)
                )

            except Exception:

                flow_evidence_score = None
                flow_evidence_level = None

            # Strong flow evidence independently indicates
            # behavior consistent with Infiltration.

            if (
                flow_evidence_score is not None
                and
                flow_evidence_score
                >= FLOW_EVIDENCE_TRIGGER_THRESHOLD
            ):

                flow_evidence_triggered = True

                # Only use flow evidence to identify
                # Infiltration when there is no stronger
                # attack-family signal already available.

                if attack in [None, "Benign"]:

                    attack = "Infiltration"

        # ====================================================
        # NO ATTACK REQUIRING EVIDENCE
        # ====================================================

        if attack in [None, "Benign"]:

            flagged_for_review = (
                flow_evidence_level == "high"
                or
                flow_evidence_level == "moderate"
            )

            return {

                "agent":
                    self.name,

                "evidence_state":
                    "NO_ATTACK_EVIDENCE_REQUIRED",

                "evidence_found":
                    False,

                "requires_review":
                    flagged_for_review,

                "attack":
                    "Benign",

                # Rare detector information
                "rare_family_triggered":
                    rare_family_triggered,

                "rare_family":
                    rare_family,

                "rare_probability":
                    rare_probability,

                # Flow evidence
                "flow_evidence_score":
                    flow_evidence_score,

                "flow_evidence_level":
                    flow_evidence_level,

                "flow_evidence_triggered":
                    flow_evidence_triggered,

                "message":
                    (
                        "No confirmed attack was identified "
                        "for evidence retrieval."
                        +
                        (
                            " Flow-level behavioral analysis "
                            "flagged this flow for review "
                            f"(level: {flow_evidence_level})."
                            if flagged_for_review
                            else ""
                        )
                    ),
            }

        # ====================================================
        # RETRIEVE AUTHORITATIVE EVIDENCE
        # ====================================================

        try:

            evidence = get_evidence_for_attack(
                attack
            )

        except Exception as e:

            return {

                "agent":
                    self.name,

                "evidence_state":
                    "EVIDENCE_RETRIEVAL_FAILED",

                "evidence_found":
                    False,

                "requires_review":
                    True,

                "attack":
                    attack,

                "rare_family_triggered":
                    rare_family_triggered,

                "rare_family":
                    rare_family,

                "rare_probability":
                    rare_probability,

                "error":
                    type(e).__name__,

                "message":
                    "Evidence retrieval failed.",

                "flow_evidence_score":
                    flow_evidence_score,

                "flow_evidence_level":
                    flow_evidence_level,

                "flow_evidence_triggered":
                    flow_evidence_triggered,
            }

        # ====================================================
        # EVIDENCE NOT FOUND
        # ====================================================

        if not evidence:

            return {

                "agent":
                    self.name,

                "evidence_state":
                    "EVIDENCE_NOT_FOUND",

                "evidence_found":
                    False,

                "requires_review":
                    True,

                "attack":
                    attack,

                "rare_family_triggered":
                    rare_family_triggered,

                "rare_family":
                    rare_family,

                "rare_probability":
                    rare_probability,

                "message":
                    (
                        "No authoritative evidence was found "
                        "for the suspected attack."
                    ),

                "flow_evidence_score":
                    flow_evidence_score,

                "flow_evidence_level":
                    flow_evidence_level,

                "flow_evidence_triggered":
                    flow_evidence_triggered,
            }

        # ====================================================
        # EXTRACT EVIDENCE DATA
        # ====================================================

        evidence_data = evidence.get(
            "evidence",
            {}
        )

        # ====================================================
        # SUCCESSFUL EVIDENCE RESULT
        # ====================================================

        return {

            "agent":
                self.name,

            "evidence_state":
                "EVIDENCE_RETRIEVED",

            "evidence_found":
                True,

            "requires_review":
                False,

            "attack":
                attack,

            # ------------------------------------------------
            # RARE FAMILY
            # ------------------------------------------------

            "rare_family_triggered":
                rare_family_triggered,

            "rare_family":
                rare_family,

            "rare_probability":
                rare_probability,

            # ------------------------------------------------
            # AUTHORITATIVE SOURCE
            # ------------------------------------------------

            "source_name":
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

            # ------------------------------------------------
            # EVIDENCE CONTENT
            # ------------------------------------------------

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

            "investigation_guidance":
                evidence_data.get(
                    "detection_guidance",
                    evidence_data.get(
                        "investigation_guidance",
                        []
                    )
                ),

            "mitigation_guidance":
                evidence_data.get(
                    "mitigation_guidance",
                    []
                ),

            # ------------------------------------------------
            # INDEPENDENT FLOW EVIDENCE
            # ------------------------------------------------

            "flow_evidence_score":
                flow_evidence_score,

            "flow_evidence_level":
                flow_evidence_level,

            "flow_evidence_triggered":
                flow_evidence_triggered,

            # ------------------------------------------------
            # MESSAGE
            # ------------------------------------------------

            "message":
                (
                    "Rare-family detector flagged "
                    f"{rare_family} "
                    f"(probability={rare_probability:.3f}); "
                    "independent flow evidence was also "
                    f"calculated at "
                    f"{flow_evidence_score:.3f} "
                    f"(level={flow_evidence_level}), "
                    "and authoritative evidence was retrieved."
                    if (
                        rare_family_triggered
                        and rare_family
                        and isinstance(
                            rare_probability,
                            (int, float)
                        )
                        and isinstance(
                            flow_evidence_score,
                            (int, float)
                        )
                    )
                    else
                    (
                        "Rare-family detector flagged "
                        f"{rare_family}; independent flow "
                        "evidence was calculated and "
                        "authoritative evidence was retrieved."
                        if (
                            rare_family_triggered
                            and rare_family
                            and flow_evidence_score is not None
                        )
                        else
                        (
                            "Rare-family detector flagged "
                            f"{rare_family} and authoritative "
                            "evidence was retrieved."
                            if (
                                rare_family_triggered
                                and rare_family
                            )
                            else
                            (
                                "Independent flow-level "
                                "behavioral evidence detected "
                                "a strong pattern consistent "
                                "with Infiltration, and "
                                "authoritative evidence was "
                                "retrieved."
                                if flow_evidence_triggered
                                else
                                "Authoritative cybersecurity "
                                "evidence was retrieved for "
                                "the suspected attack."
                            )
                        )
                    )
                ),
        }


# ============================================================
# AGENT INSTANCE
# ============================================================

evidence_agent = EvidenceAgent()