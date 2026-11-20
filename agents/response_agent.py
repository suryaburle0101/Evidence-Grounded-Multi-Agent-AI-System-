class ResponseAgent:
    """
    Response Agent (v2 - decision-aware)

    Responsibilities:
    1. Receive investigation findings, evidence AND the final
       decision from the Decision / Correlation Agent.
    2. Determine the appropriate incident-response action.
    3. Provide containment, investigation, and mitigation steps.
    4. Return a structured response for the orchestrator.

    CHANGE FROM v1:
        v1 ignored the Decision Agent, so a flow escalated to
        ATTACK/REVIEW (e.g. stealthy Infiltration) could still get
        NO_RESPONSE_REQUIRED. v2 treats the decision as primary.
        decision_result is optional, so old call sites still work.
    """

    def __init__(self):
        self.name = "Response Agent"

    def analyze(
        self,
        investigation_result,
        evidence_result,
        decision_result=None,
        risk_result=None
    ):
        # ----------------------------------------------------
        # Validate input
        # ----------------------------------------------------
        if not isinstance(investigation_result, dict):
            return {
                "agent": self.name,
                "response_state": "INVALID_INPUT",
                "requires_action": False,
                "message": "Invalid investigation result."
            }

        if not isinstance(evidence_result, dict):
            return {
                "agent": self.name,
                "response_state": "INVALID_INPUT",
                "requires_action": False,
                "message": "Invalid evidence result."
            }

        if decision_result is not None and not isinstance(decision_result, dict):
            decision_result = None

        # ----------------------------------------------------
        # Extract information
        # ----------------------------------------------------
        finding = investigation_result.get("finding", "UNKNOWN")
        severity = investigation_result.get("severity", "LOW")
        risk_level = (risk_result or {}).get("level", "LOW")
        severity_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        if severity_rank.get(risk_level, 0) > severity_rank.get(str(severity).upper(), 0):
            severity = risk_level

        final_decision = (
            decision_result.get("final_decision")
            if decision_result else None
        )
        final_attack = (
            decision_result.get("final_attack")
            if decision_result else None
        )

        evidence_attack = evidence_result.get(
            "attack",
            investigation_result.get("random_forest_attack")
        )

        # Decision Agent's attack label wins when available
        if final_decision in ("ATTACK", "REVIEW") and final_attack:
            attack = final_attack
        elif final_decision == "BENIGN":
            attack = "Benign"
        else:
            attack = evidence_attack

        evidence_found = evidence_result.get("evidence_found", False)
        mitigation = evidence_result.get("mitigation_guidance", [])
        investigation = evidence_result.get("investigation_guidance", [])
        indicators = evidence_result.get("indicators", [])

        decision_info = {}
        if decision_result:
            decision_info = {
                "final_decision": final_decision,
                "decision_confidence":
                    decision_result.get("decision_confidence"),
                "correlation_score":
                    decision_result.get("correlation_score"),
                "decision_explanation":
                    decision_result.get("explanation", "")
            }

        # ----------------------------------------------------
        # No attack (decision says BENIGN, or no decision and
        # no attack label)
        # ----------------------------------------------------
        if final_decision == "BENIGN" or (
            final_decision is None and attack in [None, "Benign"]
        ):
            return {
                "agent": self.name,
                "response_state": "NO_RESPONSE_REQUIRED",
                "requires_action": False,
                "severity": "LOW",
                "attack": "Benign",
                "finding": finding,
                "recommended_actions": [],
                "message":
                    "No malicious activity requiring "
                    "incident response was identified.",
                **decision_info
            }

        if attack in [None, "Benign"]:
            attack = "Suspicious"

        # ----------------------------------------------------
        # REVIEW -> analyst review, not automatic containment
        # ----------------------------------------------------
        if final_decision == "REVIEW":
            actions = [
                "Route this flow to a security analyst for manual review.",
                "Review related network and endpoint activity for the "
                "source and destination hosts.",
                "Increase logging/monitoring on the affected hosts "
                "while the review is pending."
            ]
            actions.extend(mitigation)
            actions = list(dict.fromkeys(actions))

            return {
                "agent": self.name,
                "response_state": "ANALYST_REVIEW",
                "requires_action": True,
                "severity": severity,
                "attack": attack,
                "finding": finding,
                "evidence_found": evidence_found,
                "indicators": indicators,
                "investigation_actions": investigation,
                "recommended_actions": actions,
                "source_name": evidence_result.get("source_name", ""),
                "technique_id": evidence_result.get("technique_id", ""),
                "technique_name": evidence_result.get("technique_name", ""),
                "message":
                    "The correlation decision is REVIEW: evidence is "
                    "suggestive but not conclusive. Analyst review "
                    "is recommended before containment.",
                **decision_info
            }

        # ----------------------------------------------------
        # ATTACK (or legacy path without a decision)
        # ----------------------------------------------------
        effective_severity = severity
        if final_decision == "ATTACK" and severity not in ("CRITICAL", "HIGH", "MEDIUM"):
            # A confirmed ATTACK decision is never below MEDIUM
            effective_severity = "MEDIUM"

        if effective_severity in ("CRITICAL", "HIGH"):
            response_state = "IMMEDIATE_CONTAINMENT"
        elif effective_severity == "MEDIUM":
            response_state = "INVESTIGATION_AND_CONTAINMENT"
        else:
            response_state = "MONITOR_AND_INVESTIGATE"

        recommended_actions = []

        if effective_severity in ["HIGH", "MEDIUM"]:
            recommended_actions.append(
                "Isolate or restrict the suspected affected system "
                "where operationally appropriate."
            )
            recommended_actions.append(
                "Investigate the source and destination network "
                "connections associated with the suspicious flow."
            )

        recommended_actions.append(
            "Review related network and endpoint activity."
        )

        if mitigation:
            recommended_actions.extend(mitigation)

        recommended_actions = list(dict.fromkeys(recommended_actions))

        return {
            "agent": self.name,
            "response_state": response_state,
            "requires_action": True,
            "severity": effective_severity,
            "attack": attack,
            "finding": finding,
            "evidence_found": evidence_found,
            "indicators": indicators,
            "investigation_actions": investigation,
            "recommended_actions": recommended_actions,
            "source_name": evidence_result.get("source_name", ""),
            "technique_id": evidence_result.get("technique_id", ""),
            "technique_name": evidence_result.get("technique_name", ""),
            "message":
                "Incident-response actions were generated "
                "based on the correlated decision, investigation "
                "findings and available cybersecurity evidence.",
            **decision_info
        }


# ============================================================
# AGENT INSTANCE
# ============================================================

response_agent = ResponseAgent()
