"""Transparent likelihood-impact risk scoring with explainable factors."""

from __future__ import annotations


class RiskAnalyzer:
    CRITICALITY = {"low": 0.30, "medium": 0.60, "high": 0.82, "critical": 1.0}

    def analyze(self, decision: dict, investigation: dict, intel: dict | None = None,
                asset: dict | None = None) -> dict:
        decision = decision or {}
        investigation = investigation or {}
        intel = intel or {}
        asset = asset or {}
        outcome = str(decision.get("final_decision", "REVIEW")).upper()
        confidence = float(decision.get("decision_confidence", 0.0) or 0.0)
        attack_probability = float(decision.get("average_attack_probability", 0.0) or 0.0)
        severity = str(investigation.get("severity", "LOW")).upper()
        if outcome == "ATTACK":
            likelihood = max(0.70, confidence, attack_probability)
        elif outcome == "REVIEW":
            likelihood = max(0.45, attack_probability, confidence * 0.75)
        else:
            likelihood = min(0.25, attack_probability)
        if severity == "HIGH":
            likelihood += 0.10
        elif severity == "MEDIUM":
            likelihood += 0.05
        intel_confidence = float(intel.get("max_confidence", 0.0) or 0.0)
        if intel.get("matched"):
            likelihood = max(likelihood, intel_confidence)
        likelihood = min(1.0, max(0.0, likelihood))

        criticality = str(asset.get("criticality", "medium")).lower()
        impact = self.CRITICALITY.get(criticality, self.CRITICALITY["medium"])
        exposure = str(asset.get("exposure", "internal")).lower()
        if exposure in {"internet", "public", "internet_facing"}:
            impact = min(1.0, impact + 0.15)
        raw = 100.0 * likelihood * impact
        if intel.get("matched"):
            raw = min(100.0, raw + min(15.0, 15.0 * intel_confidence))
        score = round(raw, 1)
        level = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 35 else "LOW"
        return {
            "score": score,
            "level": level,
            "severity": level,
            "likelihood": round(likelihood, 4),
            "impact": round(impact, 4),
            "asset_criticality": criticality,
            "asset_exposure": exposure,
            "factors": {
                "decision": outcome,
                "decision_confidence": round(confidence, 4),
                "investigation_severity": severity,
                "threat_intel_match": bool(intel.get("matched")),
                "threat_intel_confidence": round(intel_confidence, 4),
            },
            "handling": (
                "Immediate human triage; follow approved containment playbook."
                if level in {"CRITICAL", "HIGH"}
                else "Analyst review and evidence preservation."
                if level == "MEDIUM"
                else "Continue monitoring; retain the analysis record."
            ),
        }


risk_analyzer = RiskAnalyzer()
