"""Build traceable evidence rows from signals already used by analysis."""

from __future__ import annotations

import re


def _number(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _model_direction(model_result):
    family = str(model_result.get("attack_family", "")).strip().casefold()
    attack_probability = model_result.get("binary_attack_probability")
    prediction = model_result.get("binary_prediction")
    if attack_probability is not None and _number(attack_probability) >= 0.5:
        return "supports ATTACK"
    if prediction == 1 or (family and family != "benign"):
        return "supports ATTACK"
    if prediction == 0 and family == "benign":
        return "supports BENIGN"
    return "neutral"


def _ids_for_reason(reason, ids, all_ids):
    text = reason.casefold()
    selected = []
    for trigger, key in (
        ("rare-family", "rare_family"),
        ("threat-intelligence", "threat_intel"),
        ("flow evidence", "flow_evidence"),
        ("flow-level", "flow_evidence"),
        ("authoritative cybersecurity evidence", "reference_doc"),
        ("investigation agent", "investigation"),
        ("random forest", "model"),
        ("xgboost", "model"),
        ("ml models", "model"),
        ("the models", "model"),
        ("model probabilities", "model"),
        ("binary attack score", "model"),
        ("attack probability", "model"),
        ("class prediction", "model"),
    ):
        if trigger in text and ids.get(key) and ids[key] not in selected:
            selected.append(ids[key])

    if "final decision:" in text:
        selected.extend(item_id for item_id in all_ids if item_id not in selected)

    if not selected:
        selected = [ids.get("model")] if ids.get("model") else all_ids[:1]
    return selected


def _cite_reason(reason, evidence_ids):
    citations = " ".join(f"[{item_id}]" for item_id in evidence_ids)
    if not citations:
        return reason

    sentences = re.split(r"(?<=[.!?])\s+", str(reason).strip())
    cited_sentences = []
    for sentence in sentences:
        punctuation = re.search(r"([.!?]+[\"'”’)}\]]*)$", sentence)
        if punctuation:
            body = sentence[:punctuation.start()].rstrip()
            ending = punctuation.group(1)
            cited_sentences.append(f"{body} {citations}{ending}")
        else:
            cited_sentences.append(f"{sentence.rstrip()} {citations}")
    return " ".join(cited_sentences)


def build_evidence_trail(
    detection_result,
    investigation_result,
    evidence_result,
    rare_result,
    threat_intel_result,
    contribution_weights,
    reasons,
):
    """Return trail rows and reasons annotated with IDs from those rows."""
    detection_result = detection_result or {}
    investigation_result = investigation_result or {}
    evidence_result = evidence_result or {}
    rare_result = rare_result or {}
    threat_intel_result = threat_intel_result or {}
    contribution_weights = contribution_weights or {}

    trail = []

    def add(item_type, source, value, direction, weight):
        item_id = f"E{len(trail) + 1}"
        trail.append({
            "id": item_id,
            "type": item_type,
            "source": source,
            "value": value,
            "direction": direction,
            "weight": weight,
        })
        return item_id

    model_results = []
    for model_key, model_name in (
        ("random_forest", "Random Forest"),
        ("xgboost", "XGBoost"),
    ):
        model_result = detection_result.get(model_key) or {}
        if not model_result:
            continue
        model_results.append(model_result)
        add(
            "model",
            model_name,
            {
                "attack_family": model_result.get("attack_family"),
                "binary_prediction": model_result.get("binary_prediction"),
                "binary_attack_probability": model_result.get("binary_attack_probability"),
                "binary_benign_probability": model_result.get("binary_benign_probability"),
                "confidence": model_result.get("confidence"),
            },
            _model_direction(model_result),
            None,
        )

    model_weights = {
        key: contribution_weights.get(key, 0.0)
        for key in (
            "model_agreement", "model_confidence", "attack_probability",
            "probability_alignment",
        )
    }
    model_item_id = None
    if model_results:
        average_probability = _number(investigation_result.get("average_attack_probability"))
        model_agreement = bool(detection_result.get("model_agreement"))
        family_names = [str(item.get("attack_family", "")).casefold() for item in model_results]
        if average_probability >= 0.5:
            direction = "supports ATTACK"
        elif model_agreement and family_names and all(name == "benign" for name in family_names):
            direction = "supports BENIGN"
        else:
            direction = "neutral"
        model_item_id = add(
            "decision",
            "correlation/decision_agent.py",
            {
                "model_agreement": model_agreement,
                "average_attack_probability": investigation_result.get("average_attack_probability"),
                "probability_difference": investigation_result.get("probability_difference"),
                "contributions": model_weights,
            },
            direction,
            sum(model_weights.values()),
        )

    ids = {"model": model_item_id}
    if investigation_result:
        finding = investigation_result.get("finding") or investigation_result.get("investigation_finding")
        if str(finding).upper() == "ATTACK_INDICATED":
            investigation_direction = "supports ATTACK"
        elif str(finding).upper() == "NO_ATTACK_INDICATED":
            investigation_direction = "supports BENIGN"
        else:
            investigation_direction = "neutral"
        investigation_weights = {
            key: contribution_weights.get(key, 0.0)
            for key in ("investigation_severity", "investigation_finding")
        }
        ids["investigation"] = add(
            "investigation",
            "agents/investigation_agent.py",
            {
                "finding": finding,
                "severity": investigation_result.get("severity"),
            },
            investigation_direction,
            sum(investigation_weights.values()),
        )

    rare_scores = rare_result.get("scores") or {}
    rare_triggered = bool(rare_result.get("any_triggered"))
    rare_family = rare_result.get("top_family")
    rare_source = (
        f"models/rare_{str(rare_family).casefold()}.pkl"
        if rare_family
        else "detection/rare_family_detector.py"
    )
    ids["rare_family"] = add(
        "rare_family",
        rare_source,
        {
            "available": bool(rare_result.get("available")),
            "top_family": rare_family,
            "top_probability": rare_result.get("top_probability"),
            "scores": rare_scores,
            "triggered": rare_result.get("triggered") or {},
        },
        "supports ATTACK" if rare_triggered else "neutral",
        contribution_weights.get("rare_family", 0.0),
    )

    flow_score = evidence_result.get("flow_evidence_score")
    if flow_score is not None:
        ids["flow_evidence"] = add(
            "flow_evidence",
            "evidence/flow_evidence.py",
            {
                "score": flow_score,
                "level": evidence_result.get("flow_evidence_level"),
                "triggered": bool(evidence_result.get("flow_evidence_triggered")),
            },
            "supports ATTACK" if _number(flow_score) >= 0.4 else "neutral",
            contribution_weights.get("flow_evidence", 0.0),
        )

    intel_matches = threat_intel_result.get("matches") or []
    intel_matched = bool(threat_intel_result.get("matched"))
    ids["threat_intel"] = add(
        "threat_intel",
        "storage/evidence_store.py",
        {
            "available": bool(threat_intel_result.get("available")),
            "matched": intel_matched,
            "match_count": threat_intel_result.get("match_count", len(intel_matches)),
            "max_confidence": threat_intel_result.get("max_confidence", 0.0),
            "family": threat_intel_result.get("family"),
            "matches": intel_matches,
        },
        "supports ATTACK" if intel_matched else "neutral",
        contribution_weights.get("threat_intel", 0.0),
    )

    if evidence_result.get("evidence_found"):
        family = evidence_result.get("attack") or evidence_result.get("attack_family")
        technique_id = evidence_result.get("technique_id")
        document_id = (
            f"{str(family).casefold()}:{technique_id or 'local'}"
            if family
            else "evidence/knowledge/authoritative_sources.json"
        )
        ids["reference_doc"] = add(
            "reference_doc",
            document_id,
            {
                "family": family,
                "title": evidence_result.get("technique_name"),
                "source_name": evidence_result.get("source_name"),
                "technique_id": technique_id,
            },
            "supports ATTACK",
            contribution_weights.get("reference_doc", 0.0),
        )

    all_ids = [item["id"] for item in trail]
    cited_reasons = [
        _cite_reason(reason, _ids_for_reason(str(reason), ids, all_ids))
        for reason in (reasons or [])
    ]
    return trail, cited_reasons




