"""Shared incident persistence and reporting layer for CLI and API callers."""

from __future__ import annotations

from collections.abc import Mapping
import time

from agents.orchestrator import orchestrator
from storage.evidence_store import evidence_store
from pipeline.flow_metadata import extract_flow_context, normalize_name


GROUND_TRUTH_FIELDS = {"label", "attack", "attack cat", "class", "target", "source label", "ground truth label"}


def _inference_flow(flow):
    """Remove dataset labels before any analysis agent sees a row."""
    if hasattr(flow, "to_dict") and not isinstance(flow, Mapping):
        flow = flow.to_dict()
    if isinstance(flow, Mapping):
        return {key: value for key, value in flow.items()
                if normalize_name(key) not in GROUND_TRUTH_FIELDS}
    return flow


def analyze_flow(flow, asset_context=None, source="pipeline", persist=True,
                 generate_llm=False) -> dict:
    flow_context = extract_flow_context(flow)
    result = orchestrator.analyze(
        _inference_flow(flow), asset_context=asset_context, generate_llm=generate_llm
    )
    if not result.get("pipeline_completed"):
        return result
    # Persist endpoint/time metadata with the incident while keeping it outside
    # the fixed model feature matrix. The detector still receives only its 77
    # named numeric features through prepare_input().
    if flow_context:
        result["flow_context"] = flow_context
    if persist and result.get("final_decision") in {"ATTACK", "REVIEW"}:
        incident_id = evidence_store.save_incident(result, source=source)
        result["incident_id"] = incident_id
        result["response_workflow"]["incident_id"] = incident_id
    return result


def analyze_batch_fast(flows, asset_context=None, source="pipeline", persist=True,
                       generate_llm=False) -> list[dict]:
    """Optional vectorized RF/XGBoost inference followed by the normal pipeline."""
    import pandas as pd
    from detection import model_predictor

    if isinstance(flows, pd.DataFrame):
        flow_rows = flows.to_dict(orient="records")
    else:
        flow_rows = list(flows)
    if not flow_rows:
        return []

    inference_rows = [_inference_flow(flow) for flow in flow_rows]
    model_frame = model_predictor.prepare_input(pd.DataFrame(inference_rows))
    batch_started = time.perf_counter()
    predictions = {
        model_type: model_predictor.predict_attack_family_batch(model_frame, model_type)
        for model_type in ("random_forest", "xgboost")
    }
    detection_seconds_per_flow = (time.perf_counter() - batch_started) / len(flow_rows)
    results = []
    for index, flow in enumerate(flow_rows):
        context = extract_flow_context(flow)
        precomputed = {name: values[index] for name, values in predictions.items()}
        result = orchestrator.analyze(
            inference_rows[index], asset_context=asset_context,
            generate_llm=generate_llm,
            precomputed_detection_results=precomputed,
        )
        if result.get("pipeline_completed"):
            timings = result.setdefault("timings", {})
            timings["detection"] = round(float(timings.get("detection", 0.0)) + detection_seconds_per_flow, 4)
            timings["total"] = round(float(timings.get("total", 0.0)) + detection_seconds_per_flow, 4)
            trace = result.get("agent_trace") or []
            if trace and trace[0].get("agent") == "Detection Agent":
                trace[0]["duration_ms"] = int(trace[0].get("duration_ms", 0) + round(detection_seconds_per_flow * 1000))
        if not result.get("pipeline_completed"):
            results.append(result)
            continue
        if context:
            result["flow_context"] = context
        if persist and result.get("final_decision") in {"ATTACK", "REVIEW"}:
            incident_id = evidence_store.save_incident(result, source=source)
            result["incident_id"] = incident_id
            result["response_workflow"]["incident_id"] = incident_id
        results.append(result)
    return results
