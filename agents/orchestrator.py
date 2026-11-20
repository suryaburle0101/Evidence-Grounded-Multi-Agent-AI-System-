import time
import traceback

from agents.detection_agent import detection_agent
from agents.investigation_agent import investigation_agent
from agents.evidence_agent import evidence_agent
from agents.response_agent import response_agent

from correlation.decision_agent import decision_agent

from detection.rare_family_detector import rare_family_detector
from intel.threat_intel import analyze_flow as analyze_threat_intel
from rag.local_rag import local_rag
from risk.risk_analysis import risk_analyzer
from response.workflow import build_workflow
from pipeline.build_info import build_info
from pipeline.agent_schemas import AgentTraceEntry
from response.playbooks import build_playbook


_AGENT_METADATA = {
    "detection": ("Detection Agent", "Runs the Random Forest and XGBoost classifiers."),
    "rare_family": ("Rare Family Detector", "Checks the supported rare attack-family models."),
    "investigation": ("Investigation Agent", "Interprets model outputs and assigns finding and severity."),
    "evidence": ("Evidence Agent", "Calculates flow signals and retrieves reference evidence."),
    "threat_intelligence": ("Threat Intelligence", "Checks flow indicators against the local IOC store."),
    "decision": ("Decision / Correlation Agent", "Combines existing signals into a decision and reasons."),
    "risk_analysis": ("Risk Analyzer", "Calculates impact-aware risk and contributing factors."),
    "response": ("Response Agent", "Prepares analyst-reviewed response recommendations."),
    "local_rag": ("Local Evidence RAG", "Retrieves context and prepares an evidence-grounded note."),
}


def _summary(value, output=False):
    if hasattr(value, "shape"):
        shape = value.shape
        return f"{type(value).__name__} with shape {tuple(shape)}"
    if isinstance(value, dict):
        labels = (
            "agent", "detection_state", "model_agreement", "predicted_attack",
            "finding", "severity", "available", "any_triggered", "top_family",
            "matched", "match_count", "evidence_found", "flow_evidence_level",
            "final_decision", "final_attack", "decision_confidence", "level",
            "score", "response_state", "requires_action", "status", "note_validation",
        )
        details = []
        for key in labels:
            item = value.get(key)
            if isinstance(item, (str, int, float, bool)) or item is None and key in value:
                details.append(f"{key}={item}")
            if len(details) == 4:
                break
        if output and details:
            return "; ".join(details)
        fields = ", ".join(str(key) for key in list(value)[:4])
        suffix = f" ({fields})" if fields else ""
        return f"Mapping with {len(value)} fields{suffix}"
    if isinstance(value, (list, tuple)):
        return f"{type(value).__name__} with {len(value)} items"
    if value is None:
        return "No value"
    if isinstance(value, (str, int, float, bool)):
        return str(value)[:120]
    return type(value).__name__


def _input_summary(args, kwargs):
    parts = [f"arg {index + 1}: {_summary(value)}" for index, value in enumerate(args)]
    parts.extend(f"{key}: {_summary(value)}" for key, value in kwargs.items())
    return "; ".join(parts) or "No inputs"


class CybersecurityOrchestrator:

    def __init__(self):
        self.name = "Cybersecurity Multi-Agent Orchestrator"

    # ========================================================
    # RUN ONE PIPELINE STEP
    # ========================================================

    def _run_step(
        self,
        step_name,
        fn,
        *args,
        agent_trace: list[AgentTraceEntry] | None = None,
        **kwargs
    ):

        start = time.perf_counter()

        try:

            result = fn(
                *args,
                **kwargs
            )

            duration = round(time.perf_counter() - start, 4)
            error = None

        except Exception as e:

            error = {
                "step":
                    step_name,

                "error_type":
                    type(e).__name__,

                "message":
                    str(e),

                "traceback":
                    traceback.format_exc()
            }

            result = None
            duration = round(time.perf_counter() - start, 4)

        reported_unavailable = (
            isinstance(result, dict)
            and (result.get("available") is False or result.get("status") == "unavailable")
        )
        stage_unavailable = error is not None or reported_unavailable

        if agent_trace is not None:
            agent_name, role = _AGENT_METADATA.get(step_name, (step_name, "Analysis stage."))
            agent_trace.append({
                "agent": agent_name,
                "role": role,
                "status": "unavailable" if stage_unavailable else "complete",
                "duration_ms": round(duration * 1000),
                "input_summary": _input_summary(args, kwargs),
                "output_summary": (
                    f"Unavailable ({error['error_type']})." if error
                    else "Stage reported unavailable." if reported_unavailable
                    else _summary(result, output=True)
                ),
            })

        return result, error, duration

    # ========================================================
    # PIPELINE FAILURE
    # ========================================================

    def _fail(
        self,
        error,
        timings,
        partial,
        agent_trace,
    ):

        return {
            **build_info(),
            "system":
                self.name,

            **partial,

            "evidence_trail":
                (partial.get("decision") or {}).get("evidence_trail", []),

            "pipeline_completed":
                False,

            "error":
                error,

            "timings":
                timings,

            "agent_trace":
                agent_trace
        }

    # ========================================================
    # MAIN ANALYSIS PIPELINE
    # ========================================================

    def analyze(self, X, asset_context=None, generate_llm=False, config=None,
                precomputed_detection_results=None):

        # Optional research ablation switches. Omitting config preserves the
        # established production path and full set of analysis stages.
        if config is None:
            settings = {
                "models": ("random_forest", "xgboost"),
                "rare_family": True,
                "investigation": True,
                "evidence": True,
                "threat_intel": True,
                "stop_after_decision": False,
            }
            use_default_detection = True
        else:
            settings = {
                "models": tuple(config.get("models", ("random_forest", "xgboost"))),
                "rare_family": bool(config.get("rare_family", True)),
                "investigation": bool(config.get("investigation", True)),
                "evidence": bool(config.get("evidence", True)),
                "threat_intel": bool(config.get("threat_intel", True)),
                "stop_after_decision": bool(config.get("stop_after_decision", False)),
            }
            use_default_detection = False
        if not settings["models"] or not set(settings["models"]).issubset({"random_forest", "xgboost"}):
            raise ValueError("config.models must contain random_forest and/or xgboost")

        timings = {}

        partial = {}
        agent_trace: list[AgentTraceEntry] = []

        def run_step(step_name, fn, *args, **kwargs):
            return self._run_step(step_name, fn, *args, agent_trace=agent_trace, **kwargs)

        # ====================================================
        # STEP 1 - ML DETECTION
        # ====================================================

        detection_args = (X,) if use_default_detection else (X,)
        detection_kwargs = {} if use_default_detection else {"model_types": settings["models"]}
        if precomputed_detection_results is not None:
            detection_kwargs["precomputed_results"] = precomputed_detection_results
        detection_result, err, t = run_step(
            "detection", detection_agent.analyze, *detection_args, **detection_kwargs
        )

        timings["detection"] = t

        if err:

            return self._fail(
                err,
                timings,
                partial,
                agent_trace
            )

        partial["detection"] = detection_result

        # ====================================================
        # STEP 1b - RARE FAMILY DETECTOR
        # ====================================================

        # Dedicated models are used for rare attack families
        # such as Infiltration and Heartbleed.

        if settings["rare_family"]:
            rare_result, err, t = run_step("rare_family", rare_family_detector.analyze, X)
        else:
            rare_result, err, t = ({"available": False, "any_triggered": False,
                                    "top_family": None, "top_probability": None,
                                    "scores": {}, "message": "Disabled by analysis configuration."}, None, 0.0)

        timings["rare_family"] = t

        # Rare detector failure is non-fatal.
        if err:

            rare_result = {
                "available":
                    False,

                "any_triggered":
                    False,

                "top_family":
                    None,

                "top_probability":
                    None,

                "error":
                    err["message"]
            }

        partial["rare_family"] = rare_result

        # ====================================================
        # STEP 2 - INVESTIGATION
        # ====================================================

        if settings["investigation"]:
            investigation_result, err, t = run_step("investigation", investigation_agent.analyze, detection_result)
        else:
            active = [detection_result[name] for name in settings["models"]]
            probabilities = [float(item.get("binary_attack_probability", 0.5)) for item in active]
            binary_predictions = [int(item.get("binary_prediction", 0)) for item in active]
            attack_probability = sum(probabilities) / len(probabilities)
            benign_probability = 1.0 - attack_probability
            attack_indicated = any(binary_predictions)
            investigation_result = {
                "agent": "Investigation Agent (disabled)",
                "finding": "ATTACK_INDICATED" if attack_indicated else "NO_ATTACK_INDICATED",
                "severity": "LOW", "investigation_required": attack_indicated,
                "probability_difference": max(probabilities) - min(probabilities),
                "random_forest_attack_probability": probabilities[0] if "random_forest" in settings["models"] else 0.5,
                "xgboost_attack_probability": probabilities[0] if "xgboost" in settings["models"] and len(probabilities) == 1 else (probabilities[-1] if "xgboost" in settings["models"] else 0.5),
                "random_forest_benign_probability": 1.0 - (probabilities[0] if "random_forest" in settings["models"] else 0.5),
                "xgboost_benign_probability": 1.0 - (probabilities[0] if "xgboost" in settings["models"] and len(probabilities) == 1 else (probabilities[-1] if "xgboost" in settings["models"] else 0.5)),
                "average_attack_probability": attack_probability,
                "average_benign_probability": benign_probability,
            }
            err, t = None, 0.0

        timings["investigation"] = t

        if err:

            return self._fail(
                err,
                timings,
                partial,
                agent_trace
            )

        partial["investigation"] = (
            investigation_result
        )

        # ====================================================
        # STEP 3 - EVIDENCE
        # ====================================================

        # Preserve the complete raw flow so the Evidence Agent
        # can independently calculate flow-level evidence.

        raw_flow = (
            X.iloc[0]
            if hasattr(X, "iloc")
            else X
        )

        # IMPORTANT:
        # rare_result is explicitly passed to Evidence Agent.
        #
        # This allows a rare-family detection such as:
        #
        #     Infiltration
        #     Heartbleed
        #
        # to be used when retrieving authoritative evidence.

        if settings["evidence"]:
            evidence_result, err, t = run_step(
                "evidence", evidence_agent.analyze, investigation_result,
                flow=raw_flow, rare_result=rare_result
            )
        else:
            evidence_result = {
                "agent": "Evidence Agent (disabled)", "evidence_found": False,
                "requires_review": False, "flow_evidence_score": None,
                "flow_evidence_level": None, "flow_evidence_triggered": False,
                "message": "Disabled by analysis configuration.",
            }
            err, t = None, 0.0

        timings["evidence"] = t

        if err:

            return self._fail(
                err,
                timings,
                partial,
                agent_trace
            )

        partial["evidence"] = evidence_result

        # ====================================================
        # STEP 3b - LOCAL THREAT INTELLIGENCE
        # ====================================================

        if settings["threat_intel"]:
            threat_intel_result, err, t = run_step("threat_intelligence", analyze_threat_intel, raw_flow)
        else:
            threat_intel_result = {"available": False, "matched": False,
                                   "match_count": 0, "max_confidence": 0.0,
                                   "message": "Disabled by analysis configuration."}
            err, t = None, 0.0
        timings["threat_intelligence"] = t
        if err:
            threat_intel_result = {
                "available": False, "matched": False,
                "match_count": 0, "max_confidence": 0.0,
                "error": err["message"]
            }
        partial["threat_intel"] = threat_intel_result

        # ====================================================
        # STEP 4 - DECISION / CORRELATION
        # ====================================================

        decision_result, err, t = run_step(
            "decision",
            decision_agent.analyze,
            detection_result,
            investigation_result,
            evidence_result,
            rare_result,
            threat_intel_result
        )

        timings["decision"] = t

        if err:

            return self._fail(
                err,
                timings,
                partial,
                agent_trace
            )

        partial["decision"] = decision_result

        if settings["stop_after_decision"]:
            timings["total"] = round(sum(timings.values()), 4)
            return {
                **build_info(), "system": self.name,
                **partial,
                "evidence_trail": decision_result.get("evidence_trail", []),
                "pipeline_completed": True,
                "timings": timings,
                "agent_trace": agent_trace,
                "ablation_config": {key: list(value) if key == "models" else value
                                    for key, value in settings.items()},
            }

        # ====================================================
        # STEP 4c - RISK ANALYSIS
        # ====================================================

        risk_result, err, t = run_step(
            "risk_analysis",
            risk_analyzer.analyze,
            decision_result,
            investigation_result,
            threat_intel_result,
            asset_context
        )
        timings["risk_analysis"] = t
        if err:
            return self._fail(err, timings, partial, agent_trace)
        partial["risk"] = risk_result

        # ====================================================
        # STEP 5 - RESPONSE
        # ====================================================

        response_result, err, t = run_step(
            "response",
            response_agent.analyze,
            investigation_result,
            evidence_result,
            decision_result,
            risk_result
        )

        timings["response"] = t

        if err:

            return self._fail(
                err,
                timings,
                partial,
                agent_trace
            )

        partial["response"] = response_result

        # ====================================================
        # EVIDENCE-GROUNDED NOTE AND LOCAL RETRIEVAL
        # ====================================================

        rag_result, err, t = run_step(
            "local_rag",
            local_rag.analyze,
            decision_result.get("final_attack", "Unknown"),
            decision_result.get("final_decision", "REVIEW"),
            evidence_result,
            flow=raw_flow,
            generate=generate_llm,
            evidence_trail=decision_result.get("evidence_trail", []),
            response=response_result,
        )
        timings["local_rag"] = t
        if err:
            rag_result = {
                "status": "unavailable", "answer": None,
                "error": err["message"], "sources": [],
                "analyst_note": None,
                "note_validation": "failed",
                "note_validation_reason": "The note component failed before validation.",
            }
        partial["rag"] = rag_result

        response_workflow = build_workflow(response_result, risk_result)
        playbook = build_playbook(
            decision_result.get("final_attack"),
            decision_result.get("evidence_trail", []),
        )

        # ====================================================
        # TOTAL PIPELINE TIME
        # ====================================================

        timings["total"] = round(
            sum(timings.values()),
            4
        )

        # ====================================================
        # FINAL PIPELINE RESULT
        # ====================================================

        return {

            **build_info(),

            "system":
                self.name,

            "detection":
                detection_result,

            "rare_family":
                rare_result,

            "investigation":
                investigation_result,

            "evidence":
                evidence_result,

            "threat_intel":
                threat_intel_result,

            "decision":
                decision_result,

            "evidence_trail":
                decision_result.get("evidence_trail", []),

            "agent_trace":
                agent_trace,

            "rag":
                rag_result,

            "risk":
                risk_result,

            "response":
                response_result,

            "response_workflow":
                response_workflow,

            "playbook":
                playbook,


            "final_decision":
                decision_result.get(
                    "final_decision"
                ),

            "final_attack":
                decision_result.get(
                    "final_attack"
                ),

            "timings":
                timings,

            "pipeline_completed":
                True
        }


# ============================================================
# ORCHESTRATOR INSTANCE
# ============================================================

orchestrator = CybersecurityOrchestrator()
