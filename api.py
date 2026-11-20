"""Local REST and WebSocket API for flow analysis and incident operations."""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
from pathlib import Path
from typing import Any

import sklearn
import xgboost
import urllib.error
from fastapi import Body, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.concurrency import run_in_threadpool
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from analysis_service import analyze_flow
from detection.model_predictor import prepare_input
from intel.threat_intel import sync_threatfox, threatfox_status
from pipeline.flow_metadata import extract_flow_context
from pipeline.build_info import PIPELINE_VERSION, build_info
from pipeline.request_limits import RequestBodyLimitMiddleware
from rag.local_rag import local_rag
from reporting.incident_report import write_report
from storage.evidence_store import evidence_store

app = FastAPI(
    title="Cyber Incident Analysis API",
    version=PIPELINE_VERSION,
    description="Local network-flow analysis, incident records, IOC lookup, and response validation.",
)
logger = logging.getLogger(__name__)


def sanitize_api_error_details(value: Any, context: str = "API result") -> Any:
    """Keep exception diagnostics in server logs, not client-visible payloads."""
    if isinstance(value, dict):
        if "error" in value:
            logger.error("%s: %s", context, value["error"])
            value["error"] = "Component unavailable."
        if "error_type" in value and "message" in value:
            logger.error("%s (%s): %s", context, value["error_type"], value["message"])
            value["error_type"] = "component_error"
            value["message"] = "Component unavailable."
        if "traceback" in value:
            logger.error("%s traceback:\n%s", context, value["traceback"])
            value["traceback"] = "Details recorded in server log."
        for key, child in value.items():
            if key not in {"error", "error_type", "message", "traceback"}:
                sanitize_api_error_details(child, context)
    elif isinstance(value, list):
        for child in value:
            sanitize_api_error_details(child, context)
    return value


def token_matches(supplied: str, expected: str) -> bool:
    return hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8"))


@app.middleware("http")
async def optional_api_token_auth(request: Request, call_next):
    token = os.environ.get("CYBER_API_TOKEN")
    path = request.url.path
    protected = path.startswith("/api/") or path in {"/docs", "/redoc", "/openapi.json"}
    if token and protected:
        authorization = request.headers.get("authorization", "")
        scheme, _, supplied = authorization.partition(" ")
        if scheme.lower() != "bearer" or not supplied or not token_matches(supplied, token):
            logger.warning("Rejected unauthenticated API request: %s %s", request.method, path)
            return JSONResponse(
                status_code=401,
                content={"detail": "Authentication required."},
                headers={"WWW-Authenticate": "Bearer"},
            )
    return await call_next(request)


@app.exception_handler(RequestValidationError)
async def request_validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.warning("Invalid API request at %s %s: %s", request.method, request.url.path, exc.errors())
    return JSONResponse(status_code=422, content={"detail": "Invalid request."})


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled API error at %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error."})

MAX_JSON_REQUEST_BYTES = 8 * 1024 * 1024


app.add_middleware(RequestBodyLimitMiddleware, max_bytes=MAX_JSON_REQUEST_BYTES)
REPORT_DIR = Path(__file__).resolve().parent / "reports" / "incidents"
FRONTEND_DIR = Path(__file__).resolve().parent / "frontend"


@app.get("/api/health")
async def health():
    local_llm_status = await run_in_threadpool(local_rag.model_status)
    if local_llm_status.get("error"):
        logger.warning("Local model health check failed: %s", local_llm_status.pop("error"))
    return {
        **build_info(),
        "status": "ok",
        "models": {"scikit_learn": sklearn.__version__, "xgboost": xgboost.__version__},
        "evidence_store": "ready",
        "threat_intelligence": threatfox_status(),
        "local_llm": local_llm_status,
        "endpoints": ["POST /api/analyze", "GET /api/incidents", "GET /api/incidents/correlated",
                      "POST /api/threat-intel/import", "POST /api/threat-intel/sync", "WS /ws/events"],
    }


@app.post("/api/analyze")
async def analyze(body: dict[str, Any] = Body(...)):
    flow = body.get("flow", body)
    asset_context = body.get("asset_context")
    generate_note = body.get("generate_note", False)
    if not isinstance(flow, dict):
        raise HTTPException(status_code=400, detail="flow must be an object of feature values")
    if not isinstance(generate_note, bool):
        raise HTTPException(status_code=422, detail="generate_note must be a boolean")
    try:
        # Catch schema/input errors before entering the multi-agent pipeline.
        prepare_input(flow)
    except (TypeError, ValueError) as exc:
        logger.info("Flow input validation failed: %s", exc)
        raise HTTPException(status_code=422, detail="Invalid flow input.") from exc
    result = await run_in_threadpool(
        analyze_flow, flow, asset_context, "api", True, generate_note
    )
    if not result.get("pipeline_completed"):
        logger.error("Flow analysis pipeline failed: %s", result.get("error", "unknown error"))
        return JSONResponse(
            status_code=500,
            content={
                "detail": "Analysis failed.",
                "pipeline_completed": False,
                "agent_trace": result.get("agent_trace", []),
            },
        )
    if result.get("incident_id"):
        result["report_files"] = await run_in_threadpool(
            write_report, result, REPORT_DIR, result["incident_id"]
        )
    await run_in_threadpool(
        evidence_store.record_event,
        "analysis.completed",
        {"decision": result.get("final_decision"), "attack": result.get("final_attack"),
         "risk": result.get("risk", {}).get("level")},
        result.get("incident_id"),
    )
    return sanitize_api_error_details(result, "Analysis component error")


@app.post("/api/analyze-batch")
async def analyze_batch(body: dict[str, Any] = Body(...)):
    """Analyze a bounded batch of flow objects submitted by the local dashboard."""
    flows = body.get("flows")
    if not isinstance(flows, list) or not flows:
        raise HTTPException(status_code=422, detail="flows must be a non-empty list")
    if len(flows) > 100:
        raise HTTPException(status_code=413, detail="A dashboard batch is limited to 100 rows")
    if any(not isinstance(flow, dict) for flow in flows):
        raise HTTPException(status_code=422, detail="Every flow must be an object of feature values")

    def process_batch():
        results = []
        for row_number, flow in enumerate(flows, start=1):
            try:
                prepare_input(flow)
                result = analyze_flow(flow, source="web-dashboard", persist=True)
                if not result.get("pipeline_completed"):
                    logger.error("Batch analysis pipeline failed for row %s: %s", row_number, result.get("error", "unknown error"))
                    result["error"] = "Analysis failed."
            except Exception as exc:
                logger.exception("Batch analysis failed for row %s", row_number)
                result = {**build_info(), "pipeline_completed": False, "error": "Analysis failed."}
            result.update(build_info())
            result.setdefault("evidence_trail", [])
            result.setdefault("agent_trace", [])
            result["row_number"] = row_number
            result["flow_metrics"] = {
                key: flow.get(key) for key in (
                    "Flow Bytes/s", "Flow Packets/s", "Flow Duration", "SYN Flag Count"
                ) if key in flow
            }
            # Analyze path stores source/destination and timestamp context on the
            # incident itself, not just the ephemeral batch response.
            result.setdefault("flow_context", extract_flow_context(flow))
            if result.get("incident_id"):
                try:
                    result["report_files"] = write_report(result, REPORT_DIR, result["incident_id"])
                except OSError as exc:
                    logger.warning("Could not write report for batch row %s: %s", row_number, exc)
                    result["report_error"] = "Analysis saved, but its report could not be written."
            results.append(sanitize_api_error_details(result, f"Batch row {row_number} component error"))
        return results

    results = await run_in_threadpool(process_batch)
    from collections import Counter
    decisions = Counter(item.get("final_decision", "FAILED") for item in results)
    from pipeline.drift import assess_batch_drift
    input_drift = await run_in_threadpool(assess_batch_drift, flows)
    return {
        **build_info(),
        "rows": len(results),
        "pipeline_failures": sum(not item.get("pipeline_completed") for item in results),
        "decisions": dict(decisions),
        "input_drift": input_drift,
        "results": results,
    }


@app.get("/api/sample-flows")
async def sample_flows(limit: int = 10, attack_type: str = "all"):
    """Return demo flows, optionally sampled from one labeled CICIDS2017 attack."""
    if not 1 <= limit <= 40:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 40")
    root = Path(__file__).resolve().parent
    attack_sources = {
        "botnet": ("Botnet", "Botnet-Friday-no-metadata.parquet", "bot"),
        "ftp_brute_force": ("FTP Brute Force", "Bruteforce-Tuesday-no-metadata.parquet", "ftppatator"),
        "ssh_brute_force": ("SSH Brute Force", "Bruteforce-Tuesday-no-metadata.parquet", "sshpatator"),
        "ddos": ("DDoS", "DDoS-Friday-no-metadata.parquet", "ddos"),
        "dos_hulk": ("DoS Hulk", "DoS-Wednesday-no-metadata.parquet", "doshulk"),
        "dos_goldeneye": ("DoS GoldenEye", "DoS-Wednesday-no-metadata.parquet", "dosgoldeneye"),
        "dos_slowloris": ("DoS Slowloris", "DoS-Wednesday-no-metadata.parquet", "dosslowloris"),
        "dos_slowhttptest": ("DoS Slow HTTP test", "DoS-Wednesday-no-metadata.parquet", "dosslowhttptest"),
        "infiltration": ("Infiltration", "Infiltration-Thursday-no-metadata.parquet", "infiltration"),
        "port_scan": ("Port Scan", "Portscan-Friday-no-metadata.parquet", "portscan"),
        "web_brute_force": ("Web Brute Force", "WebAttacks-Thursday-no-metadata.parquet", "webattackbruteforce"),
        "web_xss": ("Web XSS", "WebAttacks-Thursday-no-metadata.parquet", "webattackxss"),
        "web_sql_injection": ("Web SQL Injection", "WebAttacks-Thursday-no-metadata.parquet", "webattacksqlinjection"),
        "heartbleed": ("Heartbleed", "DoS-Wednesday-no-metadata.parquet", "heartbleed"),
    }
    if attack_type != "all" and attack_type not in attack_sources:
        raise HTTPException(status_code=422, detail="Choose a supported attack type or 'all'.")
    if attack_type == "all":
        path = root / "data" / "processed" / "end_to_end_sample.parquet"
        if not path.is_file():
            raise HTTPException(status_code=404, detail="Bundled demo sample is unavailable")
    else:
        display_name, file_name, _ = attack_sources[attack_type]
        path = root / "data" / "raw" / "CICIDS2017" / file_name
        if not path.is_file():
            # The release ZIP omits raw benchmark captures. The compact processed
            # demo sample still contains DDoS, Infiltration, and Heartbleed rows.
            path = root / "data" / "processed" / "end_to_end_sample.parquet"
            bundled_attack_fallback = True
        else:
            bundled_attack_fallback = False
        if not path.is_file():
            raise HTTPException(
                status_code=404,
                detail=(
                    f"CICIDS2017 source file is missing for {display_name}, and the bundled "
                    "demo sample is unavailable. Add the raw capture or restore the demo sample."
                ),
            )
    if attack_type == "all":
        bundled_attack_fallback = False

    def read_sample():
        import re
        import pandas as pd
        frame = pd.read_parquet(path)
        label_column = next((c for c in frame.columns if str(c).strip().casefold() == "label"), None)
        if label_column is None:
            return [], 0
        display_name = None
        if attack_type != "all":
            display_name, _, target_key = attack_sources[attack_type]
            normalized = frame[label_column].astype(str).str.casefold().map(
                lambda value: re.sub(r"[^a-z0-9]+", "", value)
            )
            frame = frame.loc[normalized == target_key].copy()
        available = len(frame)
        if not available:
            return [], 0
        if len(frame) > limit:
            frame = frame.sample(n=limit, random_state=20261012)
        # The demo's labels are ground truth for offline scoring, never model input.
        frame = frame.drop(columns=[label_column], errors="ignore")
        return frame.to_dict(orient="records"), available

    flows, available = await run_in_threadpool(read_sample)
    if not flows:
        if attack_type != "all" and bundled_attack_fallback:
            raise HTTPException(
                status_code=404,
                detail=(
                    f"{attack_sources[attack_type][0]} is not present in the bundled demo sample. "
                    "Add the corresponding CICIDS2017 capture to data/raw/CICIDS2017."
                ),
            )
        raise HTTPException(status_code=404, detail="No demo flows are available for this selection.")
    chosen_name = "All sample types" if attack_type == "all" else attack_sources[attack_type][0]
    source = (
        "bundled demonstration sample"
        if attack_type == "all" or bundled_attack_fallback
        else f"CICIDS2017 · {chosen_name}"
    )
    return {"source": source, "attack_type": chosen_name, "rows_available": available,
            "rows_selected": len(flows), "flows": flows}


@app.get("/api/incidents")
async def incidents(limit: int = 100, status: str | None = None):
    return await run_in_threadpool(evidence_store.list_incidents, limit, status)


@app.get("/api/incidents/correlated")
async def correlated_incidents(window_minutes: int = 60, limit: int = 500):
    """Return analyst-review candidates sharing an endpoint over time."""
    if not 1 <= window_minutes <= 10080:
        raise HTTPException(status_code=422, detail="window_minutes must be between 1 and 10080")
    if not 2 <= limit <= 1000:
        raise HTTPException(status_code=422, detail="limit must be between 2 and 1000")
    return await run_in_threadpool(evidence_store.correlate_incidents, window_minutes, limit)


@app.get("/api/audit")
async def audit_trail(limit: int = 100):
    return await run_in_threadpool(evidence_store.audit_trail, limit)


@app.get("/api/incidents/{incident_id}")
async def incident(incident_id: str):
    result = await run_in_threadpool(evidence_store.get_incident, incident_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return result


@app.post("/api/incidents/{incident_id}/response/approve")
async def approve_response(incident_id: str, body: dict[str, Any] = Body(default={} )):
    try:
        result = await run_in_threadpool(
            evidence_store.approve_response,
            incident_id,
            str(body.get("approved_by", "analyst")),
        )
    except ValueError as exc:
        logger.warning("Response approval rejected for incident %s: %s", incident_id, exc)
        raise HTTPException(status_code=409, detail="Response approval is unavailable.") from exc
    if result is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    result["report_files"] = await run_in_threadpool(
        write_report, result.get("payload", {}), REPORT_DIR, incident_id
    )
    return result


@app.post("/api/incidents/{incident_id}/validation")
async def validate_response(incident_id: str, body: dict[str, Any] = Body(...)):
    try:
        result = await run_in_threadpool(
            evidence_store.validate_incident,
            incident_id,
            str(body.get("state", "")),
            str(body.get("note", "")),
            str(body.get("action_taken", "")),
        )
    except ValueError as exc:
        logger.info("Incident validation rejected for %s: %s", incident_id, exc)
        if "transition" in str(exc):
            raise HTTPException(status_code=409, detail="That incident state transition is not allowed.") from exc
        raise HTTPException(status_code=422, detail="Invalid incident validation.") from exc
    if result is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return result


@app.post("/api/threat-intel/import")
async def import_threat_intel(body: dict[str, Any] = Body(...)):
    entries = body.get("indicators", [])
    if not isinstance(entries, list):
        raise HTTPException(status_code=422, detail="indicators must be a list")
    if len(entries) > 5000:
        raise HTTPException(status_code=413, detail="An import is limited to 5,000 indicators")
    try:
        stored = await run_in_threadpool(
            evidence_store.add_iocs,
            entries,
            str(body.get("source", "api")),
        )
    except (TypeError, ValueError) as exc:
        logger.info("Threat-intelligence import validation failed: %s", exc)
        raise HTTPException(status_code=422, detail="Invalid threat-intelligence input.") from exc
    await run_in_threadpool(
        evidence_store.record_event,
        "threat_intel.imported",
        {"source": body.get("source", "api"), "received": len(entries), "stored": stored},
    )
    return {"received": len(entries), "stored": stored}


@app.post("/api/threat-intel/sync")
async def sync_threat_intelligence(days: int = 3):
    """Pull recent IOCs from configured ThreatFox credentials."""
    if not 1 <= days <= 7:
        raise HTTPException(status_code=422, detail="days must be between 1 and 7")
    try:
        result = await run_in_threadpool(sync_threatfox, days)
    except RuntimeError as exc:
        logger.warning("Threat-intelligence sync unavailable: %s", exc)
        raise HTTPException(status_code=503, detail="Threat-intelligence sync is unavailable.") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        logger.warning("Threat-intelligence provider request failed: %s", exc)
        raise HTTPException(status_code=502, detail="Threat-intelligence provider request failed.") from exc
    except ValueError as exc:
        logger.warning("Threat-intelligence provider returned invalid data: %s", exc)
        raise HTTPException(status_code=502, detail="ThreatFox returned invalid data") from exc
    await run_in_threadpool(evidence_store.record_event, "threat_intel.synced", result)
    return result


@app.get("/api/threat-intel")
async def threat_intel(limit: int = 100):
    return await run_in_threadpool(evidence_store.list_iocs, limit)


@app.get("/api/evidence/search")
async def search_evidence(q: str, limit: int = 4):
    docs = await run_in_threadpool(local_rag.retrieve, q, limit)
    return {"query": q, "results": docs}


@app.get("/api/incidents/{incident_id}/report")
async def report(incident_id: str):
    item = await run_in_threadpool(evidence_store.get_incident, incident_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    files = await run_in_threadpool(write_report, item["payload"], REPORT_DIR, incident_id)
    return files


@app.get("/api/incidents/{incident_id}/report/download")
async def download_report(incident_id: str):
    item = await run_in_threadpool(evidence_store.get_incident, incident_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    files = await run_in_threadpool(write_report, item["payload"], REPORT_DIR, incident_id)
    report_path = Path(files["markdown"]).resolve()
    if REPORT_DIR.resolve() not in report_path.parents:
        raise HTTPException(status_code=500, detail="Invalid report path")
    return FileResponse(report_path, media_type="text/markdown", filename=f"incident-{incident_id}.md")


@app.websocket("/ws/events")
async def event_stream(websocket: WebSocket):
    await websocket.accept()
    token = os.environ.get("CYBER_API_TOKEN")
    if token:
        try:
            auth_message = await asyncio.wait_for(websocket.receive_json(), timeout=15)
        except WebSocketDisconnect:
            logger.warning("Rejected unauthenticated WebSocket connection")
            return
        except (ValueError, asyncio.TimeoutError):
            logger.warning("Rejected unauthenticated WebSocket connection")
            await websocket.close(code=1008)
            return
        supplied = auth_message.get("token", "") if isinstance(auth_message, dict) and auth_message.get("type") == "auth" else ""
        if not isinstance(supplied, str) or not token_matches(supplied, token):
            logger.warning("Rejected unauthenticated WebSocket connection")
            await websocket.close(code=1008)
            return
    try:
        requested_cursor = websocket.query_params.get("after")
        cursor = (int(requested_cursor) if requested_cursor is not None else
                  await run_in_threadpool(evidence_store.latest_event_id))
        while True:
            events = await run_in_threadpool(evidence_store.events_since, cursor, 100)
            for event in events:
                cursor = event["id"]
                event["payload"] = __import__("json").loads(event.pop("payload_json"))
                await websocket.send_json(event)
            await asyncio.sleep(0.5)
    except (WebSocketDisconnect, ValueError):
        return


@app.get("/**", include_in_schema=False)
async def redirect_wildcard_browser_url():
    """Treat a pasted wildcard URL as the dashboard root instead of a server error."""
    return RedirectResponse(url="/", status_code=307)


if FRONTEND_DIR.is_dir():
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
