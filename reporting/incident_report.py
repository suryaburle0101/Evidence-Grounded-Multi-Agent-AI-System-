"""JSON and Markdown incident report generation."""

from __future__ import annotations

import json
import re
from pathlib import Path

from pipeline.build_info import build_info


def render_markdown(result: dict, incident_id: str | None = None) -> str:
    incident_id = incident_id or result.get("incident_id", "unpersisted")
    decision = result.get("decision", {})
    risk = result.get("risk", {})
    intel = result.get("threat_intel", {})
    evidence = result.get("evidence", {})
    decision_reasons = decision.get("correlation_reasons", [])
    response = result.get("response", {})
    response_workflow = result.get("response_workflow", {})
    playbook = result.get("playbook") or {}
    lifecycle_history = result.get("lifecycle_history") or []
    rag = result.get("rag", {})
    agent_trace = result.get("agent_trace") or []
    unavailable_agents = [entry for entry in agent_trace if entry.get("status") == "unavailable"]
    detector = result.get("detection", {}).get("random_forest", {})
    shap = detector.get("attack_probability_explanation", {})
    flow_context = result.get("flow_context", {})
    actions = response.get("recommended_actions", [])
    sources = rag.get("sources", [])
    evidence_trail = result.get("evidence_trail") or []
    lines = [
        f"# Incident report: {incident_id}", "",
        f"- **Pipeline version:** {result.get('pipeline_version', build_info()['pipeline_version'])}",
        f"- **Git commit:** {result.get('git_commit_hash', build_info()['git_commit_hash'])}",
        "",
        "## Summary", "",
        f"- **Decision:** {result.get('final_decision', 'UNKNOWN')}",
        f"- **Attack family:** {result.get('final_attack', 'Unknown')}",
        f"- **Risk:** {risk.get('level', 'UNASSESSED')} ({risk.get('score', 'n/a')}/100)",
        f"- **Decision confidence:** {decision.get('decision_confidence', 'n/a')}",
        f"- **Pipeline:** {'complete' if result.get('pipeline_completed') else 'incomplete'}",
        f"- **Threat-intelligence match:** {'yes' if intel.get('matched') else 'no'}",
        "", "## Evidence", "",
        evidence.get("description") or evidence.get("message") or "No evidence description was recorded.",
    ]
    context_lines = []
    for label, key in (
        ("Source host", "source_host"), ("Source IP", "source_ip"),
        ("Source port", "source_port"), ("Destination host", "destination_host"),
        ("Destination IP", "destination_ip"), ("Destination port", "destination_port"),
        ("Protocol", "protocol"), ("Timestamp", "timestamp"), ("Flow ID", "flow_id"),
    ):
        value = flow_context.get(key)
        if value is not None:
            context_lines.append(f"- **{label}:** {value}")
    if context_lines:
        lines.extend(["", "## Observed flow context", "", *context_lines])
    if shap.get("status") == "available":
        lines.extend([
            "", "## Model feature contributions", "",
            "Tree SHAP values explain the Random Forest binary attack score; they are not causal proof.",
            f"- Baseline score: {shap.get('baseline_value', 'n/a')}",
            f"- Model score: {shap.get('model_output', 'n/a')}",
            f"- Additivity check error: {shap.get('additivity_absolute_error', 'n/a')}",
        ])
        for item in shap.get("top_features", []):
            lines.append(
                f"- `{item.get('feature', 'feature')}` = {item.get('value', 'n/a')}: "
                f"{item.get('contribution', 'n/a')} ({item.get('direction', 'contribution')})"
            )
    indicators = evidence.get("indicators") or []
    lines.extend(["", "### Indicators", ""])
    lines.extend([f"- {item}" for item in indicators] or ["- None recorded."])
    lines.extend(["", "## Decision reasons", ""])
    lines.extend([f"- {reason}" for reason in decision_reasons] or ["- No decision reasons were recorded."])
    lines.extend(["", "## Evidence trail", ""])
    lines.append("Decision reasons cite the evidence IDs listed here. Weights are correlation contributions where applicable.")
    lines.extend([
        "",
        "| ID | Type | Source | Value | Direction | Weight |",
        "| --- | --- | --- | --- | --- | ---: |",
    ])
    if evidence_trail:
        for item in evidence_trail:
            cells = [
                item.get("id", ""),
                item.get("type", ""),
                item.get("source", ""),
                item.get("value", ""),
                item.get("direction", ""),
                item.get("weight"),
            ]
            rendered = []
            for value in cells:
                if isinstance(value, (dict, list)):
                    value = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
                if value is None:
                    value = "—"
                rendered.append(str(value).replace("|", r"\|").replace("\r", " ").replace("\n", " "))
            lines.append("| " + " | ".join(rendered) + " |")
    else:
        lines.append("| — | — | — | No evidence trail available. | neutral | — |")
    if agent_trace:
        lines.extend(["", "## Agent trace", ""])
        if unavailable_agents:
            failed_names = ", ".join(entry.get("agent", "Unknown stage") for entry in unavailable_agents)
            lines.extend([
                f"> **Warning:** One or more analysis stages were unavailable: {failed_names}. "
                "Review the partial results before acting.",
                "",
            ])
        lines.extend([
            "| Agent | Role | Status | Duration (ms) | Input summary | Output summary |",
            "| --- | --- | --- | ---: | --- | --- |",
        ])
        for entry in agent_trace:
            cells = [
                entry.get("agent", ""), entry.get("role", ""), entry.get("status", "unknown"),
                entry.get("duration_ms", ""), entry.get("input_summary", ""),
                entry.get("output_summary", ""),
            ]
            lines.append("| " + " | ".join(
                str(value).replace("|", r"\|").replace("\r", " ").replace("\n", " ")
                for value in cells
            ) + " |")
    lines.extend(["", "## Analysis", "", rag.get("answer") or "No generated narrative; use the structured evidence above.", ""])
    if rag.get("analyst_note"):
        lines.extend([
            "## Analyst note", "",
            rag["analyst_note"], "",
            f"- **Note source:** {rag.get('note_source', 'unknown')}",
            f"- **Note validation:** {rag.get('note_validation', 'not recorded')}",
        ])
        if rag.get("note_validation_reason"):
            lines.append(f"- **Validation reason:** {rag['note_validation_reason']}")
        lines.append("")
    elif rag.get("llm_draft"):
        lines.extend([
            "### Local LLM draft — analyst review required", "",
            rag["llm_draft"], "",
        ])
    elif rag.get("generation_error"):
        lines.extend([
            "### Local LLM draft", "",
            "The model draft was omitted because generation timed out or reached its output limit. "
            "The factual summary and retrieved sources above remain available.", "",
        ])
    if sources:
        lines.extend(["### Sources", ""])
        for source in sources:
            name = source.get("source_name") or source.get("title") or "Reference"
            url = source.get("source_url")
            lines.append(f"- [{name}]({url})" if url else f"- {name} — {source.get('title', '')}")
        lines.append("")
    lines.extend(["## Recommended actions", ""])
    lines.extend([f"- {item}" for item in actions] or ["- No action recommended."])
    if playbook:
        lines.extend(["", "## Incident playbook", "",
                      f"- Family: {playbook.get('family', 'Unknown')}",
                      f"- Playbook: {playbook.get('playbook_label', 'generic playbook')}",
                      f"- ATT&CK technique: {playbook.get('technique_id') or 'not present in the local knowledge base'}"
                      + (f" — {playbook['technique_name']}" if playbook.get("technique_name") else ""),
                      f"- Knowledge source: {playbook.get('knowledge_base_source', 'not recorded')}",
                      "- Nothing in this playbook is executed automatically."])
        if playbook.get("knowledge_base_note"):
            lines.append(f"- Note: {playbook['knowledge_base_note']}")
        for phase in playbook.get("phases", []):
            lines.extend(["", f"### {str(phase.get('name', 'phase')).title()}", ""])
            if not phase.get("steps"):
                lines.append("No step has supporting evidence in this incident.")
            for step in phase.get("steps", []):
                technique = step.get("technique_id") or "No ATT&CK technique mapped"
                ids = ", ".join(step.get("evidence_ids", [])) or "no supporting evidence IDs"
                lines.append(f"- {step.get('action', '')} — {technique}; evidence: {ids}")
    simulation_logs = response_workflow.get("simulation_logs", [])
    if simulation_logs:
        lines.extend(["", "## SIMULATION dry-run log", "",
                      "These are records of proposed work only. No commands were executed and no real systems were changed."])
        for log in simulation_logs:
            lines.extend(["", f"### SIMULATION · {log.get('created_at', 'time not recorded')}", "",
                          f"- Mode: {log.get('mode', 'dry-run')}",
                          f"- Executed: {'yes' if log.get('executed') else 'no'}",
                          f"- Approved by: {log.get('approved_by', 'unknown')}"])
            for step in log.get("steps", []):
                ids = ", ".join(step.get("evidence_ids", [])) or "none"
                technique = step.get("technique_id") or "none"
                lines.append(f"- [{step.get('phase', 'response')}] {step.get('action', '')} "
                             f"(would run; technique {technique}; evidence {ids})")
    if lifecycle_history:
        lines.extend(["", "## Incident timeline", ""])
        for event in sorted(lifecycle_history, key=lambda item: item.get("created_at", "")):
            event_type = event.get("event_type")
            timestamp = event.get("created_at", "time not recorded")
            if event_type == "incident.validated":
                description = f"State changed: {event.get('previous_state', 'unknown')} → {event.get('state', 'unknown')}"
                if event.get("note"):
                    description += f"; note: {event['note']}"
                if event.get("action_taken"):
                    description += f"; action recorded: {event['action_taken']}"
            elif event_type == "response.simulation_logged":
                description = (f"SIMULATION dry-run log written; {event.get('steps_count', 0)} proposed steps; "
                               f"executed: {'yes' if event.get('executed') else 'no'}")
            elif event_type == "response.approved":
                description = f"Response approved for simulation by {event.get('approved_by', 'unknown')}"
            else:
                description = f"{event_type or 'Incident event'} recorded"
            lines.append(f"- **{timestamp}:** {description}")
    lines.extend(["", "## Response workflow", "",
                  f"- State: {response_workflow.get('state', 'not-created')}",
                  "- Approval only writes a SIMULATION dry-run log; it does not execute actions or change systems.", ""])
    return "\n".join(lines)


def write_report(result: dict, output_dir: str | Path, incident_id: str | None = None) -> dict:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    identifier = incident_id or result.get("incident_id") or "incident"
    safe = re.sub(r"[^A-Za-z0-9_-]+", "_", str(identifier))
    markdown_path = output_dir / f"{safe}.md"
    json_path = output_dir / f"{safe}.json"
    markdown_path.write_text(render_markdown(result, identifier), encoding="utf-8")
    json_path.write_text(json.dumps(result, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    return {"markdown": str(markdown_path), "json": str(json_path)}
