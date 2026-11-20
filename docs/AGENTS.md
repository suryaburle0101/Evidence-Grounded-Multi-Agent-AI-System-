# Analysis agents

The typed payload contracts live in [`pipeline/agent_schemas.py`](../pipeline/agent_schemas.py). They describe the normalized flow row and the payloads exchanged by the orchestrator. Agent methods currently accept ordinary Python mappings (the rare-family detector also accepts pandas inputs); the orchestrator normalizes those forms before forwarding data.

Each completed or failed analysis result includes `agent_trace`, in execution order. Every trace item has the `AgentTraceEntry` shape: `agent` (display name), `role` (purpose), `status` (`complete` or `unavailable`), `duration_ms` (integer elapsed milliseconds), `input_summary`, and `output_summary`. Summaries describe shapes, counts, and selected result fields; they do not copy raw flow values. Exceptions are retained in the server-side pipeline error record, while trace summaries expose only the exception type.

| Agent | Role | Input schema | Output schema | Failure behavior |
| --- | --- | --- | --- | --- |
| Detection Agent | Runs Random Forest and XGBoost and reports their predictions and agreement. | `DetectionInput` (`flow`) | `DetectionOutput` with `ModelPrediction` values | Fatal: stops the pipeline; partial result contains an unavailable trace row. |
| Rare Family Detector | Checks supported rare attack-family models. | `RareFamilyInput` (`flow`) | `RareFamilyOutput` | Non-fatal: records `available: false`, marks its trace row unavailable, and continues. |
| Investigation Agent | Interprets detector outputs and assigns a finding, severity, and investigation priority. | `InvestigationInput` (`detection`) | `InvestigationOutput` | Fatal: stops the pipeline with the partial trace. |
| Evidence Agent | Calculates flow-level evidence and retrieves reference guidance. | `EvidenceInput` (`investigation`, `flow`, optional `rare_family`) | `EvidenceOutput` | Fatal: stops the pipeline with the partial trace. |
| Threat Intelligence | Checks flow indicators against locally stored IOCs. | `ThreatIntelInput` (`flow`) | `ThreatIntelOutput` | Non-fatal: records an unavailable result with no match and continues. |
| Decision / Correlation Agent | Combines the already-computed detection, investigation, evidence, rare-family, and IOC results. | `DecisionInput` | `DecisionOutput`, including the final decision, reasons, and evidence trail | Fatal: stops the pipeline with the partial trace. |
| Risk Analyzer | Calculates impact-aware risk and reports its factors. | `RiskInput` (`decision`, `investigation`, `threat_intel`, optional `asset_context`) | `RiskOutput` | Fatal: stops the pipeline with the partial trace. |
| Response Agent | Creates response recommendations for human review. It does not execute controls. | `ResponseInput` (`investigation`, `evidence`, optional `decision` and `risk`) | `ResponseOutput` | Fatal: stops the pipeline with the partial trace. |
| Local Evidence RAG | Retrieves local reference material and prepares an evidence-grounded note when requested. | `LocalRagInput` (`attack`, `decision`, `evidence`, optional `flow`, `generate`, `evidence_trail`, `response`) | `LocalRagOutput` | Non-fatal: records an unavailable note result and continues. |

`ResponseWorkflowOutput` is built by the orchestrator after the response agent. It packages approval-gated tasks and is a utility step, not a separate analysis agent. The utility is not included in the agent trace.

## Failure visibility

The orchestrator's `_run_step` wrapper appends a trace row whether an agent returns normally or raises. A raised exception produces `status: unavailable`; a returned result with `available: false` or `status: unavailable` also produces `unavailable`. Other normally returned fallbacks or empty results are `complete`. The incident detail view displays the trace table and a warning banner whenever an unavailable row is present. Batch results show a warning even when a fatal step prevents incident creation. Markdown reports include the same trace and a warning listing unavailable stages. JSON reports retain the structured `agent_trace`.

Fatal stages stop downstream processing, so their trace contains only stages that actually ran. Non-fatal rare-family, threat-intelligence, and local retrieval failures are represented in the result and trace while the pipeline continues.
