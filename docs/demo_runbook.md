# Demo Runbook: Evidence-Linked Network-Flow Triage

**Purpose:** show the analyst workflow on one bundled DDoS example, then clearly distinguish that in-distribution demonstration from the cross-capture evaluation. The dashboard analyzes pre-extracted rows; it is not live packet capture.

## Start-up

1. From the project folder, start the local API with `.\.venv\Scripts\python.exe api.py` as shown in the README Quickstart.
2. Open `http://127.0.0.1:8000/` and confirm the API status is connected.
3. Open `/api/health` and record the version and commit hash shown for this run. Do not describe a dirty working tree as a clean release.
4. In the analysis panel, run the bundled DDoS sample. The project notes previously observed ten DDoS rows returning ATTACK; the actual current output must be checked live before presenting it.

## Walkthrough (about 5 minutes)

| Time | Screen | What to show / say |
|---|---|---|
| 0:00–0:40 | Overview | “This is a local network-flow triage prototype and a capture-aware evaluation. It analyzes pre-extracted CICFlowMeter-style records; it does not capture packets or block traffic.” |
| 0:40–1:25 | Run demo on sample rows | Show the result table and an incident link. State the actual row count and outcomes displayed; repeated rows may be the same bundled example, so do not present them as independent field events. |
| 1:25–2:20 | Open the DDoS incident | Show the final decision, risk factors, and top reason. Explain that DDoS here is an in-distribution demonstration from CICIDS2017-style data and is not evidence of general DDoS recall. |
| 2:20–3:15 | Evidence and trace | Open E1… evidence, the ordered agent trace, and the SHAP contribution list. Explain that the trace records which stages completed or were unavailable, and that feature contributions describe this model output rather than causal proof. |
| 3:15–4:00 | Response/playbook | Show the recommended response and ATT&CK references. Say explicitly that these are suggestions for analyst review; no network control is executed. If a phase is empty, point out the evidence requirement message. |
| 4:00–4:40 | Lifecycle | If the lifecycle controls are verified, demonstrate a safe test incident moving to Triaged and a simulation approval log. Do not use an operational incident during a public demo. If not verified, state that clearly and skip the interaction. |
| 4:40–5:00 | Limitations | “The source-aligned 99.4% accuracy may overlap training captures, whose exact membership is unknown. In a separate three-seed leave-one-capture-out family pilot, recall was 23.0%; grouping the labels did not produce an established gain over 12 types. The dashboard is a human triage aid, not a guarantee of detection on new captures.” |

## Pre-demo checklist

- Confirm the dashboard is connected and `/api/health` reports `status: ok`.
- Confirm the incident details load and the current display fixes appear: unique readable SHAP labels, readable evidence-cited note, matching E4 finding/severity, E3/E4 types, and empty-phase evidence message.
- Check footer text and record the hash. Health and footer should be consistent; if they differ, report the discrepancy rather than explaining it away.
- API verification for the demo incident `d63d28bc-df48-4fda-821a-36f57543fa1b` recorded `Triaged`, history events `incident.validated`, `response.approved`, and `response.simulation_logged`, and a `SIMULATION` dry-run with three steps and `executed: false`. The visible badge still needs a manual browser check after Ctrl+F5.
- Use fresh screenshots only after the current build is running. Save one each for overview, incident evidence/trace, playbook, and lifecycle. Avoid exposing local paths, tokens, or unrelated incident data.
- Keep the LODO results and acceptance-gate report available as the out-of-distribution context. Do not claim the in-distribution example contradicts or invalidates the held-out results.

## Current evidence and open demo checks

Previously observed in the dashboard: results table, export/filter controls, evidence citations, agent trace, playbook, SHAP panel, local API health endpoint, and WebSocket event connection in one server session. Current API lifecycle state/history/simulation are verified; the badge’s visual rendering is pending a manual Ctrl+F5 check. Health and footer version/hash should be rechecked before describing the current build.
