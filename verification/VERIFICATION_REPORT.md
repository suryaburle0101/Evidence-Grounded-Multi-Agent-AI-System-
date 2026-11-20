# End-to-End Verification Report

Date: 2026-10-31 (Asia/Calcutta)

Scope: Read-only project verification. The report and temporary verification database/reports were created only under `D:\cyber\verification\`. No source, model, data, or ablation report files were edited in this verification. The prior ablation session handle was unavailable; I did not restart it. A read-only process check found no Python process running at that check time. No full test suite was run.

| Check | Description | Status | Evidence |
|---:|---|---|---|
| A1 | Required pipeline result fields | PASS | `analysis_service.analyze_flow` completed on four flows; each had `final_decision`, a `risk` mapping, `pipeline_version: 1.0.0`, and `git_commit_hash: 5fc8914 (dirty)`. |
| A2 | Evidence trail schema and cited reasons | PASS | All four trails had 7–8 items with `id/type/source/value/direction/weight`; every `decision.correlation_reasons` sentence contained a valid trail ID. |
| A3 | Agent trace coverage | PASS | Each result had 9 trace entries with all six requested fields; all expected stages appeared and none was `unavailable`. |
| A4 | Rare-family stage | PASS | `rare_family.available` was `true` and `rare_family.error` was absent/null for DoS, WebAttack, Heartbleed, and benign samples. |
| A5 | LLM-off deterministic note | PASS | Each LLM-off result used `note_source: template` with `note_validation: passed`; repeating the template-note function with the same Heartbleed evidence/response returned identical text. |
| B6 | Incident creation by decision | PASS | DoS, WebAttack, and Heartbleed each returned ATTACK with an incident ID and incident-count increase of 1; the benign flow returned BENIGN with no ID and count increase of 0. |
| B7 | Incident detail fields | NOT VERIFIED | The temporary store detail payload contained evidence trail, agent trace, and playbook, with lifecycle history after transition; the HTTP GET detail did not return because `TestClient` stalled on its first request. |
| B8 | Playbook technique/evidence grounding | PASS | DDoS playbook generation returned four steps using `T1498`, each with evidence IDs; an unknown family returned `generic playbook` with no technique ID. |
| B9 | Lifecycle and audit | PASS | Direct temporary-store calls allowed New → Triaged, rejected New → Resolved, and recorded the state change in `audit_trail` with previous and new states; HTTP status mapping was not exercised. |
| B10 | Approval and simulation log | PASS | Direct temporary-store calls rejected approval from New, accepted after Triaged, and created a log labeled `SIMULATION`, mode `dry-run`, with `executed: false`. |
| B11 | Incident report endpoint | NOT VERIFIED | Direct `write_report` created Markdown and JSON with version, evidence trail, agent trace, playbook, and timeline sections; the HTTP report endpoint itself was not observed because the in-process client stalled. |
| C12 | API token behavior | NOT VERIFIED | No successful HTTP health response was captured; the `TestClient` workflow stalled, and the direct middleware/health attempt did not return before it was stopped. |
| C13 | Generic API exception response | NOT VERIFIED | The handler source returns `Internal server error.` and logs exception detail, but no forced-exception HTTP response was captured. |
| C14 | Health version and commit | NOT VERIFIED | Pipeline calls directly returned version `1.0.0` and commit `5fc8914 (dirty)`; `/api/health` itself did not return in the stalled client check. |
| D15 | Frontend feature paths (static inspection) | PASS | `renderBatchTable`/`exportBatchResults` and batch filter/search IDs; `evidenceTrailHtml`; `agentTraceHtml` plus `agent-trace-warning`; `explainHtml`/SHAP chart rows; `playbookHtml`/`renderIncidentHistory`; `renderIncidents` with search/decision/state/sort controls; footer `#pipelineBuildInfo` updated from health data. |
| D16 | JavaScript syntax and external URLs | PASS | `node --check` passed for all five frontend JS files, including both vendor modules; `rg 'https?://'` found no hits in `app.js`, `scenes.js`, `three-scene.js`, `index.html`, or `styles.css`. |
| E17 | `results.jsonl` age vs decision logic | PASS | `results.jsonl` timestamp: 2026-10-04 23:23:58; `correlation/decision_agent.py` timestamp: 2026-10-25 20:37:08. The result file is older than the current decision logic file. |
| E18 | Root generated-looking files, ignore coverage, and Git status | FAIL | Generated-looking root files not covered by `.gitignore`: `infiltration_analysis_report.md`, `infiltration_feature_analysis.csv`, and `mermaid-diagram.png` (all tracked). `results.jsonl`, `results_check.jsonl`, and `system_smoke.jsonl` are ignored by JSONL rules. Git status was not clean: `evaluation/ablation_study.py`, `reports/ablation_study/README.md`, `reports/ablation_study/ablation_metrics.csv` modified and `reports/ablation_study_v2/` untracked before this verification; this task also created `verification/`. |

## FAIL items and likely causes

- **E18:** The worktree already contained ablation-script/report changes and an untracked v2 output folder, so `git status --short` was not clean. The three listed root artifacts are tracked but have no ignore rules.

## NOT VERIFIED items and manual browser checks

- **B7:** Open an ATTACK incident in the dashboard. Confirm the detail request returns evidence trail, agent trace, playbook, and a chronological lifecycle history, and confirm the history panel renders it.
- **B11:** From that incident, open its report and confirm the Markdown and JSON include pipeline version, evidence trail, agent trace, playbook, and timeline. The underlying report writer passed; the API endpoint response was not observed.
- **C12:** Open `/api/health` with `CYBER_API_TOKEN` unset and confirm 200. Restart with a token configured; confirm a request without a bearer token gets 401 and the same request with the correct bearer token gets 200.
- **C13:** There is no dashboard action that deliberately raises an unhandled server exception. In a local-only fault-injection check, trigger one and confirm the client sees only `Internal server error.` while details stay in the server log.
- **C14:** Open `/api/health` and confirm it shows pipeline version `1.0.0` and the current non-`no-git` commit hash; confirm the same values appear in the dashboard footer.

The frontend checks were static only; open the dashboard in a browser to confirm these elements render and work together. The in-process client stalled, so I did not claim API endpoint behavior passed. No API server was started and no loopback restriction was observed.

## Ready for demo?

**Not fully verified yet.** Direct pipeline analysis and temporary-store incident workflows passed, and frontend syntax/static checks passed. Verify the listed API endpoints and dashboard behavior in a browser before relying on the end-to-end demo.
