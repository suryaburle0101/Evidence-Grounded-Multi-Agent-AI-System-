# Capture-Aware Evaluation of Flow-Based Intrusion Detection

> **Source checkout:** This copy includes source code, tests, and selected evaluation results.
> See [Local data and model setup](docs/local_artifacts.md) before launching the API
> or reproducing dataset-backed experiments.

**Project:** Cyber multi-agent network-flow triage prototype

This project analyzes CICIDS2017-style network-flow records with two general
classifiers, dedicated rare-family detectors, an investigation agent, flow and
reference evidence, a correlation decision agent, and a response recommender.
The response agent produces recommendations only; it does not isolate hosts or
change network controls.

The original research target was detection of at least 10 distinct attack
types on unseen captures. The available experiments do not meet that target;
the defensible contribution is the capture-aware evaluation and its limits.
The CICIDS2017 and CSE-CIC-IDS2018 files support a 12-type candidate: Botnet,
FTP brute force, SSH brute force, DDoS, four DoS types, Infiltration, web brute
force, XSS, and SQL injection. This is a benchmark scope, not a claim that the
system detects every attack in real networks.

Run `.\.venv\Scripts\python.exe evaluation\ten_type_candidate.py` to
reproduce the current non-deploying candidate evaluation. It trains on whole
capture files from both datasets, calibrates on benign flows from two separate
captures, tests on six held-out capture files, and excludes feature-identical
rows across splits. The latest run trained on 232,629 rows and evaluated
108,737 held-out flows. With separate thresholds per type, XGBoost flagged
54.6% of attack flows and correctly classified 44.2% on average across types,
with a 1.44% held-out benign false-positive rate. Random Forest reached 31.1%
mean correct-type recall at a 0.94% false-positive rate. Both fail the
requirement of at least 80% correct-type recall for each of the 12 types and
at most 1% benign false alarms. Several rare test types have fewer than 100
flows, so their estimates are especially uncertain. Results are in
`reports\ten_type_candidate\ten_type_candidate.json`. No candidate is active
in the dashboard.

This six-held-out-file candidate run uses per-type thresholds and is a
different protocol from the 18-capture family pilot below. Its values are
reported for that candidate only and should not be compared as if the samples
and operating points were identical.

The capture-held-out family experiment is a separate, non-deploying research
candidate. Across three matched seeds, the five-family XGBoost pilot reached
23.0% mean attack recall, compared with 22.4% for the 12-type baseline; the
paired capture-bootstrap interval for the difference was −5.0 to +7.0
percentage points. The interval includes zero, so family aggregation did not
establish an improvement. The detailed report and rerun command are in
`experiments/family_design_20261116/`.

A separate 12-detector one-vs-rest candidate was also evaluated across the same
18 held-out captures. Mean capture recall rose from 22.4% to 25.0%, but the
paired capture interval (−9.2 to +14.3 points) includes zero. Pooled FPR rose
from 0.61% to 10.35%, worst-capture FPR from 3.5% to 53.7%, and mean capture
PR-AUC fell from 0.777 to 0.664. The candidate was rejected. See
`experiments/unseen_generalization_20261117/RESULTS.md` for per-type outcomes.

A larger 5,000-row-per-label XGBoost run raised mean capture recall to 37.0%,
but pooled FPR rose to 5.20% and worst-capture FPR to 20.48%. A follow-up using
four diverse benign calibration captures from the held-out dataset brought
worst FPR down to 1.10% at the 1,000-row cap, but recall fell to 18.6%; at the
5,000-row cap recall was 19.3% and worst FPR remained 2.68%. None meets both
the recall and false-alarm requirements. These one-seed candidates are
research-only; details and rerun commands are in
`experiments/unseen_generalization_20261117/SAMPLE_CAP_AND_CALIBRATION.md`.

The source-aligned CICIDS2017 check reported 99.4% Random Forest accuracy, but
the model's exact training-capture membership is unknown. Treat that score as
an optimistic source-aligned result, not an independent same-capture holdout.
It is not directly comparable with the reduced-sample leave-one-capture-out
recall above. Cross-dataset family transfer was also directional: worst-capture
FPR was 5.7% from CICIDS2017 to CSE-CIC-IDS2018 and 20.7% in reverse. No
attack type or family currently meets the project's reliability rule for
unseen captures. Better evidence requires additional independent capture days
for the weak families, especially Botnet, brute force, and Infiltration. A
metadata-bearing CICIDS2017 mirror was inspected, but an exact 77-feature plus
label join matched only 1 of 17,708 sampled rows (2 more were ambiguous), so
metadata was not attached to prepared samples. A separate raw-source temporal
feature study across 17 CICIDS2017/CSE-CIC-IDS2018 captures did not resolve the
generalization gap: four history features lowered mean attack recall to 19.3%;
same-destination-port history alone gave 24.1% detected recall but 10.3%
correct-type recall and 12.65% worst-capture FPR. Both are one-seed exploratory
results, not production candidates. See
`experiments/unseen_generalization_20261117/metadata_behavior_loco/RESULTS.md`,
`experiments/unseen_generalization_20261117/METADATA_AUDIT.md`, and the earlier
search report in `experiments/behavior_features_20261114/`.

The active dashboard still uses its existing family-level models. The
five-family pilot is research-only and is not the per-flow confidence model in
the dashboard. Dashboard output is for human triage; its raw classifier scores
are not calibrated real-world probabilities. In the incident list and detail
view, the displayed family name groups DoS/DDoS subtypes, brute-force labels,
and web-attack labels under the broader five-family research taxonomy. The raw
classifier label remains available in the incident detail. The dashboard also
shows the pilot's per-family aggregate recall as context; those values are not
per-flow predictions, and no family met the stated unseen-capture reliability
rule. Labels outside that pilot taxonomy are shown as their original model
label and marked as not evaluated there.

**Status:** a local prototype and demonstration, not a production security tool. The detector was trained on CICIDS2017 and is validated only for CICIDS2017-style flows; on CSE-CIC-IDS2018 it missed most attacks (see External validation below). A Benign verdict must not be read as "safe". It analyzes supplied flow files and supports offline PCAP conversion through a separately installed, configured flow extractor; it does not capture live traffic. API token authentication is optional and off by default; the server still binds to `127.0.0.1` by default.

## Quickstart

1. **Install:** Create a fresh environment and install the runtime dependencies:
   ```powershell
   py -3.11 -m venv .venv
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   ```
   If the Python launcher reports that no 3.11 runtime is installed, replace
   the first command with `& 'C:\Path\To\Python311\python.exe' -m venv .venv`,
   using the full path to your installed Python 3.11 executable.
2. **Start:** From the project folder, run `.\.venv\Scripts\python.exe api.py` and leave that window open. The dashboard starts without the optional local language model.
3. **Open the dashboard:** Visit [http://127.0.0.1:8000/](http://127.0.0.1:8000/) and choose **Run quick demo** to try the flow.

The release ZIP includes the 40-row processed sample at
`data/processed/end_to_end_sample.parquet` so the demo works without raw
captures. Raw benchmark captures are not included.

Install notebook, plotting, and other research extras with
`.\.venv\Scripts\python.exe -m pip install -r requirements-research.txt`.
Older standalone evaluation scripts are in `evaluation\legacy_scripts` and
resolve their data and model paths from the project root.

## Usage guide

### Interactive flow topology

The dashboard's flow topology groups analyzed connections by supplied source
and destination IP/host metadata, colors connections by the pipeline decision,
and lets an analyst select an endpoint to inspect associated flow details. The
locally bundled Three.js perspective view is bounded to 100 connections and 32 displayed
endpoints; excess endpoints are grouped. A short particle animation is a visual cue only, not
live packet timing or captured traffic. If Three.js or WebGL cannot start, the dashboard
switches to a 2D Canvas graph and shows a short notice. If endpoint metadata is
missing, the graph groups those flows into clearly labeled unknown source and
destination nodes rather than implying they are real devices. **Play attack simulation** runs a separate animated
storyboard for the selected or detected family, including different paths for
DDoS, DoS, brute force, port scans, botnets, infiltration, SQL injection, XSS,
and Heartbleed. When analyzing all sample types, the replay follows the
highest-risk ATTACK result. It explains the detected label; flow records do not
contain enough information to recreate the original packets or an exact video.

### Dashboard

```powershell
.\.venv\Scripts\python.exe api.py
```

Leave that window open, then open http://127.0.0.1:8000 and press **Run demo**. The dashboard analyzes up to 100 rows per batch and binds to localhost only. Input must be CICFlowMeter-style CSV or Parquet with the 77 CICIDS2017 features. Run the tests with `.\.venv\Scripts\python.exe -m unittest discover -s test`.

### Command line

After creating `.venv` with the Quickstart instructions, run the CLI directly
with that environment. This keeps the trained models on their pinned library
versions:

```powershell
.\.venv\Scripts\python.exe cyber.py data\processed\end_to_end_sample.parquet --all --output results.jsonl
```

If the included environment is unavailable, create a new one and install the
dependencies:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

The CLI checks the installed scikit-learn and XGBoost versions before loading
models and reports a direct interpreter command if they do not match.

Analyze a CICIDS2017 capture after placing it in the local `data\raw` folder.
Raw benchmark captures are not included in the release ZIP:

```powershell
.\.venv\Scripts\python.exe cyber.py data\raw\CICIDS2017\Benign-Monday-no-metadata.parquet --output results.jsonl
```

By default, the CLI analyzes the first 10 rows so a large capture does not
start an unexpectedly long run. Each output line is one JSON object containing
the complete pipeline result, the input file, and a one-based row number. Use
`--limit 100` to set a different cap, or `--all` to process every row. The
pipeline takes about 1–2 seconds per row on the included CPU environment, so
processing a full benchmark dataset may take hours. Progress is reported every
100 rows. Omit `--output` to write JSON Lines to the console.

The CSV or Parquet file must contain the 77 numeric model features. An optional
`Label` column is ignored by feature selection and is never used to make
predictions.

Pre-extracted flow files may also include source/destination IPs, hosts, ports,
timestamps, and flow identifiers. The preparation and analysis paths preserve
recognized metadata separately from the model's numeric feature matrix; known
ground-truth label columns are stripped before the analysis agents run. This is
not a packet-capture implementation: a PCAP must first be converted into a
compatible flow schema by a separately validated extractor.

Run `.\.venv\Scripts\python.exe cyber.py --help` for command options. The trained model files in
`models/` are loaded when analysis begins. The large raw datasets in `data/raw/`
are only needed for training and evaluation, not for analyzing a supplied flow
file. `results.jsonl` contains the 40-row end-to-end sample run across benign,
DDoS, Infiltration, and Heartbleed flows; the sample input is in
`data/processed/end_to_end_sample.parquet`.

The active XGBoost models are stored in UBJSON format in `models/`. The original
pickle artifacts remain alongside them. Their predictions matched exactly on
the included 40-flow sample when the UBJSON files were created.

### Three-dataset validation

Run `.\.venv\Scripts\python.exe evaluation\tri_dataset_benchmark.py`
to benchmark CICIDS2017, CSE-CIC-IDS2018, and UNSW-NB15. It holds out whole
capture files for calibration and testing, removes invalid and within-file
duplicate rows, excludes feature-identical calibration/test rows seen in an
earlier split, and reports calibrated binary metrics, confusion counts,
Brier/ECE scores, a benign-trained novelty baseline, and feature drift in
`reports\tri_dataset_benchmark\`. Cross-file duplicate counts are audited.
Because
UNSW-NB15 does not have the CICFlowMeter 77-feature schema, the benchmark uses
an explicitly reduced shared feature set and also measures UNSW-trained models
on an UNSW held-out file. These are candidate research models; they do not
replace the current dashboard detector automatically.

The latest 20,000-rows-per-file run, with cross-split feature duplicates
excluded, found XGBoost recall of 2.38% on held-out CICIDS2017 captures, 1.58%
on CSE-CIC-IDS2018, and 0.16% on the external UNSW-NB15 group at a 1%
calibration false-positive target. The UNSW-specific XGBoost candidate reached
73.66% recall at 0.77% false-positive rate on the held-out UNSW file. These
figures are from sampled laboratory data and one fixed file split; they do not
justify enabling the shared candidate in production or establish field
performance. The report also flags substantial feature drift on the external
UNSW evaluation. The benchmark now also reports an evaluation-only analyst-
review union: flag a flow for review if either the binary classifier or a
benign-trained Isolation Forest flags it. On the held-out 2018 captures, this
raised recall to 53.72% (Random Forest) and 55.30% (XGBoost), with 1.12% and
1.22% benign false-positive rates, respectively. The novelty signal alone
recalled 53.72% at 0.69% FPR. This still misses nearly half the attacks and
does not meet the 1% gate for the combined XGBoost review signal; it is not
enabled in the production detector. Metrics are now also broken out by held-out
capture in `reports/tri_dataset_benchmark/benchmark.json` to expose variability.

### Four-feature ablation experiment

Run `.\.venv\Scripts\python.exe evaluation\feature_ablation_2018.py`
to reproduce a research-only comparison of matched Random Forest candidates
with all 77 production features and with ECE Flag Count, RST Flag Count, Fwd
Seg Size Min, and Fwd Header Length removed. Training, calibration, and
within-dataset test captures are separated; the candidates are also scored on
all ten CSE-CIC-IDS2018 captures. The report is saved to
`reports\feature_ablation_2018\feature_ablation.json`; production model files
are not modified.

In the bounded per-label sample used for this experiment, removing the four
features raised external CSE-CIC-IDS2018 recall from 24.9% to 28.8% and AUC
from 0.713 to 0.727, but also raised the external false-positive rate from
1.68% to 7.63%. Performance varied by capture. Thresholds were calibrated on
one CICIDS2017 capture, so this result does not validate the ablated model for
deployment and does not establish which feature definitions caused the shift.

### 2018 threshold-transfer and dataset-shift diagnostics

Run `.\.venv\Scripts\python.exe evaluation\threshold_transfer_2018.py`
to set each production model's threshold from benign scores in five complete
CSE-CIC-IDS2018 captures, then test on the other five and swap the groups. The
calibration threshold is selected to keep empirical calibration FPR at or
below 1%, including tied scores. The production model files are not changed.
The report is saved to `reports\threshold_transfer_2018\threshold_transfer.json`.

In this sampled two-fold run, pooled out-of-fold FPR was 0.75% for Random
Forest and 0.60% for XGBoost. Attack recall remained low: Random Forest
recalled 41.2% of DoS, 18.5% of DDoS, 30.6% of Web Attack, 1.8% of Brute
Force, 1.3% of Infiltration, and 0.2% of Botnet flows. XGBoost recalled
37.8%, 18.2%, 11.9%, 1.0%, 1.4%, and 0.2%, respectively. Some individual
capture FPRs exceeded 1%, so the pooled result does not establish a per-capture
1% guarantee. Neither model meets an 80%-per-family recall target.

Run `.\.venv\Scripts\python.exe evaluation\adversarial_dataset_validation.py`
to test whether benign CICIDS2017 and CSE-CIC-IDS2018 rows can be distinguished
using grouped, capture-held-out cross-validation. The sampled out-of-fold AUC
was 0.987. The most associated features are reported in
`reports\adversarial_validation\benign_dataset_shift.json`. This is evidence
that the benign feature distributions differ; it does not explain why or prove
that changing a listed feature will improve attack detection.

## Pipeline output

The orchestrator returns these stages:

1. `detection`: Random Forest and XGBoost predictions and probabilities.
2. `rare_family`: optional dedicated Infiltration and Heartbleed signals.
3. `investigation`: severity, finding, and investigation priority.
4. `evidence`: flow-level signals and locally stored reference material.
5. `decision`: correlated `BENIGN`, `REVIEW`, or `ATTACK` outcome.
6. `response`: suggested investigation and mitigation actions.

Detection scores are raw classifier outputs and are not calibrated probabilities. When both classifiers agree but the score is within 0.05 of the 0.50 attack boundary, the decision is `REVIEW` instead of a hard call. The Random Forest result includes a per-flow SHAP attribution, which describes the model's score and does not show that an attack occurred. The batch endpoint (`POST /api/analyze-batch`, used by the dashboard) also returns an `input_drift` object from the input range check described below; the single-flow endpoint does not.

An unavailable rare-family model or evidence source is reported in the result;
review those fields before relying on an outcome. The models were trained on
specific benchmark data and should be independently validated on the traffic,
feature extraction pipeline, and operating conditions where they will be used.

## Project map

- `agents/`, `detection/`, `correlation/`, `evidence/`, `response/`: analysis pipeline
- `models/`: trained model artifacts and label encoder
- `data/raw/`: CICIDS2017, CSE-CIC-IDS2018, and UNSW-NB15 source data
- `evaluation/`: validation, benchmark and drift-baseline scripts
- `test/`: unit tests (`python -m unittest discover -s test`); the top-level `test_*.py` files are older evaluation scripts
- `pipeline/drift.py`: live input-range check used by the dashboard API
- `scripts/debug/`: one-off diagnostic scripts (set `PYTHONPATH` to the project folder to run them)
- `train_multidataset.py`: multi-dataset training workflow
- `train_rare_family_models.py`: training workflow for rare-family models
- `notebooks/`, `experiments/`, `reports/`: research and diagnostic material

The evaluation scripts expect the datasets in their existing directory layout
under `data/raw/`. Training scripts may overwrite model artifacts; back up any
model files you need to preserve before retraining.

## End-to-end operations

The backend includes schema profiling and preparation, model analysis, IOC
matching, local evidence retrieval, risk scoring, persistent incident records,
reports, approval-gated response recommendations, post-response validation,
and REST/WebSocket events. College-specific data integration remains outside
the project scope.

### Local web dashboard

The project includes a local web interface served by the API. Its JavaScript, CSS, and Three.js 0.186.1 modules are bundled under `frontend/` and served locally.
Start it with:

```powershell
.\.venv\Scripts\python.exe api.py
```

Then open `http://127.0.0.1:8000/`. The dashboard provides incident and risk
summary cards, an interactive 3D flow view, incident details and validation,
approval-gated response recording, IOC import, local evidence search, live
system events, and flow analysis. Under **Analyze flows**, choose **All sample
types** for the bundled 40-row example, or choose one of the labeled CICIDS2017
attack types and analyze matching rows. The release ZIP's processed sample
contains Benign, DDoS, Infiltration, and Heartbleed; other attack types require
raw CICIDS2017 captures, which are not included. Dataset labels are used only to select the demonstration
rows and are removed before analysis; predictions shown are produced by the
detector. After analysis, the attack simulation follows the highest-risk flow
with an ATTACK verdict and uses its detected family (for example, botnet
command-and-control, multi-source DDoS, internal infiltration, or SQL
injection). If a selected attack dataset produces no ATTACK verdict, the
dashboard says so and does not play a simulation that would imply a detection.
You can also
upload a prepared CSV with the 77 model feature
columns; dashboard batches are capped at 100 rows. Parquet and large-dataset
processing remain available through the CLI. The dashboard loads its assets and API over the local origin; it makes no third-party requests on page load. Flow data is analyzed on this machine. ThreatFox sync sends an outbound request only when an analyst starts a sync, and external reference links load only when clicked. The scenes are not packet recordings and do not prove a host was compromised. Real IP, host, and port values are shown only if the supplied flow includes them. The app does not capture or send live network traffic. If Ollama or the optional local model is unavailable, the API still starts in retrieval-only mode and the detector/dashboard remain available.

Prepare a CSV or Parquet file before analysis when its headers differ from the
trained CICIDS2017 feature schema. Preparation maps supported CICFlowMeter
aliases, converts feature values to numbers, drops invalid rows, retains the
original label, and writes compressed Parquet:

```powershell
.\.venv\Scripts\python.exe prepare_data.py profile data\raw\CSE_CIC_IDS2018\DDoS1-Tuesday-20-02-2018_TrafficForML_CICFlowMeter.parquet
.\.venv\Scripts\python.exe prepare_data.py validate data\processed\end_to_end_sample.parquet
.\.venv\Scripts\python.exe prepare_data.py prepare data\raw\flows.csv data\processed\flows_prepared.parquet
.\.venv\Scripts\python.exe cyber.py data\processed\flows_prepared.parquet --all --output results.jsonl --report-dir reports\incidents
```

An optional asset context JSON can provide `criticality` (`low`, `medium`,
`high`, or `critical`) and `exposure` (`internal` or `internet_facing`). An IOC
feed can be supplied with `--intel-feed feed.json` or `--intel-feed feed.csv`.
Reports and the SQLite evidence store are local under `reports\incidents` and
`data\evidence_store.sqlite`.

Start the local operations API in one terminal:

```powershell
.\.venv\Scripts\python.exe api.py
```

It listens on `127.0.0.1:8000`. Interactive endpoint documentation is at
`http://127.0.0.1:8000/docs`. The API supports flow analysis, incident search,
manual response approval, resolution validation, IOC import, evidence search,
incident report retrieval, and a WebSocket at `/ws/events`. Response approval
records permission for manual execution; the backend does not change firewall,
host, or network controls.

Optional bearer-token authentication protects API routes, API documentation,
and the event WebSocket. It is disabled when `CYBER_API_TOKEN` is unset or
empty. To enable it in PowerShell before starting the API:

```powershell
$env:CYBER_API_TOKEN = "replace-with-a-long-random-token"
.\start_offline_api.ps1
```

API clients send `Authorization: Bearer <token>`. The dashboard asks for the
token when the server requires one and keeps it only in page memory. The
WebSocket authenticates with an initial token message. Keep the API on
localhost unless you have separately configured secure network access.

The local RAG layer retrieves from the bundled evidence library without a
language model. This PC has about 8 GB RAM and CPU-only inference, so use the
smaller `llama3.2:1b` model for efficient local notes. The trained classifiers
remain responsible for detection; the language model only summarizes retrieved
evidence. Install Ollama, download the model into the project data folder, then
start the API with:

```powershell
.\install_offline_model.ps1
.\start_offline_api.ps1
```

The setup scripts store the weights in `data\ollama_models`, disable Ollama
cloud features, and use a dedicated local Ollama port (11435) so an existing
desktop Ollama service cannot hide the project model directory. They check
that the model is installed before starting the API.
Pass `-Model` to `install_offline_model.ps1` or `start_offline_api.ps1` to use a
different model.

Note generation is opt-in to keep CPU analysis fast. Add `--generate-notes`
to `cyber.py`, or send `"generate_note": true` in an `/api/analyze` request.
The API health response reports whether the model is reachable and installed.
Without generation, the project produces a deterministic summary from the
classifier decision, input metrics, and retrieved references. If enabled, a
complete model draft is clearly marked for analyst review; truncated or timed
out drafts are omitted. Benign flows skip generation. The ML pipeline remains
responsible for detection, and reports include the retrieved evidence sources.

## Model validation status and limits

The active 77-feature CICIDS2017 production artifacts remain the deployed detector. Their classifier probabilities are explicitly labeled **raw and uncalibrated** in results; agreement between the classifiers does not make them independent. Agreed results within 0.05 of the existing 0.50 attack boundary now go to **REVIEW** instead of a hard call. These rules are provisional until the production model is recalibrated on capture-group holdouts.

The Random Forest result now includes a per-flow Tree SHAP explanation of the binary attack score. It lists the top signed feature contributions, verifies that the baseline plus contributions reconstructs the model score, and labels the attribution as non-causal. Explanations appear in incident details and JSON/Markdown reports. The dependency is pinned in `requirements.txt`.

Run `.\.venv\Scripts\python.exe evaluation\tri_dataset_benchmark.py` to evaluate CICIDS2017, CSE-CIC-IDS2018, and UNSW-NB15. It maps a small common set of flow measurements, holds out capture files, reports calibrated binary metrics and feature-distribution drift, and saves to `reports\tri_dataset_benchmark`. This is a research candidate, not the production detector. Current cross-dataset results are too weak to activate it; review per-dataset recall and false-positive rates instead of headline accuracy. CICFlowMeter-ready CSV/Parquet is accepted after schema validation. Direct PCAP capture/replay is not integrated, so real-time monitoring is not claimed.

The improvement/acceptance loop is report-only. The current target is the 12 distinct types listed above, not five aggregated families. The three-dataset benchmark and the historical `evaluation\model_acceptance_gate.py` remain useful binary/family-level context, but cannot certify the 12-type requirement. The detailed current decision is in `reports\ten_type_candidate\ten_type_candidate.json`; it records per-capture and per-type outcomes and never promotes or changes a model. The active production detector has not been updated because the current candidate fails the per-type recall and false-alarm criteria.

Cross-incident correlation is available through `GET /api/incidents/correlated?window_minutes=60&limit=500`. It surfaces candidate groups that share a source/destination IP within an ingestion-time window. The result is an analyst lead, not proof of a common campaign; it uses ingestion time because capture timestamps may be absent or inconsistent. This is local correlation only, not a live SIEM timeline.

The live 3D-style flow topology draws supplied source and destination endpoints as nodes and each analyzed flow as a colored connection. It caps a dashboard view at 100 connections and 32 visible nodes, groups excess endpoints, and stops its brief particle replay after five seconds. When endpoint metadata is absent, it groups flows into labeled unknown-source and unknown-destination nodes, and summarizes connections by decision so the view stays readable. These groups are not real devices. This is a Canvas projection, not a packet-level or live-traffic visualization; the separate attack replay remains illustrative.

The Incidents dashboard includes the same correlation query and links each candidate incident. The data-acquisition helper `.\.venv\Scripts\python.exe -m pipeline.kaggle_acquisition owner/dataset --destination data\raw\<dataset-folder>` invokes the configured Kaggle CLI, safely extracts one dataset archive into an empty destination, and writes an acquisition manifest with the archive checksum. Install/configure Kaggle CLI credentials locally first. The downloader does not automatically certify dataset licenses, schema compatibility, label quality, or model suitability; validate those before training.

Offline PCAP processing is available through `.\.venv\Scripts\python.exe -m pipeline.pcap_ingestion capture.pcap --output reports\pcap\analysis.jsonl`. Configure `CICFLOWMETER_COMMAND` as a JSON array of arguments with `{pcap}` and `{output_dir}` placeholders, using an installed CICFlowMeter-compatible command-line extractor. The extracted CSV is checked against all 77 production features before inference; incompatible output is rejected before incidents are created. The extractor is a separate native tool and is not bundled or installed by this project. This path processes saved captures only; it is not live packet capture.

ThreatFox recent-indicator synchronization is available through `POST /api/threat-intel/sync?days=3` and the Threat Intelligence dashboard button. Set `THREATFOX_AUTH_KEY` in the local process environment; the API key is not stored in the repository or database. Only supported indicator types are imported; expired and unsupported entries are skipped. Sync is analyst-triggered and read-only with respect to the provider. Network access and a provider key are required.

Real response execution remains intentionally unconnected: it requires an identified firewall/EDR platform, an authorized test tenant, and platform credentials. Approval in this project still records authorization for manual action; it does not execute a block or independently verify host remediation. Do not treat the demo 3D view as a response simulation.

The local API rejects request bodies above 8 MiB, including chunked requests, dashboard batches above 100 flows, and threat-intelligence imports above 5,000 indicators. It binds to `127.0.0.1` by default. Optional token authentication is a basic access check; do not expose it to a shared network without roles, HTTPS, and deployment audit controls.

## External validation on CSE-CIC-IDS2018

The active CICIDS2017 production models (Random Forest and XGBoost, 77 features) were evaluated, without retraining, on all 10 CSE-CIC-IDS2018 capture files with `evaluation\production_model_validation.py`. Each file was sampled with a seeded per-label reservoir (up to 5,000 flows per label). Full results: `reports\production_model_validation\production_external_2018.json`. Scores are raw and uncalibrated; binary attack detection uses the 0.5 threshold.

| Capture | Attack flows sampled | RF recall | XGB recall | RF AUC | XGB AUC |
|---|---|---|---|---|---|
| Botnet (2 Mar) | 5000 | 0.000 | 0.000 | 0.457 | 0.837 |
| Brute force (14 Feb) | 5053 | 0.000 | 0.000 | 0.987 | 0.897 |
| DDoS (20 Feb) | 5000 | 0.000 | 0.000 | 0.972 | 0.955 |
| DDoS (21 Feb) | 6730 | 0.000 | 0.000 | 0.195 | 0.239 |
| DoS (15 Feb) | 10000 | 0.505 | 0.566 | 0.937 | 0.935 |
| DoS (16 Feb) | 5055 | 0.001 | 0.000 | 0.575 | 0.949 |
| Infiltration (28 Feb) | 5000 | 0.000 | 0.002 | 0.491 | 0.501 |
| Infiltration (1 Mar) | 5000 | 0.000 | 0.003 | 0.485 | 0.502 |
| Web (22 Feb) | 341 | 0.000 | 0.029 | 0.688 | 0.810 |
| Web (23 Feb) | 541 | 0.000 | 0.018 | 0.747 | 0.852 |

Findings:
- False-positive rates on benign traffic were 0.54% or lower in every capture, but attack recall was near zero for most captures: the models labeled most external attack flows Benign.
- Only the 15 Feb DoS capture was partly detected.
- Some captures have high AUC but zero recall (for example DDoS 20 Feb), so scores rank flows usefully there but the 0.5 cutoff does not transfer. Infiltration AUC is at chance, and DDoS 21 Feb is below 0.5.
- Several captures mix attack tools (for example SSH and FTP brute force, HOIC and LOIC-UDP), so a per-capture figure averages over tools. The web captures have the fewest attack flows (341 and 541), so their estimates are the least precise.

Conclusion: the production detector is validated only for CICIDS2017-style traffic. A Benign result on data from another source or feature extractor must not be read as "safe". These are laboratory results, not live-network accuracy.

Overall across all 10 captures (97,720 sampled flows: 50,000 benign, 47,720 attack), Random Forest at the 0.5 threshold had attack recall 10.6%, precision 99.7%, false-positive rate 0.03% and ROC AUC 0.685. Precision depends on the sampled benign/attack mix and is not an estimate of real-world precision.


## Input range check

Each dashboard batch is compared with per-feature 0.5th to 99.5th percentile bounds from CICIDS2017 (`models\drift_baseline.json`, built by `evaluation\build_drift_baseline.py`). A flow counts as unfamiliar when more than 10.4% of its 77 features fall outside those bounds (the 99th percentile for held-out CICIDS2017 flows). A batch shows a caution when at least 25% of its flows are unfamiliar and a warning at 50% or more; nothing is shown when the check passes.

Limitation: this check did not flag CSE-CIC-IDS2018. At most 0.6% of sampled flows in any capture were unfamiliar, against 0.8% for held-out CICIDS2017, even though the production models missed most attacks there. It catches gross input problems (wrong units, corrupt or missing values) but not the dataset shift documented above. The absence of a warning does not mean a verdict is reliable.

### Drift experiments

An Isolation Forest trained on CICIDS2017 was tried as a second novelty signal. At the 99th percentile of held-out CICIDS2017 scores it flagged 1.0% of held-out 2017 flows and 0.0% to 10.2% of sampled CSE-CIC-IDS2018 flows per capture (mostly under 1%, highest on the web captures). It did not separate the datasets, so it was not adopted.

Averaged over the ten 2018 captures, the features most often outside the CICIDS2017 training range were ECE Flag Count and RST Flag Count (26% of sampled flows each), Fwd Seg Size Min (23%) and Fwd Header Length (22%). This suggests feature-definition differences between CICFlowMeter versions as one candidate cause of the poor transfer. A matched Random Forest ablation removing these four features has now been tested; recall and AUC improved slightly in the bounded 2018 sample, while false-positive rate increased substantially. This neither establishes these features as the cause of transfer failure nor supports removing them from production. See the Four-feature ablation experiment above.

## Attack-family coverage

The multiclass classifier distinguishes seven classes: Benign, Botnet, Brute Force, DDoS, DoS, Port Scan and Web Attack. Heartbleed and Infiltration are handled by dedicated rare-family detectors. Together the system can label Benign plus eight attack families, and unknown traffic may still be mislabeled as one of them or as Benign.

Having a detector for a family does not mean it is reliable on new data. These were trained on CICIDS2017; on CSE-CIC-IDS2018 (see the validation section above) most families were missed at the 0.5 threshold, and Infiltration scores were at chance. The 3D attack scenes are illustrative and are not evidence that an attack occurred.
