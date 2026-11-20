# Reproducing the reports

This guide describes how to regenerate the benchmark and diagnostic reports using the scripts currently in the repository. Commands below are for PowerShell from the repository root (`D:\cyber`). They are documentation only; I did not run report-generation commands. Those commands write into `reports/` and some train temporary in-memory candidates, so running them will replace report files.

## Environment

The repository pins runtime dependencies in `requirements.txt`; research/notebook extras are in `requirements-research.txt`. The current `recovery_venv` was observed using CPython `3.11.9` with these core versions: NumPy `2.4.6`, pandas `3.0.5`, PyArrow `25.0.1`, scikit-learn `1.6.1`, SciPy `1.17.1`, joblib `1.5.3`, XGBoost `2.1.3`, and SHAP `0.51.0`. These match the version pins in `requirements.txt`.

The optional research/notebook package pins are Beautiful Soup `4.15.0`, ipykernel `7.3.0`, Jupyter `1.1.1`, JupyterLab `4.6.3`, Matplotlib `3.11.1`, Notebook `7.6.2`, openpyxl `3.1.5`, PyYAML `6.0.3`, requests `2.34.2`, and seaborn `0.13.2`, as listed in `requirements-research.txt`.

The existing JSON reports do **not** record the Python version, installed package versions, source dataset checksums, or source dataset release/version used at generation time. The versions above describe the environment inspected now; they cannot prove the exact historical report-generation environment.

Create a fresh environment and install the pinned runtime dependencies:

```powershell
py -3.11 -m venv .repro-venv
.\.repro-venv\Scripts\python.exe -m pip install --upgrade pip
.\.repro-venv\Scripts\python.exe -m pip install -r requirements.txt
```

Use CPython `3.11.9` for the closest match to the currently inspected environment. The `py -3.11` launcher selects an installed Python `3.11`; it does not guarantee patch version `3.11.9`. The project does not include a Python-version lock file or fully locked transitive dependency file.

## Datasets and expected local layout

| Dataset | Where to obtain it | Local files expected by the scripts |
|---|---|---|
| CICIDS2017 | [UNB Canadian Institute for Cybersecurity dataset page](https://www.unb.ca/cic/datasets/ids-2017.html) | Per-capture Parquet files under `data/raw/CICIDS2017/` |
| CSE-CIC-IDS2018 | [UNB dataset page and AWS download instructions](https://www.unb.ca/cic/datasets/ids-2018.html). The page documents the public S3 bucket `s3://cse-cic-ids2018/`; AWS CLI command: `aws s3 sync --no-sign-request --region <your-region> "s3://cse-cic-ids2018/" <destination>` (replace the placeholders as directed by UNB) | Per-capture Parquet files under `data/raw/CSE_CIC_IDS2018/` |
| UNSW-NB15 | [UNSW Research dataset page](https://research.unsw.edu.au/projects/unsw-nb15-dataset) | `data/raw/UNSW_NB15/UNSW-NB15_1.csv` through `UNSW-NB15_4.csv` and `data/raw/UNSW_NB15/NUSW-NB15_features.csv` |
| CIC-IDS-Collection | [Kaggle CIC-IDS-Collection dataset](https://www.kaggle.com/datasets/dhoogla/cicidscollection/versions/2) | `data/raw/CIC_IDS_Collection/cic-collection.parquet` |

The `tri_dataset_benchmark.py` code currently looks for `NUSW-NB15_features.csv` (with `NUSW`), while the UNSW page calls the feature list `UNSW-NB15_features.csv`. A source file with the former exact spelling is required at the path shown above unless the script is changed. This naming mismatch is a reproducibility issue.

The CICIDS2017 and CSE-CIC-IDS2018 benchmark scripts require capture-level Parquet inputs. The project has a generic mapper/cleaner (`prepare_data.py prepare <input> <output>`), but the repository does not document a complete, verified command sequence that converts the official downloads into the exact per-capture Parquet filenames and labels expected here. Raw dataset download alone is therefore not sufficient to reproduce the reports byte-for-byte. Confirm mapped headers, labels, and capture filenames before running a report script.

For CIC-IDS-Collection, the project provides a Kaggle helper. It needs an installed/configured Kaggle CLI and a destination path that does not already exist:

```powershell
.\.repro-venv\Scripts\python.exe -m pipeline.kaggle_acquisition dhoogla/cicidscollection --destination data\raw\CIC_IDS_Collection_download
```

The helper records the downloaded archive checksum in `ACQUISITION_MANIFEST.json`, but its interface does not pin a Kaggle dataset version. The expected `cic-collection.parquet` path and dataset release must be checked after download; the existing report does not record a Kaggle version/checksum.

## Commands for benchmark report folders

Run each command from the repository root after installing requirements and placing the expected datasets and production artifacts locally. The scripts use the default output paths under `reports/`.

| Report folder / output | Command | Random seed and notes |
|---|---|---|
| `reports/adversarial_validation/benign_dataset_shift.json` | `.\.repro-venv\Scripts\python.exe evaluation\adversarial_dataset_validation.py` | Seed `20261011`; five capture-group folds; caps at `3000` rows per raw label per capture. |
| `reports/cic_collection_candidate/candidate_study.json` | `.\.repro-venv\Scripts\python.exe evaluation\cic_collection_candidate.py` | Seed `20261011`; research candidates are fit in memory and not saved/promoted. Requires CICIDS2017, CSE-CIC-IDS2018, CIC-IDS-Collection Parquet. |
| `reports/dataset_compatibility/cic_collection.json` | `.\.repro-venv\Scripts\python.exe evaluation\profile_cic_collection.py` | No random seed; static schema/data profile. Requires CIC-IDS-Collection Parquet. |
| `reports/feature_ablation_2018/feature_ablation.json` | `.\.repro-venv\Scripts\python.exe evaluation\feature_ablation_2018.py` | Seed `20261011`; trains matched research-only Random Forest candidates in memory. Requires CICIDS2017 and CSE-CIC-IDS2018 capture Parquet. |
| `reports/threshold_transfer_2018/threshold_transfer.json` | `.\.repro-venv\Scripts\python.exe evaluation\threshold_transfer_2018.py` | Seed `20261011`; reads the active production models and reports a two-fold capture-held-out threshold transfer. |
| `reports/model_acceptance/acceptance_gate.json` | `.\.repro-venv\Scripts\python.exe evaluation\model_acceptance_gate.py` | No random seed; reads `reports/threshold_transfer_2018/threshold_transfer.json` by default. The command writes its JSON and exits `1` when the decision is `IMPROVE`; that nonzero exit is an expected gate result, not a failure to write the report. |
| `reports/priority_family_candidate/priority_family_candidate.json` | `.\.repro-venv\Scripts\python.exe evaluation\priority_family_candidate.py` | Seed `20261011`; trains non-deploying in-memory candidates. Requires CICIDS2017 and CSE-CIC-IDS2018 capture Parquet. |
| `reports/production_model_validation/production_external_2018.json` | `.\.repro-venv\Scripts\python.exe evaluation\production_model_validation.py` | Seed `20261008` by default; override with `--seed`. Defaults: `--max-rows-per-label 5000`, `--batch-size 20000`. Reads but does not retrain or change the production artifacts. |
| `reports/ten_type_candidate/ten_type_candidate.json` | `.\.repro-venv\Scripts\python.exe evaluation\ten_type_candidate.py` | Seed `42`; trains research-only in-memory candidates; no production artifact promotion. Requires CICIDS2017 and CSE-CIC-IDS2018 capture Parquet. |
| `reports/tri_dataset_benchmark/benchmark.json` and `metrics.csv` | `.\.repro-venv\Scripts\python.exe evaluation\tri_dataset_benchmark.py` | Seed `42`; default `--rows-per-file 20000`, `--target-fpr 0.01`, `--minimum-recall 0.80`. Requires CICIDS2017/CSE-CIC-IDS2018 Parquet and all four UNSW-NB15 CSV parts plus the required feature-name file. |

The acceptance gate depends on the threshold-transfer report, so run `threshold_transfer_2018.py` before `model_acceptance_gate.py`. Each table seed is the script's source-code constant/default; these are not all recorded in the output report itself.

## Reports that cannot currently be reproduced from a documented command

- **`reports/production_model_validation/production_2017_source_check.json`: not currently reproducible.** No current tracked evaluation script was found that writes this file. `evaluation/production_model_validation.py` writes `production_external_2018.json` only. The source-check report says it evaluates CICIDS2017, but the exact script/command, random seed, and exact sampled input snapshot are not available.
- **`reports/evaluator_demo/`: not a benchmark report directory.** These incident-specific JSON/Markdown reports are written when the CLI or API analyzes flows. Each output depends on its original input file and row; the exact command/input combination for each saved report is not documented as a bulk regeneration procedure. `cyber.py` accepts a flow file and supports `--report-dir`; regenerate only when the original input is available, e.g. `.\.repro-venv\Scripts\python.exe cyber.py data\processed\flows_prepared.parquet --all --output results.jsonl --report-dir reports\evaluator_demo` (only if that input file exists and matches the original inputs).
- **`reports/incidents/`: not a benchmark report directory.** These are per-incident reports written during API/CLI analysis and state updates. There is no single script that reconstructs this directory; original flow inputs and interaction history are required, and the saved reports do not identify all source inputs in a reproducible manifest.
- **Dataset preparation and provenance:** The source reports do not capture source URLs, dataset release identifiers, file hashes, preparation commands, or exact Python/library versions at report-generation time. Reproducing the same named script is possible only if input data and active model artifacts match the original versions. Exact historical reruns are not currently guaranteed.

## Seeds recorded in source scripts

| Script | Seed |
|---|---:|
| `evaluation/adversarial_dataset_validation.py` | `20261011` |
| `evaluation/cic_collection_candidate.py` | `20261011` |
| `evaluation/feature_ablation_2018.py` | `20261011` |
| `evaluation/priority_family_candidate.py` | `20261011` |
| `evaluation/production_model_validation.py` | `20261008` (default; CLI override supported) |
| `evaluation/ten_type_candidate.py` | `42` |
| `evaluation/threshold_transfer_2018.py` | `20261011` |
| `evaluation/tri_dataset_benchmark.py` | `42` |
| `evaluation/profile_cic_collection.py` and `evaluation/model_acceptance_gate.py` | no random sampling/training seed used |
| CICIDS2017 production source-check report | not available; no current generator found |

