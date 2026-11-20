# Leave-one-dataset-out evaluation

Git commit: `5b929ca`

## Method

Shared features come from `evaluation/tri_dataset_benchmark.py`. Each held-out fold trains on the other two datasets. Each training dataset is capped at 50,000 stratified rows (within the requested maximum of 200,000); each held-out capture is capped at 10,000 rows to keep the multi-fold study tractable. Validation is drawn only from the training datasets. Exact feature vectors shared between training and held-out data are removed from training. Seeds: 42–46 (includes the requested 42–44 and supplies seeds 45–46 required by ablation v3).

The active production models require 77 CICIDS features, while this cross-dataset mapping has 11. Production comparator values are therefore unavailable; omitted features were not fabricated.

CIC_IDS_Collection is excluded after the full audit found only 57 of 77 production features and no compatible shared-feature reader for this capture. See reports/dataset_audit/audit.json.

## Capture files and rows

| Dataset | Capture file | Rows used | Benign | Attack |
|---|---|---:|---:|---:|
| CICIDS2017 | `data\raw\CICIDS2017\Benign-Monday-no-metadata.parquet` | 8680 | 8680 | 0 |
| CICIDS2017 | `data\raw\CICIDS2017\Botnet-Friday-no-metadata.parquet` | 8682 | 8608 | 74 |
| CICIDS2017 | `data\raw\CICIDS2017\Bruteforce-Tuesday-no-metadata.parquet` | 8623 | 8403 | 220 |
| CICIDS2017 | `data\raw\CICIDS2017\DDoS-Friday-no-metadata.parquet` | 7485 | 3863 | 3622 |
| CICIDS2017 | `data\raw\CICIDS2017\DoS-Wednesday-no-metadata.parquet` | 8959 | 5919 | 3040 |
| CICIDS2017 | `data\raw\CICIDS2017\Infiltration-Thursday-no-metadata.parquet` | 8446 | 8413 | 33 |
| CICIDS2017 | `data\raw\CICIDS2017\Portscan-Friday-no-metadata.parquet` | 8513 | 8363 | 150 |
| CICIDS2017 | `data\raw\CICIDS2017\WebAttacks-Thursday-no-metadata.parquet` | 8586 | 8452 | 134 |
| CSE-CIC-IDS2018 | `data\raw\CSE_CIC_IDS2018\Botnet-Friday-02-03-2018_TrafficForML_CICFlowMeter.parquet` | 8072 | 6594 | 1478 |
| CSE-CIC-IDS2018 | `data\raw\CSE_CIC_IDS2018\Bruteforce-Wednesday-14-02-2018_TrafficForML_CICFlowMeter.parquet` | 8544 | 6940 | 1604 |
| CSE-CIC-IDS2018 | `data\raw\CSE_CIC_IDS2018\DDoS1-Tuesday-20-02-2018_TrafficForML_CICFlowMeter.parquet` | 6261 | 3208 | 3053 |
| CSE-CIC-IDS2018 | `data\raw\CSE_CIC_IDS2018\DDoS2-Wednesday-21-02-2018_TrafficForML_CICFlowMeter.parquet` | 8944 | 6129 | 2815 |
| CSE-CIC-IDS2018 | `data\raw\CSE_CIC_IDS2018\DoS1-Thursday-15-02-2018_TrafficForML_CICFlowMeter.parquet` | 8118 | 7696 | 422 |
| CSE-CIC-IDS2018 | `data\raw\CSE_CIC_IDS2018\DoS2-Friday-16-02-2018_TrafficForML_CICFlowMeter.parquet` | 7969 | 7475 | 494 |
| CSE-CIC-IDS2018 | `data\raw\CSE_CIC_IDS2018\Infil1-Wednesday-28-02-2018_TrafficForML_CICFlowMeter.parquet` | 8361 | 7337 | 1024 |
| CSE-CIC-IDS2018 | `data\raw\CSE_CIC_IDS2018\Infil2-Thursday-01-03-2018_TrafficForML_CICFlowMeter.parquet` | 8328 | 6218 | 2110 |
| CSE-CIC-IDS2018 | `data\raw\CSE_CIC_IDS2018\Web1-Thursday-22-02-2018_TrafficForML_CICFlowMeter.parquet` | 7545 | 7338 | 207 |
| CSE-CIC-IDS2018 | `data\raw\CSE_CIC_IDS2018\Web2-Friday-23-02-2018_TrafficForML_CICFlowMeter.parquet` | 7372 | 7136 | 236 |
| UNSW-NB15 | `data\raw\UNSW_NB15\UNSW-NB15_1.csv` | 8296 | 8163 | 133 |
| UNSW-NB15 | `data\raw\UNSW_NB15\UNSW-NB15_2.csv` | 7748 | 7579 | 169 |
| UNSW-NB15 | `data\raw\UNSW_NB15\UNSW-NB15_3.csv` | 5700 | 5374 | 326 |
| UNSW-NB15 | `data\raw\UNSW_NB15\UNSW-NB15_4.csv` | 5853 | 5553 | 300 |

## Results

`results.csv` contains per-seed metrics and capture-block bootstrap intervals. `summary.csv` and `results.json` report mean and standard deviation across seeds, including per-family recall.

## Limitations

Family labels are inferred from capture names in this shared-reader workflow and may be coarse. The confidence intervals resample capture files; intervals are unavailable when a held-out dataset has fewer than two captures. The metrics use a fixed 0.5 threshold.
