# Results Summary

This summary was prepared from files already present under `reports/` only. No models were run and no metric was recalculated. Every reported numeric value below is copied from its cited report; cited JSON values retain the stored precision. When a requested item is not recorded in the source, it is marked **not available**. Per-capture, per-family, and other detailed breakdowns remain in the cited source report.

The benchmark folders covered are `adversarial_validation`, `cic_collection_candidate`, `dataset_compatibility`, `feature_ablation_2018`, `model_acceptance`, `priority_family_candidate`, `production_model_validation`, `ten_type_candidate`, `threshold_transfer_2018`, and `tri_dataset_benchmark`. The `evaluator_demo` and `incidents` folders contain evaluator/incident artifacts rather than benchmark folders, so they are not summarized as benchmarks.

## `adversarial_validation`

- **What it tests:** Whether benign flows from CICIDS2017 and CSE-CIC-IDS2018 can be distinguished by a dataset classifier, using capture-group-held-out folds. This is a dataset-shift diagnostic, not attack detection.
- **Dataset(s):** Benign CICIDS2017 and CSE-CIC-IDS2018 capture flows. The report samples up to `3000` rows per raw label per capture and holds out complete captures. Source: `reports/adversarial_validation/benign_dataset_shift.json` (`sampling_cap_per_raw_label_per_capture`, `group_split`).
- **Metrics reported:** `sampled_rows` `54000`; `sampled_cicids2017_rows` `24000`; `sampled_cse_cic_ids2018_rows` `30000`; `out_of_fold_roc_auc` `0.9867181104166667`; `out_of_fold_accuracy_at_0_5` `0.9233888888888889`. Source for each value: `reports/adversarial_validation/benign_dataset_shift.json` (same-named fields). The report also gives fold-level ROC AUC and accuracy and univariate dataset-AUC and feature-importance rankings.
- **Key finding:** The sampled benign datasets are highly distinguishable (reported out-of-fold ROC AUC `0.9867181104166667`; source: `reports/adversarial_validation/benign_dataset_shift.json`, `out_of_fold_roc_auc`). The report explicitly says this does not establish the cause and that feature rankings are diagnostic associations, not evidence that dropping or normalizing a feature improves attack detection. It is not live-network validation. Source: `reports/adversarial_validation/benign_dataset_shift.json`, `limitations`.

## `cic_collection_candidate`

- **What it tests:** Research-only candidate models trained with a documented common-feature schema, then scored on held-out CSE-CIC-IDS2018 and collection attack rows. It also examines calibration and attack-family recall.
- **Dataset(s):** CICIDS2017 capture files for candidate training; CICIDS2018 held-out data; novel attack rows sampled from CIC-IDS-Collection. Collection rows do not have source-capture provenance, so the report excludes collection benign rows from false-positive-rate claims. Source: `reports/cic_collection_candidate/candidate_study.json` (`training_dataset`, split/calibration fields, `limitations`).
- **Metrics reported:** Random Forest — threshold `0.42000000000000004`, calibration benign rows `25000`, calibration FPR `0.0058`; held-out 2018 attack recall `0.016935519907055722`, FPR `0.00232`; collection attack recall `0.32381067120461426`, FPR `0.0`. XGBoost — threshold `0.45480710268020635`, calibration benign rows `25000`, calibration FPR `0.01732`; held-out 2018 attack recall `0.07252334778140221`, FPR `0.01084`; collection attack recall `0.23934159601222837`, FPR `0.0`. Source for every value: `reports/cic_collection_candidate/candidate_study.json` (`models.random_forest` / `models.xgboost`, `calibration_benign_rows`, `calibration_fpr`, `heldout_2018`, `novel_collection_attacks`). Family recall is also reported for each test group.
- **Key finding:** Both candidates have low overall attack recall on held-out 2018 flows. The collection attack sample shows higher recall, but cannot support a collection false-positive-rate claim because benign rows overlap prior datasets and row provenance is missing. No candidate model was saved or promoted. Source: `reports/cic_collection_candidate/candidate_study.json`, `limitations` and model result fields.

## `dataset_compatibility`

- **What it tests:** Static schema and provenance compatibility of CIC-IDS-Collection with the production feature schema; this folder contains a profile, not a model benchmark.
- **Dataset(s):** CIC-IDS-Collection. Source: `reports/dataset_compatibility/cic_collection.json`, `dataset`.
- **Metrics reported:** `rows` `9167581`; `columns` `59`; `production_schema_features` `77`; `compatible_feature_count` `57`; `row_capture_provenance_present` `false`; `safe_to_train_production_model_directly` `false`. Source for each value: `reports/dataset_compatibility/cic_collection.json` (same-named fields). The missing production feature list is in `missing_production_features` in that file.
- **Key finding:** The combined dataset lacks production-schema features and per-row capture provenance, and overlaps CICIDS2017/2018 data already in the project. Its report warns that row-random splits risk leakage and says it is not safe to train the production model directly. Source: `reports/dataset_compatibility/cic_collection.json`, `reason`.

## `feature_ablation_2018`

- **What it tests:** Whether removing four suspected features changes the active feature set's behavior on held-out CICIDS2017 captures and external CSE-CIC-IDS2018 captures. Production artifacts were not modified.
- **Dataset(s):** CICIDS2017 capture files for training/calibration and held-out testing; all CSE-CIC-IDS2018 capture files for external testing. The four removed features are `ECE Flag Count`, `RST Flag Count`, `Fwd Seg Size Min`, and `Fwd Header Length`. Source: `reports/feature_ablation_2018/feature_ablation.json` (`split`, `suspect_features_removed`).
- **Metrics reported:** Combined external CSE-CIC-IDS2018 — all `77` features: rows `59720`, attack recall `0.24942799461641993`, precision `0.9364578069732188`, F1 `0.39393134233181`, FPR `0.016766666666666666`, ROC AUC `0.7128251581426648`, average precision `0.7619203117268588`, Brier score `0.4373420849486889`; without the four features: rows `59720`, attack recall `0.2882907133243607`, precision `0.7890955977159698`, F1 `0.42229779683572377`, FPR `0.07633333333333334`, ROC AUC `0.7265186597128757`, average precision `0.7451941267782`, Brier score `0.4220458186070146`. Source for every value: `reports/feature_ablation_2018/feature_ablation.json` (`overall_external.all_77_features` / `overall_external.without_four_suspects`). The report also gives per-capture values and confusion matrices.
- **Key finding:** Removing the four features increased aggregate external attack recall and F1, while also increasing the false-positive rate and reducing precision and average precision. The results vary by capture; see the per-capture metrics in the cited JSON.

## `model_acceptance`

- **What it tests:** Whether the reported model evaluations meet acceptance criteria for priority attack-family recall and benign false-positive rate; the gate reports a decision and does not deploy artifacts.
- **Dataset(s):** CSE-CIC-IDS2018. Source: `reports/model_acceptance/acceptance_gate.json`, `dataset`.
- **Metrics reported:** Criteria: minimum recall per priority family `0.8`, maximum benign FPR `0.01`. Random Forest decision `IMPROVE`, benign FPR `0.00746`; priority-family recalls: DDoS `0.18491048593350384`, DoS `0.41222185320491533`, Botnet `0.0018`, BruteForce `0.018207005739164853`, Infiltration `0.0127`. XGBoost decision `IMPROVE`, benign FPR `0.00602`; priority-family recalls: DDoS `0.18226768968456947`, DoS `0.3782132181999336`, Botnet `0.0024`, BruteForce `0.010488818523649317`, Infiltration `0.0136`. Source for every value: `reports/model_acceptance/acceptance_gate.json` (`criteria`, `models.random_forest`, `models.xgboost`). Best-effort WebAttack recall is also reported there.
- **Key finding:** Both models are marked `IMPROVE`: each misses the minimum recall criterion for every listed priority family, although each benign FPR is below the configured maximum. The gate says acceptance does not change or deploy artifacts. Source: `reports/model_acceptance/acceptance_gate.json` (`decision`, `models.*.failures`, gate note).

## `priority_family_candidate`

- **What it tests:** A research candidate for detecting and correctly classifying five selected families on capture-held-out evaluation: DDoS, DoS, Botnet, BruteForce, and Infiltration. The acceptance target is correct-family recall `0.8` per family and maximum benign FPR `0.01`.
- **Dataset(s):** CICIDS2017 and CSE-CIC-IDS2018 capture groups, with the 2017 Botnet capture tested separately because no Botnet capture exists in the 2018 test fold. Source: `reports/priority_family_candidate/priority_family_candidate.json` (`priority_families`, `limitations`, split fields).
- **Metrics reported:** Random Forest — held-out rows `53816`, priority attack rows `23275`, benign rows `30000`, priority detection recall `0.08893662728249195`, benign FPR `0.0064`, precision among priority attacks and benign flows `0.9151193633952255`. Priority correct-family recall: DDoS `0.24784546805349184`, DoS `0.00019782393669634025`, Botnet `0.0`, BruteForce `0.0`, Infiltration `0.0584`. Source for every value: `reports/priority_family_candidate/priority_family_candidate.json` (`models.random_forest.heldout` and `.priority_family_recall`). The XGBoost model, per-capture metrics, confusion matrices, and calibration values are also reported in that JSON.
- **Key finding:** Aggregate priority detection recall and most family-level correct recalls are far below the stated target. The report states that candidate artifacts were not saved or promoted, and that dataset row frequencies are not real-world prevalence. Source: `reports/priority_family_candidate/priority_family_candidate.json`, `limitations` and `acceptance_criteria`.

## `production_model_validation`

This folder contains two different evaluations of the active production artifacts.

### `production_2017_source_check.json`

- **What it tests:** A sampled, source-aligned diagnostic of the production models against CICIDS2017, their training source. The report cautions that training split membership is unknown and evaluated captures may overlap training data.
- **Dataset(s):** CICIDS2017. Source: `reports/production_model_validation/production_2017_source_check.json`, `dataset`, `evaluation_type`.
- **Metrics reported:** On `18720` rows at threshold `0.5`, Random Forest binary detection: accuracy `0.9936965811965812`, precision `0.9999056959637872`, recall `0.9890858208955224`, F1 `0.9944663290189458`, FPR `0.000125`, ROC AUC `0.9998935925839553`, average precision `0.9999102695430729`. XGBoost: accuracy `0.9857905982905983`, precision `0.9986643770272848`, recall `0.9764925373134329`, F1 `0.9874540137722856`, FPR `0.00175`, ROC AUC `0.9996687674906717`, average precision `0.9997378944246277`. Source for every value: `reports/production_model_validation/production_2017_source_check.json` (`models.*.binary_attack_detection`). The report also provides family-classification reports, per-capture scores, raw uncalibrated Brier/ECE, and confusion matrices.
- **Key finding:** Strong source-aligned scores are explicitly described as in-sample and optimistic, since CICIDS2017 is the production training source and split membership is unknown. Heartbleed and Infiltration are handled by separate rare-family detectors and are not part of the multiclass encoder. Source: `reports/production_model_validation/production_2017_source_check.json`, `limitations` and `rare_family_detector_note`.

### `production_external_2018.json`

- **What it tests:** External evaluation of the active CICIDS2017 production artifacts on CSE-CIC-IDS2018 capture files; the models were not retrained or recalibrated by this evaluation.
- **Dataset(s):** CSE-CIC-IDS2018. The report samples by raw label within each capture. Source: `reports/production_model_validation/production_external_2018.json` (`external_dataset`, `split`, `sampled_rows_per_raw_label_per_capture`).
- **Metrics reported:** On `97720` rows at threshold `0.5`, Random Forest binary detection: accuracy `0.5632419156774457`, precision `0.9968454258675079`, recall `0.10595138306789606`, F1 `0.19154417335959995`, FPR `0.00032`, ROC AUC `0.6849287225481977`, average precision `0.6927917707063753`. XGBoost: accuracy `0.5692488743348342`, precision `0.9860079461046813`, recall `0.11961441743503771`, F1 `0.21334728737221775`, FPR `0.00162`, ROC AUC `0.7409925953478627`, average precision `0.7628257835481472`. Source for every value: `reports/production_model_validation/production_external_2018.json` (`overall.*.binary_attack_detection`). Family classification includes accuracy, macro F1, class-wise precision/recall/F1/support, and confusion matrices; raw uncalibrated Brier and ECE are also reported in the same file.
- **Key finding:** On this external dataset, both models report low attack recall despite high attack precision, and family classification is weak overall. The source cautions that this is not a live-network test and that sampling is bounded. Source: `reports/production_model_validation/production_external_2018.json` (`limitations`, `overall`).

## `ten_type_candidate`

- **What it tests:** Whether a capture-held-out candidate can detect and correctly classify `12` attack types across CICIDS2017/CSE-CIC-IDS2018. Criteria require at least `10` attack types with held-out examples, correct-type recall `0.8` per type, and benign FPR no more than `0.01`. Source for these values: `reports/ten_type_candidate/ten_type_candidate.json` (`schema`, `acceptance_criteria`).
- **Dataset(s):** CICIDS2017 and CSE-CIC-IDS2018 capture files; training, benign-only calibration, and full-capture test groups are separated, with duplicate feature rows removed from later groups. Source: `reports/ten_type_candidate/ten_type_candidate.json` (`split`, `removed_overlap_rows`).
- **Metrics reported:** The report includes shared-threshold and per-type-threshold results for Random Forest and XGBoost, including held-out rows, benign FPR, attack-detection recall, macro correct-type recall, and per-type support/detection recall/correct-type recall. Example Random Forest aggregate under the shared-threshold baseline: held-out rows `108737`, benign rows `48000`, in-scope attack rows `60737`, benign FPR `0.027333333333333334`, attack-detection recall `0.04257701236478588`, macro correct-type recall `0.1532823805345808`. Source for every value: `reports/ten_type_candidate/ten_type_candidate.json` (`models.random_forest.shared_threshold_baseline.heldout`). Other aggregate and per-type values are in the same file.
- **Key finding:** It is a cross-dataset research evaluation, not a guarantee of real-world attack detection; the report excludes PortScan and Heartbleed from the target because held-out 2018 support is inadequate. Models are in-memory candidates only and do not replace production artifacts. Source: `reports/ten_type_candidate/ten_type_candidate.json`, `limitations`.

## `threshold_transfer_2018`

- **What it tests:** Transfer of benign-only thresholds to capture-held-out CSE-CIC-IDS2018 flows using the active production models. Test thresholds are not tuned on test rows.
- **Dataset(s):** CSE-CIC-IDS2018, split into folds with distinct calibration and test captures. Source: `reports/threshold_transfer_2018/threshold_transfer.json` (`dataset`, `folds`).
- **Metrics reported:** Threshold method: “99th percentile of raw scores for benign calibration flows only”; target calibration FPR `0.01`; test-threshold tuning `false`. Source for each setting: `reports/threshold_transfer_2018/threshold_transfer.json` (`threshold_method`, `target_calibration_fpr`, `test_threshold_tuning`). Fold/model results report calibrated threshold, calibration benign rows/FPR, and test metrics per held-out capture: rows, attack rows, threshold, recall, precision, F1, FPR, ROC AUC, average precision, confusion matrix, and family recall. Source: `reports/threshold_transfer_2018/threshold_transfer.json` (`folds`, `out_of_fold_by_capture`, `out_of_fold_per_family`).
- **Key finding:** The report provides per-capture and per-family results rather than a single all-capture aggregate; a single combined result is **not available** in this file. The detailed breakdown must be interpreted capture by capture. Limitations are listed in the cited JSON.

## `tri_dataset_benchmark`

- **What it tests:** Binary attack/benign detection and novelty review across capture-held-out and external tests, using a documented common semantic feature subset. The report explicitly does not combine attack-family accuracy across incompatible taxonomies.
- **Dataset(s):** CICIDS2017, CSE-CIC-IDS2018, and UNSW-NB15. Source: `reports/tri_dataset_benchmark/benchmark.json`, `datasets`.
- **Metrics reported:** Across the eight experiment/model/test combinations, fields include rows, threshold, accuracy, attack precision/recall/F1, false-positive rate, Brier score, expected calibration error, ROC AUC, average precision, novelty attack recall, novelty benign FPR, review-union metrics, feature-drift PSI, and confusion matrices. Primary binary detection values below are copied from `reports/tri_dataset_benchmark/benchmark.json` (`results[].metrics`); corresponding full rows and source CSV are in `reports/tri_dataset_benchmark/metrics.csv`.

| Experiment / model / test | Rows | Threshold | Accuracy | Attack precision | Attack recall | Attack F1 | FPR | ROC AUC | Average precision |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| RF_2017_2018_to_heldout_2017_2018 / RandomForest / CICIDS2017 held-out groups | `30377` | `0.3262` | `0.959772` | `0.067114` | `0.009149` | `0.016103` | `0.004747` | `0.810785` | `0.112932` |
| RF_2017_2018_to_heldout_2017_2018 / RandomForest / CSE-CIC-IDS2018 held-out groups | `28188` | `0.3262` | `0.979991` | `0.0` | `0.0` | `0.0` | `0.004361` | `0.623232` | `0.024627` |
| RF_2017_2018_to_heldout_2017_2018 / RandomForest / UNSW-NB15 external test group | `11275` | `0.3262` | `0.943415` | `0.0` | `0.0` | `0.0` | `0.002158` | `0.549448` | `0.055108` |
| XGB_2017_2018_to_heldout_2017_2018 / XGBoost / CICIDS2017 held-out groups | `30377` | `0.424409` | `0.957632` | `0.105691` | `0.023788` | `0.038835` | `0.007513` | `0.713267` | `0.09937` |
| XGB_2017_2018_to_heldout_2017_2018 / XGBoost / CSE-CIC-IDS2018 held-out groups | `28188` | `0.424409` | `0.979317` | `0.045455` | `0.015801` | `0.023451` | `0.005298` | `0.27192` | `0.014481` |
| XGB_2017_2018_to_heldout_2017_2018 / XGBoost / UNSW-NB15 external test group | `11275` | `0.424409` | `0.921863` | `0.003731` | `0.001626` | `0.002265` | `0.025047` | `0.499039` | `0.051956` |
| RF_UNSW_group_holdout / RandomForest / UNSW-NB15 held-out group | `10141` | `0.670441` | `0.972488` | `0.866812` | `0.645528` | `0.739981` | `0.006404` | `0.993516` | `0.883688` |
| XGB_UNSW_group_holdout / XGBoost / UNSW-NB15 held-out group | `10141` | `0.58921` | `0.976827` | `0.861217` | `0.736585` | `0.79404` | `0.007663` | `0.994446` | `0.914996` |

For every numeric cell in the table, the source is `reports/tri_dataset_benchmark/benchmark.json`, `results[].metrics` (matching each row's experiment/model/test); the same primary fields are also in `reports/tri_dataset_benchmark/metrics.csv`. Additional novelty-review, calibration, drift, feature-importance, and confusion-matrix metrics appear in those two files.

- **Key finding:** The combined CICIDS2017/CSE-CIC-IDS2018-trained models have very low attack recall on held-out 2018 and UNSW-NB15 tests at the reported thresholds. UNSW-trained held-out results are stronger, but the report notes that these are laboratory datasets and that UNSW-NB15 uses a documented shared semantic subset rather than all production flow features. Source: `reports/tri_dataset_benchmark/benchmark.json` (`results[].metrics`, `limitations`).

