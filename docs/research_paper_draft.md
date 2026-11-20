# Capture-Aware Evaluation of Flow-Based Intrusion Detection: The Gap Between Source-Aligned Scores and Unseen Captures

**Surya Burle**<br>
Vellagapudi Ramakrishna Siddhartha Engineering College<br>
Guide: Dr K Praveen Kumar

**AI assistance disclosure:** Generative AI tools were used to assist with language editing and organization. The author reviewed the text and remains responsible for the analysis, results, citations, and final content.

**Status:** working manuscript updated with the family-design pilot on 16 November 2026. Target venue and ethics/licensing details for locally acquired data still require confirmation. Results are transcribed from local reports and experiment outputs.

## Abstract

Flow-based intrusion detection can look highly accurate on source-aligned data yet miss attacks on new captures. This study reframes a local multi-agent network-flow application as a triage prototype and examines that generalization gap. The application combines Random Forest and XGBoost family labels with investigation, flow evidence, reference retrieval, risk scoring, and response recommendations; it records an ordered trace and does not alter network controls.

Across 18 CICIDS2017 and CSE-CIC-IDS2018 captures, a reduced-sample, three-seed five-family XGBoost pilot reached 23.0% mean attack recall (seed SD 1.8%) at a mean capture FPR of 0.38% and a worst-capture FPR of 2.0%. The matched 12-type baseline reached 22.4% recall; the paired capture-bootstrap difference was +0.6 percentage points (95% interval −5.0 to +7.0), so family aggregation did not establish an improvement. A separate one-seed 12-detector one-vs-rest pilot raised mean capture recall to 25.0%, but its paired interval (−9.2 to +14.3 points) included zero, pooled FPR rose to 10.35%, and worst-capture FPR reached 53.7%; it was rejected. A separate source-aligned CICIDS2017 check reported 99.4% Random Forest accuracy, but exact training-capture membership is unknown; it is not an independent holdout or a directly comparable estimate. Cross-dataset transfer was directional, with worst-capture FPRs of 5.7% (2017→2018) and 20.7% (2018→2017). No type or family met the stated reliability rule. The evidence supports an evaluation and analyst-triage contribution, not a production detection claim.

## 1. Introduction

Supervised network intrusion detection is commonly evaluated on benchmark flow datasets. Those datasets differ in capture procedures, labels, and feature schemas, which makes cross-dataset performance difficult to interpret. CICIDS2017 provides labeled CICFlowMeter records from a testbed with benign and attack traffic [1]. CSE-CIC-IDS2018 uses profile-based traffic generation and includes attack scenarios such as brute force, Heartbleed, botnet, denial of service, web attacks, and infiltration [2]. UNSW-NB15 uses a separate collection and feature-generation pipeline with 49 features [3]. Work on common flow features has likewise identified feature incompatibility as an obstacle to meaningful cross-dataset comparisons [4].

This project asks two bounded engineering questions: (1) can a local multi-stage flow-analysis pipeline expose the sources and availability of its findings to an analyst, and (2) what do the available held-out capture experiments show about cross-dataset transfer and the added value of downstream analysis stages? The intended contribution is a traceable triage workflow and an honest evaluation of its limits, rather than a new state-of-the-art classifier.

The application accepts pre-extracted flow records. It does not capture live packets, and its response stage recommends actions rather than executing them. The dashboard's ATTACK/REVIEW labels and risk scores are decision-support outputs, not a guarantee that BENIGN traffic is safe.

## 2. System

The current analysis path uses Random Forest and XGBoost binary models, optional rare-family models, an investigation stage, flow-level evidence, local reference retrieval, correlation/decision logic, risk analysis, and response recommendations. Each completed or partial result carries an ordered trace containing the stage name, role, status, elapsed time, and concise input/output summaries. The summaries are intended to describe shapes and counts rather than reproduce raw flow values. Evidence references are surfaced in the dashboard and analyst note. SHAP explanations are used for feature-level model context [5]. A failed optional stage can be marked unavailable while analysis continues; failures in required stages stop downstream processing and leave a partial trace.

The response workflow is human-reviewed and simulation-only. No claim is made that the system blocks an address, isolates an endpoint, or operates as a live network sensor.

## 3. Data and methods

### 3.1 Data audit and provenance

The audit covered CSV and Parquet capture tables in four local dataset folders. It records per-capture row and label counts, feature coverage, duplicate and invalid-value statistics, available date ranges, training-membership evidence, and cross-dataset duplicate feature vectors. The active production model's exact CICIDS2017 capture membership could not be established from the available training scripts and artifact metadata; the audit therefore marks the captures as unknown rather than inferring membership. The 9.16-million-row CIC-IDS-Collection file had 57 of the 77 production features and no per-row capture provenance. It was not used for LODO training.

### 3.2 Leave-one-dataset-out candidates

The LODO study trains Random Forest and XGBoost candidates on two datasets and evaluates on the third, using the common 11-feature mapping in the benchmark workflow. Training is capped at 50,000 stratified rows per dataset, with validation drawn only from training datasets. Exact shared feature vectors are excluded across train and test. Seeds 42–46 are reported. Active production-model comparisons are reported as unavailable: the active detector uses 77 CICFlowMeter features, whereas the LODO study uses 11 common features, and no compatible same-row 77-feature comparator was established. The LODO metrics and capture-level results are in `reports/lodo/results.csv`, `results.json`, and `summary.csv`.

### 3.3 Calibration

Platt scaling and isotonic regression are fitted on validation data drawn from training datasets, then evaluated on held-out datasets [6, 7]. The study reports Brier score, 10-bin expected calibration error, reliability-curve points, and held-out recall at thresholds selected to target a 1% validation benign false-alarm rate [8, 9]. These results apply to the LODO candidate models. Active-model calibration was excluded because training-capture membership is unknown and the schema differs; calibration on potentially seen training data could be misleading. Calibration artifacts remain experimental and are not loaded by the API or CLI.

### 3.4 Pipeline ablation

The v3 ablation evaluates seven configurations, from the RF/XGBoost classifiers through the full downstream pipeline, on sampled capture-held-out CICIDS2017/CSE-CIC-IDS2018 flows. It uses five seeds (42–46), up to 1,000 sampled flows per seed, and 95% percentile intervals from 10,000 bootstrap draws resampling capture files. “Recall” counts ATTACK or REVIEW as detected; strict recall counts ATTACK only; benign false-alarm rate counts ATTACK or REVIEW on benign flows. The candidate acceptance gate requires at least 0.80 recall for each priority family and at most 0.01 benign false-positive rate. It is a non-deploying report gate.

### 3.5 Optional batch inference

An optional batch path vectorizes RF/XGBoost model calls and reuses SHAP explainers; the existing single-flow path remains the default. One local profile used the same 200 rows in separate fresh processes with persistence and local language-model generation disabled. The project records a 50-flow equivalence check in `test/test_analysis_batch_fast.py`; that test was not rerun while preparing this manuscript.

## 4. Results

### 4.1 Cross-dataset performance

The 11-feature LODO study is descriptive of its candidate setup and cannot be compared directly to the active 77-feature detector. Each training dataset contributes at most 50,000 rows and each held-out capture at most 10,000 rows. The report states that the active-model comparator is unavailable. The per-dataset, per-family and seed results, including capture-block intervals where estimable, are provided in `reports/lodo/`.

### 4.2 Calibration

The calibration report contains raw, Platt-scaled, and isotonic metrics and reliability-curve data for 30 LODO candidate model-fold combinations. The 60 calibrated bundles are experimental artifacts. They do not establish calibration of the active production artifacts and do not justify interpreting any BENIGN output as a safety guarantee. Numeric values should be selected directly from `reports/calibration/calibration_metrics.csv` for any final table.

### 4.3 Pipeline ablation and acceptance

Across the five seeds, the full `+threat_intel` configuration reported attack-or-review recall of 0.2204 ± 0.0376, strict recall of 0.1462 ± 0.0270, benign false-alarm rate of 0.0495 ± 0.0142, and precision of 0.8532 ± 0.0203. The model-only RF+XGB configuration reported recall 0.1444 ± 0.0259 and benign false-alarm rate 0.0316 ± 0.0114. The full pipeline improves measured recall on this sample but raises the benign false-alarm rate; its capture-bootstrap 95% intervals are broad, and the benign false-alarm interval [0.0172, 0.0953] is above the 1% target. This does not establish a reliable broad improvement.

Family results expose a serious failure: the full configuration reported zero attack-or-review recall for DDoS and BruteForce, 0.0049 ± 0.0067 for Botnet (with zero strict ATTACK recall), 0.4749 ± 0.0935 for DoS, and 0.0195 ± 0.0158 for Infiltration. WebAttack recall was 0.5647 ± 0.2584, but support averaged only 17 flows per seed; Heartbleed support averaged two. Those family estimates are imprecise. The v3 model acceptance gate returned **IMPROVE**. Both LODO candidates failed the priority-family criteria; XGBoost also exceeded the benign false-positive limit. No candidate was promoted.

### 4.4 Capture-held-out family evaluation

The separate family-design pilot reused the existing 1,000-row-per-raw-label capture samples and compared the requested five-family taxonomy, a coarse three-family taxonomy, and the 12-type baseline. The five-family model averaged 23.0% attack recall (SD 1.8% across three seed means), mean capture PR-AUC 0.797, and 2.0% worst-capture FPR. Its paired capture-bootstrap recall difference from the matched 12-type baseline was +0.6 points, with a 95% interval from −5.0 to +7.0 points; the interval includes zero. This is exploratory reduced-sample evidence, not a demonstrated benefit from relabeling.

The conservative 0.5% calibration target reduced mean family-model recall from 23.0% to 9.6% while reducing worst-capture FPR from 2.0% to 1.3%. In cross-dataset family transfer, CICIDS2017→CSE-CIC-IDS2018 produced 9.4% mean attack recall and 5.7% worst-capture FPR; the reverse produced 22.5% mean recall and 20.7% worst-capture FPR. The transfer results show that pooled or source-calibrated operating points do not ensure similar behavior across captures.

No type or family met the project rule of greater than 70% recall on most positive held-out captures and worst-capture FPR at or below 2%. The report labels types with only two positive capture files low-confidence. Because the five-family bootstrap did not establish a gain, the prespecified feature-count search and new two-level detector/family/subtype model were skipped. Full per-capture results, reliability labels, and data gaps are in `experiments/family_design_20261116/RESULTS.md`.

### 4.4.1 One-vs-rest 12-type candidate

To test whether class-specific detectors and thresholds could improve exact-type recognition, a separate one-seed XGBoost candidate trained one binary model per attack type on the existing seed-42 capture samples. It used the same 18 capture identities, separate benign calibration captures, and a Bonferroni allocation of the 1% calibration false-positive budget across the 12 class detectors. The mean capture recall rose from 22.4% to 25.0%, but the paired capture bootstrap interval was −9.2 to +14.3 percentage points. Pooled attack recall remained approximately 22.3%; mean capture PR-AUC fell from 0.777 to 0.664. Most importantly, pooled benign FPR rose from 0.61% to 10.35%, and worst-capture FPR rose from 3.5% to 53.7%. The candidate was rejected. Its per-type table shows some recall gains, notably Infiltration, but these came with excessive false alarms and did not establish a general improvement. This single-seed experiment is exploratory; all outputs are in `experiments/unseen_generalization_20261117/RESULTS.md`.

### 4.4.2 Sample-size and calibration-pool follow-up

Increasing the per-raw-label cap from 1,000 to 5,000 in the same 18-capture XGBoost LOCO evaluation raised mean capture attack recall from 22.4% to 37.0% (paired capture-bootstrap 95% interval for the difference, +8.3 to +21.8 points). However, pooled FPR increased from 0.61% to 5.20%, worst-capture FPR from 3.5% to 20.48%, and mean PR-AUC declined from 0.777 to 0.749. Additional rows from these same files improved recall only at an unacceptable false-alarm rate.

A follow-up reserved four non-held-out benign calibration captures from the known held-out dataset, selected to span benign feature-median variation. At the 1,000-row cap, this lowered pooled FPR to 0.28% and worst-capture FPR to 1.10%, but mean recall fell to 18.6%; the paired recall change was −3.8 points (95% interval −9.2 to −0.6). At the 5,000-row cap, pooled FPR was 0.48%, worst-capture FPR 2.68%, and mean recall 19.3%; the paired recall interval (−13.0 to +5.5 points) included zero. The 5,000-row candidate still had zero mean correct-type recall for Botnet, FTP-BruteForce, and DoS-SlowHTTPTest. These are one-seed, post-hoc exploratory candidates and were not promoted. Full metrics, per-type tables, and commands are in `experiments/unseen_generalization_20261117/SAMPLE_CAP_AND_CALIBRATION.md`.

### 4.5 Runtime

For the 200-flow local profile, baseline wall time was 150.9 s and optional batch-path wall time was 110.1 s, a 27.0% reduction. Throughput rose from 1.33 to 1.82 flows/s (37.1%). This is a single-machine measurement on one sampled capture and should not be treated as a general performance guarantee.

## 5. Discussion

The measured results favor framing this system as a local, evidence-linked triage prototype and capture-aware evaluation. Agent traces, evidence references, structured outputs, and response recommendations make the analysis path more inspectable. Family grouping did not establish better unseen-capture detection, and the one-vs-rest candidate's recall change was uncertain while its false-alarm rate became unacceptable. The held-out evidence does not support deployment. The speed path is promising but requires broader profiling and a freshly recorded equivalence run before a performance claim is finalized.

Cross-dataset evaluation is constrained by feature incompatibility and unknown active-model training membership. The LODO study's 11-feature candidates are not a direct 77-feature production comparison. CIC-IDS-Collection cannot safely repair this gap because of incomplete schema coverage and absent capture provenance. Shared-feature data can support useful exploratory comparisons, but the mapping changes the task and must be stated alongside every metric [4].

The evidence base is limited to public laboratory datasets and selected capture files. Capture files can be correlated; hence the v3 interval procedure resamples capture files rather than individual flows. Small family support still yields unstable estimates. No live-network evaluation, external operational validation, or independently verified lifecycle click-through is included in this draft.

The next useful data improvement is capture diversity: add independent sessions for each weak attack type and more varied benign traffic. A third-party CICIDS2017 metadata mirror and official processed CSE-CIC-IDS2018 CSVs provided timestamps and destination ports, but no source IPs in the CSE files. An exact 77-feature-plus-label join to prepared CICIDS2017 samples found only one unique match among 17,708 rows, so metadata was not attached to those samples. Instead, a separate one-seed, raw-source experiment calculated strictly past-only history features before sampling across 17 captures. Four history features lowered mean attack recall from 22.9% to 19.3%, with worst-capture FPR falling from 13.93% to 7.73%; a two-feature same-destination-port variant reached 24.1% detected recall but only 10.3% correct-type recall and 12.65% worst-capture FPR. The paired recall interval included zero gain. These exploratory variants do not establish all-12 generalization and were not promoted. Details and rerun commands are in `experiments/unseen_generalization_20261117/metadata_behavior_loco/RESULTS.md`.

## 6. Conclusion

This project demonstrates a traceable multi-stage workflow for analyzing pre-extracted network flows and evaluates its limits on held-out captures. Source-aligned accuracy is high but potentially optimistic because the active model's training-capture membership is unknown; the more stringent capture-held-out and cross-dataset results show low recall, unstable family performance, and false-alarm rates above target in some captures. Neither family aggregation nor one-vs-rest classification established a reliable gain, and no attack type or family meets the stated reliability rule. The appropriate conclusion is a research and human-triage prototype, with additional independent captures, metadata-bearing flows, and field validation still needed.

## References

1. I. Sharafaldin, A. H. Lashkari, and A. A. Ghorbani, “Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization,” *Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP)*, 2018. Dataset paper listed by the [Canadian Institute for Cybersecurity CICIDS2017 page](https://www.unb.ca/cic/datasets/ids-2017.html).
2. Canadian Institute for Cybersecurity, “CSE-CIC-IDS2018 on AWS,” dataset resource, n.d., accessed 2 November 2026. [Dataset page](https://www.unb.ca/cic/datasets/ids-2018.html).
3. N. Moustafa and J. Slay, “UNSW-NB15: a comprehensive data set for network intrusion detection systems,” *2015 Military Communications and Information Systems Conference (MilCIS)*, 2015, doi: [10.1109/MilCIS.2015.7348942](https://doi.org/10.1109/MilCIS.2015.7348942). Dataset and citation guidance: [UNSW-NB15 project page](https://research.unsw.edu.au/projects/unsw-nb15-dataset).
4. M. Sarhan, S. Layeghy, N. Moustafa, and M. Portmann, “NetFlow Datasets for Machine Learning-Based Network Intrusion Detection Systems,” in *Big Data Technologies and Applications*, Lecture Notes of the Institute for Computer Sciences, Social Informatics and Telecommunications Engineering, vol. 371, pp. 117–135, Springer, 2021. [https://doi.org/10.1007/978-3-030-72802-1_9](https://doi.org/10.1007/978-3-030-72802-1_9).
5. S. M. Lundberg and S.-I. Lee, “A Unified Approach to Interpreting Model Predictions,” *Advances in Neural Information Processing Systems 30*, 2017. [NeurIPS paper](https://papers.nips.cc/paper_files/paper/2017/hash/8a20a8621978632d76c43dfd28b67767-Abstract.html).
6. J. C. Platt, “Probabilistic Outputs for Support Vector Machines and Comparisons to Regularized Likelihood Methods,” in *Advances in Large Margin Classifiers*, MIT Press, 1999, pp. 61–74.
7. B. Zadrozny and C. Elkan, “Transforming Classifier Scores into Accurate Multiclass Probability Estimates,” *Proceedings of the Eighth ACM SIGKDD International Conference on Knowledge Discovery and Data Mining*, 2002, pp. 694–699. [ACM DOI: 10.1145/775047.775151](https://doi.org/10.1145/775047.775151).
8. G. W. Brier, “Verification of Forecasts Expressed in Terms of Probability,” *Monthly Weather Review*, 78(1), 1–3, 1950. [DOI: 10.1175/1520-0493(1950)078<0001:VOFEIT>2.0.CO;2](https://doi.org/10.1175/1520-0493(1950)078%3C0001%3AVOFEIT%3E2.0.CO;2).
9. Y. Ovadia et al., “Can You Trust Your Model’s Uncertainty? Evaluating Predictive Uncertainty Under Dataset Shift,” *Advances in Neural Information Processing Systems 32*, 2019. [NeurIPS paper](https://papers.nips.cc/paper/9547-can-you-trust-your-models-uncertainty-evaluating-predictive-uncertainty-under-dataset-shift).

## Local evidence files

- Dataset inventory and provenance: `reports/dataset_audit/MANIFEST.md`
- LODO methods and results: `reports/lodo/README.md`, `results.csv`, `results.json`
- Calibration methods and results: `reports/calibration/README.md`, `calibration_metrics.csv`, `calibration_results.json`
- Pipeline ablation and gate: `reports/ablation_study_v3/README.md`, `model_acceptance_gate.json`
- Runtime profile: `reports/performance/profile.md`
- Hand-checked metric summary: `docs/RESULTS_SUMMARY.md`
