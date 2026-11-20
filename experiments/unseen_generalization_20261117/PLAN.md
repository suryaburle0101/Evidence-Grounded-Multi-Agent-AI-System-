# 12-type unseen-capture improvement plan

## Current finding

The active dashboard model is not a 12-type classifier. Its multiclass encoder contains Benign, Botnet, Brute Force, DDoS, DoS, Port Scan, and Web Attack; separate rare-family checks do not turn those outputs into a validated 12-type detector.

The existing 12-type capture-held-out experiment has only two or three positive capture files per requested type. Five-seed mean recall ranges from 0.04% for SSH-BruteForce and 0.17% for Botnet up to 68.1% for DoS-Slowloris. The capture variation is large, and the 12-type baseline's worst-capture false-positive rate reaches 12.6%. No type meets the project reliability rule. SMOTE, weighting, two-stage classification, drift-filtered features, family grouping, and threshold sensitivity have already been evaluated; none established a reliable all-type improvement.

These are dataset-specific exploratory results. More rows from the same capture days do not create new unseen environments, and a random row split would overstate generalization.

## Next safe experiment

The most promising untested local-data feature idea is backward-only source behavior for FTP/SSH brute force. It requires metadata-bearing flows with timestamp and source address, while the local 18 Parquet captures lack those fields. The official CICIDS2017 page says the labeled-flow archive includes labels, timestamps, and source/destination addresses, but its download link currently presents a request form. Do not submit the user's personal information to obtain it without a separate, explicit submission decision.

After metadata-bearing captures are made available, use the existing behavior-feature implementation and evaluation plan under `experiments/behavior_features_20261114/`. Keep IPs and timestamps out of model inputs; derive only past-window aggregates; split by whole capture; fit all transformations on training captures; calibrate thresholds on separate benign captures; and preserve a raw-feature baseline. A gain on only CICIDS2017 must not be presented as 12-type unseen-dataset success.

### Metadata source checked on 2026-11-17

An 8-file CICIDS2017 metadata mirror was downloaded into `raw_metadata_2017/` and inspected. The schema contains metadata and the 77 feature concepts, but an exact feature-plus-label join matched only 1 unique row out of the 17,708 seed-42 CICIDS2017 sample rows (2 additional rows had ambiguous duplicate matches). Therefore, no metadata was attached to the existing sample and no behavior-feature claim was made. The files are from already represented CICIDS2017 segments and do not increase independent capture coverage. Details are in `METADATA_AUDIT.md`.

The separately evaluated 12 one-vs-rest detector candidate is rejected: pooled recall did not improve, the recall-difference interval includes zero, mean FPR rose to 10.35%, and worst-capture FPR reached 53.7%. See `RESULTS.md`; no candidate has been promoted to the dashboard.

Increasing the sample cap from 1,000 to 5,000 rows per raw label raised recall to 37.0%, but pooled FPR rose to 5.20% and worst-capture FPR to 20.48%. A four-capture same-dataset calibration pool brought worst FPR to 1.10% at the 1,000-row cap but reduced mean recall to 18.6%; at 5,000 rows it reached 19.3% recall and 2.68% worst FPR. These one-seed follow-ups do not establish reliable 12-type performance; details are in `SAMPLE_CAP_AND_CALIBRATION.md`.

## Additional independent sources

| Source | Potential contribution | Limitation for this 12-type task |
|---|---|---|
| CIC-DDoS2019 | Adds independent day-based DDoS scenarios and CICFlowMeter-V3 features. Useful for a DDoS-family robustness test. | Its attacks are DDoS variants, not the four named CIC DoS types or the other 11 requested categories. The official download is a large external dataset. |
| CTU-13 | Adds 13 independent botnet scenarios. Useful for binary botnet generalization after feature harmonization. | Labels are botnet, normal, and background; its flow schema is not the project's 77-feature schema. It cannot supply the other requested labels. |
| CIC IoT 2023 | Adds an IoT environment and 33 attacks, including SQL injection, XSS, and dictionary brute force. The official page describes a separate feature-generation pipeline with 46 features. | These records cannot be called the exact FTP/SSH/web brute-force or named DoS subtypes without verifying protocol and behavior. It is an out-of-domain or family-level test unless raw PCAPs are consistently reprocessed and label semantics are validated. |

Do not merge incompatible labels into one of the 12 classes merely to increase counts. Keep additional sources as independent external tests first; promote them into training only with a documented semantic mapping, compatible feature extraction, source capture IDs, and leakage checks.

## Acceptance gate before production use

1. Every requested attack type must occur in multiple independent captures, with separate benign captures for calibration.
2. Hold out complete capture identities and, separately, at least one source dataset. Remove exact duplicate feature vectors across train/calibration/test.
3. Report per-type recall and confusion, macro and pooled PR-AUC, pooled and worst-capture FPR, plus capture-level spread.
4. Set the threshold using calibration captures only. A threshold change is not an improvement if it only trades recall for an unacceptable worst-capture FPR.
5. Keep the 12-type research candidate separate from production models until the acceptance criteria are met. If any class fails, show abstain/unknown or a broad family result and state the measured limitation.

## External dataset documentation

- [CICIDS2017 official dataset page](https://www.unb.ca/cic/datasets/ids-2017.html): five collection days and labeled flows with source/destination and time metadata.
- [CIC-DDoS2019 official dataset page](https://www.unb.ca/cic/datasets/ddos-2019.html): day-organized captures, DDoS-specific labels, and CICFlowMeter-V3 features.
- [CTU-13 official Stratosphere page](https://www.stratosphereips.org/datasets/): thirteen botnet scenarios with botnet, command-and-control, normal, or background labels.
- [CIC IoT 2023 official dataset page](https://www.unb.ca/cic/datasets/iotdataset-2023.html): 33 attacks across seven families in a 105-device IoT topology, with a separate 46-feature pipeline.
