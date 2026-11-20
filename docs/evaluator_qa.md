# Evaluator questions and evidence-based answers

## Why does the source-aligned result show about 99% accuracy while unseen-capture recall is about 23%?

The 99.4% Random Forest accuracy is from a CICIDS2017 source-aligned check where the active model's exact training-capture membership is unknown. It may overlap training data, so it is not an independent capture-held-out estimate. The 23.0% figure is from a separate, reduced-sample five-family pilot evaluated with leave-one-capture-out; these metrics use different protocols and should be presented as a warning about evaluation design, not a controlled head-to-head comparison.

## Did merging attack types into families fix recall?

No. The five-family pilot reached 23.0% mean attack recall compared with 22.4% for the matched 12-type baseline. The paired capture-bootstrap interval was −5.0 to +7.0 percentage points, which includes zero; the experiment does not show a reliable improvement from label aggregation.

## Did training with more rows per attack solve unseen-capture detection?

No. Raising the cap from 1,000 to 5,000 rows per raw label increased mean capture recall from 22.4% to 37.0%, but pooled FPR rose to 5.20% and worst-capture FPR to 20.48%. A follow-up calibration pool lowered false alarms, but recall fell to 18.6% at the 1,000-row cap; at the 5,000-row cap mean recall was 19.3% and worst-capture FPR was still 2.68%. None of the 12 labels is reliably detected across unseen captures; see `experiments/unseen_generalization_20261117/SAMPLE_CAP_AND_CALIBRATION.md`.

## Did temporal behavior features solve unseen-capture detection?

No. A separate raw-source, 17-capture experiment added past-only flow-history features. Four history features reduced mean attack recall from 22.9% to 19.3%, while worst-capture FPR remained 7.73%. Using only prior flows to the same destination port gave 24.1% detected recall, but correct-type recall fell to 10.3% and worst-capture FPR remained 12.65%; its capture-bootstrap interval included zero gain. These are one-seed, 1,000-row-cap exploratory results. See `experiments/unseen_generalization_20261117/metadata_behavior_loco/RESULTS.md`.

## Why not use calibration captures from the same dataset as the test capture?

That follow-up reduced worst-capture FPR to 1.10% at the 1,000-row cap, but also lowered recall and requires knowing the dataset identity before calibration. The 5,000-row version had 19.3% mean recall and 2.68% worst-capture FPR. The method was designed after observing dataset-specific false alarms and remains exploratory; it was not activated in the dashboard.

## What should the audience infer from a flagged flow?

Treat it as a triage cue for human review. The dashboard's active classifier reports a family-level label and raw, uncalibrated scores; it does not estimate an individual flow's real-world likelihood or a specific 12-type subtype. The 23% research recall is an aggregate candidate result, not the confidence of the displayed flow. No family has passed the project's unseen-capture reliability rule.

The incident list groups the active model's DoS/DDoS, brute-force, and web-attack labels into the broader families used by the separate research pilot. The incident detail preserves the raw classifier label. The pilot's mean held-out-capture recall was 36.8% for DoS/DDoS, 36.0% for Web attack, 24.4% for Brute force, 0.6% for Infiltration, and 0% for Botnet; these results are context only and are not the active model's measured per-family performance.

## Why does the demo show 10/10 DDoS while the ablation reports zero DDoS recall?

The bundled demo is an in-distribution CICIDS2017-style example, while the v3 ablation is a capture-held-out evaluation over sampled CICIDS2017 and CSE-CIC-IDS2018 captures. They answer different questions and use different samples. The demo is an analyst-workflow example, not evidence of general DDoS recall. The ablation's full configuration had zero DDoS attack-or-review recall in its sampled held-out data.

## Why were the LODO candidates not promoted?

The candidates used 11 shared features, while the active production detector requires 77, so this is not a like-for-like replacement test. The held-out candidate results also failed priority-family criteria and the acceptance gate returned `IMPROVE`. Full-pipeline mean attack-or-review recall was 0.2204 and benign false-alarm rate was 0.0495; these results do not meet the gate's requirements.

## What do the investigation agents add?

They add an ordered trace, evidence links, and explanations grounded in flow evidence and retrieved references. In the v3 sample, the full pipeline's recall was higher than the RF+XGBoost configuration (0.2204 versus 0.1444), while its benign false-alarm rate was also higher (0.0495 versus 0.0316). The capture-bootstrap intervals are broad, and this sample does not establish a general improvement. These are analyst-support features, not proof of better overall detection.

## Why did Random Forest recall have zero variation in the v2 ablation?

Do not attribute this to heavy seed overlap: checkpoint row-hash checks found only 5–7 shared rows per 1,000 between seed 42 and each other seed (0.5–0.7%). The v2 CSV reports the same family supports across seeds and RF-only recall of 1.0 for DoS (mean support 259) and Heartbleed (support 2), with zero for the other five families. Those detected-family rates and supports produce the reported overall recall of 0.4272 with no meaningful seed variation. DoS was the largest family in this sample and accounted for almost all RF detections; the data does not establish that the same individual “easy” flows drove each seed. The v2 report used pooled flow-level intervals, which can understate uncertainty when flows within a capture are correlated; v3 uses capture-block bootstrap intervals.

## What does the SIMULATION entry mean?

The lifecycle API record shows three dry-run steps with `executed: false`. It records a proposed response workflow; it did not execute network controls. The visual Triaged badge still needs a manual browser refresh/check.

## How should the feature counts be compared?

The LODO experiments use an 11-feature common mapping. The active production detector expects 77 features, and its exact training-capture membership is not documented. Results from those systems should not be presented as a direct head-to-head comparison.
