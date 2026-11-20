# CICIDS2017 metadata source audit

## Source and scope

Eight metadata-bearing CICIDS2017 Parquet files were placed in `raw_metadata_2017/` from the third-party [Hugging Face mirror](https://huggingface.co/datasets/bvsam/cic-ids-2017/tree/main/traffic_labels). Their combined size is 305,935,672 bytes and they contain 3,119,345 rows. The files expose Flow ID, source/destination IP and ports, timestamp, CICFlowMeter features, and a label. This is a mirror, not a verified official download; the feature data should not be described as a newly collected dataset.

The schema audit found all 77 model feature concepts after applying documented name aliases. The mirror has eight file-level capture segments, but they correspond to the same CICIDS2017 scenarios already represented locally. Metadata does not add independent attack days or environments. In this release the sparsest relevant labels remain concentrated in one segment: Infiltration has 36 rows, SQL-Injection 21 rows, and Botnet 1,966 rows; FTP- and SSH-BruteForce are both in Tuesday's segment. Several requested classes are absent from CICIDS2017.

## Exact-join result

The probe compared the seed-42 CICIDS2017 samples against all rows in the corresponding mirror file using the ordered 77 numeric model features plus canonical label. It found **1 unique exact match, 2 rows with ambiguous repeated-vector matches, and 17,705 rows without an exact match, out of 17,708 sampled rows**. No metadata was joined to local model rows. The match rate is too low to attach timestamps or addresses safely; the raw metadata and the existing prepared sample appear to differ in row population and/or feature representation.

The result is recorded in `metadata_join_probe.json`; the repeatable diagnostic is `probe_metadata_join.py`. Hash equality is deliberately required: a fuzzy nearest-neighbor join could attach another flow's IP or timestamp and contaminate behavioral features.

## Decision and follow-up

Do not attach metadata to the existing seed-42 samples: the exact-join rate is far too low. A separate research evaluation was subsequently built directly from metadata-bearing raw source files, so its rows and capture identities are independent of those prepared samples. See `metadata_behavior_loco/RESULTS.md` and the adjacent outputs. It combined CICIDS2017 mirror captures with nine CSE-CIC-IDS2018 processed captures (the 20-Feb DDoS file was too large to include), and added strictly past-only flow-history features without passing IPs, ports, or timestamps to the classifier.

The feature result did not solve generalization. Four history features lowered mean recall from 22.9% to 19.3% and worst-capture FPR from 13.93% to 7.73%; the two same-destination-port history features alone raised mean detected recall to 24.1%, but exact-type recall fell from 13.6% to 10.3%, worst-capture FPR remained 12.65%, and the paired recall interval included zero. The work is one-seed and capped at 1,000 rows per label, so it is exploratory. Neither variant supports a claim that all 12 attack types generalize to unseen data. The one-vs-rest experiment in `RESULTS.md` is also rejected because its recall increase came with 10.35% mean FPR and 53.7% worst-capture FPR.

No files in `data/`, `models/`, or existing `reports/` were changed. The downloaded files and audit outputs are confined to this dated experiment folder.
