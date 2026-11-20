# Metadata-based temporal feature candidate

This is a research-only, one-seed capture-held-out comparison on original metadata-bearing source files. It uses 17 capture files and caps each raw label at 1,000 sampled rows per capture after calculating causal history over valid source flows. The candidate adds four features counting preceding flows in the previous 60/300 seconds and preceding flows to the same destination port in those windows. IPs, ports, timestamps, and flow IDs are excluded from model inputs.

| Metric | Raw 77 features | Raw 77 + four history features | Raw 77 + same-port history only |
|---|---:|---:|---:|
| Mean attack recall over attack-bearing captures | 22.9% | 19.3% | 24.1% |
| Pooled attack recall | 20.0% | 14.1% | 19.7% |
| Mean capture PR-AUC | 0.747 | 0.746 | 0.742 |
| Mean capture FPR | 2.36% | 1.33% | 2.00% |
| Pooled FPR | 2.37% | 1.33% | 2.01% |
| Worst-capture FPR | 13.93% | 7.73% | 12.65% |
| Mean correct-type recall | 13.6% | 9.8% | 10.3% |

The four-feature history variant changed mean recall by -3.6 percentage points (capture-bootstrap 95% interval -12.9 to +3.0). The same-port-only variant changed mean recall by +1.2 points (95% interval -9.6 to +10.4), so neither interval establishes a gain. Same-port history helped detected recall for SSH-BruteForce and DoS-Hulk in this sample, but exact-type recall for SSH-BruteForce remained zero; it also sharply reduced DoS-Slowloris and SQL-Injection exact-type recall. Per-type and confusion tables are in adjacent CSV files. These results do not establish all-12 unseen-network performance: they use one seed, a reduced sample, and public lab captures only.

## Per-type outcomes

“Detected recall” counts an attack as detected even if it receives the wrong type; “correct-type recall” requires the exact label. Captures indicates the number of positive held-out capture files represented.

| Attack type | Captures | Raw correct | Raw detected | Four-history correct | Four-history detected | Same-port correct | Same-port detected |
|---|---:|---:|---:|---:|---:|---:|---:|
| Botnet | 2 | 0.0% | 3.1% | 0.0% | 4.5% | 0.0% | 6.6% |
| FTP-BruteForce | 2 | 0.0% | 0.1% | 0.0% | 0.0% | 0.0% | 0.0% |
| SSH-BruteForce | 2 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 53.6% |
| DDoS | 2 | 0.0% | 31.9% | 0.0% | 31.2% | 0.0% | 30.6% |
| DoS-Hulk | 2 | 0.0% | 0.9% | 10.3% | 26.9% | 3.7% | 27.6% |
| DoS-GoldenEye | 2 | 7.0% | 12.6% | 0.0% | 2.1% | 0.0% | 3.7% |
| DoS-Slowloris | 2 | 62.9% | 63.5% | 0.0% | 0.6% | 0.0% | 1.2% |
| DoS-SlowHTTPTest | 2 | 0.0% | 61.2% | 0.0% | 47.1% | 0.0% | 47.1% |
| Infiltration | 3 | 7.7% | 9.6% | 7.2% | 8.2% | 5.8% | 6.8% |
| Web-BruteForce | 3 | 37.5% | 38.3% | 46.0% | 46.8% | 48.0% | 50.6% |
| Web-XSS | 3 | 49.3% | 49.5% | 27.9% | 29.4% | 46.4% | 47.5% |
| SQL-Injection | 3 | 25.0% | 52.7% | 11.3% | 24.0% | 12.6% | 26.9% |

## Dataset-level outcomes

| Source dataset | Features | Mean attack recall | Mean capture FPR | Worst capture FPR |
|---|---|---:|---:|---:|
| CICIDS2017 | Raw 77 | 13.4% | 0.51% | 1.11% |
| CICIDS2017 | + history | 11.4% | 0.61% | 1.91% |
| CSE-CIC-IDS2018 | Raw 77 | 29.2% | 4.00% | 13.93% |
| CSE-CIC-IDS2018 | + history | 24.6% | 1.97% | 7.73% |

Thresholds are selected from two separate benign captures within the known held-out dataset; the held-out capture is excluded from model fitting and threshold selection. The CSE-CIC-IDS2018 source files lack source/destination IPs, and the very large 20-Feb DDoS source file was excluded. No candidate was promoted to production.

Reproduce the preparation and evaluation:

```powershell
.\.venv\Scripts\python.exe experiments\unseen_generalization_20261117\metadata_behavior_loco.py --prepare
.\.venv\Scripts\python.exe experiments\unseen_generalization_20261117\metadata_behavior_loco.py --evaluate
.\.venv\Scripts\python.exe experiments\unseen_generalization_20261117\metadata_behavior_loco.py --evaluate --port-only
```
