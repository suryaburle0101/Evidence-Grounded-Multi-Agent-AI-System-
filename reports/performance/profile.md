# Analysis pipeline performance profile

## Method

Measured 200 sampled rows from `data/raw/CICIDS2017/DoS-Wednesday-no-metadata.parquet` (sample selection seed 42; at most 100 rows per raw label before selecting 200). Both paths used the same rows in separate fresh Python processes, with persistence and local LLM generation disabled. All 200 analyses completed on the batch path. Timings below are per flow; mean, median, and p95 are reported. The baseline end-to-end measured wall time was 150.9 seconds; the optional batch path took 110.1 seconds.

## Time per stage

| Stage | Current path mean ms | Current median ms | Current p95 ms | Batch path mean ms | Batch median ms | Batch p95 ms |
|---|---:|---:|---:|---:|---:|---:|
| Detection (RF + XGBoost; batch cost amortized) | 656.7 | 625.5 | 822.0 | 487.0 | 487.0 | 487.0 |
| Rare-family check | 87.2 | 90.3 | 123.0 | 56.1 | 53.8 | 68.6 |
| Evidence | 2.1 | 0.3 | 0.5 | 1.5 | 0.2 | 0.4 |
| Local RAG / analyst note | 4.1 | 4.3 | 5.6 | 3.2 | 3.5 | 4.3 |
| Decision | 0.3 | 0.3 | 0.4 | 0.2 | 0.2 | 0.3 |
| Threat intelligence | 0.1 | 0.1 | 0.1 | 0.0 | 0.0 | 0.1 |
| Investigation | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| Risk analysis | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| Response | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| **Total reported by pipeline** | **750.4** | **720.4** | **938.3** | **548.0** | **544.4** | **559.7** |

The existing per-stage timer rounds to 0.1 ms; values shown as 0.0 ms are below that reporting resolution, not proof that the stage takes no time. Detection timing in the batch path includes the vectorized model prediction cost divided across the batch and its per-flow result assembly.

## Before / after

| Measure | Current path | Optional batch path | Change |
|---|---:|---:|---:|
| Measured wall time, 200 flows | 150.9 s | 110.1 s | 27.0% lower |
| Mean reported end-to-end per flow | 750.4 ms | 548.0 ms | 27.0% lower |
| Throughput | 1.33 flows/s | 1.82 flows/s | 37.1% higher |

These are measurements from one capture and one machine/session, not a broad benchmark. The optional path preserves the existing single-flow default; see `test/test_analysis_batch_fast.py` for the 50-flow decision, risk, and probability equivalence check (probability tolerance 1e-9).
