"""
flow_evidence.py
-----------------
Flow-level evidence scoring for the Evidence Agent.

WHY THIS EXISTS
================
The current Evidence Agent only confirms ML decisions (it looks up
authoritative knowledge for whatever attack_family the ML models already
predicted). It cannot challenge a "Benign" prediction, so 35/36 real
Infiltration flows in the 397-flow evaluation were never even considered
for evidence lookup once the models called them Benign.

This module gives the Evidence Agent an INDEPENDENT signal, computed
directly from the raw flow features, that does not depend on what the ML
models predicted. It is meant to be one input into the Decision Agent's
correlation logic alongside ML confidence/agreement -- NOT a standalone
classifier. Analysis on the CICIDS2017 Thursday-Infiltration dataset (36
true Infiltration flows vs. Benign reference) showed that hard threshold
rules trade recall for an unacceptable false-positive rate (e.g. a lenient
5-condition rule reached 91.7% recall but flagged 24.4% of benign traffic).
A continuous percentile-based score instead gave a much cleaner separation:

    Infiltration flows: median score 0.96 (IQR 0.84-0.97)
    Benign flows:        median score 0.28 (IQR 0.20-0.67)

At score >= 0.9: ~72% Infiltration recall with only ~6% benign flagged.
At score >= 0.8: ~81% Infiltration recall with ~13% benign flagged.

Use the score as a CONTINUOUS corroborating signal, not a hard cutoff --
feed it into the Decision Agent's correlation weighting so a flow with
score 0.95 counts as much stronger evidence than one with score 0.55.

WHY THESE FEATURES
====================
Ranked by Mann-Whitney U effect size (rank-biserial r) on 36 Infiltration
vs. 5000 sampled Benign flows, the most discriminative features were flow
duration and forward-direction activity volume/timing -- consistent with
Infiltration's known "low-and-slow" behavior (long-lived connection, low
packets/sec, but a large TOTAL amount of forward data/time relative to
typical short benign flows):

    Feature                     effect size (r)   p-value
    Fwd IAT Total                     0.797        ~1e-16
    Fwd Act Data Packets              0.785        ~3e-17
    Subflow Fwd Packets               0.782        ~4e-17
    Total Fwd Packets                 0.782        ~4e-17
    Fwd IAT Max                       0.777        ~5e-16
    Flow Duration                     0.772        ~1e-15
    Fwd Packets Length Total          0.770        ~1e-15
    Fwd Packet Length Std             0.759        ~1e-19
    Active Mean                       0.652        ~7e-24

Notably, Down/Up Ratio and PSH Flag Count -- which might intuitively seem
attack-relevant -- showed almost NO separation (rank 65th/65th and
61st/65th of all numeric features tested) and should not be used as
infiltration indicators.

USAGE
======
    from flow_evidence import FlowEvidenceScorer

    scorer = FlowEvidenceScorer.from_reference_parquet("cicids/Benign-Monday-no-metadata.parquet")
    # or: scorer = FlowEvidenceScorer(reference_df=my_benign_dataframe)

    score = scorer.score(flow_row)          # flow_row: dict or pandas Series with the raw features
    label = scorer.interpret(score)         # "low" / "moderate" / "high" / "very_high"

Integrate into the Decision Agent as an extra weighted input, e.g.:

    decision_confidence = combine(
        ml_confidence=0.55,          # model said "benign-ish", weak
        model_agreement=False,
        flow_evidence_score=0.93,    # but flow behavior looks very infiltration-like
        authoritative_evidence=None, # ML never called it Infiltration, so this was empty before
    )
"""

from __future__ import annotations
import numpy as np
import pandas as pd
from dataclasses import dataclass, field
from typing import Mapping, Union

# Top discriminative features found by the analysis (see module docstring).
# Ordered roughly by effect size; all are used with equal weight in the
# default scorer, but you can pass custom weights.
DEFAULT_FEATURES = [
    "Flow Duration",
    "Fwd Act Data Packets",
    "Total Fwd Packets",
    "Fwd IAT Total",
    "Fwd IAT Max",
    "Fwd Packets Length Total",
    "Fwd Packet Length Std",
    "Active Mean",
]


@dataclass
class FlowEvidenceScorer:
    """Scores a single flow's similarity to known 'low-and-slow' Infiltration
    behavior, using a benign reference distribution as the baseline.

    The score for each feature is the fraction of the benign reference
    distribution that falls BELOW the flow's value for that feature
    (i.e. an empirical CDF / percentile rank). The final score is the mean
    across features, so a flow that is unusually high (relative to normal
    benign traffic) on most of these features gets a score near 1.0.
    """

    reference_df: pd.DataFrame
    features: list = field(default_factory=lambda: list(DEFAULT_FEATURES))
    weights: Mapping[str, float] | None = None

    def __post_init__(self):
        missing = [f for f in self.features if f not in self.reference_df.columns]
        if missing:
            raise ValueError(f"Reference data is missing required columns: {missing}")
        # Pre-sort each reference column for fast percentile lookup
        self._sorted_ref = {
            f: np.sort(self.reference_df[f].replace([np.inf, -np.inf], np.nan).dropna().values)
            for f in self.features
        }
        if self.weights is None:
            w = 1.0 / len(self.features)
            self.weights = {f: w for f in self.features}
        else:
            total = sum(self.weights.values())
            self.weights = {f: w / total for f, w in self.weights.items()}

    @classmethod
    def from_reference_parquet(cls, path: str, sample_size: int = 20000, **kwargs):
        df = pd.read_parquet(path)
        if len(df) > sample_size:
            df = df.sample(n=sample_size, random_state=1)
        return cls(reference_df=df, **kwargs)

    def _percentile_rank(self, feature: str, value: float) -> float:
        arr = self._sorted_ref[feature]
        if len(arr) == 0 or pd.isna(value):
            return 0.5  # neutral if we can't compute
        idx = np.searchsorted(arr, value, side="left")
        return idx / len(arr)

    def score(self, flow: Union[Mapping, pd.Series]) -> float:
        """Returns a continuous score in [0, 1]. Higher = more consistent
        with Infiltration-style low-and-slow behavior relative to normal
        benign traffic on this network."""
        total = 0.0
        for f in self.features:
            value = flow[f] if f in flow else None
            rank = self._percentile_rank(f, value) if value is not None else 0.5
            total += self.weights[f] * rank
        return float(total)

    def score_batch(self, flows_df: pd.DataFrame) -> pd.Series:
        return flows_df.apply(self.score, axis=1)

    @staticmethod
    def interpret(score: float) -> str:
        """Rough qualitative bucket for use in reports / evidence output.
        Thresholds chosen from the validation run: score>=0.9 -> ~72%
        Infiltration recall / ~6% benign FP; score>=0.8 -> ~81% recall /
        ~13% benign FP. Tune per-deployment if your traffic mix differs."""
        if score >= 0.9:
            return "very_high"
        if score >= 0.8:
            return "high"
        if score >= 0.6:
            return "moderate"
        return "low"


if __name__ == "__main__":
    # Quick self-test / demo using the CICIDS2017 files, if present locally.
    import sys
    try:
        inf = pd.read_parquet("cicids/Infiltration-Thursday-no-metadata.parquet")
        inf = inf[inf["Label"] == "Infiltration"]
        ben = pd.read_parquet("cicids/Benign-Monday-no-metadata.parquet")
    except FileNotFoundError:
        print("Run this from a directory containing the cicids/ parquet files to self-test.")
        sys.exit(0)

    scorer = FlowEvidenceScorer(reference_df=ben.sample(20000, random_state=1))
    inf_scores = scorer.score_batch(inf)
    ben_scores = scorer.score_batch(ben.sample(2000, random_state=2))

    print("Infiltration scores:\n", inf_scores.describe())
    print("\nBenign scores:\n", ben_scores.describe())
    print("\nInterpretation counts (Infiltration):")
    print(inf_scores.apply(FlowEvidenceScorer.interpret).value_counts())