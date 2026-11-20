"""
flow_evidence_service.py
--------------------------
Place this file in: evidence/flow_evidence_service.py
(alongside your existing evidence/flow_evidence.py)

Thin singleton wrapper around FlowEvidenceScorer so the benign reference
distribution is loaded ONCE when the module is first imported, not on
every single flow. Loading a 20k-row parquet sample per flow would make
the 397-flow evaluation extremely slow otherwise.
"""

from pathlib import Path
from evidence.flow_evidence import FlowEvidenceScorer

# ============================================================
# PATH -- matches the pattern used in evidence_retriever.py
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

BENIGN_REFERENCE_FILE = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "CICIDS2017"
    / "Benign-Monday-no-metadata.parquet"
)

# ============================================================
# LAZY SINGLETON
# ============================================================

_scorer = None


def _get_scorer():
    global _scorer
    if _scorer is None:
        _scorer = FlowEvidenceScorer.from_reference_parquet(
            str(BENIGN_REFERENCE_FILE)
        )
    return _scorer


def score_flow(flow):
    """
    flow: a pandas Series (or dict-like) of raw flow features, using the
    SAME column names as the CICIDS2017 parquet files
    (e.g. 'Flow Duration', 'Total Fwd Packets', ...).

    Returns:
        (score, level)
        score: float in [0, 1], or None if scoring failed
               (e.g. missing required columns)
        level: one of "very_high" / "high" / "moderate" / "low", or None

    Higher score = more consistent with "low-and-slow" Infiltration-style
    behavior relative to normal benign traffic on this network.
    """
    scorer = _get_scorer()
    try:
        score = scorer.score(flow)
    except Exception:
        return None, None
    level = scorer.interpret(score)
    return score, level
