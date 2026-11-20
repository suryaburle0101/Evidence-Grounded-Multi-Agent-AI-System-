import json
from pathlib import Path


# ============================================================
# PATH
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

KNOWLEDGE_FILE = (
    PROJECT_ROOT
    / "evidence"
    / "knowledge"
    / "authoritative_sources.json"
)


# ============================================================
# LOAD AUTHORITATIVE KNOWLEDGE
# ============================================================

with open(
    KNOWLEDGE_FILE,
    "r",
    encoding="utf-8"
) as f:

    authoritative_data = json.load(f)


# ============================================================
# EVIDENCE RETRIEVAL
# ============================================================

def get_evidence_for_attack(attack_family):
    """
    Retrieve authoritative evidence for a detected
    attack family.
    """

    if not attack_family:
        return None

    for source in authoritative_data.get(
        "sources",
        []
    ):

        if (
            source.get("attack_family", "").lower()
            == attack_family.lower()
        ):

            return {
                "attack_family":
                    source.get(
                        "attack_family"
                    ),

                "source_name":
                    source.get(
                        "source_name"
                    ),

                "source_type":
                    source.get(
                        "source_type"
                    ),

                "technique_id":
                    source.get(
                        "technique_id",
                        ""
                    ),

                "technique_name":
                    source.get(
                        "technique_name",
                        ""
                    ),

                "evidence":
                    source.get(
                        "evidence",
                        {}
                    ),

                "source_url":
                    source.get(
                        "source_url",
                        ""
                    )
            }

    return None