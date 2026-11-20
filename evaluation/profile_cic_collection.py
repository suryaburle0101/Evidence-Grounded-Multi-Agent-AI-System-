"""Profile Kaggle's combined CIC-IDS parquet for schema and leakage risks."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pyarrow.parquet as pq

from evaluation.production_model_validation import canonical_family
from pipeline.data_pipeline import FEATURES

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "data" / "raw" / "CIC_IDS_Collection" / "cic-collection.parquet"
OUTPUT = ROOT / "reports" / "dataset_compatibility" / "cic_collection.json"


def profile(path: Path = SOURCE) -> dict:
    parquet = pq.ParquetFile(path)
    columns = [str(name).strip() for name in parquet.schema.names]
    available = set(columns)
    missing = [feature for feature in FEATURES if feature not in available]
    extra = sorted(available - set(FEATURES) - {"Label", "ClassLabel"})
    labels: Counter = Counter()
    family_counts: Counter = Counter()
    for batch in parquet.iter_batches(batch_size=250_000, columns=["Label"]):
        for value, count in Counter(batch.column(0).to_pylist()).items():
            labels[str(value)] += count
            family_counts[canonical_family(value)] += count
    return {
        "schema": "cic-collection-compatibility-profile-v1",
        "dataset": "CIC-IDS-Collection",
        "source_file": str(path.relative_to(ROOT)),
        "rows": int(parquet.metadata.num_rows),
        "row_groups": int(parquet.num_row_groups),
        "columns": len(columns),
        "production_schema_features": len(FEATURES),
        "compatible_feature_count": len(FEATURES) - len(missing),
        "missing_production_features": missing,
        "non_label_extra_columns": extra,
        "raw_label_counts": dict(sorted(labels.items(), key=lambda item: (-item[1], item[0]))),
        "canonical_family_counts": dict(sorted(family_counts.items(), key=lambda item: (-item[1], item[0]))),
        "row_capture_provenance_present": any(
            name.strip().casefold() in {"capture", "capture_file", "source_dataset", "dataset_source"}
            for name in columns
        ),
        "safe_to_train_production_model_directly": False,
        "reason": (
            "The combined file omits production features and does not identify the source capture per row. "
            "It also includes CICIDS2017/2018 data already present in this project, so row-random splits risk leakage. "
            "Use a separate candidate with a documented common-feature schema and source-disjoint evaluation."
        ),
        "label_counts": {str(key): int(value) for key, value in labels.items()},
    }


def main() -> int:
    result = profile()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "rows": result["rows"],
        "production_features_missing": len(result["missing_production_features"]),
        "compatible_features": result["compatible_feature_count"],
        "row_capture_provenance_present": result["row_capture_provenance_present"],
        "families": result["canonical_family_counts"],
        "output": str(OUTPUT),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
