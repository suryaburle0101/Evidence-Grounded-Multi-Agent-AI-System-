"""Streaming profiling, schema mapping, validation, and preparation."""

from __future__ import annotations

import json
import os
import re
import tempfile
from collections import Counter
from pathlib import Path
from typing import Iterator

import numpy as np
import pandas as pd
from pipeline.flow_metadata import resolve_metadata_columns

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = Path(__file__).with_name("feature_schema.json")
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
FEATURES = SCHEMA["features"]
LABEL = SCHEMA["label_column"]

# CICFlowMeter 2018 header variants mapped to the trained CICIDS2017 schema.
ALIASES = {
    "Tot Fwd Pkts": "Total Fwd Packets",
    "Tot Bwd Pkts": "Total Backward Packets",
    "TotLen Fwd Pkts": "Fwd Packets Length Total",
    "TotLen Bwd Pkts": "Bwd Packets Length Total",
    "Fwd Pkt Len Max": "Fwd Packet Length Max",
    "Fwd Pkt Len Min": "Fwd Packet Length Min",
    "Fwd Pkt Len Mean": "Fwd Packet Length Mean",
    "Fwd Pkt Len Std": "Fwd Packet Length Std",
    "Bwd Pkt Len Max": "Bwd Packet Length Max",
    "Bwd Pkt Len Min": "Bwd Packet Length Min",
    "Bwd Pkt Len Mean": "Bwd Packet Length Mean",
    "Bwd Pkt Len Std": "Bwd Packet Length Std",
    "Flow Byts/s": "Flow Bytes/s",
    "Flow Pkts/s": "Flow Packets/s",
    "Fwd IAT Tot": "Fwd IAT Total",
    "Bwd IAT Tot": "Bwd IAT Total",
    "Fwd Pkts/s": "Fwd Packets/s",
    "Bwd Pkts/s": "Bwd Packets/s",
    "Pkt Len Min": "Packet Length Min",
    "Pkt Len Max": "Packet Length Max",
    "Pkt Len Mean": "Packet Length Mean",
    "Pkt Len Std": "Packet Length Std",
    "Pkt Len Var": "Packet Length Variance",
    "FIN Flag Cnt": "FIN Flag Count",
    "SYN Flag Cnt": "SYN Flag Count",
    "RST Flag Cnt": "RST Flag Count",
    "PSH Flag Cnt": "PSH Flag Count",
    "ACK Flag Cnt": "ACK Flag Count",
    "URG Flag Cnt": "URG Flag Count",
    "Pkt Size Avg": "Avg Packet Size",
    "Fwd Seg Size Avg": "Avg Fwd Segment Size",
    "Bwd Seg Size Avg": "Avg Bwd Segment Size",
    "Fwd Byts/b Avg": "Fwd Avg Bytes/Bulk",
    "Fwd Pkts/b Avg": "Fwd Avg Packets/Bulk",
    "Fwd Blk Rate Avg": "Fwd Avg Bulk Rate",
    "Bwd Byts/b Avg": "Bwd Avg Bytes/Bulk",
    "Bwd Pkts/b Avg": "Bwd Avg Packets/Bulk",
    "Bwd Blk Rate Avg": "Bwd Avg Bulk Rate",
    "Subflow Fwd Pkts": "Subflow Fwd Packets",
    "Subflow Fwd Byts": "Subflow Fwd Bytes",
    "Subflow Bwd Pkts": "Subflow Bwd Packets",
    "Subflow Bwd Byts": "Subflow Bwd Bytes",
    "Init Fwd Win Byts": "Init Fwd Win Bytes",
    "Init Bwd Win Byts": "Init Bwd Win Bytes",
    "Fwd Act Data Pkts": "Fwd Act Data Packets",
    "Fwd Seg Size Min": "Fwd Seg Size Min",
    "Pkt Len Min": "Packet Length Min",
}

LABEL_ALIASES = {
    "benign": "Benign", "normal": "Benign",
    "bot": "Botnet", "botnet": "Botnet",
    "ftp patator": "Brute Force", "ssh patator": "Brute Force",
    "brute force": "Brute Force", "bruteforce": "Brute Force",
    "ddos": "DDoS", "loic http": "DDoS", "hoic": "DDoS",
    "dos hulk": "DoS", "dos goldeneye": "DoS", "dos slowloris": "DoS",
    "dos slowhttptest": "DoS", "dos": "DoS",
    "portscan": "Port Scan", "port scan": "Port Scan",
    "web attack": "Web Attack", "web attack brute force": "Web Attack",
    "web attack xss": "Web Attack", "web attack sql injection": "Web Attack",
    "infiltration": "Infiltration", "heartbleed": "Heartbleed",
}


def _label_column(columns) -> str | None:
    return next((str(c) for c in columns if str(c).strip().lower() in {
        "label", "attack", "class", "target"
    }), None)


def map_schema(frame: pd.DataFrame) -> tuple[pd.DataFrame, dict[str, str]]:
    """Normalize headers and map known CICFlowMeter aliases without overwrites."""
    result = frame.copy()
    result.columns = [str(c).replace("\ufeff", "").strip() for c in result.columns]
    mapping: dict[str, str] = {}
    present = set(result.columns)
    for source, target in ALIASES.items():
        if source in present and target not in present:
            mapping[source] = target
            present.add(target)
    result = result.rename(columns=mapping)
    # Resolve case/spacing-only differences against the trained schema.
    normalized = {re.sub(r"\s+", " ", c).strip().casefold(): c for c in result.columns}
    rename = {}
    for feature in FEATURES:
        candidate = normalized.get(re.sub(r"\s+", " ", feature).strip().casefold())
        if candidate is not None and candidate != feature and feature not in result.columns:
            rename[candidate] = feature
    if rename:
        result = result.rename(columns=rename)
        mapping.update(rename)
    label = _label_column(result.columns)
    if label and label != LABEL:
        if LABEL not in result.columns:
            result = result.rename(columns={label: LABEL})
            mapping[label] = LABEL
    return result, mapping


def canonical_label(value) -> str:
    raw = str(value).replace("_", " ").strip()
    key = re.sub(r"\s+", " ", raw).casefold()
    return LABEL_ALIASES.get(key, raw)


def iter_frames(path: str | Path, batch_size: int = 50_000) -> Iterator[pd.DataFrame]:
    path = Path(path)
    if path.suffix.lower() == ".csv":
        yield from pd.read_csv(path, chunksize=batch_size, low_memory=False)
        return
    if path.suffix.lower() in {".parquet", ".pq"}:
        import pyarrow.parquet as pq
        for batch in pq.ParquetFile(path).iter_batches(batch_size=batch_size):
            yield batch.to_pandas()
        return
    raise ValueError("Supported input types are CSV and Parquet")


def validate_frame(frame: pd.DataFrame, require_label: bool = False) -> dict:
    mapped, mapping = map_schema(frame)
    missing = [name for name in FEATURES if name not in mapped.columns]
    label_col = _label_column(mapped.columns)
    errors = []
    warnings = []
    if missing:
        errors.append(f"Missing {len(missing)} required model features: {missing}")
    if require_label and label_col is None:
        errors.append("A Label/Attack/Class column is required for labeled data")
    invalid_counts = {}
    invalid_rows = 0
    if not missing:
        for name in FEATURES:
            values = pd.to_numeric(mapped[name], errors="coerce")
            invalid_counts[name] = int((values.isna() | ~np.isfinite(values)).sum())
        bad = {name: count for name, count in invalid_counts.items() if count}
        if bad:
            numeric = mapped[FEATURES].apply(pd.to_numeric, errors="coerce")
            invalid_rows = int((numeric.isna() | ~np.isfinite(numeric)).any(axis=1).sum())
            errors.append(f"{invalid_rows} row(s) contain missing, non-numeric, or infinite model values")
    return {
        "valid": not errors,
        "schema_version": SCHEMA["schema_version"],
        "feature_count": len(FEATURES),
        "missing_features": missing,
        "label_column": label_col,
        "column_mapping": mapping,
        "invalid_value_counts": invalid_counts,
        "invalid_rows": invalid_rows,
        "errors": errors,
        "warnings": warnings,
    }


def profile_file(path: str | Path, batch_size: int = 50_000, sample_rows: int = 20_000) -> dict:
    path = Path(path)
    samples = []
    sampled_count = 0
    counts = Counter()
    rows_seen = 0
    for frame in iter_frames(path, batch_size):
        rows_seen += len(frame)
        if sampled_count < sample_rows:
            sample = frame.head(sample_rows - sampled_count)
            samples.append(sample)
            sampled_count += len(sample)
        label = _label_column(frame.columns)
        if label:
            counts.update(frame[label].dropna().astype(str).value_counts().to_dict())
    sampled = pd.concat(samples, ignore_index=True) if samples else pd.DataFrame()
    if sampled.empty:
        return {"source": str(path), "rows": rows_seen, "sampled_rows": 0, "columns": []}
    mapped, aliases = map_schema(sampled)
    columns = []
    for name in mapped.columns:
        series = mapped[name]
        item = {
            "name": name,
            "dtype": str(series.dtype),
            "missing_count_sample": int(series.isna().sum()),
            "missing_percent_sample": round(float(series.isna().mean() * 100), 3),
            "distinct_sample": int(series.nunique(dropna=True)),
        }
        if pd.api.types.is_numeric_dtype(series):
            finite = pd.to_numeric(series, errors="coerce")
            finite = finite[np.isfinite(finite)]
            if len(finite):
                item["min"] = float(finite.min())
                item["max"] = float(finite.max())
        columns.append(item)
    return {
        "source": str(path),
        "rows": rows_seen,
        "sampled_rows": len(sampled),
        "column_count": len(columns),
        "schema_version": SCHEMA["schema_version"],
        "feature_coverage": round(sum(f in mapped.columns for f in FEATURES) / len(FEATURES), 4),
        "column_mapping": aliases,
        "label_distribution": dict(counts),
        "columns": columns,
        "validation": validate_frame(sampled),
    }


def prepare_file(source: str | Path, output: str | Path, batch_size: int = 50_000) -> dict:
    """Map and clean flow files to model schema; reject files missing features."""
    source, output = Path(source), Path(output)
    if output.suffix.lower() not in {".parquet", ".pq"}:
        raise ValueError("Prepared output must be Parquet (.parquet or .pq)")
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix="cyber-prepare-", suffix=".parquet", dir=output.parent)
    os.close(fd)
    temp = Path(temp_name)
    writer = None
    output_schema = None
    counts = {"rows_read": 0, "rows_written": 0, "rows_dropped_invalid": 0}
    mapping = {}
    label_present = None
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
        for raw in iter_frames(source, batch_size):
            counts["rows_read"] += len(raw)
            frame, found = map_schema(raw)
            mapping.update(found)
            missing = [name for name in FEATURES if name not in frame.columns]
            if missing:
                raise ValueError(f"Input lacks {len(missing)} trained features: {missing}")
            label = _label_column(frame.columns)
            if label_present is None:
                label_present = label is not None
            if label_present != (label is not None):
                raise ValueError("Label column presence changed between input batches")
            selected = frame[FEATURES].apply(pd.to_numeric, errors="coerce")
            selected = selected.replace([np.inf, -np.inf], np.nan)
            valid_rows = selected.notna().all(axis=1)
            counts["rows_dropped_invalid"] += int((~valid_rows).sum())
            selected = selected.loc[valid_rows].astype("float64")
            metadata_columns = resolve_metadata_columns(frame.columns)
            for canonical, source_column in metadata_columns.items():
                # Protocol is already a numeric model feature; preserving it a
                # second time as context adds no endpoint value.
                if source_column in FEATURES or source_column == label:
                    continue
                selected[canonical] = frame.loc[valid_rows, source_column].to_numpy()
            if label is not None:
                raw_labels = frame.loc[valid_rows, label].astype(str).str.strip()
                selected["source_label"] = raw_labels.to_numpy()
                selected[LABEL] = raw_labels.map(canonical_label).to_numpy()
            if selected.empty:
                continue
            table = pa.Table.from_pandas(selected, preserve_index=False)
            if writer is None:
                output_schema = table.schema
                writer = pq.ParquetWriter(temp, table.schema, compression="zstd")
            elif table.schema != output_schema:
                table = table.cast(output_schema)
            writer.write_table(table)
            counts["rows_written"] += len(selected)
        if writer is None:
            raise ValueError("No valid flow rows were found in the input")
        writer.close()
        writer = None
        temp.replace(output)
    except Exception:
        if writer is not None:
            writer.close()
        temp.unlink(missing_ok=True)
        raise
    return {
        "source": str(source), "output": str(output),
        "schema_version": SCHEMA["schema_version"],
        "feature_count": len(FEATURES), "column_mapping": mapping,
        "label_present": bool(label_present), **counts,
    }


def validate_file(path: str | Path, batch_size: int = 50_000) -> dict:
    path = Path(path)
    rows = 0
    invalid = 0
    missing_features = []
    labels = Counter()
    initial = None
    batch_errors = []
    for frame in iter_frames(path, batch_size):
        rows += len(frame)
        report = validate_frame(frame)
        if initial is None:
            initial = report
        for error in report.get("errors", []):
            if error not in batch_errors:
                batch_errors.append(error)
        invalid += report.get("invalid_rows", 0)
        missing_features = report.get("missing_features", missing_features)
        mapped, _ = map_schema(frame)
        label = _label_column(mapped.columns)
        if label:
            labels.update(mapped[label].dropna().astype(str).value_counts().to_dict())
    if initial is None:
        return {"valid": False, "rows": 0, "errors": ["Input is empty"]}
    errors = [e for e in batch_errors if "row(s) contain" not in e]
    if invalid:
        errors.append(f"{invalid} row(s) across the file contain missing, non-numeric, or infinite model values")
    return {**initial, "valid": initial["valid"] and rows > 0 and invalid == 0,
            "errors": errors, "invalid_rows": invalid, "rows": rows,
            "rows_with_invalid_values": invalid,
            "missing_features": missing_features,
            "label_distribution": dict(labels)}
