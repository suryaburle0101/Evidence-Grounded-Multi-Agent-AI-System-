"""Stream an inventory audit of raw capture files without training models.

The audit writes checkpoints and reports only beneath its output directory.
It can be resumed safely after interruption; rows are processed in batches.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sqlite3
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import numpy as np
import pandas as pd
import pyarrow.parquet as pq


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATASET_FOLDERS = ("CICIDS2017", "CSE_CIC_IDS2018", "UNSW_NB15", "CIC_IDS_Collection")
TABLE_SUFFIXES = {".csv", ".parquet"}
LABEL_CANDIDATES = ("label", "classlabel", "attack_cat", "class", "target")
BENIGN_LABELS = {"benign", "normal", "0", "0.0", "false"}
INFINITY_TEXT = {"inf", "+inf", "-inf", "infinity", "+infinity", "-infinity"}

# Mirrors the feature-name aliases documented in train_multidataset.py. This
# maps source columns for feature comparison only; it does not alter any rows.
ALIASES_2018 = {
    "Dst Port": "Destination Port", "Tot Fwd Pkts": "Total Fwd Packets",
    "Tot Bwd Pkts": "Total Backward Packets",
    "TotLen Fwd Pkts": "Total Length of Fwd Packets",
    "TotLen Bwd Pkts": "Total Length of Bwd Packets",
    "Fwd Pkt Len Max": "Fwd Packet Length Max", "Fwd Pkt Len Min": "Fwd Packet Length Min",
    "Fwd Pkt Len Mean": "Fwd Packet Length Mean", "Fwd Pkt Len Std": "Fwd Packet Length Std",
    "Bwd Pkt Len Max": "Bwd Packet Length Max", "Bwd Pkt Len Min": "Bwd Packet Length Min",
    "Bwd Pkt Len Mean": "Bwd Packet Length Mean", "Bwd Pkt Len Std": "Bwd Packet Length Std",
    "Flow Byts/s": "Flow Bytes/s", "Flow Pkts/s": "Flow Packets/s",
    "Fwd IAT Tot": "Fwd IAT Total", "Bwd IAT Tot": "Bwd IAT Total",
    "Fwd Header Len": "Fwd Header Length", "Bwd Header Len": "Bwd Header Length",
    "Fwd Pkts/s": "Fwd Packets/s", "Bwd Pkts/s": "Bwd Packets/s",
    "Pkt Len Min": "Min Packet Length", "Pkt Len Max": "Max Packet Length",
    "Pkt Len Mean": "Packet Length Mean", "Pkt Len Std": "Packet Length Std",
    "Pkt Len Var": "Packet Length Variance", "FIN Flag Cnt": "FIN Flag Count",
    "SYN Flag Cnt": "SYN Flag Count", "RST Flag Cnt": "RST Flag Count",
    "PSH Flag Cnt": "PSH Flag Count", "ACK Flag Cnt": "ACK Flag Count",
    "URG Flag Cnt": "URG Flag Count", "ECE Flag Cnt": "ECE Flag Count",
    "Pkt Size Avg": "Average Packet Size", "Fwd Seg Size Avg": "Avg Fwd Segment Size",
    "Bwd Seg Size Avg": "Avg Bwd Segment Size", "Fwd Byts/b Avg": "Fwd Avg Bytes/Bulk",
    "Fwd Pkts/b Avg": "Fwd Avg Packets/Bulk", "Fwd Blk Rate Avg": "Fwd Avg Bulk Rate",
    "Bwd Byts/b Avg": "Bwd Avg Bytes/Bulk", "Bwd Pkts/b Avg": "Bwd Avg Packets/Bulk",
    "Bwd Blk Rate Avg": "Bwd Avg Bulk Rate", "Subflow Fwd Pkts": "Subflow Fwd Packets",
    "Subflow Fwd Byts": "Subflow Fwd Bytes", "Subflow Bwd Pkts": "Subflow Bwd Packets",
    "Subflow Bwd Byts": "Subflow Bwd Bytes", "Init Fwd Win Byts": "Init_Win_bytes_forward",
    "Init Bwd Win Byts": "Init_Win_bytes_backward", "Fwd Act Data Pkts": "act_data_pkt_fwd",
    "Fwd Seg Size Min": "min_seg_size_forward",
}


def _normalize_column(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value).strip()).casefold()


def load_production_features(repo_root: Path = PROJECT_ROOT) -> list[str]:
    """Read the active 77-feature schema recorded with the drift baseline."""
    path = repo_root / "models" / "drift_baseline.json"
    metadata = json.loads(path.read_text(encoding="utf-8"))
    features = metadata.get("features", [])
    if len(features) != 77:
        raise ValueError(f"Expected 77 production features in {path}, found {len(features)}")
    return list(features)


def _unsw_columns(data_root: Path) -> list[str]:
    path = data_root / "UNSW_NB15" / "NUSW-NB15_features.csv"
    metadata = pd.read_csv(path, encoding="cp1252")
    if "Name" not in metadata.columns:
        raise ValueError(f"UNSW column metadata lacks a Name column: {path}")
    return [str(name).strip() for name in metadata["Name"].tolist()]


def _capture_files(data_root: Path) -> tuple[list[tuple[str, Path]], list[str]]:
    captures: list[tuple[str, Path]] = []
    skipped: list[str] = []
    for dataset in DATASET_FOLDERS:
        folder = data_root / dataset
        if not folder.exists():
            continue
        for path in sorted(folder.rglob("*")):
            if not path.is_file():
                continue
            if path.suffix.casefold() not in TABLE_SUFFIXES:
                skipped.append(path.relative_to(data_root).as_posix())
                continue
            if dataset == "UNSW_NB15" and "features" in path.stem.casefold():
                skipped.append(path.relative_to(data_root).as_posix() + " (column dictionary)")
                continue
            captures.append((dataset, path))
    return captures, skipped


def _columns_for(path: Path, dataset: str, data_root: Path) -> tuple[list[str], bool]:
    if path.suffix.casefold() == ".parquet":
        return list(pq.ParquetFile(path).schema.names), False
    if dataset == "UNSW_NB15" and re.fullmatch(r"UNSW-NB15_[1-4]", path.stem, re.IGNORECASE):
        return _unsw_columns(data_root), True
    return list(pd.read_csv(path, nrows=0, encoding="latin-1").columns), False


def _iter_batches(path: Path, dataset: str, data_root: Path, columns: list[str], headerless: bool,
                  batch_size: int) -> Iterator[pd.DataFrame]:
    if path.suffix.casefold() == ".parquet":
        parquet = pq.ParquetFile(path)
        for batch in parquet.iter_batches(batch_size=batch_size, columns=columns):
            yield batch.to_pandas()
        return
    options: dict[str, Any] = {"chunksize": batch_size, "encoding": "latin-1"}
    if headerless:
        options.update({"header": None, "names": columns})
    for chunk in pd.read_csv(path, **options):
        yield chunk


def _label_column(columns: list[str]) -> str | None:
    by_normalized = {_normalize_column(column): column for column in columns}
    return next((by_normalized[name] for name in LABEL_CANDIDATES if name in by_normalized), None)


def _feature_column_map(columns: list[str], features: list[str], dataset: str) -> dict[str, str]:
    direct = {_normalize_column(column): column for column in columns}
    aliases = {_normalize_column(alias): target for alias, target in ALIASES_2018.items()} if dataset == "CSE_CIC_IDS2018" else {}
    result: dict[str, str] = {}
    for feature in features:
        normalized = _normalize_column(feature)
        if normalized in direct:
            result[feature] = direct[normalized]
            continue
        for alias, target in aliases.items():
            if _normalize_column(target) == normalized and alias in direct:
                result[feature] = direct[alias]
                break
    return result


def _training_provenance(dataset: str, repo_root: Path = PROJECT_ROOT) -> tuple[str, str]:
    source_path = repo_root / "reports" / "production_model_validation" / "production_2017_source_check.json"
    external_path = repo_root / "reports" / "production_model_validation" / "production_external_2018.json"
    model_path = repo_root / "models" / "drift_baseline.json"
    train_path = repo_root / "train_multidataset.py"
    relative = lambda path: path.relative_to(repo_root).as_posix()
    model_metadata = json.loads(model_path.read_text(encoding="utf-8"))
    model_files = sorted(
        path.name for path in (repo_root / "models").iterdir()
        if path.is_file() and ("cicids2017" in path.name.casefold() or path.name.startswith("rare_"))
    )
    train_source = train_path.read_text(encoding="utf-8", errors="replace")
    candidate_output = "models/multidataset" in train_source and "does NOT touch existing models" in train_source
    sources = [relative(train_path), relative(model_path)] + [f"models/{name}" for name in model_files]
    if dataset == "CSE_CIC_IDS2018":
        external = json.loads(external_path.read_text(encoding="utf-8"))
        external_files = {Path(item.get("file", "")).name for item in external.get("files", [])}
        identified_external = external.get("external_dataset") == "CSE-CIC-IDS2018" and "external to" in external.get("split", "").casefold()
        if identified_external:
            if candidate_output:
                sources.extend([relative(external_path), "train_multidataset.py documents candidate output under models/multidataset/"])
            else:
                sources.append(relative(external_path))
            return "no", "; ".join(sources)
        return "unknown", "; ".join(sources + [relative(external_path)])
    if dataset == "CICIDS2017":
        source_check = json.loads(source_path.read_text(encoding="utf-8"))
        membership_note = str(source_check.get("evaluation_type", "")).casefold()
        known_unknown = "membership is unknown" in membership_note or "split membership is unknown" in membership_note
        files = {Path(item.get("file", "")).name for item in source_check.get("per_capture", [])}
        if known_unknown or files:
            sources.append(relative(source_path))
        return "unknown", "; ".join(sources)
    return "unknown", "; ".join(sources)


def _empty_summary(dataset: str, relative_path: str, columns: list[str], features: list[str],
                   feature_map: dict[str, str], repo_root: Path) -> dict[str, Any]:
    training_status, evidence = _training_provenance(dataset, repo_root)
    label_column = _label_column(columns)
    date_candidates = [column for column in columns if re.search(r"date|time|timestamp|^stime$|^ltime$", str(column), re.I)]
    return {
        "dataset": dataset, "file": relative_path, "row_count": 0,
        "label_column": label_column, "label_counts": {},
        "production_features_present": len(feature_map),
        "production_feature_columns": len(features),
        "row_limit_applied": False,
        "duplicate_row_count": 0, "duplicate_row_rate": 0.0,
        "rows_with_nan": 0, "rows_with_inf": 0, "rows_with_nan_or_inf": 0,
        "date_column": date_candidates[0] if date_candidates else None,
        "date_min": None, "date_max": None,
        "cross_dataset_duplicate_vector_count": 0,
        "cross_dataset_comparison": "all 77 production features available" if len(feature_map) == 77 else f"not compared: only {len(feature_map)} of 77 production features are present",
        "used_for_active_training": training_status, "training_evidence": evidence,
        "complete": False,
    }


def _label_key(value: Any) -> str:
    if pd.isna(value):
        return "<missing>"
    return str(value).strip()


def _nan_inf_counts(frame: pd.DataFrame) -> tuple[int, int, int]:
    nan_rows = frame.isna().any(axis=1)
    inf_rows = pd.Series(False, index=frame.index)
    for column in frame.columns:
        values = frame[column]
        if pd.api.types.is_numeric_dtype(values.dtype):
            try:
                inf_rows |= np.isinf(values.to_numpy(dtype=float, na_value=np.nan))
            except (TypeError, ValueError):
                continue
        elif pd.api.types.is_object_dtype(values.dtype) or pd.api.types.is_string_dtype(values.dtype):
            inf_rows |= values.astype("string").str.strip().str.casefold().isin(INFINITY_TEXT).fillna(False)
    return int(nan_rows.sum()), int(inf_rows.sum()), int((nan_rows | inf_rows).sum())


def _date_values(frame: pd.DataFrame, column: str | None) -> tuple[str | None, str | None]:
    if not column or column not in frame.columns:
        return None, None
    source = frame[column]
    if pd.api.types.is_numeric_dtype(source.dtype):
        values = pd.to_numeric(source, errors="coerce").dropna()
        if values.empty:
            return None, None
        magnitude = float(values.abs().median())
        unit = "s" if magnitude < 1e11 else "ms" if magnitude < 1e14 else "us" if magnitude < 1e17 else "ns"
        parsed = pd.to_datetime(source, errors="coerce", utc=True, unit=unit)
    else:
        parsed = pd.to_datetime(source, errors="coerce", utc=True)
    valid = parsed.dropna()
    if valid.empty:
        return None, None
    return valid.min().isoformat(), valid.max().isoformat()


def _new_checkpoint(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.executescript("""
        CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS capture_state (
            capture TEXT PRIMARY KEY, dataset TEXT NOT NULL, source_signature TEXT NOT NULL,
            next_batch INTEGER NOT NULL, summary_json TEXT NOT NULL, status TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS row_hashes (
            capture TEXT NOT NULL, row_hash TEXT NOT NULL, PRIMARY KEY (capture, row_hash)
        );
        CREATE TABLE IF NOT EXISTS feature_seen (
            fingerprint TEXT NOT NULL, dataset TEXT NOT NULL, capture TEXT NOT NULL, first_row INTEGER NOT NULL,
            PRIMARY KEY (fingerprint, dataset, capture)
        );
        CREATE TABLE IF NOT EXISTS cross_duplicates (
            fingerprint TEXT NOT NULL, dataset_a TEXT NOT NULL, capture_a TEXT NOT NULL, row_a INTEGER NOT NULL,
            dataset_b TEXT NOT NULL, capture_b TEXT NOT NULL, row_b INTEGER NOT NULL,
            PRIMARY KEY (fingerprint, capture_a, capture_b)
        );
        CREATE TEMP TABLE IF NOT EXISTS batch_features (
            fingerprint TEXT NOT NULL, dataset TEXT NOT NULL, capture TEXT NOT NULL, first_row INTEGER NOT NULL,
            PRIMARY KEY (fingerprint, dataset, capture)
        );
    """)
    return connection


def _atomic_text(path: Path, content: str) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(content, encoding="utf-8", newline="\n")
    temporary.replace(path)


def _class_counts(summary: dict[str, Any]) -> tuple[int | None, int | None]:
    if not summary.get("label_column"):
        return None, None
    benign = 0
    attack = 0
    for label, count in summary["label_counts"].items():
        normalized = str(label).strip().casefold()
        if normalized in BENIGN_LABELS:
            benign += int(count)
        elif normalized != "<missing>":
            attack += int(count)
    return benign, attack


def _all_summaries(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    result = []
    for row in connection.execute("SELECT summary_json FROM capture_state ORDER BY dataset,capture"):
        result.append(json.loads(row[0]))
    cross_by_capture: Counter[str] = Counter()
    for row in connection.execute("""
        SELECT capture_a, capture_b, COUNT(DISTINCT fingerprint)
        FROM cross_duplicates GROUP BY capture_a,capture_b
    """):
        cross_by_capture[row[0]] += row[2]
        cross_by_capture[row[1]] += row[2]
    for summary in result:
        summary["cross_dataset_duplicate_vector_count"] = cross_by_capture[summary["file"]]
        summary["duplicate_row_rate"] = (
            summary["duplicate_row_count"] / summary["row_count"] if summary["row_count"] else 0.0
        )
    return result


def _write_reports(output_dir: Path, connection: sqlite3.Connection, features: list[str], skipped: list[str],
                   data_root: Path, repo_root: Path) -> None:
    summaries = _all_summaries(connection)
    columns = [
        "dataset", "file", "row_count", "label_column", "label_counts", "production_features_present",
        "production_feature_columns", "duplicate_row_count", "duplicate_row_rate", "rows_with_nan",
        "rows_with_inf", "rows_with_nan_or_inf", "date_column", "date_min", "date_max",
        "cross_dataset_duplicate_vector_count", "cross_dataset_comparison", "row_limit_applied", "used_for_active_training",
        "training_evidence", "complete",
    ]
    csv_path = output_dir / "audit.csv"
    temporary_csv = csv_path.with_suffix(".csv.tmp")
    with temporary_csv.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for summary in summaries:
            row = dict(summary)
            row["label_counts"] = json.dumps(row["label_counts"], ensure_ascii=False, sort_keys=True)
            writer.writerow(row)
    temporary_csv.replace(csv_path)

    duplicate_groups = []
    for dataset_a, capture_a, dataset_b, capture_b, count in connection.execute("""
        SELECT dataset_a,capture_a,dataset_b,capture_b,COUNT(DISTINCT fingerprint)
        FROM cross_duplicates GROUP BY dataset_a,capture_a,dataset_b,capture_b
        ORDER BY dataset_a,capture_a,dataset_b,capture_b
    """):
        examples = [
            {"hash": r[0], "row_a": r[1], "row_b": r[2]}
            for r in connection.execute(
            "SELECT fingerprint,row_a,row_b FROM cross_duplicates WHERE capture_a=? AND capture_b=? ORDER BY fingerprint LIMIT 3",
            (capture_a, capture_b),
        )]
        duplicate_groups.append({
            "dataset_a": dataset_a, "capture_a": capture_a,
            "dataset_b": dataset_b, "capture_b": capture_b,
            "unique_duplicate_feature_vectors": count,
        "sample_vector_hashes_pandas64": examples,
        })

    payload = {
        "schema": "dataset-audit-v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "data_root": str(data_root),
        "production_feature_count": len(features),
        "production_feature_source": "models/drift_baseline.json",
        "training_evidence_sources": [
            "train_multidataset.py", "models/drift_baseline.json",
            "reports/production_model_validation/production_2017_source_check.json",
            "reports/production_model_validation/production_external_2018.json",
        ],
        "skipped_non_capture_inputs": skipped,
        "captures": summaries,
        "cross_dataset_duplicate_feature_vectors": duplicate_groups,
    }
    _atomic_text(output_dir / "audit.json", json.dumps(payload, indent=2, ensure_ascii=False) + "\n")

    lines = [
        "# Raw dataset audit", "",
        f"- Data root: `{data_root}`",
        "- Scope: CSV and Parquet capture tables in the four requested folders; no models were trained.",
        f"- Production features: {len(features)} from `models/drift_baseline.json`.",
        "- Resume/checkpoint database: `.audit_state.sqlite` in this output folder.",
        "- Capture rows may show as partial until the full run completes.", "",
        "## Per-capture audit", "",
        "| Dataset | File | Rows | Benign | Attack | Used for active training | Evidence |",
        "|---|---|---:|---:|---:|---|---|",
    ]
    for summary in summaries:
        benign, attack = _class_counts(summary)
        lines.append(
            f"| {summary['dataset']} | `{summary['file']}` | {summary['row_count']} | "
            f"{benign if benign is not None else 'not available'} | "
            f"{attack if attack is not None else 'not available'} | {summary['used_for_active_training']} | "
            f"{summary['training_evidence']} |"
        )
    lines.extend(["", "## Cross-dataset duplicate feature vectors", ""])
    if duplicate_groups:
        lines.extend([
            "Fingerprints compare finite vectors over all 77 production features in production schema order. Hashes are pandas 64-bit row hashes.", "",
            "| Dataset A / capture | Dataset B / capture | Unique matching vectors | Sample matching rows / hashes |",
            "|---|---|---:|---|",
        ])
        for item in duplicate_groups:
            left = f"{item['dataset_a']} / `{item['capture_a']}`"
            right = f"{item['dataset_b']} / `{item['capture_b']}`"
            sample_matches = ", ".join(f"A:{match['row_a']} ↔ B:{match['row_b']} ({match['hash']})" for match in item["sample_vector_hashes_pandas64"])
            lines.append(f"| {left} | {right} | {item['unique_duplicate_feature_vectors']} | `{sample_matches}` |")
    else:
        lines.append("No full 77-feature cross-dataset duplicate vectors have been recorded so far.")
    lines.extend(["", "## Inputs not treated as captures", ""])
    lines.extend([f"- `{path}`" for path in skipped] or ["- None."])
    lines.append("")
    _atomic_text(output_dir / "MANIFEST.md", "\n".join(lines))


def _check_run_config(connection: sqlite3.Connection, config: dict[str, Any]) -> None:
    encoded = json.dumps(config, sort_keys=True)
    existing = connection.execute("SELECT value FROM meta WHERE key='run_config'").fetchone()
    if existing and existing[0] != encoded:
        raise ValueError("Checkpoint settings differ from this run. Use a new --output-dir to start a separate audit.")
    connection.execute("INSERT OR IGNORE INTO meta(key,value) VALUES('run_config',?)", (encoded,))
    connection.commit()


def run_audit(data_root: Path, output_dir: Path, batch_size: int = 50_000,
              max_rows_per_capture: int | None = None, repo_root: Path = PROJECT_ROOT) -> dict[str, Any]:
    data_root = Path(data_root).resolve()
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    features = load_production_features(repo_root)
    captures, skipped = _capture_files(data_root)
    if not captures:
        raise FileNotFoundError(f"No CSV or Parquet captures found under {data_root}")
    connection = _new_checkpoint(output_dir / ".audit_state.sqlite")
    _check_run_config(connection, {
        "data_root": str(data_root), "batch_size": batch_size,
        "max_rows_per_capture": max_rows_per_capture,
        "production_features_sha256": hashlib.sha256("\n".join(features).encode()).hexdigest(),
    })
    print(f"Dataset audit: {len(captures)} capture files; batch size {batch_size}.", flush=True)
    for dataset, path in captures:
        relative = path.relative_to(data_root).as_posix()
        signature = f"{path.stat().st_size}:{path.stat().st_mtime_ns}"
        columns, headerless = _columns_for(path, dataset, data_root)
        feature_map = _feature_column_map(columns, features, dataset)
        existing = connection.execute(
            "SELECT source_signature,next_batch,summary_json,status FROM capture_state WHERE capture=?",
            (relative,),
        ).fetchone()
        if existing and existing[0] != signature:
            raise ValueError(f"Source capture changed since checkpoint: {relative}; use a new output directory")
        if existing and existing[3] == "complete":
            print(f"[complete] {relative}: resumed from checkpoint", flush=True)
            continue
        next_batch = int(existing[1]) if existing else 0
        summary = json.loads(existing[2]) if existing else _empty_summary(
            dataset, relative, columns, features, feature_map, repo_root
        )
        summary["row_limit_applied"] = max_rows_per_capture is not None
        if existing is None:
            connection.execute(
                "INSERT INTO capture_state VALUES(?,?,?,?,?,?)",
                (relative, dataset, signature, 0, json.dumps(summary, ensure_ascii=False), "running"),
            )
            connection.commit()
        label_column = summary["label_column"]
        date_column = summary["date_column"]
        feature_columns = [feature_map[feature] for feature in features] if len(feature_map) == 77 else []
        started = time.time()
        print(f"[{dataset}] {relative}: starting at batch {next_batch + 1}", flush=True)
        for batch_index, frame in enumerate(_iter_batches(path, dataset, data_root, columns, headerless, batch_size)):
            if batch_index < next_batch:
                continue
            if max_rows_per_capture is not None:
                remaining = max_rows_per_capture - summary["row_count"]
                if remaining <= 0:
                    break
                frame = frame.iloc[:remaining]
            if frame.empty:
                break
            row_start = summary["row_count"]
            counts_before = Counter(summary["label_counts"])
            if label_column and label_column in frame.columns:
                counts = frame[label_column].map(_label_key).value_counts(dropna=False)
                counts_before.update({str(k): int(v) for k, v in counts.items()})
            nan_count, inf_count, invalid_count = _nan_inf_counts(frame)
            row_hashes = pd.util.hash_pandas_object(frame, index=False, categorize=True).astype("uint64")
            hashes = [f"{value:016x}" for value in row_hashes.tolist()]
            dates_min, dates_max = _date_values(frame, date_column)
            fingerprint_rows: list[tuple[str, str, str, int]] = []
            if feature_columns:
                numeric = frame[feature_columns].apply(pd.to_numeric, errors="coerce").astype("float64")
                valid = np.isfinite(numeric.to_numpy()).all(axis=1)
                if valid.any():
                    vector_hashes = pd.util.hash_pandas_object(numeric.loc[valid], index=False).astype("uint64")
                    valid_offsets = np.flatnonzero(valid)
                    fingerprint_rows = [
                        (f"{value:016x}", dataset, relative, row_start + int(offset) + 1)
                        for value, offset in zip(vector_hashes.tolist(), valid_offsets)
                    ]
            connection.execute("DELETE FROM batch_features")
            before_changes = connection.total_changes
            connection.executemany("INSERT OR IGNORE INTO row_hashes(capture,row_hash) VALUES(?,?)",
                                   ((relative, item) for item in hashes))
            new_row_hashes = connection.total_changes - before_changes
            connection.executemany("INSERT OR IGNORE INTO batch_features VALUES(?,?,?,?)", fingerprint_rows)
            connection.execute("""
                INSERT OR IGNORE INTO cross_duplicates
                SELECT b.fingerprint,s.dataset,s.capture,s.first_row,b.dataset,b.capture,b.first_row
                FROM batch_features b JOIN feature_seen s ON s.fingerprint=b.fingerprint
                WHERE b.dataset<>s.dataset
            """)
            connection.execute("""
                INSERT OR IGNORE INTO feature_seen
                SELECT fingerprint,dataset,capture,first_row FROM batch_features
            """)
            summary["row_count"] += len(frame)
            summary["label_counts"] = dict(counts_before)
            summary["duplicate_row_count"] += len(frame) - new_row_hashes
            summary["rows_with_nan"] += nan_count
            summary["rows_with_inf"] += inf_count
            summary["rows_with_nan_or_inf"] += invalid_count
            if dates_min:
                summary["date_min"] = min(filter(None, [summary["date_min"], dates_min]))
                summary["date_max"] = max(filter(None, [summary["date_max"], dates_max]))
            summary["duplicate_row_rate"] = summary["duplicate_row_count"] / summary["row_count"]
            connection.execute(
                "UPDATE capture_state SET next_batch=?,summary_json=?,status='running' WHERE capture=?",
                (batch_index + 1, json.dumps(summary, ensure_ascii=False), relative),
            )
            connection.commit()
            print(f"  batch {batch_index + 1}: {summary['row_count']} rows checkpointed", flush=True)
            if max_rows_per_capture is not None and summary["row_count"] >= max_rows_per_capture:
                break
        summary["complete"] = True
        connection.execute(
            "UPDATE capture_state SET summary_json=?,status=? WHERE capture=?",
            (json.dumps(summary, ensure_ascii=False), "complete", relative),
        )
        connection.commit()
        _write_reports(output_dir, connection, features, skipped, data_root, repo_root)
        print(f"[{dataset}] {relative}: {summary['row_count']} rows recorded in {time.time()-started:.1f}s", flush=True)
    _write_reports(output_dir, connection, features, skipped, data_root, repo_root)
    complete_count = connection.execute("SELECT COUNT(*) FROM capture_state WHERE status='complete'").fetchone()[0]
    print(f"Audit checkpoint saved: {complete_count}/{len(captures)} captures complete.", flush=True)
    result = {"capture_count": len(captures), "complete_count": complete_count,
              "output_dir": str(output_dir), "state_database": str(output_dir / ".audit_state.sqlite")}
    connection.close()
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, default=PROJECT_ROOT / "data" / "raw")
    parser.add_argument("--output-dir", type=Path, default=PROJECT_ROOT / "reports" / "dataset_audit")
    parser.add_argument("--batch-size", type=int, default=50_000)
    parser.add_argument("--limit-rows", type=int, default=None,
                        help="Optional smoke-test cap applied separately to each capture file.")
    args = parser.parse_args(argv)
    if args.batch_size <= 0 or (args.limit_rows is not None and args.limit_rows <= 0):
        parser.error("batch size and limit rows must be positive")
    run_audit(args.data_root, args.output_dir, args.batch_size, args.limit_rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
