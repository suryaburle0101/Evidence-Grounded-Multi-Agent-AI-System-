"""Offline PCAP-to-incident bridge using an explicitly configured flow extractor.

The extractor must emit a CICFlowMeter-compatible CSV. Its column names and values
are checked against the production model before any incidents are created.
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import tempfile
from pathlib import Path

import pandas as pd

from analysis_service import analyze_flow
from detection.model_predictor import FEATURE_NAMES, prepare_input
from pipeline.build_info import build_info


def parse_command_template(raw: str | None = None) -> list[str]:
    raw = raw if raw is not None else os.environ.get("CICFLOWMETER_COMMAND", "")
    if not raw:
        raise RuntimeError("Configure CICFLOWMETER_COMMAND as a JSON argument array or quoted command template")
    try:
        command = json.loads(raw)
    except json.JSONDecodeError:
        command = shlex.split(raw, posix=False)
    if not isinstance(command, list) or not command or any(not isinstance(arg, str) for arg in command):
        raise ValueError("CICFLOWMETER_COMMAND must be a non-empty JSON array of argument strings")
    if not any("{pcap}" in arg for arg in command) or not any("{output_dir}" in arg for arg in command):
        raise ValueError("Extractor command must include {pcap} and {output_dir} placeholders")
    return command


def expand_command(command: list[str], pcap: Path, output_dir: Path) -> list[str]:
    return [arg.replace("{pcap}", str(pcap.resolve())).replace("{output_dir}", str(output_dir.resolve()))
            for arg in command]


def validate_feature_csv(path: Path, chunksize: int = 4096) -> int:
    columns = set(pd.read_csv(path, nrows=0).columns)
    missing = [name for name in FEATURE_NAMES if name not in columns]
    if missing:
        raise ValueError(f"Extractor output is not compatible with the production model; missing {len(missing)} features: {missing}")
    rows = 0
    for frame in pd.read_csv(path, chunksize=chunksize):
        prepare_input(frame)
        rows += len(frame)
    if not rows:
        raise ValueError("Extractor produced no flow rows")
    return rows


def ingest_pcap(pcap_path: str | Path, output_path: str | Path, *, command: list[str] | None = None,
                timeout_seconds: int = 3600) -> dict:
    pcap = Path(pcap_path).resolve()
    if not pcap.is_file() or pcap.suffix.casefold() not in {".pcap", ".pcapng", ".cap"}:
        raise ValueError("Input must be an existing .pcap, .pcapng, or .cap file")
    if timeout_seconds < 1 or timeout_seconds > 86400:
        raise ValueError("timeout_seconds must be between 1 and 86400")
    extractor_command = command or parse_command_template()
    destination = Path(output_path).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cyber-pcap-") as temp_name:
        work = Path(temp_name)
        feature_dir = work / "features"
        feature_dir.mkdir()
        args = expand_command(extractor_command, pcap, feature_dir)
        try:
            completed = subprocess.run(args, capture_output=True, text=True,
                                       timeout=timeout_seconds, check=False)
        except FileNotFoundError as exc:
            raise RuntimeError(f"Configured PCAP extractor was not found: {args[0]}") from exc
        if completed.returncode:
            detail = (completed.stderr or completed.stdout).strip()[-1500:]
            raise RuntimeError(f"PCAP feature extraction failed ({completed.returncode}): {detail}")
        csv_files = list(feature_dir.rglob("*.csv"))
        if len(csv_files) != 1:
            raise RuntimeError(f"Expected exactly one extracted flow CSV, found {len(csv_files)}")
        feature_csv = csv_files[0]
        preflight_rows = validate_feature_csv(feature_csv)
        from pipeline.flow_metadata import extract_flow_context
        analyzed = 0
        failures = 0
        processed = 0
        with destination.open("w", encoding="utf-8") as result_file:
            for frame in pd.read_csv(feature_csv, chunksize=128):
                for row in frame.to_dict(orient="records"):
                    try:
                        result = analyze_flow(row, source="pcap", persist=True)
                        if result.get("pipeline_completed"):
                            analyzed += 1
                        else:
                            failures += 1
                    except Exception as exc:  # retain row-level diagnostics, continue bounded batch
                        failures += 1
                        result = {**build_info(), "pipeline_completed": False, "error": str(exc),
                                  "flow_context": extract_flow_context(row)}
                    processed += 1
                    result.update(build_info())
                    result["row_number"] = processed
                    result_file.write(json.dumps(result, ensure_ascii=False, default=str) + "\n")
    return {**build_info(), "pcap": str(pcap), "feature_rows": preflight_rows, "processed": processed, "analyzed": analyzed,
            "failures": failures, "results_jsonl": str(destination),
            "extractor": "configured CICFlowMeter-compatible command",
            "production_model_schema": "cicids2017-77-v1"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--output", type=Path, required=True, help="Result JSONL output path")
    parser.add_argument("--timeout-seconds", type=int, default=3600)
    args = parser.parse_args()
    result = ingest_pcap(args.pcap, args.output, timeout_seconds=args.timeout_seconds)
    print(json.dumps(result, indent=2))
    return 0 if result["failures"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
