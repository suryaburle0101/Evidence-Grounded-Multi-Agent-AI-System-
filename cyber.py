"""Command-line interface for analyzing CICIDS-style flow files."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import pandas as pd


MODEL_RUNTIME_VERSIONS = {
    "scikit-learn": "1.6.1",
    "xgboost": "2.1.3",
}


def _check_model_runtime() -> None:
    """Fail clearly when this interpreter cannot safely load the model files."""
    import sklearn
    import xgboost

    installed_versions = {
        "scikit-learn": sklearn.__version__,
        "xgboost": xgboost.__version__,
    }
    for package, expected in MODEL_RUNTIME_VERSIONS.items():
        installed = installed_versions[package]
        if installed != expected:
            raise RuntimeError(
                f"Model compatibility requires {package}=={expected}, "
                f"but this Python has {installed}. Run the project "
                "interpreter directly: "
                ".\\recovery_venv\\Scripts\\python.exe cyber.py ..."
            )


def _json_default(value: Any) -> Any:
    """Convert common NumPy/Pandas values to JSON-compatible values."""
    if hasattr(value, "item"):
        return value.item()
    if isinstance(value, (Path,)):
        return str(value)
    raise TypeError(f"Cannot serialize {type(value).__name__}")


def _iter_flows(path: Path, limit: int | None):
    suffix = path.suffix.lower()
    if suffix == ".csv":
        chunks = pd.read_csv(path, chunksize=256)
        seen = 0
        for chunk in chunks:
            if limit is not None:
                chunk = chunk.head(limit - seen)
            if not chunk.empty:
                yield chunk
                seen += len(chunk)
            if limit is not None and seen >= limit:
                break
        return
    if suffix in {".parquet", ".pq"}:
        import pyarrow.parquet as parquet

        seen = 0
        for batch in parquet.ParquetFile(path).iter_batches(batch_size=256):
            frame = batch.to_pandas()
            if limit is not None:
                frame = frame.head(limit - seen)
            if not frame.empty:
                yield frame
                seen += len(frame)
            if limit is not None and seen >= limit:
                break
        return
    raise ValueError("Input must be a .csv, .parquet, or .pq file")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze network-flow rows with the Cyber multi-agent pipeline."
    )
    parser.add_argument("input", type=Path, help="CSV or Parquet file of flow features")
    parser.add_argument(
        "-o", "--output", type=Path,
        help="JSONL output path (default: write results to stdout)",
    )
    parser.add_argument("--asset-context", type=Path,
                        help="JSON asset metadata applied to each flow (criticality/exposure)")
    parser.add_argument("--intel-feed", type=Path,
                        help="Import a CSV/JSON IOC feed before analysis")
    parser.add_argument("--report-dir", type=Path,
                        help="Write Markdown and JSON reports for ATTACK/REVIEW incidents")
    parser.add_argument("--generate-notes", action="store_true",
                        help="Generate local LLM drafts for ATTACK/REVIEW rows (slower on CPU)")
    size = parser.add_mutually_exclusive_group()
    size.add_argument(
        "--limit", type=int,
        default=10,
        help="Analyze at most the first N rows (default: 10)",
    )
    size.add_argument(
        "--all", action="store_true",
        help="Analyze every row; large datasets can take a long time",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.limit < 1:
        print("--limit must be at least 1", file=sys.stderr)
        return 2
    if not args.input.is_file():
        print(f"Input file not found: {args.input}", file=sys.stderr)
        return 2
    if args.input.suffix.lower() not in {".csv", ".parquet", ".pq"}:
        print("Input must be a .csv, .parquet, or .pq file", file=sys.stderr)
        return 2

    try:
        _check_model_runtime()
        # Import lazily so --help and input validation do not load large models.
        from analysis_service import analyze_flow
        from reporting.incident_report import write_report
        from intel.threat_intel import import_feed

        asset_context = None
        if args.asset_context:
            asset_context = json.loads(args.asset_context.read_text(encoding="utf-8"))
            if not isinstance(asset_context, dict):
                raise ValueError("--asset-context JSON must be an object")
        if args.intel_feed:
            print(f"Imported threat feed: {import_feed(args.intel_feed)}", file=sys.stderr)

        output = args.output.open("w", encoding="utf-8") if args.output else sys.stdout
        seen = 0
        failed = 0
        limit = None if args.all else args.limit
        try:
            for flows in _iter_flows(args.input, limit):
                for _, flow in flows.iterrows():
                    seen += 1
                    result = analyze_flow(
                        flow, asset_context=asset_context, source="cli",
                        generate_llm=args.generate_notes,
                    )
                    if not result.get("pipeline_completed", False):
                        failed += 1
                    result["input_file"] = str(args.input)
                    result["row_number"] = seen
                    if (args.report_dir and result.get("incident_id")):
                        result["report_files"] = write_report(
                            result, args.report_dir, result["incident_id"]
                        )
                    output.write(json.dumps(result, default=_json_default) + "\n")
                    if seen % 100 == 0:
                        print(f"Analyzed {seen} flow rows...", file=sys.stderr)
        finally:
            if args.output:
                output.close()
        if seen == 0:
            print("Input contains no rows to analyze", file=sys.stderr)
            return 2
        print(f"Analyzed {seen} flow rows; {failed} pipeline failures.", file=sys.stderr)
        if failed:
            return 1
    except Exception as exc:
        print(f"Analysis failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
