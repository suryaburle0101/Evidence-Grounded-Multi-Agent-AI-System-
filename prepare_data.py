"""Profile, validate, and map CSV/Parquet flow datasets."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from pipeline.data_pipeline import prepare_file, profile_file, validate_file


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    profile = actions.add_parser("profile", help="Summarize schema and value distributions")
    profile.add_argument("input", type=Path)
    profile.add_argument("--sample-rows", type=int, default=20_000)
    validate = actions.add_parser("validate", help="Check required features and data quality")
    validate.add_argument("input", type=Path)
    prepare = actions.add_parser("prepare", help="Map and clean into model-ready Parquet")
    prepare.add_argument("input", type=Path)
    prepare.add_argument("output", type=Path)
    args = parser.parse_args(argv)
    try:
        if not args.input.is_file():
            raise FileNotFoundError(args.input)
        if args.action == "profile":
            result = profile_file(args.input, sample_rows=args.sample_rows)
        elif args.action == "validate":
            result = validate_file(args.input)
        else:
            result = prepare_file(args.input, args.output)
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        return 0 if result.get("valid", True) else 1
    except Exception as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
