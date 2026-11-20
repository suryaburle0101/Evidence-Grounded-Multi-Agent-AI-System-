"""Authenticated Kaggle dataset download with guarded archive extraction.

The Kaggle CLI owns authentication. This module never accepts or stores tokens;
configure Kaggle's supported local credentials before invoking the CLI.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_UNPACKED_BYTES = 50 * 1024**3
MAX_ARCHIVE_MEMBERS = 20000


def _safe_extract(archive: Path, destination: Path) -> list[str]:
    destination = destination.resolve()
    extracted = []
    total_bytes = 0
    with zipfile.ZipFile(archive) as zf:
        members = zf.infolist()
        if len(members) > MAX_ARCHIVE_MEMBERS:
            raise ValueError("Dataset archive contains too many files")
        for member in members:
            name = member.filename.replace("\\", "/")
            target = (destination / name).resolve()
            if name.startswith("/") or target != destination and destination not in target.parents:
                raise ValueError(f"Unsafe path in dataset archive: {member.filename}")
            # Refuse Unix symlinks; do not follow archive-provided links.
            mode = member.external_attr >> 16
            if mode & 0o170000 == 0o120000:
                raise ValueError(f"Symbolic links are not allowed in dataset archives: {member.filename}")
            total_bytes += member.file_size
            if total_bytes > MAX_UNPACKED_BYTES:
                raise ValueError("Dataset archive exceeds the 50 GiB extraction limit")
            zf.extract(member, destination)
            if not member.is_dir():
                extracted.append(name)
    return extracted


def acquire(dataset_id: str, destination: str | Path, *, kaggle_executable: str = "kaggle") -> dict:
    dataset_id = dataset_id.strip()
    if not dataset_id or "/" not in dataset_id or any(ch.isspace() for ch in dataset_id):
        raise ValueError("dataset_id must be a Kaggle owner/dataset slug")
    target = Path(destination).resolve()
    if target.exists():
        raise ValueError(f"Destination must not already exist; refusing to overwrite: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    extraction_stage = Path(tempfile.mkdtemp(prefix="kaggle-extract-", dir=target.parent))
    try:
        with tempfile.TemporaryDirectory(prefix="kaggle-download-") as staging_name:
            staging = Path(staging_name)
            command = [kaggle_executable, "datasets", "download", "-d", dataset_id, "-p", str(staging)]
            completed = subprocess.run(command, capture_output=True, text=True, timeout=1800, check=False)
            if completed.returncode:
                message = (completed.stderr or completed.stdout).strip()[-2000:]
                raise RuntimeError(f"Kaggle CLI download failed ({completed.returncode}): {message}")
            archives = list(staging.glob("*.zip"))
            if len(archives) != 1:
                raise RuntimeError(f"Expected one Kaggle archive, found {len(archives)}")
            archive = archives[0]
            hasher = hashlib.sha256()
            with archive.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    hasher.update(chunk)
            digest = hasher.hexdigest()
            files = _safe_extract(archive, extraction_stage)
        manifest = {
            "dataset_id": dataset_id,
            "source": f"https://www.kaggle.com/datasets/{dataset_id}",
            "downloaded_at": datetime.now(timezone.utc).isoformat(),
            "archive_sha256": digest,
            "files": files,
            "license_review": "required before research, redistribution, or deployment",
            "status": "downloaded_not_yet_validated",
        }
        (extraction_stage / "ACQUISITION_MANIFEST.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        os.replace(extraction_stage, target)
        return manifest
    except Exception:
        shutil.rmtree(extraction_stage, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset_id", help="Kaggle dataset slug owner/dataset")
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--kaggle-executable", default="kaggle")
    args = parser.parse_args()
    result = acquire(args.dataset_id, args.destination, kaggle_executable=args.kaggle_executable)
    print(json.dumps({"dataset_id": result["dataset_id"], "files": len(result["files"]),
                      "destination": str(args.destination.resolve()), "status": result["status"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
