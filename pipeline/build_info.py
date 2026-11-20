"""Shared version and source revision metadata for analysis outputs."""

from __future__ import annotations

import subprocess
from pathlib import Path


PIPELINE_VERSION = "1.0.0"


def _git_commit_hash() -> str:
    project_root = Path(__file__).resolve().parents[1]
    try:
        result = subprocess.run(
            ["git", "-C", str(project_root), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            timeout=2,
        )
        status = subprocess.run(
            ["git", "-C", str(project_root), "status", "--porcelain"],
            capture_output=True,
            text=True,
            check=True,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return "no-git"
    commit = result.stdout.strip() or "no-git"
    if commit != "no-git" and status.stdout.strip():
        commit += " (dirty)"
    return commit


GIT_COMMIT_HASH = _git_commit_hash()


def build_info() -> dict[str, str]:
    return {
        "pipeline_version": PIPELINE_VERSION,
        "git_commit_hash": GIT_COMMIT_HASH,
    }
