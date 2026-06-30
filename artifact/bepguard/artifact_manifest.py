"""Artifact manifest reachability and capsule-surface audit."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, List

REQUIRED_ROOT_FILES = [
    "artifact/README.md",
    "artifact/quickstart.md",
    "artifact/paper_metadata.json",
    "artifact/reproduction.md",
    "artifact/reproduction_ladder.json",
    "artifact/checksum_manifest.csv",
    "artifact/results/result_index.csv",
    "artifact/results/validation_summary.json",
    "paper/main.pdf",
    "paper/supplement.pdf",
]


def run_artifact_manifest_reachability(root: Path) -> Dict[str, Any]:
    problems: List[str] = []
    for rel in REQUIRED_ROOT_FILES:
        if not (root / rel).exists():
            problems.append(f"required deliverable/capsule file missing: {rel}")
    result_index = root / "artifact/results/result_index.csv"
    rows = []
    if result_index.exists():
        with result_index.open(newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        path_keys = [k for k in rows[0].keys()] if rows else []
        # The index format has varied across hardening rounds; accept any column containing a file path.
        path_col = next((k for k in path_keys if "path" in k.lower() or "file" in k.lower()), None)
        if path_col:
            missing = [r.get(path_col, "") for r in rows if r.get(path_col) and not (root / r.get(path_col, "")).exists()]
            if missing:
                problems.append(f"result_index references missing files: {missing[:5]}")
        elif rows:
            problems.append("result_index has no discoverable path/file column")
    else:
        problems.append("missing result_index.csv")
    checksum_rows = 0
    manifest = root / "artifact/checksum_manifest.csv"
    if manifest.exists():
        with manifest.open(newline="", encoding="utf-8") as fh:
            checksum_rows = sum(1 for _ in csv.DictReader(fh))
        if checksum_rows < 300:
            problems.append(f"checksum manifest unexpectedly small: {checksum_rows}")
    else:
        problems.append("missing checksum manifest")
    return {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems[:100],
        "required_files_checked": len(REQUIRED_ROOT_FILES),
        "result_index_rows": len(rows),
        "checksum_rows": checksum_rows,
        "interpretation": "Checks that the release artifact capsule exposes evidence-facing entry files and that materialized indices are reachable.",
    }


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
