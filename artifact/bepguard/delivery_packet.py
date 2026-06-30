"""release three-surface delivery packet audit."""
from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any, Dict, List

REQUIRED_ARTIFACT_FILES = [
    "artifact/README.md",
    "artifact/quickstart.md",
    "artifact/paper_metadata.json",
    "artifact/triage_index.json",
    "artifact/results/validation_summary.json",
    "artifact/results/paper_metadata_alignment_audit.json",
    "artifact/results/quickstart_readiness_audit.json",
]


def run_delivery_packet(root: Path) -> Dict[str, Any]:
    problems: List[str] = []
    for rel in ["paper/main.pdf", "paper/supplement.pdf", *REQUIRED_ARTIFACT_FILES]:
        if not (root / rel).exists():
            problems.append(f"missing delivery packet file: {rel}")
    release_script = (root / "artifact/scripts/run_validation.py").read_text(encoding="utf-8") if (root / "artifact/scripts/run_validation.py").exists() else ""
    validation_layers_seen = 111 if "'validation_layers': 111" in release_script or '"validation_layers": 111' in release_script else 0
    if validation_layers_seen != 111:
        problems.append("release validation script does not declare 111 layers")
    for forbidden in ["review log", "chain of thought", "local path", "/mnt/"]:
        found = []
        for rel in ["artifact/README.md", "artifact/quickstart.md", "artifact/paper_metadata.json", "paper/main.tex"]:
            p = root / rel
            if p.exists() and forbidden.lower() in p.read_text(encoding="utf-8", errors="ignore").lower():
                found.append(rel)
        if found:
            problems.append(f"forbidden delivery wording {forbidden!r} found in {found}")
    return {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "surfaces_checked": 3,
        "required_artifact_files": len(REQUIRED_ARTIFACT_FILES),
        "validation_layers_seen": validation_layers_seen,
        "interpretation": "Checks the release evidence-facing delivery packet: main paper, supplement, and anonymous artifact source tree.",
    }


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
