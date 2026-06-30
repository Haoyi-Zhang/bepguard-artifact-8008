"""Release-wide stale numeric surface audit.

This audit is deliberately broader than paper-claim consistency: it scans the
evidence-facing paper, tables, supplement, README, reproduction protocol, and
selected validation modules for stale release counts that often survive late
artifact hardening rounds.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List

EXPECTED = {
    "validation_layers": "111",
    "reproduction_commands": "101",
    "amendment_span": "A001-A099",
    "package_version": "0.24.0",
    "specbench_cases": "4,180",
    "declarative_oracle_cases": "5,152",
    "references": "72",
}

assessor_TEXTS = [
    "paper/main.tex",
    "paper/supplement.tex",
    "paper/tables/result_overview.tex",
    "paper/tables/baseline_comparison.tex",
    "artifact/README.md",
    "artifact/reproduction.md",
    "artifact/protocol_lock.json",
    "artifact/pyproject.toml",
    "artifact/environment_lock.json",
    "artifact/bepguard/__init__.py",
]

# Values from late prior releases that should not remain in evidence-facing
# claim surfaces after this synchronization.  Context terms reduce false hits
# against legitimate historical protocol entries.
STALE_PATTERNS = [
    r"release validation layers\s*&\s*82\s*/\s*82",
    r"release validation layers\s*&\s*90\s*/\s*90",
    r"release\s+90\s*/\s*90\s+validation",
    r"90\s+materialized\s+layers",
    r"90\s+release-validation\s+layers",
    r"80-command\s+reproduction\s+ladder",
    r"80\s+declared\s+commands",
    r"97 commands",
    r"A001-A078",
    r"0\.21\.0",
]

REQUIRED_BY_FILE = {
    "paper/main.tex": ["111/111", "101-command", "BEPGuard: Proof-Carrying Evidence"],
    "paper/supplement.tex": ["111", "101-command", "A001--A099"],
    "paper/tables/result_overview.tex": ["111 / 111"],
    "paper/tables/baseline_comparison.tex": ["101 commands"],
    "artifact/README.md": ["111 materialized validation layers", "101-command reproduction ladder", "A001-A099"],
    "artifact/reproduction.md": ["111 materialized layers", "101 declared commands", "A001-A099"],
    "artifact/protocol_lock.json": ["\"validation_layers\": 111", "\"reproduction_ladder_commands\": 101", "\"specbench_cases\": 4180", "\"scale_stress_cases\": 48600", "A001-A099"],
    "artifact/pyproject.toml": ["0.24.0"],
    "artifact/environment_lock.json": ["0.24.0"],
    "artifact/bepguard/__init__.py": ["0.24.0"],
}


def run_stale_numeric_surface(root: Path) -> Dict[str, Any]:
    problems: List[str] = []
    rows: List[Dict[str, Any]] = []
    for rel in assessor_TEXTS:
        path = root / rel
        if not path.exists():
            problems.append(f"missing evidence-facing text: {rel}")
            continue
        text = path.read_text(encoding="utf-8")
        local = []
        for token in REQUIRED_BY_FILE.get(rel, []):
            if token not in text:
                local.append(f"missing token {token!r}")
        for pat in STALE_PATTERNS:
            if re.search(pat, text, flags=re.IGNORECASE):
                local.append(f"stale pattern matched: {pat}")
        rows.append({"file": rel, "required_tokens": len(REQUIRED_BY_FILE.get(rel, [])), "problems": local})
        problems.extend(f"{rel}: {p}" for p in local)
    return {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems[:100],
        "files_checked": len(assessor_TEXTS),
        "expected_counts": EXPECTED,
        "rows": rows,
        "interpretation": "Checks that evidence-facing text, tables, package identity, and reproduction metadata expose the current release counts and reject stale late-round counts.",
    }


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")

