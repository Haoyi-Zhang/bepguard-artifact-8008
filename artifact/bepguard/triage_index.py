"""assessor triage-index audit."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

REQUIRED_QUESTIONS = [
    "contribution", "locked denominator", "overfitting", "positive finding", "repairs",
    "external tools", "paper/metadata", "run first"
]


def run_triage_index(root: Path) -> Dict[str, Any]:
    problems: List[str] = []
    path = root / "artifact/triage_index.json"
    if not path.exists():
        return {"status": "fail", "problem_count": 1, "problems": ["missing assessor triage index"], "entries_checked": 0}
    data = json.loads(path.read_text(encoding="utf-8"))
    entries = data.get("entries", [])
    text = json.dumps(entries).lower()
    for q in REQUIRED_QUESTIONS:
        if q not in text:
            problems.append(f"triage index missing question class: {q}")
    for entry in entries:
        if not entry.get("question") or not entry.get("surface"):
            problems.append("triage entry missing question or surface")
    return {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "entries_checked": len(entries),
        "required_question_classes": len(REQUIRED_QUESTIONS),
        "interpretation": "Checks that assessors can quickly map common objections to concrete paper/artifact evidence surfaces.",
    }


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
