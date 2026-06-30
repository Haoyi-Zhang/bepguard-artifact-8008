"""Main-paper and supplement count-alignment audit."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List

COUNTS = {
    "validation": ["111", "111/111", "111 / 111"],
    "ladder": ["101-command", "101 commands", "101 declared commands"],
    "references": ["72"],
    "specbench": ["4,180"],
    "oracle": ["5,152"],
    "claim_cards": ["45"],
    "evidence_cards": ["418"],
}


def run_supplement_alignment(root: Path) -> Dict[str, Any]:
    problems: List[str] = []
    main = (root / "paper/main.tex").read_text(encoding="utf-8") if (root / "paper/main.tex").exists() else ""
    supp = (root / "paper/supplement.tex").read_text(encoding="utf-8") if (root / "paper/supplement.tex").exists() else ""
    readme = (root / "artifact/README.md").read_text(encoding="utf-8") if (root / "artifact/README.md").exists() else ""
    repro = (root / "artifact/reproduction.md").read_text(encoding="utf-8") if (root / "artifact/reproduction.md").exists() else ""
    surfaces = {"main": main, "supplement": supp, "readme": readme, "reproduction": repro}
    for name, text in surfaces.items():
        if not text:
            problems.append(f"missing surface text: {name}")
            continue
        for key, variants in COUNTS.items():
            if not any(v in text for v in variants):
                problems.append(f"{name} missing current {key} count")
    # Guard common stale release counts on primary surfaces.
    stale_patterns = [r"99\s*/\s*99", r"99 materialized", r"89-command", r"A001--A087", r"A001-A087", r"0\.22\.0"]
    for name, text in surfaces.items():
        for pat in stale_patterns:
            if re.search(pat, text):
                problems.append(f"{name} contains stale pattern {pat}")
    return {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems[:100],
        "surfaces_checked": len(surfaces),
        "count_families_checked": len(COUNTS),
        "interpretation": "Checks that main paper, supplement, README, and reproduction text expose synchronized release counts.",
    }


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
