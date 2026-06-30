"""LaTeX figure/table/algorithm reference-closure audit."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Set

SOURCE_GLOBS = ["paper/main.tex", "paper/sections/*.tex", "paper/tables/*.tex", "paper/figures/*.tex"]


def _read_all(root: Path) -> str:
    parts: List[str] = []
    for pattern in SOURCE_GLOBS:
        for path in sorted(root.glob(pattern)):
            if path.name == "IEEEtran.cls":
                continue
            parts.append(path.read_text(encoding="utf-8"))
    return "\n".join(parts)


def run_figure_reference_closure(root: Path) -> Dict[str, Any]:
    text = _read_all(root)
    labels: Set[str] = set(re.findall(r"\\label\{([^}]+)\}", text))
    refs: Set[str] = set(re.findall(r"\\(?:ref|pageref|autoref)\{([^}]+)\}", text))
    tracked = {x for x in labels if x.startswith(("fig:", "tab:", "alg:"))}
    unreferenced = sorted(tracked - refs)
    missing = sorted(refs - labels)
    raster_refs = re.findall(r"\\includegraphics(?:\[[^]]*\])?\{([^}]+)\}", text)
    raster_release = [r for r in raster_refs if r.lower().endswith((".png", ".jpg", ".jpeg", ".pdf"))]
    problems = []
    if unreferenced:
        problems.append("unreferenced labels: " + ", ".join(unreferenced))
    if missing:
        problems.append("references without labels: " + ", ".join(missing))
    if raster_release:
        problems.append("raster/vector includegraphics used in release figure path: " + ", ".join(raster_release))
    captions = re.findall(r"\\caption\{", text)
    return {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "tracked_labels": len(tracked),
        "references_checked": len(refs),
        "captions_checked": len(captions),
        "latex_native_includegraphics": len(raster_refs) == 0,
        "interpretation": "Checks that every release paper figure/table/algorithm label is referenced, all refs resolve, and release figures remain LaTeX-native.",
    }


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
