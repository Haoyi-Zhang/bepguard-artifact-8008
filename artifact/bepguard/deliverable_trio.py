"""release paper delivery trio readiness audit: main PDF, supplement PDF, artifact link source."""
from __future__ import annotations
import json, subprocess
from pathlib import Path
from typing import Any, Dict, List

REQUIRED_ARTIFACT_FILES = [
    "artifact/README.md", "artifact/reproduction.md", "artifact/pyproject.toml", "artifact/environment_lock.json",
    "artifact/results/validation_summary.json", "artifact/results/reproducibility_ladder_audit.json",
    "artifact/results/result_index.csv", "artifact/checksum_manifest.csv",
]


def _pages(path: Path) -> int:
    out = subprocess.check_output(["pdfinfo", str(path)], text=True, stderr=subprocess.STDOUT)
    for line in out.splitlines():
        if line.startswith("Pages:"):
            return int(line.split(":",1)[1].strip())
    raise RuntimeError(f"no page count from pdfinfo for {path}")


def run_deliverable_trio_readiness(root: Path) -> Dict[str, Any]:
    problems: List[str] = []
    main = root/"paper/main.pdf"; supp = root/"paper/supplement.pdf"
    if not main.exists(): problems.append("missing paper/main.pdf")
    if not supp.exists(): problems.append("missing paper/supplement.pdf")
    main_pages = _pages(main) if main.exists() else 0
    supp_pages = _pages(supp) if supp.exists() else 0
    if main_pages != 12: problems.append(f"main.pdf pages {main_pages}, expected 12")
    if supp_pages != 8: problems.append(f"supplement.pdf pages {supp_pages}, expected 8")
    missing = [p for p in REQUIRED_ARTIFACT_FILES if not (root/p).exists()]
    problems += [f"missing artifact link-source file {p}" for p in missing]
    top = sorted(p.name for p in root.iterdir() if p.name != '.DS_Store')
    if top != ["artifact", "paper"]:
        problems.append(f"top-level deliverable entries {top}")
    for rel in ["artifact/results/clean_package_check.json", "artifact/results/anonymity_audit.json"]:
        p=root/rel
        if p.exists():
            obj=json.loads(p.read_text(encoding="utf-8"))
            if obj.get("status") == "fail" or int(obj.get("problem_count") or 0) != 0:
                problems.append(f"{rel} not passing")
    validation_summary = root / "artifact/results/validation_summary.json"
    if validation_summary.exists():
        try:
            obj = json.loads(validation_summary.read_text(encoding="utf-8"))
            if len(obj.get("validation_layers_checked", [])) != 111:
                problems.append("validation_summary.json does not expose 111 validation layers")
        except Exception as exc:
            problems.append(f"validation_summary.json is not readable JSON: {exc}")
    return {"status":"pass" if not problems else "fail", "problem_count":len(problems), "problems":problems[:100], "main_pages":main_pages, "supplement_pages":supp_pages, "artifact_link_source_files":len(REQUIRED_ARTIFACT_FILES)-len(missing), "top_level_entries":top, "interpretation":"Checks that the three evidence-facing deliverables are ready: main paper, supplement, and the artifact tree to be uploaded as the repository link."}


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True)+"\n", encoding="utf-8")
