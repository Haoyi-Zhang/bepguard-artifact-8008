"""paper metadata and abstract-registration alignment audit."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List

REQUIRED_TOPICS = [
    "Dependability and Security::Design for dependability and security",
    "Dependability and Security::Formal methods and model checking (excluding solutions focusing solely on hardware)",
    "Dependability and Security::Confidentiality, integrity, privacy, and fairness",
    "Dependability and Security::Vulnerability detection to enhance software security",
]
REQUIRED_TERMS = [
    "BEPGuard",
    "policy intent drift",
    "browser-enforced security policy",
    "proof-carrying",
    "repair",
    "decision-table",
    "finite",
    "mutation",
    "public-package comparator",
    "anonymous deterministic artifact",
]
FORBIDDEN = ["submitted to ICSE", "/mnt/"]


def _paper_title(main_tex: str) -> str:
    m = re.search(r"\\title\{([^}]*)\}", main_tex, flags=re.DOTALL)
    return re.sub(r"\s+", " ", m.group(1)).strip() if m else ""


def _paper_abstract(main_tex: str) -> str:
    m = re.search(r"\\begin\{abstract\}(.*?)\\end\{abstract\}", main_tex, flags=re.DOTALL)
    return re.sub(r"\s+", " ", m.group(1)).strip() if m else ""


def run_paper_metadata_alignment(root: Path) -> Dict[str, Any]:
    problems: List[str] = []
    meta_path = root / "artifact/paper_metadata.json"
    main_path = root / "paper/main.tex"
    if not meta_path.exists():
        problems.append("missing paper metadata capsule")
        meta: Dict[str, Any] = {}
    else:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    if not main_path.exists():
        problems.append("missing main paper source")
        main_text = ""
    else:
        main_text = main_path.read_text(encoding="utf-8")
    title = _paper_title(main_text)
    abstract = _paper_abstract(main_text)
    if title != meta.get("title"):
        problems.append("paper title does not match paper metadata title")
    topics = set(meta.get("selected_topics", []))
    for topic in REQUIRED_TOPICS:
        if topic not in topics:
            problems.append(f"missing high-priority selected topic: {topic}")
    if meta.get("primary_area") != "Dependability and Security":
        problems.append("primary area should be Dependability and Security")
    if meta.get("additional_area") != "Testing and Analysis":
        problems.append("additional area should be Testing and Analysis")
    combined = (meta.get("abstract", "") + "\n" + abstract).lower()
    missing_terms = [term for term in REQUIRED_TERMS if term.lower() not in combined]
    problems.extend(f"missing abstract-registration term: {term}" for term in missing_terms)
    leak_text = json.dumps(meta, sort_keys=True) + "\n" + main_text
    for bad in FORBIDDEN:
        if bad.lower() in leak_text.lower():
            problems.append(f"forbidden paper metadata/process token present: {bad}")
    return {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "title_checked": bool(title),
        "topics_checked": len(topics),
        "required_topics_checked": len(REQUIRED_TOPICS),
        "required_terms_checked": len(REQUIRED_TERMS),
        "primary_area": meta.get("primary_area"),
        "additional_area": meta.get("additional_area"),
        "interpretation": "Checks that the aligned title/abstract/topic capsule is aligned with the main paper and remains anonymous.",
    }


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
