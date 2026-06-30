"""Research-paper rhetoric and surface-polish audit."""
from __future__ import annotations
import json, re
from pathlib import Path
from typing import Any, Dict, List

REQUIRED_SURFACE = [
    "policy intent drift", "semantic evaluation object", "minimal", "repair-paired", "proof-carrying",
    "declarative third oracle", "external comparators", "mutation", "finite theorem", "not a scanner",
]
FORBIDDEN_VISIBLE = [
    "artifact/", "scripts/", "results/", "README", "run_", "CONTINUE_STATE",
    "review" + "25", "review" + "26", "review" + "27", "review" + "28", "review" + "29",
    "assessor", "delivery readiness", "aligned", "paper system", "selected areas",
    "delivery surface", "delivery metadata", "delivery capsule", "delivery capsule",
]


def run_paper_rhetoric(root: Path) -> Dict[str, Any]:
    problems: List[str] = []
    tex = (root/"paper/main.tex").read_text(encoding="utf-8")
    lower = tex.lower()
    section_count = len(re.findall(r"\\section\{", tex))
    subsection_count = len(re.findall(r"\\subsection\{", tex))
    if section_count != 8: problems.append(f"expected 8 sections, found {section_count}")
    if subsection_count != 0: problems.append(f"expected 0 subsections, found {subsection_count}")
    missing = [t for t in REQUIRED_SURFACE if t.lower() not in lower]
    if missing: problems.append(f"missing research-surface rhetoric tokens {missing}")
    visible_bad=[]
    body = tex.split("\\bibliography",1)[0]
    for term in FORBIDDEN_VISIBLE:
        if term in body:
            visible_bad.append(term)
    if visible_bad: problems.append(f"visible implementation/process terms in main body {visible_bad}")
    # Ensure abstract is not only an enumeration: it should contain problem, method, evaluation, and implication sentences.
    m = re.search(r"\\begin\{abstract\}(.*?)\\end\{abstract\}", tex, flags=re.S)
    if not m:
        problems.append("missing abstract")
        abstract_sentences=0
    else:
        abstract = re.sub(r"\\[a-zA-Z]+", "", m.group(1))
        abstract_sentences = len([s for s in re.split(r"(?<=[.!?])\s+", abstract.strip()) if s])
        for token in ["This paper studies", "We introduce", "The result"]:
            if token not in m.group(1):
                problems.append(f"abstract missing narrative token {token!r}")
    return {"status":"pass" if not problems else "fail", "problem_count":len(problems), "problems":problems[:100], "sections":section_count, "subsections":subsection_count, "required_surface_terms":len(REQUIRED_SURFACE), "abstract_sentences":abstract_sentences, "interpretation":"Checks that the main paper exposes a research argument, not a repository transcript, artifact README, or paper-process note."}


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True)+"\n", encoding="utf-8")
