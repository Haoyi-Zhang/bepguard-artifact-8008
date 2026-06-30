"""ICSE review-criteria to evidence closure audit."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List

CRITERIA = {
    "novelty": ["policy intent drift", "BEP-IR", "proof-carrying", "minimal semantic conflict"],
    "rigor": ["finite theorem kernel", "mutation", "declarative third oracle", "proof-card"],
    "relevance": ["browser-enforced", "software-engineering", "framework", "CI"],
    "verifiability_transparency": ["reproduction ladder", "evidence cards", "source claim", "repair"],
    "presentation": ["Figure", "Table", "References", "Conclusion"],
}

EVIDENCE_FILES = {
    "novelty": ["artifact/results/threat_closure_audit.json", "artifact/results/deep_locked/source_claim_trace_audit.json"],
    "rigor": ["artifact/results/deep_locked/theory_kernel_audit.json", "artifact/results/deep_locked/mutation_farm_summary.json", "artifact/results/deep_locked/declarative_oracle_audit.json"],
    "relevance": ["artifact/results/paper_argument_surface_audit.json", "artifact/results/deep_locked/interaction_coverage_audit.json"],
    "verifiability_transparency": ["artifact/results/reproducibility_ladder_audit.json", "artifact/results/evidence_path_multiplicity_audit.json", "artifact/results/deterministic_reexecution_audit.json"],
    "presentation": ["artifact/results/pdf_reference_boundary_audit.json", "artifact/results/figure_layout_audit.json", "artifact/results/reference_integrity_audit.json"],
}


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def run_icse_criteria_closure(root: Path) -> Dict[str, Any]:
    problems: List[str] = []
    tex = (root / "paper/main.tex").read_text(encoding="utf-8")
    lower = tex.lower()
    rows: List[Dict[str, Any]] = []
    for criterion, tokens in CRITERIA.items():
        missing = [t for t in tokens if t.lower() not in lower]
        passing_files = []
        for rel in EVIDENCE_FILES[criterion]:
            p = root / rel
            if not p.exists():
                problems.append(f"{criterion}: missing evidence file {rel}")
                continue
            obj = _load_json(p)
            if obj.get("status") == "fail" or int(obj.get("problem_count") or 0) != 0:
                problems.append(f"{criterion}: evidence file not passing {rel}")
            passing_files.append(rel)
        if missing:
            problems.append(f"{criterion}: paper missing criteria tokens {missing}")
        rows.append({"criterion": criterion, "paper_tokens": len(tokens)-len(missing), "evidence_files": len(passing_files), "missing_tokens": missing})
    return {"status": "pass" if not problems else "fail", "problem_count": len(problems), "problems": problems[:100], "criteria_checked": len(CRITERIA), "evidence_bindings": sum(len(v) for v in EVIDENCE_FILES.values()), "rows": rows, "interpretation": "Maps ICSE review criteria to assessor-visible paper language and materialized passing evidence channels."}


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True)+"\n", encoding="utf-8")
