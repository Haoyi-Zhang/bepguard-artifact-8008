"""Strict assessor scorecard over paper, supplement, and artifact readiness."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List

SCORE_COMPONENTS = [
    ("novelty", 20, "artifact/results/icse_criteria_closure_audit.json"),
    ("rigor", 20, "artifact/results/threat_closure_audit.json"),
    ("reproducibility", 20, "artifact/results/deliverable_trio_readiness_audit.json"),
    ("anti_overfit", 15, "artifact/results/deep_locked/benchmark_fingerprint_disjointness_audit.json"),
    ("paper_surface", 15, "artifact/results/paper_rhetoric_audit.json"),
    ("reference_integrity", 10, "artifact/results/reference_role_balance_audit.json"),
]


def run_scorecard(root: Path) -> Dict[str, Any]:
    problems: List[str] = []
    rows=[]; total=0; earned=0
    for name, points, rel in SCORE_COMPONENTS:
        total += points
        p = root/rel
        if not p.exists():
            problems.append(f"missing score component {rel}")
            status="missing"; got=0
        else:
            obj=json.loads(p.read_text(encoding="utf-8"))
            ok = obj.get("status") != "fail" and int(obj.get("problem_count") or 0) == 0
            status="pass" if ok else "fail"; got=points if ok else 0
            if not ok: problems.append(f"score component failing {rel}")
        earned += got
        rows.append({"component":name, "points":points, "earned":got, "evidence":rel, "status":status})
    score = round(100.0 * earned / total, 1) if total else 0.0
    return {"status":"pass" if not problems and score >= 95.0 else "fail", "problem_count":len(problems), "problems":problems[:100], "strict_assessment_score":score, "points_earned":earned, "points_total":total, "rows":rows, "interpretation":"A conservative scorecard summarizing paper novelty/rigor/relevance, artifact reproducibility, anti-overfit evidence, paper surface, and reference integrity. It is not a claim of acceptance; it is a self-assessment gate."}


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True)+"\n", encoding="utf-8")
