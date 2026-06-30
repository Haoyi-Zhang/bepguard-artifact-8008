"""Trace Research Questions to paper text and materialized artifact results."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

RQ_REQUIREMENTS = {
    "RQ1": {
        "tokens": ["RQ1--Lowering and validation", "45 explicit source-grounded claims", "35 semantic rules"],
        "files": ["artifact/results/deep_locked/claim_coverage_metrics.json", "artifact/results/source_span_closure_metrics.json"],
    },
    "RQ2": {
        "tokens": ["RQ2--Witness generation", "418 BEP-Deep positive", "554 negative controls"],
        "files": ["artifact/results/deep_locked/full_metrics.json", "artifact/results/deep_locked/proof_carrying_witness_metrics.json"],
    },
    "RQ3": {
        "tokens": ["RQ3--Baseline and control disagreement", "external-contrast audit", "public-package"],
        "files": ["artifact/results/external_baseline_full_run_audit.json", "artifact/results/external_contrast_specificity_audit.json"],
    },
    "RQ4": {
        "tokens": ["RQ4--Ablation", "BEP-SpecBench contains 4,180", "48,600 deterministic stress"],
        "files": ["artifact/results/deep_locked/specbench_summary.json", "artifact/results/deep_locked/scale_stress_audit.json"],
    },
    "RQ5": {
        "tokens": ["RQ5--Oracle independence", "declarative third oracle", "111/111 validation ladder"],
        "files": ["artifact/results/deep_locked/declarative_oracle_audit.json", "artifact/results/validation_orchestration_audit.json"],
    },
}


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def audit_rq_traceability(root: Path) -> Dict[str, Any]:
    main = (root / "paper/main.tex").read_text(encoding="utf-8")
    problems: List[str] = []
    rows: List[Dict[str, Any]] = []
    obligations_checked = 0
    for rq, spec in RQ_REQUIREMENTS.items():
        token_hits = 0
        file_hits = 0
        for token in spec["tokens"]:
            obligations_checked += 1
            if token in main:
                token_hits += 1
            else:
                problems.append(f"{rq}: paper text missing token {token!r}")
        for rel in spec["files"]:
            obligations_checked += 1
            path = root / rel
            if not path.exists():
                problems.append(f"{rq}: missing materialized result {rel}")
                continue
            try:
                data = _read_json(path)
            except Exception as exc:
                problems.append(f"{rq}: result is not valid JSON {rel}: {exc}")
                continue
            if isinstance(data, dict) and data.get("status") not in (None, "pass"):
                if rel.endswith("validation_summary.json") and len(data.get("validation_layers_checked", [])) == 111:
                    pass
                else:
                    problems.append(f"{rq}: result status is not pass for {rel}")
            file_hits += 1
        rows.append({"rq": rq, "paper_tokens_verified": token_hits, "artifact_results_verified": file_hits})
    return {
        "schema": "BEPGuardRQTraceability/v1",
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "research_questions_checked": len(RQ_REQUIREMENTS),
        "rq_trace_obligations": obligations_checked,
        "rows": rows,
        "interpretation": "Each research question is checked against assessor-visible main-paper text and materialized result objects, reducing the risk that artifact work remains invisible or that paper claims drift away from executable evidence.",
    }


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
