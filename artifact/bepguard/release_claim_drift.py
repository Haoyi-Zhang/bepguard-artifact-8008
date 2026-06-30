"""Release prose drift audit for evidence-facing counts."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

sys.dont_write_bytecode = True

CURRENT = {
    "validation_layers": "111",
    "reproduction_commands": "101",
    "amendment_range": "A001-A099",
    "specbench_cases": "4,180",
    "third_oracle_cases": "5,152",
    "counterfactual_roundtrips": "546",
    "oracle_equivalence_cases": "5,152",
    "rule_trace_obligations": "280",
}

STALE_PATTERNS = [
    r"42 materialized validation layers",
    r"52 / 52",
    r"57 / 57",
    r"57 materialized layers",
    r"61 / 61",
    r"61 materialized layers",
    r"65 materialized validation layers",
    r"65 materialized layers",
    r"65 validation",
    r"66 / 66",
    r"66 materialized validation layers",
    r"66 materialized layers",
    r"70 / 70",
    r"70 materialized validation layers",
    r"70 materialized layers",
    r"74 / 74",
    r"74 materialized validation layers",
    r"74 materialized layers",
    r"78 / 78",
    r"82 / 82",
    r"82 materialized validation layers",
    r"82 materialized layers",
    r"41-command reproduction ladder",
    r"46-command reproduction ladder",
    r"50-command reproduction ladder",
    r"50 commands / 0 problems",
    r"54-command reproduction ladder",
    r"54 declared commands",
    r"56-command reproduction ladder",
    r"60-command reproduction ladder",
    r"64-command reproduction ladder",
    r"72-command reproduction ladder",
    r"72 declared commands",
    r"A001-A047",
    r"A001-A051",
    r"A001-A055",
    r"A001-A056",
    r"A001-A060",
    r"A001-A064",
    r"A001-A069",
]
REQUIRED_PHRASES = {
    "artifact/README.md": ["111 materialized validation layers", "101-command reproduction ladder", "A001-A099", "4,180", "5,152", "claim trace-saturation", "repair compactness", "deterministic re-execution", "interaction coverage", "counterfactual round-trip", "oracle explanation-equivalence", "rule trace-matrix", "oracle triangulation", "static code-health", "repair-locality", "RQ traceability", "process-trace", "threat", "minimal-pair", "fold", "delivery capsule", "stale numeric", "ICSE criteria", "contribution trace", "reference role", "oracle structural", "deliverable trio", "paper rhetoric", "repository-entrypoint", "assessor scorecard"],
    "artifact/reproduction.md": ["A001-A099", "111 materialized layers", "101 declared commands", "4,180", "5,152", "claim trace-saturation", "repair compactness", "deterministic re-execution", "interaction coverage", "counterfactual round-trip", "oracle explanation-equivalence", "static code-health", "RQ traceability", "process-trace", "threat", "minimal-pair", "fold", "delivery capsule", "stale numeric", "ICSE criteria", "contribution trace", "reference role", "oracle structural", "deliverable trio", "paper rhetoric", "repository-entrypoint", "assessor scorecard"],
    "paper/main.tex": ["4,180", "5,152", "claim trace-saturation", "repair compactness", "deterministic re-execution", "interaction coverage", "counterfactual", "111 validation", "decision-table oracle", "declarative third oracle", "finite theorems", "release reproducibility", "threat closure", "minimal-pair", "fold stratification"],
    "paper/supplement.tex": ["111", "101", "claim trace", "repair-delta", "deterministic", "interaction", "counterfactual", "oracle", "rule trace", "pure decision-function", "repair", "process-trace", "threat", "minimal-pair", "fold", "stale numeric", "review-criteria", "contribution trace", "reference role", "oracle structural", "deliverable trio", "paper rhetoric", "repository-entrypoint", "release scorecard"],
}


def audit_release_claim_drift(root: Path) -> Dict[str, Any]:
    problems: List[str] = []
    files_checked = 0
    for rel, required in REQUIRED_PHRASES.items():
        path = root / rel
        if not path.exists():
            problems.append(f"missing release prose file: {rel}")
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        files_checked += 1
        lower = text.lower()
        for pattern in STALE_PATTERNS:
            if re.search(pattern, text, flags=re.IGNORECASE):
                problems.append(f"{rel}: stale count/pattern remains: {pattern}")
        for phrase in required:
            if phrase.lower() not in lower:
                problems.append(f"{rel}: missing required current phrase: {phrase}")
    return {
        "schema": "BEPGuardReleaseClaimDrift/v1",
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "files_checked": files_checked,
        "current_claims": CURRENT,
        "interpretation": "Release prose drift audit: evidence-facing prose must not contain stale validation-layer, amendment-range, or reproduction-ladder counts after a hardening round; required current claims must be visible in the paper and artifact-facing instructions.",
    }


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
