"""Paper-visible numerical claim consistency audits."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

sys.dont_write_bytecode = True


def _load(root: Path, rel: str):
    return json.loads((root / rel).read_text(encoding="utf-8"))


def _int(pattern: str, text: str) -> int | None:
    m = re.search(pattern, text)
    if not m:
        return None
    return int(m.group(1).replace(",", ""))


def audit_paper_claims(root: Path) -> Dict[str, Any]:
    main = (root / "paper" / "main.tex").read_text(encoding="utf-8")
    denom = _load(root, "artifact/results/denominator_lock_summary.json")
    mutation = _load(root, "artifact/results/deep_locked/mutation_farm_summary.json")
    theory = _load(root, "artifact/results/deep_locked/theory_kernel_audit.json")
    specbench = _load(root, "artifact/results/deep_locked/specbench_summary.json")
    shadow = _load(root, "artifact/results/deep_locked/shadow_generalization_audit.json")
    scale = _load(root, "artifact/results/deep_locked/scale_stress_audit.json")
    release_script = (root / "artifact/scripts/run_validation.py").read_text(encoding="utf-8")
    m_layers = re.search(r'[\"\']validation_layers[\"\']\s*:\s*(\d+)', release_script)
    counts = {
        "fixtures": denom.get("locked_fixtures_total"),
        "positives": denom.get("expected_positive_fixtures"),
        "negative_controls": denom.get("negative_control_fixtures"),
        "mutation_farm_mutants": mutation.get("mutants"),
        "theory_kernel_states": theory.get("finite_states_checked"),
        "specbench_cases": specbench.get("cases"),
        "shadow_required_cases": shadow.get("required_shadow_cases"),
        "scale_stress_cases": scale.get("stress_cases"),
        "validation_layers": int(m_layers.group(1)) if m_layers else None,
    }
    checks: List[Dict[str, Any]] = []
    problems: List[str] = []

    expectations = {
        "BEP-Deep fixtures": (r"(\d[\d,]*)\s+BEP-Deep fixtures", counts.get("fixtures")),
        "expected positives": (r"(\d[\d,]*)\s+expected-positive conflicts", counts.get("positives")),
        "negative controls": (r"(\d[\d,]*)\s+negative controls", counts.get("negative_controls")),
        "mutation farm": (r"(?:a\s+)?(\d[\d,]*)\s*(?:/\s*\d[\d,]*)?\s+obligation-(?:level\s+)?mutants?", counts.get("mutation_farm_mutants")),
        "theory states": (r"over\s+(\d[\d,]*)\s+states", counts.get("theory_kernel_states")),
        "specbench cases": (r"BEP-SpecBench contains\s+(\d[\d,]*)\s+source-derived", counts.get("specbench_cases")),
        "shadow cases": (r"BEP-Shadow[^\n]*?(\d[\d,]*)\s+required", counts.get("shadow_required_cases")),
        "scale cases": (r"BEP-Scale[^\n]*?(\d[\d,]*)\s+deterministic", counts.get("scale_stress_cases")),
        "validation layers": (r"release validation layers\s*&\s*(\d[\d,]*)\s*/", counts.get("validation_layers")),
    }
    for name, (pattern, expected) in expectations.items():
        observed = _int(pattern, main)
        ok = observed == expected
        checks.append({"claim": name, "observed": observed, "expected": expected, "ok": ok})
        if not ok:
            problems.append(f"{name}: observed {observed}, expected {expected}")

    forbidden = [
        "deployed-site vulnerability rate",
        "human inter-rater",
        "exploitability proved",
        "complete browser conformance",
    ]
    lower = main.lower()
    for phrase in forbidden:
        if phrase in lower:
            problems.append(f"forbidden overclaim phrase appears: {phrase}")
    for m in re.finditer(r"live-web prevalence", lower):
        window = lower[max(0, m.start()-40):m.end()+40]
        if "not" not in window and "without" not in window and "rather than" not in window:
            problems.append("unqualified live-web prevalence wording appears")

    return {
        "schema": "BEPGuardPaperClaimConsistency/v1",
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "claims_checked": len(checks),
        "checks": checks,
        "interpretation": "Audits that paper-visible headline numerical claims match the materialized release-validation counts and that selected forbidden overclaim phrases are absent.",
    }


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
