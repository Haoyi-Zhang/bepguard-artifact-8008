"""Policy-interaction coverage audit.

This audit makes the workload's family/interaction shape explicit.  It is not a
new empirical denominator; it is a evidence-facing map showing which policy
families and multi-policy header signatures are exercised by BEP-Deep and
source-derived boundary workloads.
"""
from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set, Tuple

HEADER_FAMILIES = {
    "CSP": {"content-security-policy", "content-security-policy-report-only"},
    "CORS": {"access-control-allow-origin", "access-control-allow-credentials", "vary"},
    "HSTS": {"strict-transport-security"},
    "COOP": {"cross-origin-opener-policy"},
    "COEP": {"cross-origin-embedder-policy"},
    "CORP": {"cross-origin-resource-policy"},
    "Permissions-Policy": {"permissions-policy"},
    "XFO": {"x-frame-options"},
    "Content-Type": {"content-type", "x-content-type-options"},
}


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _headers(fx: Dict[str, Any]) -> List[Dict[str, Any]]:
    headers = list(fx.get("headers", []) or [])
    for layer in fx.get("layers", []) or []:
        if isinstance(layer, dict):
            headers.extend(layer.get("headers", []) or [])
    return [h for h in headers if isinstance(h, dict)]


def _signature(fx: Dict[str, Any]) -> str:
    out: Set[str] = set()
    for h in _headers(fx):
        name = str(h.get("name", "")).lower()
        for family, names in HEADER_FAMILIES.items():
            if name in names:
                out.add(family)
    if not out:
        family = str(fx.get("policy_family", "")).strip()
        out.add(family or "no-header")
    return "+".join(sorted(out))


def run_interaction_coverage_audit(root: Path) -> Tuple[List[Dict[str, str]], Dict[str, Any]]:
    fixtures = _load_json(root / "artifact/data/deep_locked_fixtures.json")
    spec_cases = _load_json(root / "artifact/results/deep_locked/specbench_cases.json")
    rows: List[Dict[str, str]] = []
    by_signature: Dict[str, Counter[str]] = defaultdict(Counter)
    strata = Counter()
    for fx in fixtures:
        sig = _signature(fx)
        role = str(fx.get("fixture_role", ""))
        by_signature[sig][role] += 1
        strata[str(fx.get("policy_family", ""))] += 1
    spec_by_signature: Counter[str] = Counter()
    for case in spec_cases:
        fx = case.get("fixture", {}) if isinstance(case, dict) else {}
        spec_by_signature[_signature(fx)] += 1
    for sig, counter in sorted(by_signature.items()):
        rows.append({
            "signature": sig,
            "deep_positive": str(counter.get("positive", 0)),
            "deep_negative_control": str(counter.get("negative_control", 0)),
            "deep_paired_repair": str(counter.get("paired_repair_negative_control", 0)),
            "specbench_cases": str(spec_by_signature.get(sig, 0)),
            "is_multi_policy": str("+" in sig).lower(),
        })
    multi = [r for r in rows if r["is_multi_policy"] == "true"]
    problems: List[str] = []
    if len(strata) < 16:
        problems.append(f"expected at least 16 policy strata, observed {len(strata)}")
    if len(rows) < 12:
        problems.append(f"expected at least 12 policy signatures, observed {len(rows)}")
    if len(multi) < 5:
        problems.append(f"expected at least 5 multi-policy signatures, observed {len(multi)}")
    if len(fixtures) != 972:
        problems.append(f"unexpected fixture count {len(fixtures)}")
    summary = {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems[:50],
        "locked_fixtures_checked": len(fixtures),
        "policy_family_strata": len(strata),
        "policy_signatures": len(rows),
        "multi_policy_signatures": len(multi),
        "specbench_cases_considered": len(spec_cases),
        "strata_histogram": dict(sorted(strata.items())),
        "interpretation": "The audit exposes workload breadth across policy-family strata and multi-policy header signatures so assessors can see cross-policy coverage rather than only aggregate fixture counts.",
    }
    return rows, summary


def write_csv(path: Path, rows: List[Dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["signature", "deep_positive", "deep_negative_control", "deep_paired_repair", "specbench_cases", "is_multi_policy"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader(); writer.writerows(rows)


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
