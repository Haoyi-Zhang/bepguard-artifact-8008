"""Repair compactness and non-arbitrary counterfactual audit.

Repair-delta replay proves that paired repairs clear the target issue.  This
module adds a structural check: repairs must preserve source, intent, and policy
family while changing only a compact set of semantic units (headers, layers, or
context fields).  It guards against the degenerate repair strategy of replacing
a positive fixture with an unrelated clean fixture.
"""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

sys.dont_write_bytecode = True


def _import_semantics(root: Path):
    scripts = root / "artifact" / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import bep_semantics  # type: ignore
    return bep_semantics


def _issues(sem: Any, fixture: Dict[str, Any]) -> Tuple[str, ...]:
    return tuple(sorted(str(f.issue) for f in sem.analyze_fixture(fixture)))


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _semantic_units(fixture: Dict[str, Any]) -> Counter[Tuple[str, ...]]:
    units: Counter[Tuple[str, ...]] = Counter()
    for header in fixture.get("headers", []) or []:
        if isinstance(header, dict):
            units[("header", str(header.get("name", "")).lower(), str(header.get("value", "")))] += 1
    for index, layer in enumerate(fixture.get("layers", []) or []):
        if not isinstance(layer, dict):
            continue
        for header in layer.get("headers", []) or []:
            if isinstance(header, dict):
                units[("layer", str(index), str(layer.get("op", "")), str(layer.get("layer", "")), str(header.get("name", "")).lower(), str(header.get("value", "")))] += 1
    for key, value in sorted((fixture.get("context") or {}).items()):
        units[("context", str(key), str(value))] += 1
    for key, value in sorted((fixture.get("intent") or {}).items()):
        units[("intent", str(key), str(value))] += 1
    return units


def _edit_distance(left: Dict[str, Any], right: Dict[str, Any]) -> int:
    a = _semantic_units(left)
    b = _semantic_units(right)
    return sum((a - b).values()) + sum((b - a).values())


def run_repair_compactness_audit(root: Path) -> Tuple[List[Dict[str, str]], Dict[str, Any]]:
    sem = _import_semantics(root)
    fixtures = _load_json(root / "artifact/data/deep_locked_fixtures.json")
    repairs = _load_json(root / "artifact/data/paired_repair_controls.json")
    by_id = {str(f.get("id", "")): f for f in fixtures}
    rows: List[Dict[str, str]] = []
    problems: List[str] = []
    distances: Counter[int] = Counter()
    for repair in repairs:
        pid = str(repair.get("paired_positive_fixture_id", ""))
        positive = by_id.get(pid)
        rid = str(repair.get("id", ""))
        if positive is None:
            problems.append(f"{rid}:missing paired positive {pid}")
            continue
        target = str(repair.get("paired_target_issue", positive.get("expected_issue", "")))
        positive_issues = _issues(sem, positive)
        repair_issues = _issues(sem, repair)
        dist = _edit_distance(positive, repair)
        distances[dist] += 1
        same_claims = sorted(str(x) for x in positive.get("source_claim_ids", [])) == sorted(str(x) for x in repair.get("source_claim_ids", []))
        same_intent = positive.get("intent") == repair.get("intent")
        same_family = str(positive.get("policy_family", "")) == str(repair.get("policy_family", ""))
        status = "pass"
        if target not in positive_issues:
            problems.append(f"{pid}:target {target} absent from positive issues {positive_issues}"); status = "fail"
        if repair_issues:
            problems.append(f"{rid}:repair still has issues {repair_issues}"); status = "fail"
        if not (same_claims and same_intent and same_family):
            problems.append(f"{rid}:source/intent/family not preserved"); status = "fail"
        if not (1 <= dist <= 4):
            problems.append(f"{rid}:semantic edit distance {dist} outside compact range 1..4"); status = "fail"
        rows.append({
            "positive_fixture_id": pid,
            "repair_fixture_id": rid,
            "target_issue": target,
            "semantic_edit_distance": str(dist),
            "positive_issues": ";".join(positive_issues) or "none",
            "repair_issues": ";".join(repair_issues) or "none",
            "same_source_claims": str(same_claims).lower(),
            "same_intent": str(same_intent).lower(),
            "same_policy_family": str(same_family).lower(),
            "status": status,
        })
    summary = {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems[:50],
        "repair_pairs_checked": len(repairs),
        "compact_repairs": sum(1 for r in rows if r["status"] == "pass"),
        "min_semantic_edit_distance": min(distances) if distances else None,
        "max_semantic_edit_distance": max(distances) if distances else None,
        "edit_distance_histogram": {str(k): v for k, v in sorted(distances.items())},
        "interpretation": "Every paired repair preserves source, intent, and policy family; clears the modeled issue; and differs from the positive by a compact semantic edit distance of 1..4 units.",
    }
    return rows, summary


def write_csv(path: Path, rows: List[Dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["positive_fixture_id", "repair_fixture_id", "target_issue", "semantic_edit_distance", "positive_issues", "repair_issues", "same_source_claims", "same_intent", "same_policy_family", "status"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader(); writer.writerows(rows)


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
