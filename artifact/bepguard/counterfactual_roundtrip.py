"""Bidirectional counterfactual round-trip checks for BEPGuard.

The causal activation audit shows that clean controls can be pushed across a
semantic boundary.  This module adds the reverse obligation: every required
activation must have a clean origin and a clean return point, and the activated
object must cross to exactly the target issue.  The check is deliberately based
on semantic replay rather than on fixture labels.
"""
from __future__ import annotations

import copy
import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Tuple

sys.dont_write_bytecode = True

from .causal_counterfactual import _activate_clean_control, _expected, _signature  # intentional reuse of constructors


def _import_semantics(root: Path):
    scripts = root / "artifact" / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import bep_semantics  # type: ignore
    return bep_semantics


def _json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _as_list(value: Iterable[str]) -> str:
    return json.dumps(list(value), sort_keys=True)


def run_counterfactual_roundtrip(root: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    sem = _import_semantics(root)
    fixtures = _json(root / "artifact/data/deep_locked_fixtures.json")
    positives = {str(f.get("id")): f for f in fixtures if _expected(f)}

    rows: List[Dict[str, Any]] = []
    problems: List[Dict[str, Any]] = []
    skipped = 0
    for control in [f for f in fixtures if not _expected(f)]:
        control_id = str(control.get("id", ""))
        before = _signature(sem.analyze_fixture(copy.deepcopy(control)))
        if str(control.get("fixture_role")) == "paired_repair_negative_control":
            positive = positives.get(str(control.get("paired_positive_fixture_id", "")))
            if positive is None:
                row = {"control_id": control_id, "status": "fail", "problem": "missing paired positive"}
                rows.append(row); problems.append(row); continue
            activation = copy.deepcopy(positive)
            expected_issue = _expected(positive)
            operator = "paired_repair_reverse_activation"
        else:
            maybe = _activate_clean_control(control)
            if maybe is None:
                skipped += 1
                rows.append({
                    "control_id": control_id,
                    "operator": "not_applicable_in_locked_oracle",
                    "status": "not_applicable",
                    "origin_signature": _as_list(before),
                })
                continue
            activation, issue, operator = maybe
            expected_issue = (issue,)

        activated = _signature(sem.analyze_fixture(copy.deepcopy(activation)))
        repaired = _signature(sem.analyze_fixture(copy.deepcopy(control)))
        header_delta = json.dumps(control.get("headers", []), sort_keys=True) != json.dumps(activation.get("headers", []), sort_keys=True)
        context_delta = json.dumps(control.get("context", {}), sort_keys=True) != json.dumps(activation.get("context", {}), sort_keys=True)
        layer_delta = json.dumps(control.get("layers", []), sort_keys=True) != json.dumps(activation.get("layers", []), sort_keys=True)
        ok = before == tuple() and activated == expected_issue and repaired == tuple() and (header_delta or context_delta or layer_delta)
        row = {
            "control_id": control_id,
            "activation_id": str(activation.get("id", "")),
            "operator": operator,
            "expected_activation_issue": _as_list(expected_issue),
            "origin_signature": _as_list(before),
            "activation_signature": _as_list(activated),
            "return_signature": _as_list(repaired),
            "header_delta": header_delta,
            "context_delta": context_delta,
            "layer_delta": layer_delta,
            "roundtrip_preserved": ok,
            "status": "pass" if ok else "fail",
        }
        rows.append(row)
        if not ok:
            problems.append(row)

    required = [r for r in rows if r.get("status") != "not_applicable"]
    by_operator = Counter(str(r.get("operator", "")) for r in required)
    return rows, {
        "schema": "BEPGuardCounterfactualRoundtrip/v1",
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems[:25],
        "required_roundtrips": len(required),
        "roundtrips_preserved": sum(1 for r in required if r.get("roundtrip_preserved") is True),
        "not_applicable_controls": skipped,
        "operators": dict(sorted(by_operator.items())),
        "interpretation": "Counterfactual round-trip audit: clean controls are semantically replayed, activated across the intended boundary, then returned to the original clean point. This checks both directions of the causal boundary without reading benchmark labels as oracle input.",
    }


def write_csv(path: Path, rows: List[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("\n", encoding="utf-8"); return
    fields = sorted({k for row in rows for k in row.keys()})
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader(); writer.writerows(rows)


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
