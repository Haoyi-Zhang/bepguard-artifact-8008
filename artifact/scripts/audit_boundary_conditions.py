#!/usr/bin/env python3
"""Audit explicit non-denominator boundary cases."""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from common_paths import package_root

MIN_BOUNDARY_CASES = 49
MIN_FAMILIES = 6
LOCKED_DENOMINATOR = 972
ALLOWED_ACTIONS = {"manual_review", "unsupported_scope", "invalid_input", "not_evaluated"}


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run(root: Path) -> dict[str, Any]:
    problems: list[str] = []
    rows = load_csv(root / "artifact/data/boundary_conditions.csv")
    fixtures = json.loads((root / "artifact/data/deep_locked_fixtures.json").read_text(encoding="utf-8"))
    fixture_ids = {str(f.get("id", "")) for f in fixtures}
    case_ids = [r.get("case_id", "") for r in rows]
    families = {r.get("boundary_family", "") for r in rows}
    actions = {r.get("expected_action", "") for r in rows}
    overlaps = sorted(set(case_ids) & fixture_ids)

    if len(rows) < MIN_BOUNDARY_CASES:
        problems.append(f"too few boundary cases: {len(rows)} < {MIN_BOUNDARY_CASES}")
    if len(families) < MIN_FAMILIES:
        problems.append(f"too few boundary families: {len(families)} < {MIN_FAMILIES}")
    if len(case_ids) != len(set(case_ids)):
        problems.append("duplicate boundary case ids")
    if overlaps:
        problems.append(f"boundary cases overlap locked denominator fixtures: {overlaps[:10]}")
    if actions - ALLOWED_ACTIONS:
        problems.append(f"unexpected boundary actions: {sorted(actions - ALLOWED_ACTIONS)}")
    bad_roles = [r.get("case_id", "") for r in rows if r.get("denominator_role") != "out_of_scope"]
    if bad_roles:
        problems.append(f"boundary cases are not marked out_of_scope: {bad_roles[:10]}")
    scored = [r.get("case_id", "") for r in rows if r.get("expected_action") in {"pass", "fail"}]
    if scored:
        problems.append(f"boundary cases must not be pass/fail score rows: {scored[:10]}")

    return {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "boundary_cases": len(rows),
        "boundary_case_ratio_to_locked_denominator": round(len(rows) / LOCKED_DENOMINATOR, 4),
        "boundary_families": sorted(families),
        "allowed_actions": sorted(ALLOWED_ACTIONS),
        "locked_denominator_fixture_overlap": len(overlaps),
        "interpretation": (
            "Explicit non-denominator boundary catalog. These cases are not hidden "
            "failures or additional positives/negatives; they document unsupported, "
            "ambiguous, malformed, runtime-dependent, or browser-divergent surfaces "
            "that BEPGuard should report as manual-review or out-of-scope."
        ),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=None)
    ap.add_argument("--out", default="artifact/results/boundary_conditions_audit.json")
    args = ap.parse_args()
    root = Path(args.root).resolve() if args.root else package_root(__file__)
    result = run(root)
    write_json(root / args.out, result)
    print(json.dumps({k: result[k] for k in ["status", "problem_count", "boundary_cases", "boundary_case_ratio_to_locked_denominator"]}, sort_keys=True))
    if result["status"] != "pass":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
