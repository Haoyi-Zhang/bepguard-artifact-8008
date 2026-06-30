#!/usr/bin/env python3
"""release semantic recomputation audit for BEP-Deep/BEP-Max.

This gate recomputes the central semantic claims from released inputs without
rewriting the large result tables.  It complements release-consistency checks:
those checks prove that materialized ledgers agree, while this gate proves that
key counts are still derivable from the locked fixture inputs and executable
semantic definitions.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True

import argparse, hashlib, json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

from bep_semantics import analyze_fixture, load_fixtures
from decision_table_oracle import decision_issues, generate_finite_states

EXPECT = {
    "deep_fixtures": 972,
    "deep_positives": 418,
    "deep_negatives": 554,
    "bep_max_cases": 4306,
    "finite_states": 351,
}


def stable_hash(obj: object) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]


def expected_issues(fx: Dict[str, Any]) -> List[str]:
    issue = str(fx.get("expected_issue", "none"))
    return [] if issue == "none" else [issue]


def operational_issues(fx: Dict[str, Any]) -> List[str]:
    return sorted({finding.issue for finding in analyze_fixture(fx)})


def source_fixture_id(case_id: str) -> str:
    return case_id.split("__max_", 1)[0]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixtures", default="artifact/data/deep_locked_fixtures.json")
    ap.add_argument("--bep-max-suite", default="artifact/results/bep_max/adversarial_validation_suite.json")
    ap.add_argument("--out", default="artifact/results/semantic_recomputation_audit.json")
    args = ap.parse_args()
    problems: List[str] = []

    fixtures = load_fixtures(args.fixtures)
    if len(fixtures) != EXPECT["deep_fixtures"]:
        problems.append(f"expected {EXPECT['deep_fixtures']} BEP-Deep fixtures, observed {len(fixtures)}")

    positives = [fx for fx in fixtures if str(fx.get("expected_issue", "none")) != "none"]
    negatives = [fx for fx in fixtures if str(fx.get("expected_issue", "none")) == "none"]
    if len(positives) != EXPECT["deep_positives"] or len(negatives) != EXPECT["deep_negatives"]:
        problems.append(f"unexpected positive/negative split: {len(positives)}/{len(negatives)}")

    detected = 0
    clean_negatives = 0
    op_dt_agreements = 0
    operational_mismatches: List[Dict[str, str]] = []
    decision_mismatches: List[Dict[str, str]] = []
    issue_counts: Counter[str] = Counter()
    for fx in fixtures:
        fid = str(fx.get("id"))
        expected = expected_issues(fx)
        op = operational_issues(fx)
        dt = sorted(set(decision_issues(fx)))
        if op == expected:
            if expected:
                detected += 1
            else:
                clean_negatives += 1
        else:
            operational_mismatches.append({"fixture_id": fid, "expected": ";".join(expected) or "none", "operational": ";".join(op) or "none"})
        if dt == expected and op == dt:
            op_dt_agreements += 1
        else:
            decision_mismatches.append({"fixture_id": fid, "expected": ";".join(expected) or "none", "operational": ";".join(op) or "none", "decision_table": ";".join(dt) or "none"})
        for issue in expected:
            issue_counts[issue] += 1

    if detected != EXPECT["deep_positives"]:
        problems.append(f"detected positives mismatch: {detected}")
    if clean_negatives != EXPECT["deep_negatives"]:
        problems.append(f"clean negatives mismatch: {clean_negatives}")
    if op_dt_agreements != EXPECT["deep_fixtures"]:
        problems.append(f"operational/decision-table locked fixture agreement mismatch: {op_dt_agreements}")

    finite = generate_finite_states()
    finite_mismatches = []
    for fx in finite:
        op = operational_issues(fx)
        dt = sorted(set(decision_issues(fx)))
        if op != dt:
            finite_mismatches.append({"fixture_id": str(fx.get("id")), "operational": ";".join(op) or "none", "decision_table": ";".join(dt) or "none"})
    if len(finite) != EXPECT["finite_states"]:
        problems.append(f"finite state count mismatch: {len(finite)}")
    if finite_mismatches:
        problems.append(f"finite state oracle mismatches: {len(finite_mismatches)}")

    suite_path = Path(args.bep_max_suite)
    suite = json.loads(suite_path.read_text(encoding="utf-8"))
    source_by_id = {str(fx.get("id")): fx for fx in fixtures}
    case_ids = [str(c.get("id")) for c in suite]
    duplicate_ids = [cid for cid, n in Counter(case_ids).items() if n > 1]
    bepmax_hash_ok = 0
    bepmax_source_ok = 0
    bepmax_label_ok = 0
    bepmax_oracle_ok = 0
    bepmax_failures: List[Dict[str, str]] = []
    for case in suite:
        cid = str(case.get("id"))
        expected = expected_issues(case)
        if str(case.get("fixture_hash", "")) == stable_hash({k: v for k, v in case.items() if k != "fixture_hash"}):
            bepmax_hash_ok += 1
        sid = source_fixture_id(cid)
        src = source_by_id.get(sid)
        if src is not None:
            bepmax_source_ok += 1
            src_expected = expected_issues(src)
            variant = str(case.get("validation_variant", ""))
            if (variant == "positive_preserving_near_repair" and src_expected and expected == src_expected) or (variant.startswith("semantic_preserving") and expected == src_expected):
                bepmax_label_ok += 1
        op = operational_issues(case)
        dt = sorted(set(decision_issues(case)))
        if op == expected and dt == expected:
            bepmax_oracle_ok += 1
        elif len(bepmax_failures) < 20:
            bepmax_failures.append({"fixture_id": cid, "expected": ";".join(expected) or "none", "operational": ";".join(op) or "none", "decision_table": ";".join(dt) or "none"})
    if len(suite) != EXPECT["bep_max_cases"]:
        problems.append(f"BEP-Max suite size mismatch: {len(suite)}")
    if duplicate_ids:
        problems.append(f"BEP-Max duplicate ids: {duplicate_ids[:5]}")
    if bepmax_hash_ok != EXPECT["bep_max_cases"]:
        problems.append(f"BEP-Max fresh hashes mismatch: {bepmax_hash_ok}")
    if bepmax_source_ok != EXPECT["bep_max_cases"] or bepmax_label_ok != EXPECT["bep_max_cases"]:
        problems.append(f"BEP-Max source/label closure mismatch: source {bepmax_source_ok}, label {bepmax_label_ok}")
    if bepmax_oracle_ok != EXPECT["bep_max_cases"]:
        problems.append(f"BEP-Max oracle agreement mismatch: {bepmax_oracle_ok}")

    result = {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "deep_fixtures": len(fixtures),
        "deep_expected_positives": len(positives),
        "deep_negative_controls": len(negatives),
        "deep_detected_positives": detected,
        "deep_clean_negative_controls": clean_negatives,
        "locked_fixture_operational_decision_agreements": op_dt_agreements,
        "operational_mismatches": operational_mismatches[:20],
        "decision_table_mismatches": decision_mismatches[:20],
        "issue_classes_recomputed": len(issue_counts),
        "finite_states_checked": len(finite),
        "finite_state_mismatches": len(finite_mismatches),
        "finite_state_mismatch_examples": finite_mismatches[:20],
        "bep_max_cases": len(suite),
        "bep_max_unique_case_ids": len(set(case_ids)),
        "bep_max_fresh_hashes": bepmax_hash_ok,
        "bep_max_valid_source_links": bepmax_source_ok,
        "bep_max_label_consistent_cases": bepmax_label_ok,
        "bep_max_operational_decision_passed": bepmax_oracle_ok,
        "bep_max_failure_examples": bepmax_failures,
        "interpretation": "Recomputes core semantic outcomes from released inputs without rewriting large result tables; not a live-web measurement.",
    }
    out = Path(args.out); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "problem_count": result["problem_count"], "deep_detected_positives": detected, "deep_clean_negative_controls": clean_negatives, "bep_max_passed": bepmax_oracle_ok}, sort_keys=True))
    if problems:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
