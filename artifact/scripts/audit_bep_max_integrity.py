#!/usr/bin/env python3
"""Integrity audit for the BEP-Max adversarial validation suite.

The adversarial validation suite is not part of the locked BEP-Deep denominator.
It is a derived stress layer around the locked fixtures.  This audit verifies
that every generated BEP-Max case has a fresh content hash, a unique identifier,
a valid source fixture, and a validation label consistent with the source case
and variant type.  It also checks that the metrics file matches the suite and
that operational and independent-decision results both match the expected label.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True

import argparse, csv, hashlib, json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

from bep_semantics import analyze_fixture
from decision_table_oracle import decision_issues, load


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
    ap.add_argument("--suite", default="artifact/results/bep_max/adversarial_validation_suite.json")
    ap.add_argument("--audit", default="artifact/results/bep_max/adversarial_validation_audit.csv")
    ap.add_argument("--metrics", default="artifact/results/bep_max/adversarial_validation_metrics.json")
    ap.add_argument("--out", default="artifact/results/bep_max/adversarial_suite_integrity.json")
    args = ap.parse_args()

    fixtures = load(args.fixtures)
    suite = load(args.suite)
    metrics = json.loads(Path(args.metrics).read_text(encoding="utf-8"))
    source_by_id = {str(fx.get("id")): fx for fx in fixtures}
    case_ids = [str(c.get("id")) for c in suite]
    id_counts = Counter(case_ids)
    duplicate_ids = sorted([cid for cid, n in id_counts.items() if n > 1])

    hash_mismatches: List[Dict[str, str]] = []
    source_failures: List[str] = []
    label_failures: List[str] = []
    oracle_failures: List[Dict[str, str]] = []
    variant_counts = Counter()

    for case in suite:
        cid = str(case.get("id"))
        variant = str(case.get("validation_variant", ""))
        variant_counts[variant] += 1
        want_hash = stable_hash({k: v for k, v in case.items() if k != "fixture_hash"})
        got_hash = str(case.get("fixture_hash", ""))
        if got_hash != want_hash:
            hash_mismatches.append({"fixture_id": cid, "expected_hash": want_hash, "observed_hash": got_hash})
        sid = source_fixture_id(cid)
        src = source_by_id.get(sid)
        if src is None:
            source_failures.append(cid)
            continue
        source_expected = expected_issues(src)
        case_expected = expected_issues(case)
        if variant == "positive_preserving_near_repair":
            if not source_expected or case_expected != source_expected:
                label_failures.append(cid)
        elif variant.startswith("semantic_preserving"):
            if case_expected != source_expected:
                label_failures.append(cid)
        else:
            label_failures.append(cid)
        op = operational_issues(case)
        dt = sorted(set(decision_issues(case)))
        if op != case_expected or dt != case_expected:
            oracle_failures.append({
                "fixture_id": cid,
                "expected": ";".join(case_expected) or "none",
                "operational": ";".join(op) or "none",
                "decision_table": ";".join(dt) or "none",
            })

    audit_rows = list(csv.DictReader(Path(args.audit).open(newline="", encoding="utf-8")))
    audit_passed = sum(1 for r in audit_rows if str(r.get("passed", "")).lower() == "true")
    metric_count_failures = []
    if metrics.get("generated_adversarial_validation_cases") != len(suite):
        metric_count_failures.append("generated_adversarial_validation_cases")
    if metrics.get("validation_cases_passed") != audit_passed:
        metric_count_failures.append("validation_cases_passed")
    if metrics.get("semantic_preserving_cases") != sum(n for v, n in variant_counts.items() if v.startswith("semantic_preserving")):
        metric_count_failures.append("semantic_preserving_cases")
    if metrics.get("positive_preserving_near_repair_cases") != variant_counts.get("positive_preserving_near_repair", 0):
        metric_count_failures.append("positive_preserving_near_repair_cases")

    result = {
        "suite_cases": len(suite),
        "unique_case_ids": len(id_counts),
        "duplicate_ids": duplicate_ids,
        "fresh_fixture_hashes": len(suite) - len(hash_mismatches),
        "hash_mismatches": hash_mismatches[:20],
        "valid_source_links": len(suite) - len(source_failures),
        "source_failures": source_failures[:20],
        "label_consistent_cases": len(suite) - len(label_failures),
        "label_failures": label_failures[:20],
        "operational_and_decision_oracle_passed": len(suite) - len(oracle_failures),
        "oracle_failures": oracle_failures[:20],
        "metric_count_failures": metric_count_failures,
        "variant_counts": dict(sorted(variant_counts.items())),
        "status": "pass" if not (duplicate_ids or hash_mismatches or source_failures or label_failures or oracle_failures or metric_count_failures) else "fail",
        "interpretation": "BEP-Max integrity audit over generated validation cases; checks freshness of content hashes, source links, label preservation, and dual-oracle agreement.",
    }
    out = Path(args.out); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "suite_cases": result["suite_cases"], "fresh_fixture_hashes": result["fresh_fixture_hashes"], "valid_source_links": result["valid_source_links"], "oracle_passed": result["operational_and_decision_oracle_passed"]}, sort_keys=True))
    if result["status"] != "pass":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
