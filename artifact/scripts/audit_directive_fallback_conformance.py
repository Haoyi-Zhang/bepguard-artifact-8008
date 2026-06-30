#!/usr/bin/env python3
"""Source-grounded directive-fallback conformance audit.

This audit checks the CSP script-element fallback obligation that is easy to
miss in fixture-level validation when no locked fixture contains both
``script-src-elem`` and ``script-src``.  It does not add fixtures or labels to
BEP-Deep.  Instead, it is a micro-obligation gate over the semantic core and the
independent decision-table oracle: both must select ``script-src-elem`` before
``script-src`` before ``default-src`` for the encoded script-element request
fragment.
"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from typing import Dict, List

sys.dont_write_bytecode = True

from bep_semantics import csp_policy_allows_script, effective_script_sources as operational_sources
from decision_table_oracle import csp_allows as decision_allows, effective_script_sources as decision_sources

APP = "https://app.example"
CDN = "https://cdn.example"

CASES: List[Dict[str, object]] = [
    {
        "case_id": "script_elem_overrides_script_src_allow",
        "policy": "script-src 'self'; script-src-elem https://cdn.example; default-src 'none'",
        "expected_sources": ["https://cdn.example"],
        "expected_allowed": True,
        "rationale": "most-specific script-src-elem must override a stricter script-src for script element requests",
    },
    {
        "case_id": "script_elem_overrides_script_src_block",
        "policy": "script-src-elem 'none'; script-src https://cdn.example; default-src *",
        "expected_sources": ["'none'"],
        "expected_allowed": False,
        "rationale": "script-src must not mask a stricter script-src-elem directive",
    },
    {
        "case_id": "script_src_before_default_allow",
        "policy": "script-src https://cdn.example; default-src 'none'",
        "expected_sources": ["https://cdn.example"],
        "expected_allowed": True,
        "rationale": "script-src is selected when script-src-elem is absent",
    },
    {
        "case_id": "script_src_before_default_block",
        "policy": "script-src 'self'; default-src https://cdn.example",
        "expected_sources": ["'self'"],
        "expected_allowed": False,
        "rationale": "default-src must not mask an explicit script-src directive",
    },
    {
        "case_id": "default_src_fallback_allow",
        "policy": "default-src https://cdn.example",
        "expected_sources": ["https://cdn.example"],
        "expected_allowed": True,
        "rationale": "default-src applies when both script-specific directives are absent",
    },
    {
        "case_id": "no_directive_allows_by_fragment_default",
        "policy": "",
        "expected_sources": ["*"],
        "expected_allowed": True,
        "rationale": "the encoded fragment has no blocking script directive when no source list is present",
    },
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="artifact/results/deep_locked/directive_fallback_conformance.json")
    args = parser.parse_args()

    problems: List[str] = []
    rows: List[Dict[str, object]] = []
    for case in CASES:
        policy = str(case["policy"])
        expected_sources = list(case["expected_sources"])  # type: ignore[arg-type]
        expected_allowed = bool(case["expected_allowed"])
        op_sources = operational_sources(policy)
        dt_sources = decision_sources(policy)
        op_allowed = csp_policy_allows_script(policy, APP, CDN)
        dt_allowed = decision_allows(policy, APP, CDN)
        if op_sources != expected_sources:
            problems.append(f"operational source selection mismatch for {case['case_id']}: {op_sources} != {expected_sources}")
        if dt_sources != expected_sources:
            problems.append(f"decision-table source selection mismatch for {case['case_id']}: {dt_sources} != {expected_sources}")
        if op_allowed != expected_allowed:
            problems.append(f"operational allow/block mismatch for {case['case_id']}: {op_allowed} != {expected_allowed}")
        if dt_allowed != expected_allowed:
            problems.append(f"decision-table allow/block mismatch for {case['case_id']}: {dt_allowed} != {expected_allowed}")
        rows.append({
            "case_id": case["case_id"],
            "policy": policy,
            "expected_sources": expected_sources,
            "operational_sources": op_sources,
            "decision_table_sources": dt_sources,
            "expected_allowed": expected_allowed,
            "operational_allowed": op_allowed,
            "decision_table_allowed": dt_allowed,
            "rationale": case["rationale"],
        })

    result = {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "cases_checked": len(CASES),
        "operational_selection_agreements": sum(1 for r in rows if r["operational_sources"] == r["expected_sources"]),
        "decision_table_selection_agreements": sum(1 for r in rows if r["decision_table_sources"] == r["expected_sources"]),
        "operational_judgment_agreements": sum(1 for r in rows if r["operational_allowed"] == r["expected_allowed"]),
        "decision_table_judgment_agreements": sum(1 for r in rows if r["decision_table_allowed"] == r["expected_allowed"]),
        "source_claim_id": "CL_CSP_04",
        "rule_id": "R_CSP_DEFAULT_SRC_FALLBACK",
        "source_span": "CSP3 §6.8.3 script-src-elem fallback list",
        "rows": rows,
        "interpretation": "Checks a source-grounded semantic micro-obligation outside the locked denominator; it adds validation burden but does not change BEP-Deep labels, counts, or baselines.",
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "problem_count": len(problems), "cases_checked": len(CASES)}, sort_keys=True))
    if problems:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
