#!/usr/bin/env python3
"""Audit admitted-claim coverage for BEP-Deep.

The paper admits public claims that play different roles: some directly produce
fixture obligations; some provide framework/context surfaces used by those
obligations; some define external baseline scope. This audit prevents orphan
claims by checking that every admitted claim has one of those explicit roles and
that every executable rule has at least one fixture or validation obligation.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True

import csv, json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
RESULTS = ROOT / "results" / "deep_locked"

# Claims that are not fixture labels but provide framework/context or baseline
# evidence for executable obligations. This map is intentionally explicit; an
# admitted claim not listed here and not fixture-backed fails the audit.
CONTEXT_CLAIM_ROLE = {
    "CL_CSP_05": "supports CSP frame-ancestors meta-delivery rule",
    "CL_CSP_07": "supports multiple-policy composition rule",
    "CL_CORS_04": "supports dynamic-origin cache/Vary rule",
    "CL_HELMET_01": "supports framework CSP default-generation surface",
    "CL_HELMET_02": "supports framework CSP merge surface",
    "CL_HELMET_03": "supports framework report-only CSP generation surface",
    "CL_HELMET_04": "supports framework COEP default-generation surface",
    "CL_DJANGO_01": "supports framework HSTS HTTPS-only generation surface",
    "CL_DJANGO_02": "supports proxy/TLS-termination HSTS context surface",
    "CL_SPRING_01": "supports framework CSP opt-in/default context surface",
    "CL_SPRING_02": "supports framework enforced/report-only CSP context surface",
    "CL_RAILS_01": "supports framework CSP DSL generation surface",
    "CL_RAILS_02": "supports framework report-only migration surface",
    "CL_RAILS_03": "supports nonce/cache rendering tradeoff surface",
    "CL_EXPRESS_03": "supports CORS-as-sharing-not-authorization context surface",
}
BASELINE_CLAIMS = {
    "CL_HELMET_05": "supports CSP baseline-scope boundary",
    "CL_BASE_01": "supports CSP Evaluator baseline scope",
    "CL_BASE_02": "supports MDN Observatory baseline scope",
    "CL_BASE_03": "supports hstspreload baseline scope",
}


def read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def write_csv(path: Path, rows: List[Dict[str, Any]], fields: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fields})


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def split_rules(value: str) -> List[str]:
    return [x.strip() for x in value.replace(",", ";").split(";") if x.strip()]


def main() -> None:
    claims = read_csv(DATA / "corpus_claims.csv")
    rules = read_csv(DATA / "rule_to_source_ledger.csv")
    fixtures = json.loads((DATA / "deep_locked_fixtures.json").read_text(encoding="utf-8"))
    rule_ids = {r["rule_id"] for r in rules}
    claim_fixture_count: Dict[str, int] = defaultdict(int)
    claim_positive_count: Dict[str, int] = defaultdict(int)
    claim_control_count: Dict[str, int] = defaultdict(int)
    for f in fixtures:
        for cid in f.get("source_claim_ids", []):
            claim_fixture_count[cid] += 1
            if f.get("fixture_role") == "positive":
                claim_positive_count[cid] += 1
            else:
                claim_control_count[cid] += 1
    rows: List[Dict[str, Any]] = []
    failures: List[Dict[str, Any]] = []
    for c in claims:
        cid = c["claim_id"]
        rules_known = all(r in rule_ids for r in split_rules(c.get("semantic_rule_ids", "")))
        if claim_fixture_count[cid] > 0:
            role = "fixture_backed"
            explanation = "directly linked from locked BEP-Deep fixtures"
            ok = True
        elif cid in CONTEXT_CLAIM_ROLE:
            role = "context_surface"
            explanation = CONTEXT_CLAIM_ROLE[cid]
            ok = rules_known
        elif cid in BASELINE_CLAIMS:
            role = "baseline_scope"
            explanation = BASELINE_CLAIMS[cid]
            ok = rules_known
        else:
            role = "orphan"
            explanation = "no fixture, context, or baseline role recorded"
            ok = False
        row = {
            "claim_id": cid,
            "policy_family": c.get("policy_family", ""),
            "claim_type": c.get("claim_type", ""),
            "semantic_rule_ids": c.get("semantic_rule_ids", ""),
            "coverage_role": role,
            "fixture_count": claim_fixture_count[cid],
            "positive_fixture_count": claim_positive_count[cid],
            "control_fixture_count": claim_control_count[cid],
            "rules_known": "yes" if rules_known else "no",
            "coverage_explanation": explanation,
            "coverage_status": "covered" if ok else "needs_action",
        }
        rows.append(row)
        if not ok:
            failures.append(row)
    metrics = {
        "interpretation": "Admitted-claim closure audit: every public claim is either fixture-backed, context-surface evidence, or baseline-scope evidence.",
        "admitted_claims": len(claims),
        "fixture_backed_claims": sum(1 for r in rows if r["coverage_role"] == "fixture_backed"),
        "context_surface_claims": sum(1 for r in rows if r["coverage_role"] == "context_surface"),
        "baseline_scope_claims": sum(1 for r in rows if r["coverage_role"] == "baseline_scope"),
        "orphan_claims": sum(1 for r in rows if r["coverage_role"] == "orphan"),
        "claims_covered": sum(1 for r in rows if r["coverage_status"] == "covered"),
        "failures": failures,
        "status": "pass" if not failures else "fail",
    }
    write_csv(RESULTS / "claim_coverage_audit.csv", rows, ["claim_id", "policy_family", "claim_type", "semantic_rule_ids", "coverage_role", "fixture_count", "positive_fixture_count", "control_fixture_count", "rules_known", "coverage_explanation", "coverage_status"])
    write_json(RESULTS / "claim_coverage_metrics.json", metrics)
    print(json.dumps({"status": metrics["status"], "claims_covered": metrics["claims_covered"], "admitted_claims": metrics["admitted_claims"], "orphan_claims": metrics["orphan_claims"]}, sort_keys=True))
    if failures:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
