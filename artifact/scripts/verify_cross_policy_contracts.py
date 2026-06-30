#!/usr/bin/env python3
"""Cross-policy contract verifier for BEP-IR composition boundaries.

The finite-state semantic-core verifier checks local invariants.  This verifier
checks cross-policy contracts that assessors can inspect independently: a policy
family should not be credited with satisfying another family's missing
precondition, and monotone composition should preserve the intended ordering.
"""
from __future__ import annotations

import argparse
import csv
import itertools
import json
import sys
from pathlib import Path
from typing import Dict, List

sys.dont_write_bytecode = True

from bep_semantics import (
    analyze_fixture,
    cors_shareable,
    cross_origin_isolation_headers_ok,
    enforced_csp_allows_script,
    hsts_preload_ready,
    parse_hsts,
    permissions_feature_disabled,
)

APP = "https://app.example"
CDN = "https://cdn.example"
EVIL = "https://evil.example"
API = "https://api.example"


def h(name: str, value: str) -> Dict[str, str]:
    return {"name": name, "value": value}


def fixture(fid: str, intent: str, headers: List[Dict[str, str]], ctx: Dict[str, object] | None = None, family: str = "cross-policy") -> Dict[str, object]:
    return {"id": fid, "policy_family": family, "expected_issue": "contract_probe", "intent": {"class": intent, "claim": "cross-policy contract"}, "headers": headers, "context": ctx or {}}


def issues(f: Dict[str, object]) -> List[str]:
    return sorted(x.issue for x in analyze_fixture(f))


def record(rows: List[Dict[str, object]], contract: str, state: Dict[str, object], passed: bool, expected: str, actual: str) -> None:
    rows.append({
        "contract": contract,
        "state": json.dumps(state, sort_keys=True),
        "passed": passed,
        "expected": expected,
        "actual": actual,
    })


def verify() -> tuple[List[Dict[str, object]], Dict[str, object]]:
    rows: List[Dict[str, object]] = []

    # C1: CSP meet monotonicity for scripts. Adding an enforced policy cannot
    # convert a blocked script into an allowed one for the same document/resource edge.
    policies = ["script-src *", "script-src https://cdn.example", "script-src 'self'", "default-src *", "default-src 'none'"]
    resources = [APP, CDN, EVIL]
    for p1, p2, resource in itertools.product(policies, policies, resources):
        before = enforced_csp_allows_script([p1], APP, resource)
        after = enforced_csp_allows_script([p1, p2], APP, resource)
        ok = (not after) or before
        record(rows, "C1_csp_meet_nonexpansion", {"p1": p1, "p2": p2, "resource": resource}, ok, "after=>before", f"before={before};after={after}")

    # C2: COEP does not by itself authorize no-cors cross-origin embedding;
    # CORP or CORS resource opt-in is required for the cross-origin edge.
    resource_headers = [
        [],
        [h("Cross-Origin-Resource-Policy", "same-origin")],
        [h("Cross-Origin-Resource-Policy", "same-site")],
        [h("Cross-Origin-Resource-Policy", "cross-origin")],
        [h("Access-Control-Allow-Origin", APP)],
    ]
    for extra in resource_headers:
        headers = [h("Cross-Origin-Embedder-Policy", "require-corp")] + extra
        f = fixture("c2", "cross_origin_isolation_without_embed_breakage", headers, {"document_origin": APP, "resource_origin": "https://cdn.other", "request_mode": "no-cors", "credentials_mode": "omit"}, "COEP/CORP/CORS")
        expected = [] if any(x.get("name") == "Cross-Origin-Resource-Policy" and x.get("value") == "cross-origin" for x in extra) else ["coep_require_corp_blocks_cross_origin_resource"]
        # ACAO does not authorize a no-cors embedding edge in the encoded fragment.
        record(rows, "C2_coep_requires_resource_opt_in", {"extra": extra}, issues(f) == expected, ";".join(expected) or "none", ";".join(issues(f)) or "none")

    # C3: COOP+COEP cross-origin isolation requires both opener and embedder
    # policy and must not be credited if Permissions-Policy disables it.
    coop_values = [None, "same-origin"]
    coep_values = [None, "require-corp", "credentialless"]
    perm_values = [None, "cross-origin-isolated=()", "geolocation=()"]
    for coop, coep, perm in itertools.product(coop_values, coep_values, perm_values):
        headers: List[Dict[str, str]] = []
        if coop: headers.append(h("Cross-Origin-Opener-Policy", coop))
        if coep: headers.append(h("Cross-Origin-Embedder-Policy", coep))
        if perm: headers.append(h("Permissions-Policy", perm))
        expected_ok = coop == "same-origin" and coep in {"require-corp", "credentialless"} and not (perm == "cross-origin-isolated=()")
        actual_ok = cross_origin_isolation_headers_ok(headers)
        f = fixture("c3", "enable_cross_origin_isolation", headers, {}, "COOP/COEP/Permissions-Policy")
        expected_issues = [] if expected_ok else ["cross_origin_isolation_incomplete"]
        record(rows, "C3_isolation_requires_joint_headers", {"coop": coop, "coep": coep, "permissions": perm}, actual_ok == expected_ok and issues(f) == expected_issues, str(expected_ok), f"ok={actual_ok};issues={';'.join(issues(f)) or 'none'}")

    # C4: HSTS preload readiness implies a valid HSTS state on HTTPS, but a valid
    # HSTS state does not imply preload readiness.  The contract prevents the
    # preload comparator from being treated as a general HSTS oracle.
    hsts_values = [
        "max-age=31536000",
        "max-age=31536000; includeSubDomains",
        "max-age=31536000; includeSubDomains; preload",
        "max-age=0; includeSubDomains; preload",
        "max-age=abc; includeSubDomains; preload",
    ]
    for value in hsts_values:
        parsed = parse_hsts(value)
        preload = hsts_preload_ready(value)
        valid_state = bool(parsed.get("valid_max_age")) and isinstance(parsed.get("max_age"), int) and int(parsed.get("max_age")) > 0
        ok = (not preload) or valid_state
        record(rows, "C4_hsts_preload_stronger_than_state", {"hsts": value}, ok, "preload=>valid_state", f"preload={preload};valid_state={valid_state}")
        if valid_state and not preload:
            f = fixture("c4", "expect_hsts_preload", [h("Strict-Transport-Security", value)], {"scheme": "https"}, "HSTS/preload")
            record(rows, "C4b_valid_hsts_not_preload_equivalent", {"hsts": value}, issues(f) == ["hsts_preload_criteria_not_met"], "hsts_preload_criteria_not_met", ";".join(issues(f)) or "none")

    # C5: CORS credentialed shareability is separate from CSP script allowance.
    # A script source list cannot repair a credentialed CORS wildcard.
    csp_policies = ["script-src *", "script-src https://api.example", "default-src *"]
    cors_headers = [h("Access-Control-Allow-Origin", "*"), h("Access-Control-Allow-Credentials", "true")]
    for policy in csp_policies:
        f = fixture("c5", "allow_credentialed_cors", [h("Content-Security-Policy", policy)] + cors_headers, {"request_origin": API, "credentials_mode": "include"}, "CORS")
        ok = not cors_shareable(cors_headers, API, "include") and issues(f) == ["cors_intended_credentialed_share_blocked"]
        record(rows, "C5_csp_cannot_authorize_credentialed_cors", {"csp": policy}, ok, "cors_intended_credentialed_share_blocked", ";".join(issues(f)) or "none")

    # C6: Permissions-Policy denial is feature-specific; disabling one feature
    # must not be credited as disabling a different requested feature.
    for requested in ["geolocation", "camera", "cross-origin-isolated"]:
        headers = [h("Permissions-Policy", "geolocation=()")]
        disabled = permissions_feature_disabled(headers, requested)
        expected = requested == "geolocation"
        f = fixture("c6", "allow_browser_feature", headers, {"feature": requested}, "Permissions-Policy")
        expected_issues = ["permissions_policy_feature_disabled"] if expected else []
        record(rows, "C6_permissions_feature_specificity", {"requested": requested}, disabled == expected and issues(f) == expected_issues, str(expected), f"disabled={disabled};issues={';'.join(issues(f)) or 'none'}")

    failures = [r for r in rows if not r["passed"]]
    by_contract: Dict[str, int] = {}
    for row in rows:
        by_contract[str(row["contract"])] = by_contract.get(str(row["contract"]), 0) + 1
    metrics = {
        "status": "pass" if not failures else "fail",
        "contracts": len(by_contract),
        "states_checked": len(rows),
        "failures": len(failures),
        "checks_by_contract": by_contract,
        "failed_contracts": sorted({str(r["contract"]) for r in failures}),
        "interpretation": "Executable cross-policy proof obligations for the encoded BEP-IR fragments; not a complete browser conformance theorem.",
    }
    return rows, metrics


def main() -> None:
    ap = argparse.ArgumentParser(description="Verify cross-policy BEP-IR contracts.")
    ap.add_argument("--csv", default="artifact/results/deep_locked/cross_policy_contract_cases.csv")
    ap.add_argument("--json", default="artifact/results/deep_locked/cross_policy_contracts.json")
    args = ap.parse_args()
    rows, metrics = verify()
    out_csv = Path(args.csv)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["contract", "state", "passed", "expected", "actual"])
        w.writeheader(); w.writerows(rows)
    Path(args.json).write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(metrics, sort_keys=True))
    if metrics["failures"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
