#!/usr/bin/env python3
"""Finite-state semantic core verifier for BEP-IR.

This script is intentionally independent from the workload labels.  It checks
small, finite abstract domains for the invariants used by the paper: delivery,
fallback, credentialed sharing, cache variation, HSTS state/scope, embedding,
permissions allowlists, ordered layers, and monotonic composition.  The checks
are not a theorem prover for the web platform; they are executable proof
obligation witnesses for the encoded fragments.
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import csv
import itertools
import json
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from bep_semantics import (
    analyze_fixture,
    csp_policy_allows_script,
    enforced_csp_allows_script,
    effective_headers_from_layers,
    header_values,
    parse_hsts,
    same_origin,
)

APP = "https://app.example"
CDN = "https://cdn.example"
EVIL = "https://evil.example"
API = "https://api.example"
OTHER = "https://other.example"


def h(name: str, value: str) -> Dict[str, str]:
    return {"name": name, "value": value}


def fixture(fid: str, intent_class: str, headers: List[Dict[str, str]], ctx: Dict[str, object] | None = None, family: str = "finite-core") -> Dict[str, object]:
    return {
        "id": fid,
        "policy_family": family,
        "expected_issue": "finite_state_check",
        "intent": {"class": intent_class, "claim": "finite-state invariant"},
        "headers": headers,
        "context": ctx or {},
    }


def issues(f: Dict[str, object]) -> List[str]:
    return sorted(x.issue for x in analyze_fixture(f))


def record(rows: List[Dict[str, object]], name: str, state: Dict[str, object], passed: bool, expected: str, actual: str) -> None:
    rows.append({
        "invariant": name,
        "state": json.dumps(state, sort_keys=True),
        "passed": passed,
        "expected": expected,
        "actual": actual,
    })


def verify() -> Tuple[List[Dict[str, object]], Dict[str, object]]:
    rows: List[Dict[str, object]] = []

    # I1: CSP report-only delivery is monitoring, not enforcement.  Any
    # report-only-only surface under an enforcement intent must create the same
    # report-only witness, independent of source-list details.
    ro_policies = ["default-src 'self'", "script-src 'none'", "script-src https://trusted.example", "default-src *"]
    for p in ro_policies:
        f = fixture("i1", "enforce_script_restriction", [h("Content-Security-Policy-Report-Only", p)], {"document_origin": APP, "resource_origin": CDN}, "CSP")
        ok = issues(f) == ["csp_report_only_not_enforced"]
        record(rows, "I1_report_only_nonblocking", {"policy": p}, ok, "csp_report_only_not_enforced", ";".join(issues(f)))

    # I2: CSP source-list fallback priority.  script-src, when present, wins over
    # default-src; otherwise default-src is used for script probes.
    csp_cases = [
        ("default-src 'self'", CDN, False),
        ("default-src *", CDN, True),
        ("default-src *; script-src 'self'", CDN, False),
        ("default-src 'none'; script-src https://cdn.example", CDN, True),
        ("script-src 'none'", CDN, False),
        ("script-src https://cdn.example", CDN, True),
    ]
    for policy, resource, expected_allow in csp_cases:
        actual = csp_policy_allows_script(policy, APP, resource)
        record(rows, "I2_csp_fallback_priority", {"policy": policy, "resource": resource}, actual == expected_allow, str(expected_allow), str(actual))

    # I3: multiple enforced CSP policies are conjunctive, hence adding a policy
    # cannot turn a blocked script into an allowed one and cannot expand the set
    # of allowed probes.
    policies = ["script-src *", "script-src https://cdn.example", "script-src 'self'", "default-src 'none'", "default-src *"]
    resources = [APP, CDN, EVIL]
    for p1, p2, resource in itertools.product(policies, policies, resources):
        single = enforced_csp_allows_script([p1], APP, resource)
        both = enforced_csp_allows_script([p1, p2], APP, resource)
        ok = (not both) or single
        record(rows, "I3_csp_conjunctive_nonexpansion", {"p1": p1, "p2": p2, "resource": resource}, ok, "both=>single", f"single={single};both={both}")

    # I4/I5/I6: CORS credentialed sharing, duplicate ACAO, exact ACAC success
    # value, and cache variation for dynamic origins.
    acao_cases = ["*", "$ORIGIN", API, OTHER]
    acac_cases = [None, "true", "True", "FALSE"]
    cred_cases = ["include", "omit"]
    for acao, acac, cred in itertools.product(acao_cases, acac_cases, cred_cases):
        headers = [h("Access-Control-Allow-Origin", acao)]
        if acac is not None:
            headers.append(h("Access-Control-Allow-Credentials", acac))
        f = fixture("i4", "allow_credentialed_cors", headers, {"request_origin": API, "credentials_mode": cred}, "CORS")
        actual_issues = issues(f)
        expected_share = False
        if acao == "*":
            expected_share = cred != "include"
        elif acao in {"$ORIGIN", API}:
            expected_share = (cred != "include") or acac == "true"
        expected_issue = [] if expected_share else (["cors_acac_case_sensitive_not_shareable"] if acac in {"True"} and cred == "include" and acao in {"$ORIGIN", API} else ["cors_intended_credentialed_share_blocked"])
        ok = (actual_issues == expected_issue)
        record(rows, "I4_cors_credentialed_shareability", {"acao": acao, "acac": acac, "credentials": cred}, ok, ";".join(expected_issue) or "none", ";".join(actual_issues) or "none")
    dup = fixture("i5", "allow_credentialed_cors", [h("Access-Control-Allow-Origin", API), h("Access-Control-Allow-Origin", OTHER), h("Access-Control-Allow-Credentials", "true")], {"request_origin": API, "credentials_mode": "include"}, "CORS")
    record(rows, "I5_cors_duplicate_acao_rejected", {}, issues(dup) == ["cors_duplicate_acao_not_shareable"], "cors_duplicate_acao_not_shareable", ";".join(issues(dup)))
    for vary in [None, "Accept-Encoding", "Origin", "Accept-Encoding, Origin"]:
        headers = [h("Access-Control-Allow-Origin", "$ORIGIN"), h("Access-Control-Allow-Credentials", "true")]
        if vary:
            headers.append(h("Vary", vary))
        f = fixture("i6", "allow_credentialed_cors_cache_safe", headers, {"request_origin": API, "credentials_mode": "include", "dynamic_origin": True}, "CORS/cache")
        expected = [] if (vary and "origin" in [x.strip().lower() for x in vary.split(",")]) else ["cors_dynamic_origin_missing_vary"]
        record(rows, "I6_cors_dynamic_origin_vary", {"vary": vary}, issues(f) == expected, ";".join(expected) or "none", ";".join(issues(f)) or "none")

    # I7: HSTS state transition and scope/preload fragments.
    hsts_values = ["max-age=31536000", "max-age=0", "max-age=abc", "max-age=31536000; includeSubDomains", "max-age=31536000; includeSubDomains; preload"]
    for scheme, value in itertools.product(["http", "https"], hsts_values):
        f = fixture("i7", "enforce_https_only", [h("Strict-Transport-Security", value)], {"scheme": scheme}, "HSTS")
        parsed = parse_hsts(value)
        if scheme != "https":
            expected = ["hsts_header_not_honored_over_http"]
        elif not parsed["valid_max_age"]:
            expected = ["hsts_invalid_max_age_ignored"]
        elif parsed["max_age"] == 0:
            expected = ["hsts_policy_cleared_by_zero_max_age"]
        else:
            expected = []
        record(rows, "I7_hsts_transport_and_state", {"scheme": scheme, "value": value}, issues(f) == expected, ";".join(expected) or "none", ";".join(issues(f)) or "none")
    for value in hsts_values:
        f = fixture("i8", "expect_hsts_preload", [h("Strict-Transport-Security", value)], {"scheme": "https"}, "HSTS/preload")
        parsed = parse_hsts(value); max_age = parsed.get("max_age")
        criterion = isinstance(max_age, int) and max_age >= 31536000 and parsed.get("include_subdomains") and parsed.get("preload")
        expected = [] if criterion else ["hsts_preload_criteria_not_met"]
        record(rows, "I8_hsts_preload_criterion", {"value": value}, issues(f) == expected, ";".join(expected) or "none", ";".join(issues(f)) or "none")

    # I9: COEP require-corp blocks no-cors cross-origin resource unless CORP or
    # CORS explicitly opts it in.  Same-origin/no-CORS variants must be clean.
    corp_cases = [None, "same-origin", "same-site", "cross-origin"]
    resources = [APP, CDN]
    modes = ["no-cors", "cors"]
    for corp, resource, mode in itertools.product(corp_cases, resources, modes):
        headers = [h("Cross-Origin-Embedder-Policy", "require-corp")]
        if corp is not None:
            headers.append(h("Cross-Origin-Resource-Policy", corp))
        if mode == "cors":
            headers += [h("Access-Control-Allow-Origin", APP)]
        f = fixture("i9", "cross_origin_isolation_without_embed_breakage", headers, {"document_origin": APP, "resource_origin": resource, "request_mode": mode, "credentials_mode": "omit"}, "COEP/CORP/CORS")
        same = same_origin(APP, resource)
        expected_block = (not same) and mode == "no-cors" and (corp not in {"cross-origin"})
        # same-site deterministic fixture semantics treats app.example/cdn.example as same-site.
        if corp == "same-site" and resource == CDN:
            expected_block = False
        # CORS authorization is modeled only for explicit cors-mode requests; an
        # ACAO header alone does not opt a no-cors resource into COEP embedding.
        expected = ["coep_require_corp_blocks_cross_origin_resource"] if expected_block else []
        record(rows, "I9_coep_corp_cors_embedding", {"corp": corp, "resource": resource, "mode": mode}, issues(f) == expected, ";".join(expected) or "none", ";".join(issues(f)) or "none")

    # I10: Permissions-Policy empty allowlist denies a feature; wildcard
    # over-allows when a denial intent is declared.
    perms = ["geolocation=()", "geolocation=(self)", "geolocation=(*)", "camera=()"]
    for value in perms:
        f_allow = fixture("i10a", "allow_browser_feature", [h("Permissions-Policy", value)], {"feature": "geolocation"}, "Permissions-Policy")
        expected_allow = ["permissions_policy_feature_disabled"] if value == "geolocation=()" else []
        record(rows, "I10_permissions_disable", {"value": value}, issues(f_allow) == expected_allow, ";".join(expected_allow) or "none", ";".join(issues(f_allow)) or "none")
        f_deny = fixture("i10b", "deny_browser_feature", [h("Permissions-Policy", value)], {"feature": "geolocation", "target_origin": "*"}, "Permissions-Policy")
        expected_deny = ["permissions_policy_feature_overallowed"] if value == "geolocation=(*)" else []
        record(rows, "I11_permissions_overallow", {"value": value}, issues(f_deny) == expected_deny, ";".join(expected_deny) or "none", ";".join(issues(f_deny)) or "none")

    # I12: ordered layer semantics. set replaces earlier values; append preserves
    # multiple CSP policies; remove deletes previous same-named fields.
    layer_cases = [
        ([{"layer":"framework","op":"append","headers":[h("Content-Security-Policy", "script-src *")]}, {"layer":"proxy","op":"remove","headers":[h("Content-Security-Policy", "")] }], []),
        ([{"layer":"framework","op":"append","headers":[h("Content-Security-Policy", "script-src *")]}, {"layer":"route","op":"append","headers":[h("Content-Security-Policy", "script-src 'none'")]}], ["script-src *", "script-src 'none'"]),
        ([{"layer":"framework","op":"append","headers":[h("Strict-Transport-Security", "max-age=0")]}, {"layer":"proxy","op":"set","headers":[h("Strict-Transport-Security", "max-age=31536000")]}], ["max-age=31536000"]),
    ]
    for layers, expected_values in layer_cases:
        f = {"id":"i12", "headers": [], "layers": layers, "intent":{"class":"preserve_enforced_policy_across_layers"}, "context": {}}
        composed, _ = effective_headers_from_layers(f)
        values = [x["value"] for x in composed]
        record(rows, "I12_ordered_layer_composition", {"layers": layers}, values == expected_values, json.dumps(expected_values), json.dumps(values))

    # I13: conservative unknown handling. An unsupported intent class and unknown
    # header must not emit a positive witness.
    f_unknown = fixture("i13", "unsupported_policy_intent", [h("X-Experimental-Policy", "block")], {}, "unknown")
    record(rows, "I13_unknown_is_not_positive", {}, issues(f_unknown) == [], "none", ";".join(issues(f_unknown)) or "none")

    fail = [r for r in rows if not r["passed"]]
    by_inv: Dict[str, int] = {}
    for r in rows:
        by_inv[str(r["invariant"])] = by_inv.get(str(r["invariant"]), 0) + 1
    metrics = {
        "states_checked": len(rows),
        "invariants": len(by_inv),
        "failures": len(fail),
        "failed_invariants": sorted({str(r["invariant"]) for r in fail}),
        "checks_by_invariant": by_inv,
        "interpretation": "Finite-state proof-obligation checks for the encoded BEP-IR fragments; not a proof of the full web platform.",
    }
    return rows, metrics


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default="artifact/results/deep_locked/semantic_core_verification_cases.csv")
    ap.add_argument("--json", default="artifact/results/deep_locked/semantic_core_verification.json")
    args = ap.parse_args()
    rows, metrics = verify()
    out_csv = Path(args.csv); out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["invariant", "state", "passed", "expected", "actual"])
        w.writeheader(); w.writerows(rows)
    Path(args.json).write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(metrics, sort_keys=True))
    if metrics["failures"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
