#!/usr/bin/env python3
"""Synthesize conservative repairs for semantic conflict witnesses.

Repairs are not claimed to be generally optimal. Each repair is a deterministic,
issue-specific edit that preserves the fixture's high-level intent while making
that specific witness disappear under the encoded semantics. The output supports
constructive evaluation: witnesses can be turned into reproducible policy-review
patches instead of remaining scanner-style warnings.
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import copy
import csv
import json
from pathlib import Path
from typing import Dict, List, Tuple

from bep_semantics import analyze_fixture, load_fixtures


def headers(fixture: Dict[str, object]) -> List[Dict[str, str]]:
    # Layered fixtures receive a release repair layer, preserving the original
    # provenance and avoiding in-place edits to framework/proxy layers.
    layers = fixture.get("layers")
    if isinstance(layers, list):
        if not layers or not (isinstance(layers[-1], dict) and layers[-1].get("layer") == "repair_synthesizer" and layers[-1].get("op") == "append"):
            layers.append({"layer": "repair_synthesizer", "op": "append", "headers": []})
        hs = layers[-1].setdefault("headers", [])
        if not isinstance(hs, list):
            layers[-1]["headers"] = []
        return layers[-1]["headers"]  # type: ignore[index,return-value]
    hs = fixture.setdefault("headers", [])
    if not isinstance(hs, list):
        fixture["headers"] = []
    return fixture["headers"]  # type: ignore[return-value]


def remove_headers(fixture: Dict[str, object], name: str) -> None:
    layers = fixture.get("layers")
    if isinstance(layers, list):
        layers.append({"layer": "repair_synthesizer", "op": "remove", "headers": [{"name": name, "value": ""}]})
        return
    lname = name.lower()
    fixture["headers"] = [h for h in headers(fixture) if str(h.get("name", "")).lower() != lname]


def set_single_header(fixture: Dict[str, object], name: str, value: str) -> None:
    remove_headers(fixture, name)
    headers(fixture).append({"name": name, "value": value})


def first_context(fixture: Dict[str, object], key: str, default: str) -> str:
    ctx = fixture.get("context", {}) if isinstance(fixture.get("context"), dict) else {}
    return str(ctx.get(key, default))


def repair_fixture(fixture: Dict[str, object], issue: str) -> Tuple[Dict[str, object], str]:
    fixed = copy.deepcopy(fixture)
    ctx = fixed.setdefault("context", {})
    if not isinstance(ctx, dict):
        fixed["context"] = {}
        ctx = fixed["context"]  # type: ignore[assignment]
    resource = first_context(fixed, "resource_origin", "https://cdn.example")
    request = first_context(fixed, "request_origin", "https://app.example")

    if issue == "csp_report_only_not_enforced":
        ro = [h for h in headers(fixed) if str(h.get("name", "")).lower() == "content-security-policy-report-only"]
        value = ro[0].get("value", "script-src 'self'") if ro else "script-src 'self'"
        remove_headers(fixed, "Content-Security-Policy-Report-Only")
        set_single_header(fixed, "Content-Security-Policy", value)
        return fixed, "move report-only CSP into enforcing delivery surface"
    if issue == "csp_effective_script_allowance":
        set_single_header(fixed, "Content-Security-Policy", "script-src 'self'")
        return fixed, "replace effective script source list with same-origin-only script-src"
    if issue == "nonce_csp_static_render_incompatibility":
        ctx["static_render"] = False
        ctx["rendering_variant"] = "dynamic_per_request"
        return fixed, "move nonce-bearing policy to dynamic per-request rendering context"
    if issue == "csp_multiple_policy_overblocks_trusted_script":
        fixed["headers"] = [{"name": "Content-Security-Policy", "value": f"script-src {resource}"}, {"name": "Content-Security-Policy", "value": f"default-src 'self'; script-src {resource}"}]
        return fixed, "make all enforced CSP policies allow the declared trusted script edge"
    if issue == "csp_frame_ancestors_report_only_not_enforced":
        ro = [h for h in headers(fixed) if str(h.get("name", "")).lower() == "content-security-policy-report-only"]
        value = ro[0].get("value", "frame-ancestors 'none'") if ro else "frame-ancestors 'none'"
        remove_headers(fixed, "Content-Security-Policy-Report-Only")
        set_single_header(fixed, "Content-Security-Policy", str(value).replace("; report-uri /csp", ""))
        return fixed, "deliver frame-ancestors through an enforcing CSP header"
    if issue == "csp_frame_ancestors_meta_delivery_unsupported":
        meta = [h for h in headers(fixed) if str(h.get("name", "")).lower() == "content-security-policy-meta"]
        value = meta[0].get("value", "frame-ancestors 'none'") if meta else "frame-ancestors 'none'"
        remove_headers(fixed, "Content-Security-Policy-Meta")
        set_single_header(fixed, "Content-Security-Policy", str(value))
        return fixed, "move frame-ancestors from meta-style delivery to enforcing header delivery"
    if issue in {"cors_intended_credentialed_share_blocked", "cors_duplicate_acao_not_shareable", "cors_acac_case_sensitive_not_shareable"}:
        set_single_header(fixed, "Access-Control-Allow-Origin", request)
        set_single_header(fixed, "Access-Control-Allow-Credentials", "true")
        return fixed, "emit a single serialized request origin and exact ACAC true for credentialed CORS"
    if issue == "cors_reflected_origin_with_credentials":
        set_single_header(fixed, "Access-Control-Allow-Origin", "https://trusted.example")
        set_single_header(fixed, "Access-Control-Allow-Credentials", "true")
        return fixed, "replace arbitrary origin reflection with a fixed trusted origin"
    if issue in {"cors_dynamic_origin_without_vary", "cors_dynamic_origin_missing_vary"}:
        set_single_header(fixed, "Vary", "Origin")
        return fixed, "add Vary: Origin to cache-partition dynamic ACAO responses"
    if issue == "hsts_header_not_honored_over_http":
        ctx["scheme"] = "https"
        return fixed, "deliver STS over secure transport"
    if issue == "hsts_policy_cleared_by_zero_max_age":
        set_single_header(fixed, "Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return fixed, "replace zero max-age with a positive HSTS lifetime"
    if issue == "hsts_invalid_max_age_ignored":
        set_single_header(fixed, "Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return fixed, "replace invalid max-age with a numeric lifetime"
    if issue in {"hsts_missing_include_subdomains", "hsts_subdomain_scope_not_covered"}:
        set_single_header(fixed, "Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return fixed, "add includeSubDomains for a subdomain-scoped HSTS intent"
    if issue == "hsts_preload_criteria_not_met":
        set_single_header(fixed, "Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
        return fixed, "satisfy the documented preload-oriented header criterion"
    if issue == "cors_dynamic_origin_missing_vary":
        set_single_header(fixed, "Vary", "Origin")
        return fixed, "add Vary: Origin to cache-partition dynamic credentialed ACAO responses"
    if issue == "hsts_subdomain_scope_not_covered":
        set_single_header(fixed, "Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return fixed, "add includeSubDomains for the intended subdomain HSTS scope"
    if issue == "csp_conjunctive_policy_composition_blocks_required_script":
        remove_headers(fixed, "Content-Security-Policy")
        set_single_header(fixed, "Content-Security-Policy", f"script-src 'self' {resource}; object-src 'none'")
        return fixed, "replace conflicting CSP layers with a single combined policy that admits the required script"
    if issue == "layered_header_override_drops_enforcement":
        set_single_header(fixed, "Content-Security-Policy", "script-src 'self'; object-src 'none'")
        return fixed, "restore an enforced CSP in the release composed layer"
    if issue == "coep_require_corp_blocks_cross_origin_resource":
        set_single_header(fixed, "Cross-Origin-Resource-Policy", "cross-origin")
        return fixed, "opt the resource into cross-origin embedding with CORP cross-origin"
    if issue == "cross_origin_isolation_incomplete":
        set_single_header(fixed, "Cross-Origin-Opener-Policy", "same-origin")
        set_single_header(fixed, "Cross-Origin-Embedder-Policy", "require-corp")
        remove_headers(fixed, "Permissions-Policy")
        return fixed, "jointly set COOP and COEP without disabling cross-origin-isolated"
    if issue == "corp_same_site_allows_cross_origin_same_site":
        set_single_header(fixed, "Cross-Origin-Resource-Policy", "same-origin")
        return fixed, "tighten CORP from same-site to same-origin"
    if issue == "permissions_policy_feature_disabled":
        remove_headers(fixed, "Permissions-Policy")
        return fixed, "remove the empty allowlist that disables the intended feature"
    if issue == "permissions_policy_feature_overallowed":
        feature = first_context(fixed, "feature", "geolocation")
        set_single_header(fixed, "Permissions-Policy", f"{feature}=()")
        return fixed, "replace wildcard allowlist with an empty allowlist for the denied feature"
    return fixed, "no repair rule declared"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixtures", default="artifact/data/extended_fixtures.json")
    ap.add_argument("--out", default="artifact/results/extended_locked/repair_synthesis.csv")
    ap.add_argument("--fixed-fixtures", default="artifact/results/extended_locked/repaired_positive_fixtures.json")
    ap.add_argument("--metrics", default="artifact/results/extended_locked/repair_synthesis_metrics.json")
    args = ap.parse_args()
    fixtures = load_fixtures(args.fixtures)
    rows: List[Dict[str, object]] = []
    fixed_fixtures: List[Dict[str, object]] = []
    for fixture in fixtures:
        expected = str(fixture.get("expected_issue", "none"))
        if expected == "none":
            continue
        before = [f.issue for f in analyze_fixture(fixture)]
        fixed, repair = repair_fixture(fixture, expected)
        fixed["id"] = f"{fixture['id']}__repair"
        after = [f.issue for f in analyze_fixture(fixed)]
        fixed_fixtures.append(fixed)
        rows.append({
            "fixture_id": fixture.get("id", ""),
            "expected_issue": expected,
            "issues_before": ";".join(before) if before else "none",
            "repair_action": repair,
            "issues_after": ";".join(after) if after else "none",
            "target_issue_removed": expected not in after,
            "all_issues_removed": len(after) == 0,
        })
    out = Path(args.out); out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        fieldnames = ["fixture_id", "expected_issue", "issues_before", "repair_action", "issues_after", "target_issue_removed", "all_issues_removed"]
        w = csv.DictWriter(fh, fieldnames=fieldnames); w.writeheader(); w.writerows(rows)
    Path(args.fixed_fixtures).write_text(json.dumps(fixed_fixtures, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    metrics = {
        "positive_fixtures": len(rows),
        "target_issue_removed": sum(1 for r in rows if r["target_issue_removed"]),
        "all_issues_removed": sum(1 for r in rows if r["all_issues_removed"]),
        "unrepaired": [r for r in rows if not r["target_issue_removed"]],
        "interpretation": "Deterministic issue-specific repairs under encoded semantics; not proof of deployability in arbitrary applications.",
    }
    Path(args.metrics).write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(metrics, sort_keys=True))


if __name__ == "__main__":
    main()
