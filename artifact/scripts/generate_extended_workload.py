#!/usr/bin/env python3
"""Generate the protocol-amended semantic stress workload.

The extended workload keeps the original locked fixture denominator intact and
adds deterministic metamorphic variants plus source-grounded edge families. It
is designed to test whether the semantic oracle depends on policy semantics
rather than on brittle header spelling, order, or small fixture templates. The
script performs no network access.
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import copy
import csv
import hashlib
import json
from pathlib import Path
from typing import Dict, Iterable, List

ROOT = Path(__file__).resolve().parents[2]
ART = ROOT / "artifact"
DATA = ART / "data"
RESULTS = ART / "results" / "extended_locked"
DATE = "2026-06-20"


def stable_hash(obj: object) -> str:
    payload = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: List[Dict[str, object]], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows([{k: row.get(k, "") for k in fieldnames} for row in rows])


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def clone_with_id(fixture: Dict[str, object], new_id: str, variant: str, operator: str, operator_class: str) -> Dict[str, object]:
    f = copy.deepcopy(fixture)
    f["id"] = new_id
    f["variant"] = variant
    f["mutation_parent"] = fixture.get("id", "")
    f["mutation_operator"] = operator
    f["mutation_operator_class"] = operator_class
    f["locked_status"] = "protocol_amendment_AM001_extended_workload"
    return f


def lower_header_names(fixture: Dict[str, object]) -> Dict[str, object]:
    f = copy.deepcopy(fixture)
    for h in f.get("headers", []):
        h["name"] = str(h.get("name", "")).lower()
    return f


def reverse_headers(fixture: Dict[str, object]) -> Dict[str, object]:
    f = copy.deepcopy(fixture)
    f["headers"] = list(reversed(f.get("headers", [])))
    return f


def policy_whitespace(fixture: Dict[str, object]) -> Dict[str, object]:
    f = copy.deepcopy(fixture)
    for h in f.get("headers", []):
        name = str(h.get("name", "")).lower()
        if "policy" in name or "security" in name:
            h["value"] = str(h.get("value", "")).replace(";", " ; ").replace("  ", " ").strip()
    return f


def metamorphic_variants(base: List[Dict[str, object]]) -> List[Dict[str, object]]:
    variants: List[Dict[str, object]] = []
    operators = [
        ("header_name_casefold", "semantic_preserving", lower_header_names),
        ("header_order_reverse", "semantic_preserving", reverse_headers),
        ("directive_whitespace_expand", "semantic_preserving", policy_whitespace),
    ]
    for fixture in base:
        variants.append(copy.deepcopy(fixture))
        for op, op_class, fn in operators:
            mutated = fn(fixture)
            mutated = clone_with_id(mutated, f"{fixture['id']}__{op}", f"{fixture.get('variant','base')}__{op}", op, op_class)
            variants.append(mutated)
    return variants


def new_fixture(fid: str, family: str, source_claim_ids: List[str], intent_class: str, expected_issue: str, role: str, variant: str, headers: List[Dict[str, str]], context: Dict[str, object], rule_id: str, claim: str) -> Dict[str, object]:
    f: Dict[str, object] = {
        "id": fid,
        "policy_family": family,
        "public_source_id": source_claim_ids[0] if source_claim_ids else "AM001_SYNTHETIC_SOURCE_GROUNDED",
        "source_claim_ids": source_claim_ids,
        "intent": {"class": intent_class, "claim": claim},
        "expected_issue": expected_issue,
        "fixture_role": role,
        "variant": variant,
        "headers": headers,
        "context": context,
        "generation_rule_id": rule_id,
        "locked_status": "protocol_amendment_AM001_extended_workload",
        "mutation_operator": "source_grounded_template",
        "mutation_operator_class": "new_semantic_edge" if expected_issue != "none" else "negative_control",
    }
    f["fixture_hash"] = stable_hash({k: v for k, v in f.items() if k != "fixture_hash"})
    return f


def source_grounded_edges() -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    origins = [
        ("https://app.example", "https://cdn.example"),
        ("https://admin.example", "https://assets.example"),
        ("https://shop.example", "https://scripts.partner"),
        ("https://docs.example", "https://static.example"),
        ("https://a.example", "https://b.example"),
        ("https://tenant.example", "https://cdn.tenant.example"),
    ]
    # 1. Multiple enforced CSP policies overblock a trusted script.
    for i, (doc, res) in enumerate(origins, 1):
        rows.append(new_fixture(
            f"AM1_CSP_MULTI_OVERBLOCK_{i:02d}", "CSP/composition", ["CL_CSP_03"], "allow_trusted_script", "csp_multiple_policy_overblocks_trusted_script", "positive", "multiple_enforced_policy_intersection",
            [{"name": "Content-Security-Policy", "value": f"script-src {res}"}, {"name": "Content-Security-Policy", "value": "script-src 'self'"}],
            {"document_origin": doc, "resource_origin": res, "resource_kind": "script", "scheme": "https"}, "GF_CSP_MULTI_INTERSECTION", "Allow the declared trusted script source."))
    # 2. Frame ancestors delivered through report-only.
    for i, (doc, _) in enumerate(origins, 1):
        rows.append(new_fixture(
            f"AM1_CSP_FRAME_RO_{i:02d}", "CSP/framing", ["CL_CSP_01"], "enforce_framing_protection", "csp_frame_ancestors_report_only_not_enforced", "positive", "frame_ancestors_report_only",
            [{"name": "Content-Security-Policy-Report-Only", "value": "frame-ancestors 'none'; report-uri /csp"}],
            {"document_origin": doc, "ancestor_origin": "https://embedder.example", "scheme": "https"}, "GF_CSP_FRAME_ANCESTORS_DELIVERY", "Prevent cross-origin framing with frame-ancestors."))
    # 3. Frame ancestors encoded through meta-style fixture surface.
    for i, (doc, _) in enumerate(origins, 1):
        rows.append(new_fixture(
            f"AM1_CSP_FRAME_META_{i:02d}", "CSP/framing", ["CL_CSP_01"], "enforce_framing_protection", "csp_frame_ancestors_meta_delivery_unsupported", "positive", "frame_ancestors_meta_surface",
            [{"name": "Content-Security-Policy-Meta", "value": "frame-ancestors 'none'"}],
            {"document_origin": doc, "ancestor_origin": "https://embedder.example", "scheme": "https", "delivery_surface": "meta"}, "GF_CSP_FRAME_ANCESTORS_META", "Prevent cross-origin framing with frame-ancestors."))
    # 4. Duplicate ACAO blocks intended credentialed CORS.
    for i, (doc, res) in enumerate(origins, 1):
        rows.append(new_fixture(
            f"AM1_CORS_DUP_ACAO_{i:02d}", "CORS", ["CL_CORS_02"], "allow_credentialed_cors", "cors_duplicate_acao_not_shareable", "positive", "duplicate_acao",
            [{"name": "Access-Control-Allow-Origin", "value": doc}, {"name": "Access-Control-Allow-Origin", "value": res}, {"name": "Access-Control-Allow-Credentials", "value": "true"}],
            {"document_origin": res, "request_origin": doc, "credentials_mode": "include", "scheme": "https"}, "GF_CORS_DUPLICATE_ACAO", "Allow one credentialed caller."))
    # 5. ACAC exact-value mismatch.
    for i, (doc, res) in enumerate(origins, 1):
        rows.append(new_fixture(
            f"AM1_CORS_ACAC_CASE_{i:02d}", "CORS", ["CL_CORS_02"], "allow_credentialed_cors", "cors_acac_case_sensitive_not_shareable", "positive", "acac_case_mismatch",
            [{"name": "Access-Control-Allow-Origin", "value": doc}, {"name": "Access-Control-Allow-Credentials", "value": "True"}],
            {"document_origin": res, "request_origin": doc, "credentials_mode": "include", "scheme": "https"}, "GF_CORS_ACAC_CASE", "Allow one credentialed caller."))
    # 6. Dynamic origin reflection without Vary in shared-cache context.
    for i, (doc, res) in enumerate(origins, 1):
        rows.append(new_fixture(
            f"AM1_CORS_VARY_{i:02d}", "CORS/cache", ["CL_CORS_03"], "partition_cors_cache_by_origin", "cors_dynamic_origin_without_vary", "positive", "dynamic_acao_without_vary",
            [{"name": "Access-Control-Allow-Origin", "value": "$ORIGIN"}, {"name": "Access-Control-Allow-Credentials", "value": "true"}],
            {"document_origin": res, "request_origin": doc, "credentials_mode": "include", "shared_cache": True, "scheme": "https"}, "GF_CORS_DYNAMIC_VARY", "Partition dynamic CORS responses by Origin in shared caches."))
    # 7. Invalid HSTS max-age.
    for i, (doc, _) in enumerate(origins, 1):
        rows.append(new_fixture(
            f"AM1_HSTS_INVALID_{i:02d}", "HSTS", ["CL_HSTS_01"], "enforce_https_only", "hsts_invalid_max_age_ignored", "positive", "invalid_max_age",
            [{"name": "Strict-Transport-Security", "value": "max-age=abc; includeSubDomains"}],
            {"document_origin": doc, "scheme": "https"}, "GF_HSTS_INVALID_MAX_AGE", "Establish HTTPS-only state."))
    # 8. Missing includeSubDomains under subdomain intent.
    for i, (doc, _) in enumerate(origins, 1):
        rows.append(new_fixture(
            f"AM1_HSTS_SUBDOMAIN_{i:02d}", "HSTS/subdomains", ["CL_HSTS_03"], "enforce_https_subdomains", "hsts_missing_include_subdomains", "positive", "missing_include_subdomains",
            [{"name": "Strict-Transport-Security", "value": "max-age=31536000"}],
            {"document_origin": doc, "scheme": "https", "subdomain_request": True}, "GF_HSTS_INCLUDE_SUBDOMAINS", "Extend HTTPS-only state to subdomains."))
    # 9. HSTS preload criteria incomplete.
    bad_hsts = ["max-age=31536000; preload", "max-age=1000; includeSubDomains; preload", "includeSubDomains; preload", "max-age=63072000; includeSubDomains", "max-age=0; includeSubDomains; preload", "max-age=31536000"]
    for i, value in enumerate(bad_hsts, 1):
        doc = origins[i-1][0]
        rows.append(new_fixture(
            f"AM1_HSTS_PRELOAD_{i:02d}", "HSTS/preload", ["CL_HSTS_05"], "expect_hsts_preload", "hsts_preload_criteria_not_met", "positive", "preload_criterion_incomplete",
            [{"name": "Strict-Transport-Security", "value": value}],
            {"document_origin": doc, "scheme": "https"}, "GF_HSTS_PRELOAD_CRITERION", "Prepare an HSTS policy for preload eligibility."))
    # 10. CORP same-site weaker than same-origin intent.
    same_site_pairs = [
        ("https://app.example", "https://cdn.example"),
        ("https://a.shop.example", "https://b.shop.example"),
        ("https://tenant.example", "https://assets.tenant.example"),
        ("https://docs.example", "https://static.example"),
        ("https://main.example", "https://img.example"),
        ("https://foo.example", "https://bar.example"),
    ]
    for i, (doc, res) in enumerate(same_site_pairs, 1):
        rows.append(new_fixture(
            f"AM1_CORP_SAMESITE_{i:02d}", "CORP", ["CL_COEP_02"], "deny_cross_origin_embedding", "corp_same_site_allows_cross_origin_same_site", "positive", "corp_same_site_cross_origin",
            [{"name": "Cross-Origin-Resource-Policy", "value": "same-site"}],
            {"document_origin": doc, "resource_origin": res, "request_mode": "no-cors", "scheme": "https"}, "GF_CORP_SAME_SITE", "Deny cross-origin embedding, not only cross-site embedding."))
    # 11. Permissions-Policy over-allows denied feature.
    for i, (doc, res) in enumerate(origins, 1):
        rows.append(new_fixture(
            f"AM1_PERM_OVERALLOW_{i:02d}", "Permissions-Policy", ["CL_PERM_02"], "deny_browser_feature", "permissions_policy_feature_overallowed", "positive", "feature_allowlist_wildcard",
            [{"name": "Permissions-Policy", "value": "geolocation=*"}],
            {"document_origin": doc, "target_origin": res, "feature": "geolocation", "scheme": "https"}, "GF_PERMISSIONS_OVERALLOW", "Deny selected browser feature to third-party origins."))
    # 12. Positive controls for new semantics.
    for i, (doc, res) in enumerate(origins[:4], 1):
        rows.append(new_fixture(
            f"AM1_NEG_CSP_ALLOW_{i:02d}", "CSP/composition", ["CL_CSP_03"], "allow_trusted_script", "none", "negative_control", "multiple_policy_allows_trusted",
            [{"name": "Content-Security-Policy", "value": f"script-src {res}"}, {"name": "Content-Security-Policy", "value": f"default-src 'self'; script-src {res}"}],
            {"document_origin": doc, "resource_origin": res, "resource_kind": "script", "scheme": "https"}, "GF_CSP_MULTI_INTERSECTION", "Allow the declared trusted script source."))
    for i, (doc, res) in enumerate(origins[:4], 1):
        rows.append(new_fixture(
            f"AM1_NEG_CORS_OK_{i:02d}", "CORS", ["CL_CORS_02"], "allow_credentialed_cors", "none", "negative_control", "specific_acao_acac_true",
            [{"name": "Access-Control-Allow-Origin", "value": doc}, {"name": "Access-Control-Allow-Credentials", "value": "true"}, {"name": "Vary", "value": "Origin"}],
            {"document_origin": res, "request_origin": doc, "credentials_mode": "include", "shared_cache": True, "scheme": "https"}, "GF_CORS_POSITIVE_CONTROL", "Allow one credentialed caller."))
    for i, (doc, _) in enumerate(origins[:4], 1):
        rows.append(new_fixture(
            f"AM1_NEG_HSTS_PRELOAD_OK_{i:02d}", "HSTS/preload", ["CL_HSTS_05"], "expect_hsts_preload", "none", "negative_control", "preload_criterion_complete",
            [{"name": "Strict-Transport-Security", "value": "max-age=63072000; includeSubDomains; preload"}],
            {"document_origin": doc, "scheme": "https"}, "GF_HSTS_PRELOAD_CRITERION", "Prepare an HSTS policy for preload eligibility."))
    for i, (doc, res) in enumerate(origins[:4], 1):
        rows.append(new_fixture(
            f"AM1_NEG_CORP_SO_{i:02d}", "CORP", ["CL_COEP_02"], "deny_cross_origin_embedding", "none", "negative_control", "corp_same_origin_or_none",
            [{"name": "Cross-Origin-Resource-Policy", "value": "same-origin"}],
            {"document_origin": doc, "resource_origin": res, "request_mode": "no-cors", "scheme": "https"}, "GF_CORP_SAME_ORIGIN_CONTROL", "Deny cross-origin embedding, not only cross-site embedding."))
    for i, (doc, res) in enumerate(origins[:4], 1):
        rows.append(new_fixture(
            f"AM1_NEG_PERM_DENY_{i:02d}", "Permissions-Policy", ["CL_PERM_02"], "deny_browser_feature", "none", "negative_control", "feature_allowlist_empty",
            [{"name": "Permissions-Policy", "value": "geolocation=()"}],
            {"document_origin": doc, "target_origin": res, "feature": "geolocation", "scheme": "https"}, "GF_PERMISSIONS_OVERALLOW", "Deny selected browser feature to third-party origins."))
    for i, (doc, _) in enumerate(origins[:4], 1):
        rows.append(new_fixture(
            f"AM1_NEG_FRAME_ENFORCED_{i:02d}", "CSP/framing", ["CL_CSP_01"], "enforce_framing_protection", "none", "negative_control", "frame_ancestors_enforced",
            [{"name": "Content-Security-Policy", "value": "frame-ancestors 'none'"}],
            {"document_origin": doc, "ancestor_origin": "https://embedder.example", "scheme": "https"}, "GF_CSP_FRAME_ANCESTORS_DELIVERY", "Prevent cross-origin framing with frame-ancestors."))
    return rows


def manifest_rows(fixtures: List[Dict[str, object]]) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    for f in fixtures:
        if "fixture_hash" not in f:
            f["fixture_hash"] = stable_hash({k: v for k, v in f.items() if k != "fixture_hash"})
        rows.append({
            "fixture_id": f.get("id", ""),
            "policy_family": f.get("policy_family", ""),
            "source_claim_ids": ";".join(f.get("source_claim_ids", [])) if isinstance(f.get("source_claim_ids"), list) else f.get("source_claim_ids", ""),
            "intent_class": f.get("intent", {}).get("class", "") if isinstance(f.get("intent"), dict) else "",
            "expected_issue": f.get("expected_issue", ""),
            "fixture_role": f.get("fixture_role", ""),
            "variant": f.get("variant", ""),
            "mutation_parent": f.get("mutation_parent", ""),
            "mutation_operator": f.get("mutation_operator", "seed"),
            "mutation_operator_class": f.get("mutation_operator_class", "locked_seed"),
            "header_count": len(f.get("headers", [])) if isinstance(f.get("headers", []), list) else 0,
            "context_keys": ";".join(sorted(f.get("context", {}).keys())) if isinstance(f.get("context"), dict) else "",
            "generation_rule_id": f.get("generation_rule_id", ""),
            "fixture_hash": f.get("fixture_hash", ""),
            "locked_status": f.get("locked_status", "original_locked"),
        })
    return rows


def main() -> None:
    base = load_json(DATA / "locked_full_fixtures.json")
    if not isinstance(base, list):
        raise SystemExit("locked_full_fixtures.json must be a list")
    extended = metamorphic_variants(base) + source_grounded_edges()
    seen = set()
    for f in extended:
        fid = str(f["id"])
        if fid in seen:
            raise SystemExit(f"duplicate fixture id: {fid}")
        seen.add(fid)
        f["fixture_hash"] = stable_hash({k: v for k, v in f.items() if k != "fixture_hash"})
    write_json(DATA / "extended_fixtures.json", extended)
    rows = manifest_rows(extended)
    write_csv(DATA / "extended_fixture_manifest.csv", rows, [
        "fixture_id", "policy_family", "source_claim_ids", "intent_class", "expected_issue", "fixture_role", "variant",
        "mutation_parent", "mutation_operator", "mutation_operator_class", "header_count", "context_keys", "generation_rule_id", "fixture_hash", "locked_status",
    ])
    by_class: Dict[str, int] = {}
    by_issue: Dict[str, int] = {}
    for f in extended:
        by_class[str(f.get("mutation_operator_class", "locked_seed"))] = by_class.get(str(f.get("mutation_operator_class", "locked_seed")), 0) + 1
        by_issue[str(f.get("expected_issue", "none"))] = by_issue.get(str(f.get("expected_issue", "none")), 0) + 1
    summary = {
        "amendment": "AM-001",
        "base_locked_fixtures": len(base),
        "extended_fixtures": len(extended),
        "expected_positive_fixtures": sum(1 for f in extended if f.get("expected_issue") != "none"),
        "negative_controls": sum(1 for f in extended if f.get("expected_issue") == "none"),
        "mutation_operator_classes": by_class,
        "expected_issue_counts": dict(sorted(by_issue.items())),
        "interpretation": "Protocol-amended deterministic stress workload; not a live-web prevalence sample.",
    }
    write_json(RESULTS / "extended_workload_summary.json", summary)
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
