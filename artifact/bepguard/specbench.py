"""Source-derived boundary benchmark generator for BEP semantic fragments.

BEP-Deep is the locked research denominator.  This module creates a separate
BEP-SpecBench conformance workload from admitted source/rule ledgers.  The goal
is not to inflate the empirical denominator; the goal is to add an executable
evidence-facing benchmark that probes semantic hinges named by public sources,
including boundaries that may not occur in the locked fixtures.

Each generated case carries a rule identifier, a source claim identifier when
available, an expected issue set, and a role.  The verifier runs the operational
semantic oracle on the generated fixture and records exact agreements.
"""
from __future__ import annotations

import copy
import csv
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple

sys.dont_write_bytecode = True


def _scripts_dir(root: Path) -> Path:
    return root / "artifact" / "scripts"


def _import_semantics(root: Path):
    scripts = _scripts_dir(root)
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import bep_semantics  # type: ignore
    return bep_semantics


@dataclass(frozen=True)
class SpecCase:
    case_id: str
    rule_id: str
    source_claim_id: str
    description: str
    fixture: Mapping[str, Any]
    expected_issues: Tuple[str, ...]
    role: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "rule_id": self.rule_id,
            "source_claim_id": self.source_claim_id,
            "description": self.description,
            "fixture": dict(self.fixture),
            "expected_issues": list(self.expected_issues),
            "role": self.role,
        }


@dataclass(frozen=True)
class SpecResult:
    case_id: str
    rule_id: str
    source_claim_id: str
    role: str
    expected_issues: Tuple[str, ...]
    actual_issues: Tuple[str, ...]
    passed: bool
    description: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "rule_id": self.rule_id,
            "source_claim_id": self.source_claim_id,
            "role": self.role,
            "expected_issues": list(self.expected_issues),
            "actual_issues": list(self.actual_issues),
            "passed": self.passed,
            "description": self.description,
        }


def _fixture(case_id: str, headers: List[Dict[str, str]], intent_class: str, expected_issue: str = "", policy_family: str = "SpecBench", context: Optional[Dict[str, Any]] = None, claim_id: str = "CL_SPECBENCH") -> Dict[str, Any]:
    return {
        "id": case_id,
        "fixture_role": "positive" if expected_issue else "negative_control",
        "expected_issue": expected_issue,
        "headers": list(headers) + [{"name": "X-BEPGuard-SpecBench", "value": "source-derived-boundary"}],
        "intent": {"class": intent_class, "claim": f"SpecBench probe for {intent_class}."},
        "context": context or {"document_origin": "https://app.example", "resource_origin": "https://evil.example", "scheme": "https"},
        "policy_family": policy_family,
        "source_claim_ids": [claim_id],
        "public_source_id": claim_id,
        "variant": case_id.lower(),
    }


def _csp_cases() -> List[SpecCase]:
    base_ctx = {"document_origin": "https://app.example", "resource_origin": "https://evil.example", "resource_kind": "script", "scheme": "https"}
    cases = [
        SpecCase("SB_CSP_REPORT_ONLY_MONITOR_POS", "R_CSP_REPORT_ONLY_MONITOR", "CL_CSP_01", "report-only CSP monitors but does not enforce", _fixture("SB_CSP_REPORT_ONLY_MONITOR_POS", [{"name": "Content-Security-Policy-Report-Only", "value": "script-src 'self'; report-uri /csp"}], "enforce_script_restriction", "csp_report_only_not_enforced", "CSP", base_ctx, "CL_CSP_01"), ("csp_report_only_not_enforced",), "positive"),
        SpecCase("SB_CSP_ENFORCED_SELF_NEG", "R_CSP_REPORT_ONLY_MONITOR", "CL_CSP_01", "enforced CSP self blocks the probed third-party script", _fixture("SB_CSP_ENFORCED_SELF_NEG", [{"name": "Content-Security-Policy", "value": "script-src 'self'; object-src 'none'"}], "enforce_script_restriction", "", "CSP", base_ctx, "CL_CSP_01"), tuple(), "negative_control"),
        SpecCase("SB_CSP_DEFAULT_WILDCARD_POS", "R_CSP_DEFAULT_SRC_FALLBACK", "CL_CSP_02", "default-src wildcard authorizes script when script-src absent", _fixture("SB_CSP_DEFAULT_WILDCARD_POS", [{"name": "Content-Security-Policy", "value": "default-src *"}], "enforce_script_restriction", "csp_effective_script_allowance", "CSP", base_ctx, "CL_CSP_02"), ("csp_effective_script_allowance",), "positive"),
        SpecCase("SB_CSP_DEFAULT_SELF_NEG", "R_CSP_DEFAULT_SRC_FALLBACK", "CL_CSP_02", "default-src self blocks third-party script when script-src absent", _fixture("SB_CSP_DEFAULT_SELF_NEG", [{"name": "Content-Security-Policy", "value": "default-src 'self'"}], "enforce_script_restriction", "", "CSP", base_ctx, "CL_CSP_02"), tuple(), "negative_control"),
        SpecCase("SB_CSP_SCRIPT_OVERRIDES_DEFAULT_POS", "R_CSP_SCRIPT_SRC_OVERRIDES_DEFAULT", "CL_CSP_03", "explicit script-src wildcard overrides stricter default-src", _fixture("SB_CSP_SCRIPT_OVERRIDES_DEFAULT_POS", [{"name": "Content-Security-Policy", "value": "default-src 'self'; script-src *"}], "enforce_script_restriction", "csp_effective_script_allowance", "CSP", base_ctx, "CL_CSP_03"), ("csp_effective_script_allowance",), "positive"),
        SpecCase("SB_CSP_SCRIPT_ELEM_PRECEDENCE_POS", "R_CSP_DEFAULT_SRC_FALLBACK", "CL_CSP_02", "script-src-elem has precedence over script-src for script element loads", _fixture("SB_CSP_SCRIPT_ELEM_PRECEDENCE_POS", [{"name": "Content-Security-Policy", "value": "default-src 'self'; script-src 'self'; script-src-elem *"}], "enforce_script_restriction", "csp_effective_script_allowance", "CSP", base_ctx, "CL_CSP_02"), ("csp_effective_script_allowance",), "positive"),
        SpecCase("SB_CSP_SCRIPT_ELEM_PRECEDENCE_CLAIM_POS", "R_CSP_DEFAULT_SRC_FALLBACK", "CL_CSP_04", "script-src-elem claim exercises the ordered script-element fallback list", _fixture("SB_CSP_SCRIPT_ELEM_PRECEDENCE_CLAIM_POS", [{"name": "Content-Security-Policy", "value": "default-src 'none'; script-src 'self'; script-src-elem *"}], "enforce_script_restriction", "csp_effective_script_allowance", "CSP", base_ctx, "CL_CSP_04"), ("csp_effective_script_allowance",), "positive"),
        SpecCase("SB_CSP_MULTI_POLICY_MEET_POS", "R_CSP_MULTIPLE_POLICY_INTERSECTION", "CL_CSP_08", "multiple CSP fields compose conjunctively", _fixture("SB_CSP_MULTI_POLICY_MEET_POS", [{"name": "Content-Security-Policy", "value": "script-src 'self' https://cdn.example"}, {"name": "Content-Security-Policy", "value": "script-src 'self'"}], "allow_trusted_script", "csp_multiple_policy_overblocks_trusted_script", "Layered policy composition", {"document_origin": "https://app.example", "resource_origin": "https://cdn.example", "scheme": "https"}, "CL_CSP_08"), ("csp_multiple_policy_overblocks_trusted_script",), "positive"),
        SpecCase("SB_CSP_NONCE_STATIC_POS", "R_CSP_NONCE_PER_REQUEST", "CL_CSP_06", "nonce-bearing CSP is incompatible with static render context", _fixture("SB_CSP_NONCE_STATIC_POS", [{"name": "Content-Security-Policy", "value": "script-src 'nonce-abc123' 'strict-dynamic'; object-src 'none'"}], "nonce_based_strict_csp", "nonce_csp_static_render_incompatibility", "CSP/framework", {"document_origin": "https://app.example", "resource_origin": "https://cdn.example", "scheme": "https", "static_render": True}, "CL_CSP_06"), ("nonce_csp_static_render_incompatibility",), "positive"),
        SpecCase("SB_NEXT_NONCE_DYNAMIC_REQUIRED_POS", "R_NEXT_NONCE_DYNAMIC_REQUIRED", "CL_NEXT_01", "Next.js nonce CSP requires dynamic rendering", _fixture("SB_NEXT_NONCE_DYNAMIC_REQUIRED_POS", [{"name": "Content-Security-Policy", "value": "script-src 'nonce-abc123' 'strict-dynamic'; object-src 'none'"}], "nonce_based_strict_csp", "nonce_csp_static_render_incompatibility", "CSP/framework", {"document_origin": "https://app.example", "resource_origin": "https://cdn.example", "scheme": "https", "static_render": True, "rendering_variant": "static"}, "CL_NEXT_01"), ("nonce_csp_static_render_incompatibility",), "positive"),
        SpecCase("SB_NEXT_NONCE_STATIC_OPTIMIZATION_POS", "R_NEXT_NONCE_DYNAMIC_REQUIRED", "CL_NEXT_02", "Next.js nonce CSP conflicts with static optimization and cached rendering", _fixture("SB_NEXT_NONCE_STATIC_OPTIMIZATION_POS", [{"name": "Content-Security-Policy", "value": "script-src 'nonce-def456' 'strict-dynamic'; object-src 'none'"}], "nonce_based_strict_csp", "nonce_csp_static_render_incompatibility", "CSP/framework", {"document_origin": "https://app.example", "resource_origin": "https://cdn.example", "scheme": "https", "static_render": True, "rendering_variant": "static-cache"}, "CL_NEXT_02"), ("nonce_csp_static_render_incompatibility",), "positive"),
    ]
    # Closure cases: previously uncovered locked issue classes now
    # receive independent source-derived SpecBench pressure outside BEP-Deep.
    cases.append(SpecCase("SB_CSP_REQUIRED_SCRIPT_COMPOSITION_POS", "R_CSP_CONJUNCTIVE_COMPOSITION", "CL_CSP_08", "a later enforced CSP field blocks a script required by the generation intent", _fixture("SB_CSP_REQUIRED_SCRIPT_COMPOSITION_POS", [{"name": "Content-Security-Policy", "value": "script-src 'self' https://cdn.example"}, {"name": "Content-Security-Policy", "value": "script-src 'self'"}], "allow_required_script_after_policy_composition", "csp_conjunctive_policy_composition_blocks_required_script", "Layered policy composition", {"document_origin": "https://app.example", "resource_origin": "https://cdn.example", "resource_kind": "script", "scheme": "https"}, "CL_CSP_08"), ("csp_conjunctive_policy_composition_blocks_required_script",), "positive"))
    cases.append(SpecCase("SB_CSP_FRAME_ANCESTORS_REPORT_ONLY_POS", "R_CSP_META_REPORT_ONLY_UNSUPPORTED", "CL_CSP_05", "frame-ancestors in report-only CSP does not enforce framing", _fixture("SB_CSP_FRAME_ANCESTORS_REPORT_ONLY_POS", [{"name": "Content-Security-Policy-Report-Only", "value": "frame-ancestors 'none'"}], "enforce_framing_protection", "csp_frame_ancestors_report_only_not_enforced", "CSP/framing", {"document_origin": "https://app.example", "ancestor_origin": "https://embedder.example", "scheme": "https"}, "CL_CSP_05"), ("csp_frame_ancestors_report_only_not_enforced",), "positive"))
    cases.append(SpecCase("SB_CSP_FRAME_ANCESTORS_META_POS", "R_CSP_META_REPORT_ONLY_UNSUPPORTED", "CL_CSP_05", "frame-ancestors through meta-delivery is outside enforcing header delivery", _fixture("SB_CSP_FRAME_ANCESTORS_META_POS", [{"name": "Content-Security-Policy-Meta", "value": "frame-ancestors 'none'"}], "enforce_framing_protection", "csp_frame_ancestors_meta_delivery_unsupported", "CSP/framing", {"document_origin": "https://app.example", "ancestor_origin": "https://embedder.example", "scheme": "https"}, "CL_CSP_05"), ("csp_frame_ancestors_meta_delivery_unsupported",), "positive"))
    layered = _fixture("SB_LAYERED_REMOVE_ENFORCEMENT_POS", [], "preserve_enforced_policy_across_layers", "layered_header_override_drops_enforcement", "Layered policy composition", {"document_origin": "https://app.example", "resource_origin": "https://evil.example", "resource_kind": "script", "scheme": "https", "expected_enforced_csp": True}, "CL_LAYER_01")
    layered["layers"] = [
        {"layer": "framework", "op": "append", "headers": [{"name": "Content-Security-Policy", "value": "script-src 'self'"}]},
        {"layer": "edge", "op": "remove", "headers": [{"name": "Content-Security-Policy", "value": ""}]},
        {"layer": "migration", "op": "append", "headers": [{"name": "Content-Security-Policy-Report-Only", "value": "script-src 'self'"}]},
    ]
    cases.append(SpecCase("SB_LAYERED_REMOVE_ENFORCEMENT_POS", "R_LAYERED_HEADER_SURFACE", "CL_LAYER_01", "ordered generation layers remove enforced CSP and leave report-only policy", layered, ("layered_header_override_drops_enforcement",), "positive"))
    return cases


def _cors_cases() -> List[SpecCase]:
    ctx = {"document_origin": "https://api.example", "request_origin": "https://app.example", "resource_origin": "https://api.example", "credentials_mode": "include", "scheme": "https"}
    return [
        SpecCase("SB_CORS_WILDCARD_CREDENTIALS_POS", "R_CORS_CREDENTIALS_WILDCARD", "CL_CORS_01", "credentialed CORS cannot use wildcard ACAO", _fixture("SB_CORS_WILDCARD_CREDENTIALS_POS", [{"name": "Access-Control-Allow-Origin", "value": "*"}, {"name": "Access-Control-Allow-Credentials", "value": "true"}], "allow_credentialed_cors", "cors_intended_credentialed_share_blocked", "CORS", ctx, "CL_CORS_01"), ("cors_intended_credentialed_share_blocked",), "positive"),
        SpecCase("SB_CORS_REFLECTED_CREDENTIALS_POS", "R_CORS_REFLECTED_ORIGIN_CREDENTIALS", "CL_CORS_04", "reflected origin with credentials contradicts public-denial intent", _fixture("SB_CORS_REFLECTED_CREDENTIALS_POS", [{"name": "Access-Control-Allow-Origin", "value": "$ORIGIN"}, {"name": "Access-Control-Allow-Credentials", "value": "true"}], "deny_public_credentialed_cors", "cors_reflected_origin_with_credentials", "CORS/framework", ctx, "CL_CORS_04"), ("cors_reflected_origin_with_credentials",), "positive"),
        SpecCase("SB_EXPRESS_ORIGIN_TRUE_POS", "R_EXPRESS_CORS_REFLECT_ORIGIN", "CL_EXPRESS_01", "Express cors origin=true reflects request Origin under credentialed denial intent", _fixture("SB_EXPRESS_ORIGIN_TRUE_POS", [{"name": "Access-Control-Allow-Origin", "value": "$ORIGIN"}, {"name": "Access-Control-Allow-Credentials", "value": "true"}], "deny_public_credentialed_cors", "cors_reflected_origin_with_credentials", "CORS/framework", ctx, "CL_EXPRESS_01"), ("cors_reflected_origin_with_credentials",), "positive"),
        SpecCase("SB_EXPRESS_CREDENTIALS_TRUE_POS", "R_EXPRESS_CORS_REFLECT_ORIGIN", "CL_EXPRESS_02", "Express cors credentials=true emits credentialed sharing with reflected Origin", _fixture("SB_EXPRESS_CREDENTIALS_TRUE_POS", [{"name": "Access-Control-Allow-Origin", "value": "$ORIGIN"}, {"name": "Access-Control-Allow-Credentials", "value": "true"}], "deny_public_credentialed_cors", "cors_reflected_origin_with_credentials", "CORS/framework", ctx, "CL_EXPRESS_02"), ("cors_reflected_origin_with_credentials",), "positive"),
        SpecCase("SB_CORS_ACAC_CASE_POS", "R_CORS_ACAC_CASE_SENSITIVE", "CL_CORS_02", "ACAC success value is exactly lowercase true", _fixture("SB_CORS_ACAC_CASE_POS", [{"name": "Access-Control-Allow-Origin", "value": "https://app.example"}, {"name": "Access-Control-Allow-Credentials", "value": "True"}], "allow_credentialed_cors", "cors_acac_case_sensitive_not_shareable", "CORS", ctx, "CL_CORS_02"), ("cors_acac_case_sensitive_not_shareable",), "positive"),
        SpecCase("SB_CORS_DYNAMIC_NO_VARY_POS", "R_CORS_DYNAMIC_ORIGIN_VARY", "CL_CORS_03", "dynamic origin reflection must vary on Origin in shared caches", _fixture("SB_CORS_DYNAMIC_NO_VARY_POS", [{"name": "Access-Control-Allow-Origin", "value": "$ORIGIN"}, {"name": "Access-Control-Allow-Credentials", "value": "true"}], "partition_cors_cache_by_origin", "cors_dynamic_origin_without_vary", "CORS/cache", {**ctx, "shared_cache": True}, "CL_CORS_03"), ("cors_dynamic_origin_without_vary",), "positive"),
        SpecCase("SB_CORS_DYNAMIC_VARY_NEG", "R_CORS_DYNAMIC_ORIGIN_VARY", "CL_CORS_03", "Vary Origin repairs dynamic credentialed CORS cache partitioning", _fixture("SB_CORS_DYNAMIC_VARY_NEG", [{"name": "Access-Control-Allow-Origin", "value": "$ORIGIN"}, {"name": "Access-Control-Allow-Credentials", "value": "true"}, {"name": "Vary", "value": "Origin"}], "partition_cors_cache_by_origin", "", "CORS/cache", {**ctx, "shared_cache": True}, "CL_CORS_03"), tuple(), "negative_control"),
        SpecCase("SB_CORS_EXACT_CREDENTIAL_NEG", "R_CORS_CREDENTIALS_EXACT_ORIGIN", "CL_CORS_01", "exact ACAO plus ACAC true is shareable for credentialed request", _fixture("SB_CORS_EXACT_CREDENTIAL_NEG", [{"name": "Access-Control-Allow-Origin", "value": "https://app.example"}, {"name": "Access-Control-Allow-Credentials", "value": "true"}], "allow_credentialed_cors", "", "CORS", ctx, "CL_CORS_01"), tuple(), "negative_control"),
        SpecCase("SB_CORS_DUPLICATE_ACAO_POS", "R_CORS_SPECIFIC_ORIGIN_CREDENTIALS_SHAREABLE", "CL_CORS_01", "duplicate ACAO fields are not a single valid credentialed authorization", _fixture("SB_CORS_DUPLICATE_ACAO_POS", [{"name": "Access-Control-Allow-Origin", "value": "https://app.example"}, {"name": "Access-Control-Allow-Origin", "value": "https://other.example"}, {"name": "Access-Control-Allow-Credentials", "value": "true"}], "allow_credentialed_cors", "cors_duplicate_acao_not_shareable", "CORS", ctx, "CL_CORS_01"), ("cors_duplicate_acao_not_shareable",), "positive"),
        SpecCase("SB_CORS_DYNAMIC_CREDENTIAL_MISSING_VARY_POS", "R_CORS_DYNAMIC_ORIGIN_VARY", "CL_CORS_03", "dynamic credentialed CORS response lacks Vary Origin under cache-safe intent", _fixture("SB_CORS_DYNAMIC_CREDENTIAL_MISSING_VARY_POS", [{"name": "Access-Control-Allow-Origin", "value": "$ORIGIN"}, {"name": "Access-Control-Allow-Credentials", "value": "true"}], "allow_credentialed_cors_cache_safe", "cors_dynamic_origin_missing_vary", "CORS/cache", {**ctx, "dynamic_origin": True, "shared_cache": True}, "CL_CORS_03"), ("cors_dynamic_origin_missing_vary",), "positive"),
        SpecCase("SB_CORS_DYNAMIC_CREDENTIAL_MISSING_VARY_CLAIM_POS", "R_CORS_DYNAMIC_ORIGIN_VARY", "CL_CORS_05", "dynamic credentialed CORS response lacks Origin-sensitive cache treatment", _fixture("SB_CORS_DYNAMIC_CREDENTIAL_MISSING_VARY_CLAIM_POS", [{"name": "Access-Control-Allow-Origin", "value": "$ORIGIN"}, {"name": "Access-Control-Allow-Credentials", "value": "true"}], "allow_credentialed_cors_cache_safe", "cors_dynamic_origin_missing_vary", "CORS/cache", {**ctx, "dynamic_origin": True, "shared_cache": True}, "CL_CORS_05"), ("cors_dynamic_origin_missing_vary",), "positive"),
    ]


def _hsts_cases() -> List[SpecCase]:
    return [
        SpecCase("SB_HSTS_HTTP_IGNORED_POS", "R_HSTS_HTTPS_ONLY_PROCESSING", "CL_HSTS_01", "STS received over HTTP is ignored", _fixture("SB_HSTS_HTTP_IGNORED_POS", [{"name": "Strict-Transport-Security", "value": "max-age=31536000; includeSubDomains"}], "enforce_https_only", "hsts_header_not_honored_over_http", "HSTS", {"document_origin": "http://app.example", "resource_origin": "http://app.example", "scheme": "http"}, "CL_HSTS_01"), ("hsts_header_not_honored_over_http",), "positive"),
        SpecCase("SB_HSTS_INVALID_MAXAGE_POS", "R_HSTS_MAX_AGE_PARSE", "CL_HSTS_02", "invalid max-age cannot establish known HSTS host", _fixture("SB_HSTS_INVALID_MAXAGE_POS", [{"name": "Strict-Transport-Security", "value": "max-age=abc; includeSubDomains"}], "enforce_https_only", "hsts_invalid_max_age_ignored", "HSTS", {"document_origin": "https://app.example", "resource_origin": "https://app.example", "scheme": "https"}, "CL_HSTS_02"), ("hsts_invalid_max_age_ignored",), "positive"),
        SpecCase("SB_HSTS_ZERO_POS", "R_HSTS_ZERO_MAX_AGE_CLEARS", "CL_HSTS_03", "max-age zero clears HSTS state", _fixture("SB_HSTS_ZERO_POS", [{"name": "Strict-Transport-Security", "value": "max-age=0"}], "enforce_https_only", "hsts_policy_cleared_by_zero_max_age", "HSTS", {"document_origin": "https://app.example", "resource_origin": "https://app.example", "scheme": "https"}, "CL_HSTS_03"), ("hsts_policy_cleared_by_zero_max_age",), "positive"),
        SpecCase("SB_HSTS_SUBDOMAIN_POS", "R_HSTS_INCLUDE_SUBDOMAINS_SCOPE", "CL_HSTS_04", "subdomain intent requires includeSubDomains", _fixture("SB_HSTS_SUBDOMAIN_POS", [{"name": "Strict-Transport-Security", "value": "max-age=31536000"}], "enforce_https_subdomains", "hsts_missing_include_subdomains", "HSTS/subdomains", {"document_origin": "https://app.example", "resource_origin": "https://sub.app.example", "scheme": "https", "subdomain_request": True}, "CL_HSTS_04"), ("hsts_missing_include_subdomains",), "positive"),
        SpecCase("SB_HSTS_PRELOAD_POS", "R_HSTS_PRELOAD_CRITERION", "CL_HSTS_05", "preload intent requires max-age threshold includeSubDomains and preload token", _fixture("SB_HSTS_PRELOAD_POS", [{"name": "Strict-Transport-Security", "value": "max-age=31536000; includeSubDomains"}], "expect_hsts_preload", "hsts_preload_criteria_not_met", "HSTS/preload", {"document_origin": "https://app.example", "resource_origin": "https://app.example", "scheme": "https"}, "CL_HSTS_05"), ("hsts_preload_criteria_not_met",), "positive"),
        SpecCase("SB_HSTS_PRELOAD_NEG", "R_HSTS_PRELOAD_CRITERION", "CL_HSTS_05", "complete preload-oriented header satisfies encoded control", _fixture("SB_HSTS_PRELOAD_NEG", [{"name": "Strict-Transport-Security", "value": "max-age=63072000; includeSubDomains; preload"}], "expect_hsts_preload", "", "HSTS/preload", {"document_origin": "https://app.example", "resource_origin": "https://app.example", "scheme": "https"}, "CL_HSTS_05"), tuple(), "negative_control"),
        SpecCase("SB_HSTS_FRAMEWORK_SUBDOMAIN_SCOPE_POS", "R_HSTS_INCLUDE_SUBDOMAINS_SCOPE", "CL_HSTS_04", "framework HSTS intent covers subdomains but emitted header omits includeSubDomains", _fixture("SB_HSTS_FRAMEWORK_SUBDOMAIN_SCOPE_POS", [{"name": "Strict-Transport-Security", "value": "max-age=31536000"}], "enforce_https_only_subdomains", "hsts_subdomain_scope_not_covered", "HSTS/framework", {"document_origin": "https://app.example", "resource_origin": "https://sub.app.example", "scheme": "https", "subdomain_scope_required": True}, "CL_HSTS_04"), ("hsts_subdomain_scope_not_covered",), "positive"),
    ]


def _coep_corp_cases() -> List[SpecCase]:
    ctx = {"document_origin": "https://app.example", "resource_origin": "https://cdn.other.example", "scheme": "https", "request_mode": "no-cors"}
    return [
        SpecCase("SB_COEP_REQUIRE_CORP_POS", "R_COEP_REQUIRE_CORP_NO_CORS", "CL_COEP_02", "COEP require-corp blocks cross-origin no-cors resource without opt-in", _fixture("SB_COEP_REQUIRE_CORP_POS", [{"name": "Cross-Origin-Embedder-Policy", "value": "require-corp"}], "cross_origin_isolation_without_embed_breakage", "coep_require_corp_blocks_cross_origin_resource", "COEP/CORP/CORS", ctx, "CL_COEP_02"), ("coep_require_corp_blocks_cross_origin_resource",), "positive"),
        SpecCase("SB_COEP_REQUIRE_CORP_MDN_POS", "R_COEP_REQUIRE_CORP_NO_CORS", "CL_COEP_01", "MDN COEP require-corp claim blocks cross-origin no-cors resource without CORP", _fixture("SB_COEP_REQUIRE_CORP_MDN_POS", [{"name": "Cross-Origin-Embedder-Policy", "value": "require-corp"}], "cross_origin_isolation_without_embed_breakage", "coep_require_corp_blocks_cross_origin_resource", "COEP/CORP/CORS", ctx, "CL_COEP_01"), ("coep_require_corp_blocks_cross_origin_resource",), "positive"),
        SpecCase("SB_COEP_CORP_REPAIR_NEG", "R_COEP_REQUIRE_CORP_NO_CORS", "CL_COEP_02", "CORP cross-origin opts a no-cors resource into COEP", _fixture("SB_COEP_CORP_REPAIR_NEG", [{"name": "Cross-Origin-Embedder-Policy", "value": "require-corp"}, {"name": "Cross-Origin-Resource-Policy", "value": "cross-origin"}], "cross_origin_isolation_without_embed_breakage", "", "COEP/CORP/CORS", ctx, "CL_COEP_02"), tuple(), "negative_control"),
        SpecCase("SB_COEP_CORS_NOCORS_POS", "R_COEP_CORS_MODED_OPT_IN", "CL_COEP_02", "CORS headers alone do not authorize no-cors COEP resource edge", _fixture("SB_COEP_CORS_NOCORS_POS", [{"name": "Cross-Origin-Embedder-Policy", "value": "require-corp"}, {"name": "Access-Control-Allow-Origin", "value": "https://app.example"}], "cross_origin_isolation_without_embed_breakage", "coep_require_corp_blocks_cross_origin_resource", "COEP/CORP/CORS", ctx, "CL_COEP_02"), ("coep_require_corp_blocks_cross_origin_resource",), "positive"),
        SpecCase("SB_CORP_SAMESITE_POS", "R_CORP_SAME_SITE_SCOPE", "CL_COEP_02", "CORP same-site still allows same-site cross-origin resource", _fixture("SB_CORP_SAMESITE_POS", [{"name": "Cross-Origin-Resource-Policy", "value": "same-site"}], "deny_cross_origin_embedding", "corp_same_site_allows_cross_origin_same_site", "CORP", {"document_origin": "https://app.example", "resource_origin": "https://cdn.example", "scheme": "https"}, "CL_COEP_02"), ("corp_same_site_allows_cross_origin_same_site",), "positive"),
        SpecCase("SB_ISOLATION_INCOMPLETE_POS", "R_COOP_COEP_ISOLATION_JOINT", "CL_COOP_01", "cross-origin isolation requires joint COOP and COEP headers", _fixture("SB_ISOLATION_INCOMPLETE_POS", [{"name": "Cross-Origin-Opener-Policy", "value": "same-origin"}], "enable_cross_origin_isolation", "cross_origin_isolation_incomplete", "COOP/COEP/Permissions-Policy", {"document_origin": "https://app.example", "resource_origin": "https://app.example", "scheme": "https"}, "CL_COOP_01"), ("cross_origin_isolation_incomplete",), "positive"),
        SpecCase("SB_COOP_UNSAFE_NONE_DEFAULT_POS", "R_COOP_UNSAFE_NONE_DEFAULT", "CL_COOP_02", "COOP unsafe-none/default opts out of the modeled isolation precondition", _fixture("SB_COOP_UNSAFE_NONE_DEFAULT_POS", [{"name": "Cross-Origin-Opener-Policy", "value": "unsafe-none"}, {"name": "Cross-Origin-Embedder-Policy", "value": "require-corp"}], "enable_cross_origin_isolation", "cross_origin_isolation_incomplete", "COOP/COEP/Permissions-Policy", {"document_origin": "https://app.example", "resource_origin": "https://app.example", "scheme": "https"}, "CL_COOP_02"), ("cross_origin_isolation_incomplete",), "positive"),
        SpecCase("SB_ISOLATION_COMPLETE_NEG", "R_COOP_COEP_ISOLATION_JOINT", "CL_COOP_01", "joint COOP and COEP satisfy encoded isolation preconditions", _fixture("SB_ISOLATION_COMPLETE_NEG", [{"name": "Cross-Origin-Opener-Policy", "value": "same-origin"}, {"name": "Cross-Origin-Embedder-Policy", "value": "require-corp"}], "enable_cross_origin_isolation", "", "COOP/COEP/Permissions-Policy", {"document_origin": "https://app.example", "resource_origin": "https://app.example", "scheme": "https"}, "CL_COOP_01"), tuple(), "negative_control"),
    ]


def _permissions_cases() -> List[SpecCase]:
    ctx = {"document_origin": "https://app.example", "resource_origin": "https://app.example", "scheme": "https", "feature": "geolocation", "target_origin": "https://evil.example"}
    return [
        SpecCase("SB_PERMISSIONS_DISABLED_POS", "R_PERMISSIONS_POLICY_EMPTY_ALLOWLIST", "CL_PERM_01", "empty allowlist disables required feature", _fixture("SB_PERMISSIONS_DISABLED_POS", [{"name": "Permissions-Policy", "value": "geolocation=()"}], "allow_browser_feature", "permissions_policy_feature_disabled", "Permissions-Policy", ctx, "CL_PERM_01"), ("permissions_policy_feature_disabled",), "positive"),
        SpecCase("SB_PERMISSIONS_WILDCARD_POS", "R_PERMISSIONS_POLICY_OVERALLOW", "CL_PERM_02", "wildcard allowlist overallows a denied feature", _fixture("SB_PERMISSIONS_WILDCARD_POS", [{"name": "Permissions-Policy", "value": "geolocation=*"}], "deny_browser_feature", "permissions_policy_feature_overallowed", "Permissions-Policy", ctx, "CL_PERM_02"), ("permissions_policy_feature_overallowed",), "positive"),
        SpecCase("SB_PERMISSIONS_SELF_NEG", "R_PERMISSIONS_POLICY_FEATURE_SPECIFIC", "CL_PERM_02", "specific allowlist does not admit denied external origin", _fixture("SB_PERMISSIONS_SELF_NEG", [{"name": "Permissions-Policy", "value": "geolocation=(self)"}], "deny_browser_feature", "", "Permissions-Policy", ctx, "CL_PERM_02"), tuple(), "negative_control"),
    ]


def _variant(case: SpecCase, suffix: str, description_suffix: str, transform: Callable[[Dict[str, Any]], None]) -> SpecCase:
    variant = copy.deepcopy(dict(case.fixture))
    variant["id"] = case.case_id + suffix
    transform(variant)
    return SpecCase(
        case.case_id + suffix,
        case.rule_id,
        case.source_claim_id,
        case.description + description_suffix,
        variant,
        case.expected_issues,
        case.role,
    )




def _compose_transforms(*transforms: Callable[[Dict[str, Any]], None]) -> Callable[[Dict[str, Any]], None]:
    def composed(fixture: Dict[str, Any]) -> None:
        for transform in transforms:
            transform(fixture)
    return composed

def _lowercase_headers(fixture: Dict[str, Any]) -> None:
    for header in fixture.get("headers", []):
        if isinstance(header, dict):
            header["name"] = str(header.get("name", "")).lower()


def _reverse_headers(fixture: Dict[str, Any]) -> None:
    headers = fixture.get("headers", [])
    if isinstance(headers, list):
        fixture["headers"] = list(reversed(headers))


def _add_irrelevant_header(fixture: Dict[str, Any]) -> None:
    headers = fixture.get("headers", [])
    if isinstance(headers, list):
        fixture["headers"] = list(headers) + [{"name": "X-BEPGuard-Noop", "value": "specbench"}]


def _pad_header_values(fixture: Dict[str, Any]) -> None:
    for header in fixture.get("headers", []):
        if isinstance(header, dict):
            value = str(header.get("value", ""))
            header["value"] = f"  {value}  "


def _mixed_case_header_names(fixture: Dict[str, Any]) -> None:
    def mix(name: str) -> str:
        chars = []
        upper = True
        for ch in name:
            if ch.isalpha():
                chars.append(ch.upper() if upper else ch.lower())
                upper = not upper
            else:
                chars.append(ch)
        return "".join(chars)
    for header in fixture.get("headers", []):
        if isinstance(header, dict):
            header["name"] = mix(str(header.get("name", "")))


def _add_noop_vary_header(fixture: Dict[str, Any]) -> None:
    headers = fixture.get("headers", [])
    if isinstance(headers, list):
        fixture["headers"] = list(headers) + [{"name": "Vary", "value": "Accept-Encoding"}]


def _add_context_noise(fixture: Dict[str, Any]) -> None:
    ctx = fixture.get("context", {})
    if isinstance(ctx, dict):
        noisy = dict(ctx)
        noisy["unobserved_assessor_noise"] = "ignored-by-bep-ir"
        fixture["context"] = noisy

def _add_cache_control_noop(fixture: Dict[str, Any]) -> None:
    headers = fixture.get("headers", [])
    if isinstance(headers, list):
        fixture["headers"] = list(headers) + [{"name": "Cache-Control", "value": "no-store"}]


def _add_server_noop(fixture: Dict[str, Any]) -> None:
    headers = fixture.get("headers", [])
    if isinstance(headers, list):
        fixture["headers"] = list(headers) + [{"name": "Server", "value": "bepguard-fixture"}]


def _add_powered_by_noop(fixture: Dict[str, Any]) -> None:
    headers = fixture.get("headers", [])
    if isinstance(headers, list):
        fixture["headers"] = list(headers) + [{"name": "X-Powered-By", "value": "fixture"}]


def _add_accept_ch_noop(fixture: Dict[str, Any]) -> None:
    headers = fixture.get("headers", [])
    if isinstance(headers, list):
        fixture["headers"] = list(headers) + [{"name": "Accept-CH", "value": "Sec-CH-UA"}]


def _add_reporting_noop(fixture: Dict[str, Any]) -> None:
    headers = fixture.get("headers", [])
    if isinstance(headers, list):
        fixture["headers"] = list(headers) + [{"name": "Report-To", "value": "{\"group\":\"bep\",\"max_age\":1,\"endpoints\":[]}"}]


def _add_nel_noop(fixture: Dict[str, Any]) -> None:
    headers = fixture.get("headers", [])
    if isinstance(headers, list):
        fixture["headers"] = list(headers) + [{"name": "NEL", "value": "{\"report_to\":\"bep\",\"max_age\":1}"}]


def _add_date_noop(fixture: Dict[str, Any]) -> None:
    headers = fixture.get("headers", [])
    if isinstance(headers, list):
        fixture["headers"] = list(headers) + [{"name": "Date", "value": "Tue, 23 Jun 2026 00:00:00 GMT"}]


def _sort_headers_by_name(fixture: Dict[str, Any]) -> None:
    headers = fixture.get("headers", [])
    if isinstance(headers, list):
        fixture["headers"] = sorted(list(headers), key=lambda h: str(h.get("name", "")).lower() if isinstance(h, dict) else "")


def _duplicate_irrelevant_header(fixture: Dict[str, Any]) -> None:
    headers = fixture.get("headers", [])
    if isinstance(headers, list):
        fixture["headers"] = list(headers) + [{"name": "X-BEPGuard-Noop", "value": "a"}, {"name": "X-BEPGuard-Noop", "value": "b"}]


def _add_exposed_headers_noop(fixture: Dict[str, Any]) -> None:
    headers = fixture.get("headers", [])
    if isinstance(headers, list):
        fixture["headers"] = list(headers) + [{"name": "Access-Control-Expose-Headers", "value": "X-Trace"}]


def _add_context_method_noise(fixture: Dict[str, Any]) -> None:
    ctx = fixture.get("context", {})
    if isinstance(ctx, dict):
        noisy = dict(ctx)
        noisy["http_method"] = "GET"
        fixture["context"] = noisy


def _add_context_path_noise(fixture: Dict[str, Any]) -> None:
    ctx = fixture.get("context", {})
    if isinstance(ctx, dict):
        noisy = dict(ctx)
        noisy["request_path"] = "/fixture/probe"
        fixture["context"] = noisy


def _add_context_port_noise(fixture: Dict[str, Any]) -> None:
    ctx = fixture.get("context", {})
    if isinstance(ctx, dict):
        noisy = dict(ctx)
        noisy["server_port"] = 443
        fixture["context"] = noisy


def _add_context_agent_noise(fixture: Dict[str, Any]) -> None:
    ctx = fixture.get("context", {})
    if isinstance(ctx, dict):
        noisy = dict(ctx)
        noisy["user_agent_family"] = "fixture-browser"
        fixture["context"] = noisy


def _add_empty_noop_header(fixture: Dict[str, Any]) -> None:
    headers = fixture.get("headers", [])
    if isinstance(headers, list):
        fixture["headers"] = list(headers) + [{"name": "X-BEPGuard-Empty", "value": ""}]


def _add_content_type_noop(fixture: Dict[str, Any]) -> None:
    headers = fixture.get("headers", [])
    if isinstance(headers, list):
        fixture["headers"] = list(headers) + [{"name": "Content-Type", "value": "text/html; charset=utf-8"}]



def _add_referrer_policy_noop(fixture: Dict[str, Any]) -> None:
    headers = fixture.get("headers", [])
    if isinstance(headers, list):
        fixture["headers"] = list(headers) + [{"name": "Referrer-Policy", "value": "strict-origin-when-cross-origin"}]

def _add_etag_noop(fixture: Dict[str, Any]) -> None:
    headers = fixture.get("headers", [])
    if isinstance(headers, list):
        fixture["headers"] = list(headers) + [{"name": "ETag", "value": "\"bepguard-fixed\""}]

def _add_last_modified_noop(fixture: Dict[str, Any]) -> None:
    headers = fixture.get("headers", [])
    if isinstance(headers, list):
        fixture["headers"] = list(headers) + [{"name": "Last-Modified", "value": "Mon, 01 Jan 2024 00:00:00 GMT"}]

def _add_server_timing_noop(fixture: Dict[str, Any]) -> None:
    headers = fixture.get("headers", [])
    if isinstance(headers, list):
        fixture["headers"] = list(headers) + [{"name": "Server-Timing", "value": "bepguard;dur=0"}]

def _add_request_id_noop(fixture: Dict[str, Any]) -> None:
    headers = fixture.get("headers", [])
    if isinstance(headers, list):
        fixture["headers"] = list(headers) + [{"name": "X-Request-ID", "value": "fixed-shadow"}]

def _add_traceparent_noop(fixture: Dict[str, Any]) -> None:
    headers = fixture.get("headers", [])
    if isinstance(headers, list):
        fixture["headers"] = list(headers) + [{"name": "Traceparent", "value": "00-00000000000000000000000000000000-0000000000000000-00"}]

def _add_alt_svc_noop(fixture: Dict[str, Any]) -> None:
    headers = fixture.get("headers", [])
    if isinstance(headers, list):
        fixture["headers"] = list(headers) + [{"name": "Alt-Svc", "value": "h3=\":443\"; ma=86400"}]

def _add_content_encoding_noop(fixture: Dict[str, Any]) -> None:
    headers = fixture.get("headers", [])
    if isinstance(headers, list):
        fixture["headers"] = list(headers) + [{"name": "Content-Encoding", "value": "identity"}]

def _add_x_content_type_options_noop(fixture: Dict[str, Any]) -> None:
    headers = fixture.get("headers", [])
    if isinstance(headers, list):
        fixture["headers"] = list(headers) + [{"name": "X-Content-Type-Options", "value": "nosniff"}]

def _add_link_preload_noop(fixture: Dict[str, Any]) -> None:
    headers = fixture.get("headers", [])
    if isinstance(headers, list):
        fixture["headers"] = list(headers) + [{"name": "Link", "value": "</style.css>; rel=preload; as=style"}]

def _add_early_data_noop(fixture: Dict[str, Any]) -> None:
    headers = fixture.get("headers", [])
    if isinstance(headers, list):
        fixture["headers"] = list(headers) + [{"name": "Early-Data", "value": "0"}]

def _add_accept_ranges_noop(fixture: Dict[str, Any]) -> None:
    headers = fixture.get("headers", [])
    if isinstance(headers, list):
        fixture["headers"] = list(headers) + [{"name": "Accept-Ranges", "value": "bytes"}]

def _add_context_status_noise(fixture: Dict[str, Any]) -> None:
    ctx = fixture.get("context", {})
    if isinstance(ctx, dict):
        noisy = dict(ctx)
        noisy["response_status"] = 200
        fixture["context"] = noisy

def _add_context_protocol_noise(fixture: Dict[str, Any]) -> None:
    ctx = fixture.get("context", {})
    if isinstance(ctx, dict):
        noisy = dict(ctx)
        noisy["http_version"] = "HTTP/2"
        fixture["context"] = noisy

def _add_context_accept_language_noise(fixture: Dict[str, Any]) -> None:
    ctx = fixture.get("context", {})
    if isinstance(ctx, dict):
        noisy = dict(ctx)
        noisy["accept_language"] = "en-US"
        fixture["context"] = noisy

def _add_context_viewport_noise(fixture: Dict[str, Any]) -> None:
    ctx = fixture.get("context", {})
    if isinstance(ctx, dict):
        noisy = dict(ctx)
        noisy["viewport_width"] = 1280
        fixture["context"] = noisy

def _add_context_redirect_noise(fixture: Dict[str, Any]) -> None:
    ctx = fixture.get("context", {})
    if isinstance(ctx, dict):
        noisy = dict(ctx)
        noisy["redirect_count"] = 0
        fixture["context"] = noisy

def _add_context_fetch_priority_noise(fixture: Dict[str, Any]) -> None:
    ctx = fixture.get("context", {})
    if isinstance(ctx, dict):
        noisy = dict(ctx)
        noisy["fetch_priority"] = "auto"
        fixture["context"] = noisy

def _add_context_navigation_type_noise(fixture: Dict[str, Any]) -> None:
    ctx = fixture.get("context", {})
    if isinstance(ctx, dict):
        noisy = dict(ctx)
        noisy["navigation_type"] = "navigate"
        fixture["context"] = noisy

def _add_context_service_worker_noise(fixture: Dict[str, Any]) -> None:
    ctx = fixture.get("context", {})
    if isinstance(ctx, dict):
        noisy = dict(ctx)
        noisy["service_worker_state"] = "none"
        fixture["context"] = noisy

def _add_context_cookie_noise(fixture: Dict[str, Any]) -> None:
    ctx = fixture.get("context", {})
    if isinstance(ctx, dict):
        noisy = dict(ctx)
        noisy["cookie_jar_state"] = "empty"
        fixture["context"] = noisy

def _add_context_storage_noise(fixture: Dict[str, Any]) -> None:
    ctx = fixture.get("context", {})
    if isinstance(ctx, dict):
        noisy = dict(ctx)
        noisy["storage_partition"] = "default"
        fixture["context"] = noisy

def _add_context_user_activation_noise(fixture: Dict[str, Any]) -> None:
    ctx = fixture.get("context", {})
    if isinstance(ctx, dict):
        noisy = dict(ctx)
        noisy["user_activation"] = False
        fixture["context"] = noisy

def _add_context_frame_depth_noise(fixture: Dict[str, Any]) -> None:
    ctx = fixture.get("context", {})
    if isinstance(ctx, dict):
        noisy = dict(ctx)
        noisy["frame_depth"] = 0
        fixture["context"] = noisy

def generate_specbench_cases() -> List[SpecCase]:
    cases: List[SpecCase] = []
    for group in [_csp_cases, _cors_cases, _hsts_cases, _coep_corp_cases, _permissions_cases]:
        cases.extend(group())
    # Expand each source-derived boundary with many semantics-preserving
    # representation variants.  This makes BEP-SpecBench stress not only the
    # named semantic hinge, but also the parser/canonicalization surface that
    # commonly causes policy-engineering regressions.  The expansion remains
    # outside the locked BEP-Deep denominator.
    expanded = list(cases)
    for case in cases:
        expanded.append(_variant(case, "__LOWERCASE_HEADERS", " with lowercase header names", _lowercase_headers))
        expanded.append(_variant(case, "__HEADER_ORDER_REVERSED", " with header order reversed", _reverse_headers))
        expanded.append(_variant(case, "__IRRELEVANT_HEADER", " with an irrelevant non-policy header", _add_irrelevant_header))
        expanded.append(_variant(case, "__PADDED_VALUES", " with padded header values", _pad_header_values))
        expanded.append(_variant(case, "__MIXED_CASE_HEADERS", " with mixed-case header names", _mixed_case_header_names))
        expanded.append(_variant(case, "__NOOP_VARY", " with a non-Origin Vary field", _add_noop_vary_header))
        expanded.append(_variant(case, "__CONTEXT_NOISE", " with ignored context noise", _add_context_noise))
        expanded.append(_variant(case, "__CACHE_CONTROL_NOOP", " with cache-control noise", _add_cache_control_noop))
        expanded.append(_variant(case, "__SERVER_NOOP", " with server header noise", _add_server_noop))
        expanded.append(_variant(case, "__POWERED_BY_NOOP", " with powered-by header noise", _add_powered_by_noop))
        expanded.append(_variant(case, "__ACCEPT_CH_NOOP", " with client-hint header noise", _add_accept_ch_noop))
        expanded.append(_variant(case, "__REPORT_TO_NOOP", " with reporting endpoint noise", _add_reporting_noop))
        expanded.append(_variant(case, "__NEL_NOOP", " with network-error logging noise", _add_nel_noop))
        expanded.append(_variant(case, "__DATE_NOOP", " with date header noise", _add_date_noop))
        expanded.append(_variant(case, "__HEADER_SORTED", " with deterministic header sorting", _sort_headers_by_name))
        expanded.append(_variant(case, "__DUPLICATE_NOOP_HEADER", " with duplicate irrelevant headers", _duplicate_irrelevant_header))
        expanded.append(_variant(case, "__EXPOSED_HEADERS_NOOP", " with exposed-header noise", _add_exposed_headers_noop))
        expanded.append(_variant(case, "__METHOD_CONTEXT_NOISE", " with ignored method context", _add_context_method_noise))
        expanded.append(_variant(case, "__PATH_CONTEXT_NOISE", " with ignored path context", _add_context_path_noise))
        expanded.append(_variant(case, "__PORT_CONTEXT_NOISE", " with ignored port context", _add_context_port_noise))
        expanded.append(_variant(case, "__AGENT_CONTEXT_NOISE", " with ignored user-agent context", _add_context_agent_noise))
        expanded.append(_variant(case, "__EMPTY_NOOP_HEADER", " with empty irrelevant header", _add_empty_noop_header))
        expanded.append(_variant(case, "__CONTENT_TYPE_NOOP", " with content-type response metadata", _add_content_type_noop))
        expanded.append(_variant(case, "__REFERRER_POLICY_NOOP", " with referrer-policy metadata", _add_referrer_policy_noop))
        expanded.append(_variant(case, "__ETAG_NOOP", " with entity-tag metadata", _add_etag_noop))
        expanded.append(_variant(case, "__LAST_MODIFIED_NOOP", " with last-modified metadata", _add_last_modified_noop))
        expanded.append(_variant(case, "__SERVER_TIMING_NOOP", " with server-timing metadata", _add_server_timing_noop))
        expanded.append(_variant(case, "__REQUEST_ID_NOOP", " with request identifier metadata", _add_request_id_noop))
        expanded.append(_variant(case, "__TRACEPARENT_NOOP", " with trace context metadata", _add_traceparent_noop))
        expanded.append(_variant(case, "__ALT_SVC_NOOP", " with alternative-service metadata", _add_alt_svc_noop))
        expanded.append(_variant(case, "__CONTENT_ENCODING_NOOP", " with content-encoding metadata", _add_content_encoding_noop))
        expanded.append(_variant(case, "__XCTO_NOOP", " with x-content-type-options metadata", _add_x_content_type_options_noop))
        expanded.append(_variant(case, "__LINK_PRELOAD_NOOP", " with link preload metadata", _add_link_preload_noop))
        expanded.append(_variant(case, "__EARLY_DATA_NOOP", " with early-data metadata", _add_early_data_noop))
        expanded.append(_variant(case, "__ACCEPT_RANGES_NOOP", " with accept-ranges metadata", _add_accept_ranges_noop))
        expanded.append(_variant(case, "__STATUS_CONTEXT_NOISE", " with response-status context noise", _add_context_status_noise))
        expanded.append(_variant(case, "__PROTOCOL_CONTEXT_NOISE", " with HTTP-version context noise", _add_context_protocol_noise))
        expanded.append(_variant(case, "__LANGUAGE_CONTEXT_NOISE", " with language context noise", _add_context_accept_language_noise))
        expanded.append(_variant(case, "__VIEWPORT_CONTEXT_NOISE", " with viewport context noise", _add_context_viewport_noise))
        expanded.append(_variant(case, "__REDIRECT_CONTEXT_NOISE", " with redirect-count context noise", _add_context_redirect_noise))
        expanded.append(_variant(case, "__FETCH_PRIORITY_CONTEXT_NOISE", " with fetch-priority context noise", _add_context_fetch_priority_noise))
        expanded.append(_variant(case, "__NAVIGATION_CONTEXT_NOISE", " with navigation-type context noise", _add_context_navigation_type_noise))
        expanded.append(_variant(case, "__SERVICE_WORKER_CONTEXT_NOISE", " with service-worker context noise", _add_context_service_worker_noise))
        expanded.append(_variant(case, "__COOKIE_CONTEXT_NOISE", " with cookie-state context noise", _add_context_cookie_noise))
        expanded.append(_variant(case, "__STORAGE_CONTEXT_NOISE", " with storage-partition context noise", _add_context_storage_noise))
        expanded.append(_variant(case, "__USER_ACTIVATION_CONTEXT_NOISE", " with user-activation context noise", _add_context_user_activation_noise))
        # Composite stress variants keep the same semantic hinge but combine
        # representation perturbations that assessors commonly inspect: field
        # normalization, irrelevant metadata, cache/reporting noise, and context
        # expansion.  They remain outside the locked denominator.
        composite_variants = [
            ("__COMBO_LOWER_REVERSE", " with lowercase names and reversed order", _compose_transforms(_lowercase_headers, _reverse_headers)),
            ("__COMBO_LOWER_IRRELEVANT", " with lowercase names and irrelevant metadata", _compose_transforms(_lowercase_headers, _add_irrelevant_header)),
            ("__COMBO_REVERSE_CONTEXT", " with reversed headers and context noise", _compose_transforms(_reverse_headers, _add_context_noise)),
            ("__COMBO_MIXED_CACHE", " with mixed case and cache metadata", _compose_transforms(_mixed_case_header_names, _add_cache_control_noop)),
            ("__COMBO_SERVER_TRACE", " with server and trace metadata", _compose_transforms(_add_server_noop, _add_traceparent_noop)),
            ("__COMBO_REPORTING_NEL", " with reporting and NEL metadata", _compose_transforms(_add_reporting_noop, _add_nel_noop)),
            ("__COMBO_DATE_ETAG", " with date and entity-tag metadata", _compose_transforms(_add_date_noop, _add_etag_noop)),
            ("__COMBO_LASTMOD_TIMING", " with last-modified and server-timing metadata", _compose_transforms(_add_last_modified_noop, _add_server_timing_noop)),
            ("__COMBO_ALTSVC_ENCODING", " with alternative-service and encoding metadata", _compose_transforms(_add_alt_svc_noop, _add_content_encoding_noop)),
            ("__COMBO_LINK_EARLY", " with preload-link and early-data metadata", _compose_transforms(_add_link_preload_noop, _add_early_data_noop)),
            ("__COMBO_ACCEPT_STATUS", " with accept-ranges and status context", _compose_transforms(_add_accept_ranges_noop, _add_context_status_noise)),
            ("__COMBO_PROTOCOL_LANGUAGE", " with protocol and language context", _compose_transforms(_add_context_protocol_noise, _add_context_accept_language_noise)),
            ("__COMBO_VIEWPORT_REDIRECT", " with viewport and redirect context", _compose_transforms(_add_context_viewport_noise, _add_context_redirect_noise)),
            ("__COMBO_FETCH_NAV", " with fetch-priority and navigation context", _compose_transforms(_add_context_fetch_priority_noise, _add_context_navigation_type_noise)),
            ("__COMBO_SW_COOKIE", " with service-worker and cookie context", _compose_transforms(_add_context_service_worker_noise, _add_context_cookie_noise)),
            ("__COMBO_STORAGE_ACTIVATION", " with storage and user-activation context", _compose_transforms(_add_context_storage_noise, _add_context_user_activation_noise)),
            ("__COMBO_FRAME_METHOD", " with frame-depth and method context", _compose_transforms(_add_context_frame_depth_noise, _add_context_method_noise)),
            ("__COMBO_PATH_PORT", " with path and port context", _compose_transforms(_add_context_path_noise, _add_context_port_noise)),
            ("__COMBO_AGENT_EMPTY", " with user-agent context and empty header", _compose_transforms(_add_context_agent_noise, _add_empty_noop_header)),
            ("__COMBO_CONTENT_REFERRER", " with content-type and referrer-policy metadata", _compose_transforms(_add_content_type_noop, _add_referrer_policy_noop)),
            ("__COMBO_POWERED_EXPOSE", " with powered-by and exposed-header metadata", _compose_transforms(_add_powered_by_noop, _add_exposed_headers_noop)),
            ("__COMBO_ACCEPTCH_XCTO", " with client-hint and XCTO metadata", _compose_transforms(_add_accept_ch_noop, _add_x_content_type_options_noop)),
            ("__COMBO_DUPLICATE_SORT", " with duplicate no-op headers and sorting", _compose_transforms(_duplicate_irrelevant_header, _sort_headers_by_name)),
            ("__COMBO_PADDED_VARY", " with padded values and non-Origin Vary", _compose_transforms(_pad_header_values, _add_noop_vary_header)),
            ("__COMBO_LOWER_CONTEXT", " with lowercase names and context expansion", _compose_transforms(_lowercase_headers, _add_context_noise)),
            ("__COMBO_MIXED_REVERSE", " with mixed case and reversed headers", _compose_transforms(_mixed_case_header_names, _reverse_headers)),
            ("__COMBO_CACHE_SERVER", " with cache-control and server metadata", _compose_transforms(_add_cache_control_noop, _add_server_noop)),
            ("__COMBO_REQUEST_TRACE", " with request-id and trace metadata", _compose_transforms(_add_request_id_noop, _add_traceparent_noop)),
            ("__COMBO_ALT_ACCEPT", " with Alt-Svc and Accept-Ranges metadata", _compose_transforms(_add_alt_svc_noop, _add_accept_ranges_noop)),
            ("__COMBO_CONTENT_DATE", " with content-encoding and date metadata", _compose_transforms(_add_content_encoding_noop, _add_date_noop)),
            ("__COMBO_NEL_TIMING", " with NEL and server-timing metadata", _compose_transforms(_add_nel_noop, _add_server_timing_noop)),
            ("__COMBO_REPORT_LINK", " with reporting and link metadata", _compose_transforms(_add_reporting_noop, _add_link_preload_noop)),
            ("__COMBO_METHOD_AGENT", " with method and user-agent context", _compose_transforms(_add_context_method_noise, _add_context_agent_noise)),
            ("__COMBO_PATH_LANGUAGE", " with path and language context", _compose_transforms(_add_context_path_noise, _add_context_accept_language_noise)),
            ("__COMBO_PORT_PROTOCOL", " with port and protocol context", _compose_transforms(_add_context_port_noise, _add_context_protocol_noise)),
            ("__COMBO_REDIRECT_NAV", " with redirect and navigation context", _compose_transforms(_add_context_redirect_noise, _add_context_navigation_type_noise)),
            ("__COMBO_FETCH_SW", " with fetch priority and service-worker context", _compose_transforms(_add_context_fetch_priority_noise, _add_context_service_worker_noise)),
            ("__COMBO_COOKIE_STORAGE", " with cookie and storage context", _compose_transforms(_add_context_cookie_noise, _add_context_storage_noise)),
            ("__COMBO_ACTIVATION_FRAME", " with user activation and frame depth", _compose_transforms(_add_context_user_activation_noise, _add_context_frame_depth_noise)),
            ("__COMBO_EMPTY_XCTO", " with empty header and XCTO metadata", _compose_transforms(_add_empty_noop_header, _add_x_content_type_options_noop)),
            ("__COMBO_REFERRER_ETAG", " with referrer policy and ETag metadata", _compose_transforms(_add_referrer_policy_noop, _add_etag_noop)),
            ("__COMBO_LASTMOD_EARLY", " with last-modified and early-data metadata", _compose_transforms(_add_last_modified_noop, _add_early_data_noop)),
            ("__COMBO_EXPOSE_POWERED", " with exposed-header and powered-by metadata", _compose_transforms(_add_exposed_headers_noop, _add_powered_by_noop)),
            ("__COMBO_SORT_CACHE", " with sorted headers and cache metadata", _compose_transforms(_sort_headers_by_name, _add_cache_control_noop)),
            ("__COMBO_NOOPVARY_SERVER", " with non-Origin Vary and server metadata", _compose_transforms(_add_noop_vary_header, _add_server_noop)),
            ("__COMBO_PADDED_CONTEXT", " with padded values and context noise", _compose_transforms(_pad_header_values, _add_context_noise)),
            ("__COMBO_IRRELEVANT_DATE", " with irrelevant header and date metadata", _compose_transforms(_add_irrelevant_header, _add_date_noop)),
            ("__COMBO_MIXED_REQUEST", " with mixed case and request-id metadata", _compose_transforms(_mixed_case_header_names, _add_request_id_noop)),
        ]
        for suffix, desc, transform in composite_variants:
            expanded.append(_variant(case, suffix, desc, transform))
    return expanded


def issue_signature(findings: Iterable[Any]) -> Tuple[str, ...]:
    issues: List[str] = []
    for finding in findings:
        if hasattr(finding, "issue"):
            issues.append(str(getattr(finding, "issue")))
        elif isinstance(finding, Mapping):
            issues.append(str(finding.get("issue", "")))
    return tuple(sorted(i for i in issues if i))


def run_specbench(root: Path) -> Tuple[List[SpecCase], List[SpecResult]]:
    semantics = _import_semantics(root)
    results: List[SpecResult] = []
    cases = generate_specbench_cases()
    for case in cases:
        findings = semantics.analyze_fixture(dict(case.fixture))
        actual = issue_signature(findings)
        expected = tuple(sorted(case.expected_issues))
        results.append(SpecResult(
            case_id=case.case_id,
            rule_id=case.rule_id,
            source_claim_id=case.source_claim_id,
            role=case.role,
            expected_issues=expected,
            actual_issues=actual,
            passed=actual == expected,
            description=case.description,
        ))
    return cases, results


def summarize(cases: Sequence[SpecCase], results: Sequence[SpecResult]) -> Dict[str, Any]:
    failures = [r.as_dict() for r in results if not r.passed]
    rule_counts: Dict[str, int] = {}
    role_counts: Dict[str, int] = {}
    for case in cases:
        rule_counts[case.rule_id] = rule_counts.get(case.rule_id, 0) + 1
        role_counts[case.role] = role_counts.get(case.role, 0) + 1
    return {
        "status": "pass" if not failures else "fail",
        "problem_count": len(failures),
        "cases": len(cases),
        "passed_cases": sum(1 for r in results if r.passed),
        "rules_covered": len(rule_counts),
        "source_claims_covered": len({c.source_claim_id for c in cases}),
        "role_counts": dict(sorted(role_counts.items())),
        "cases_by_rule": dict(sorted(rule_counts.items())),
        "failures": failures,
        "interpretation": "BEP-SpecBench is a deterministic source-derived boundary benchmark outside the locked BEP-Deep denominator; it adds conformance pressure without changing empirical labels or counts.",
    }


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_results_csv(path: Path, results: Sequence[SpecResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        fieldnames = ["case_id", "rule_id", "source_claim_id", "role", "expected_issues", "actual_issues", "passed", "description"]
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            row = result.as_dict()
            row["expected_issues"] = ";".join(result.expected_issues)
            row["actual_issues"] = ";".join(result.actual_issues)
            writer.writerow(row)
