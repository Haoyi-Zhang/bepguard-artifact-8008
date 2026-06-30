#!/usr/bin/env python3
"""Materialize the locked pre-experiment corpus inputs.

The script creates deterministic corpus-claim records, semantic rule-source
traceability, source-snapshot metadata, a locked synthetic fixture workload,
and fixture manifests. It does not execute the analyzer on the locked workload.
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import csv
import hashlib
import json
from pathlib import Path
from typing import Dict, Iterable, List

ROOT = Path(__file__).resolve().parents[2]
ART = ROOT / "artifact"
DATA = ART / "data"
METHOD = ART / "method"
RESULTS = ART / "results"
DATE = "2026-06-20"


def stable_hash(obj: object) -> str:
    payload = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def write_csv(path: Path, rows: List[Dict[str, object]], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


sources = {
    "S_CSP_SPEC": {
        "name": "Content Security Policy Level 3 Editor Draft",
        "url": "https://w3c.github.io/webappsec-csp/",
        "version": "Editor Draft, 5 May 2026; accessed 2026-06-20",
    },
    "S_FETCH_SPEC": {
        "name": "Fetch Standard",
        "url": "https://fetch.spec.whatwg.org/",
        "version": "Living Standard; accessed 2026-06-20",
    },
    "S_RFC6797": {
        "name": "RFC 6797 HTTP Strict Transport Security",
        "url": "https://www.rfc-editor.org/rfc/rfc6797",
        "version": "RFC 6797, November 2012; accessed 2026-06-20",
    },
    "S_MDN_COEP": {
        "name": "MDN Cross-Origin-Embedder-Policy",
        "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Embedder-Policy",
        "version": "MDN page accessed 2026-06-20",
    },
    "S_MDN_COOP": {
        "name": "MDN Cross-Origin-Opener-Policy",
        "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Opener-Policy",
        "version": "MDN page last modified 2025-11-21; accessed 2026-06-20",
    },
    "S_MDN_PERMISSIONS": {
        "name": "MDN Permissions-Policy",
        "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Permissions-Policy",
        "version": "MDN page accessed 2026-06-20",
    },
    "S_NEXT_CSP_DOC": {
        "name": "Next.js Content Security Policy guide",
        "url": "https://nextjs.org/docs/app/guides/content-security-policy",
        "version": "Next.js docs accessed 2026-06-20",
    },
    "S_HELMET_DOC": {
        "name": "Helmet.js reference",
        "url": "https://helmetjs.github.io/",
        "version": "Helmet docs accessed 2026-06-20",
    },
    "S_DJANGO_SECURITY": {
        "name": "Django 5.2 SecurityMiddleware documentation",
        "url": "https://docs.djangoproject.com/en/5.2/ref/middleware/#module-django.middleware.security",
        "version": "Django 5.2 docs accessed 2026-06-20",
    },
    "S_SPRING_SECURITY_HEADERS": {
        "name": "Spring Security HTTP response headers documentation",
        "url": "https://docs.spring.io/spring-security/reference/servlet/exploits/headers.html",
        "version": "Spring Security reference accessed 2026-06-20",
    },
    "S_RAILS_SECURITY": {
        "name": "Ruby on Rails Security Guide",
        "url": "https://guides.rubyonrails.org/security.html#content-security-policy-header",
        "version": "Rails Guides accessed 2026-06-20",
    },
    "S_EXPRESS_CORS": {
        "name": "Express cors middleware documentation",
        "url": "https://expressjs.com/en/resources/middleware/cors/",
        "version": "Express docs accessed 2026-06-20",
    },
    "S_CSP_EVALUATOR": {
        "name": "Google CSP Evaluator",
        "url": "https://github.com/google/csp-evaluator",
        "version": "GitHub release v1.1.8; accessed 2026-06-20",
    },
    "S_MDN_OBSERVATORY": {
        "name": "MDN HTTP Observatory",
        "url": "https://github.com/mdn/mdn-http-observatory",
        "version": "GitHub release v1.6.2; accessed 2026-06-20",
    },
    "S_HSTSPRELOAD": {
        "name": "Chromium hstspreload Go package",
        "url": "https://pkg.go.dev/github.com/chromium/hstspreload@v0.0.0-20250618200047-d624d7c87b33",
        "version": "Go pseudo-version v0.0.0-20250618200047-d624d7c87b33; accessed 2026-06-20",
    },
}

rules = [
    {"rule_id": "R_CSP_REPORT_ONLY_MONITOR", "policy_family": "CSP", "source_ids": "S_CSP_SPEC", "source_span": "CSP ED §3.2; accessed copy lines 514-527", "semantic_obligation": "A report-only CSP can monitor/report violations but cannot enforce blocking for the protected edge.", "encoded_status": "encoded", "proof_obligation": "report_only_nonblocking"},
    {"rule_id": "R_CSP_DEFAULT_SRC_FALLBACK", "policy_family": "CSP", "source_ids": "S_CSP_SPEC", "source_span": "CSP ED §6.1.3 and §6.8.3; accessed copy lines 1414-1420 and 2698-2709", "semantic_obligation": "When a fetch directive is absent, the effective directive falls back through the ordered fallback list including default-src.", "encoded_status": "encoded", "proof_obligation": "fallback_determinism"},
    {"rule_id": "R_CSP_SCRIPT_SRC_OVERRIDES_DEFAULT", "policy_family": "CSP", "source_ids": "S_CSP_SPEC", "source_span": "CSP ED §6.1.3; accessed copy lines 1414-1420", "semantic_obligation": "An explicitly specified script-src controls script requests rather than inheriting from default-src.", "encoded_status": "encoded", "proof_obligation": "effective_directive_selection"},
    {"rule_id": "R_CSP_META_REPORT_ONLY_UNSUPPORTED", "policy_family": "CSP", "source_ids": "S_CSP_SPEC", "source_span": "CSP ED §3.2-§3.3; accessed copy lines 527-536", "semantic_obligation": "Report-only CSP is not delivered through a meta element.", "encoded_status": "planned_rule", "proof_obligation": "delivery_surface_boundary"},
    {"rule_id": "R_CSP_NONCE_UNIQUE_PER_TRANSMISSION", "policy_family": "CSP", "source_ids": "S_CSP_SPEC", "source_span": "CSP ED §7.1/nonce guidance; accessed copy line 2771", "semantic_obligation": "A nonce source requires a fresh, difficult-to-predict value when the policy is transmitted.", "encoded_status": "partially_encoded_via_rendering_context", "proof_obligation": "freshness_context_precondition"},
    {"rule_id": "R_CSP_MULTIPLE_POLICIES_RESTRICT", "policy_family": "CSP", "source_ids": "S_CSP_SPEC", "source_span": "CSP ED §8.1; accessed copy lines 2853-2863", "semantic_obligation": "Multiple enforced policies compose conjunctively, so adding an enforced policy can only further restrict capabilities.", "encoded_status": "planned_rule", "proof_obligation": "policy_meet_monotonicity"},
    {"rule_id": "R_CORS_WILDCARD_CREDENTIALS_NOT_SHAREABLE", "policy_family": "CORS", "source_ids": "S_FETCH_SPEC", "source_span": "Fetch Standard CORS table; accessed copy lines 1848-1857", "semantic_obligation": "A credentialed CORS request is not shareable when ACAO is wildcard.", "encoded_status": "encoded", "proof_obligation": "cors_shareability_determinism"},
    {"rule_id": "R_CORS_SPECIFIC_ORIGIN_CREDENTIALS_SHAREABLE", "policy_family": "CORS", "source_ids": "S_FETCH_SPEC", "source_span": "Fetch Standard CORS table; accessed copy lines 1848-1857", "semantic_obligation": "A credentialed CORS response can be shareable when ACAO is the serialized request origin and ACAC is exactly true.", "encoded_status": "encoded", "proof_obligation": "cors_positive_control"},
    {"rule_id": "R_CORS_DYNAMIC_ACAO_NEEDS_VARY", "policy_family": "CORS", "source_ids": "S_FETCH_SPEC", "source_span": "Fetch Standard CORS and caching note; accessed copy lines 4838-4841", "semantic_obligation": "Dynamic ACAO responses need cache differentiation such as Vary: Origin to avoid cached responses without the intended ACAO.", "encoded_status": "planned_rule", "proof_obligation": "cache_context_precondition"},
    {"rule_id": "R_HSTS_IGNORE_INSECURE_TRANSPORT", "policy_family": "HSTS", "source_ids": "S_RFC6797", "source_span": "RFC 6797 §8.1; accessed copy lines 1120-1123", "semantic_obligation": "A user agent ignores STS headers received over insecure transport.", "encoded_status": "encoded", "proof_obligation": "hsts_transition_soundness"},
    {"rule_id": "R_HSTS_MAX_AGE_ZERO_CLEARS", "policy_family": "HSTS", "source_ids": "S_RFC6797", "source_span": "RFC 6797 §6.1.1; accessed copy lines 960-1004", "semantic_obligation": "max-age=0 deletes the HSTS policy, including any includeSubDomains effect.", "encoded_status": "encoded", "proof_obligation": "state_clearing_soundness"},
    {"rule_id": "R_HSTS_INVALID_HEADER_IGNORED", "policy_family": "HSTS", "source_ids": "S_RFC6797", "source_span": "RFC 6797 §6.1; accessed copy lines 917-930", "semantic_obligation": "Nonconforming STS header fields are ignored by the user agent.", "encoded_status": "planned_rule", "proof_obligation": "invalid_syntax_boundary"},
    {"rule_id": "R_COEP_REQUIRE_CORP_NO_CORS", "policy_family": "COEP/CORP/CORS", "source_ids": "S_MDN_COEP", "source_span": "MDN COEP examples; accessed copy lines 256-262", "semantic_obligation": "Under COEP require-corp, cross-origin no-cors resources require compatible CORP or a violation occurs.", "encoded_status": "encoded", "proof_obligation": "embedding_context_soundness"},
    {"rule_id": "R_COEP_CORS_MODE_COMPATIBLE", "policy_family": "COEP/CORP/CORS", "source_ids": "S_MDN_COEP", "source_span": "MDN COEP CORS note; accessed copy lines 304-306", "semantic_obligation": "A cross-origin resource supporting CORS must be requested in cors mode to avoid COEP require-corp blockage through CORS permission.", "encoded_status": "encoded", "proof_obligation": "embedding_cors_compatibility"},
    {"rule_id": "R_COOP_SAME_ORIGIN_FOR_ISOLATION", "policy_family": "COOP", "source_ids": "S_MDN_COOP", "source_span": "MDN COOP directives/examples; accessed copy lines 221-225 and 272-280", "semantic_obligation": "Cross-origin isolation requires COOP same-origin together with compatible COEP.", "encoded_status": "encoded", "proof_obligation": "isolation_header_conjunction"},
    {"rule_id": "R_COOP_UNSAFE_NONE_DEFAULT", "policy_family": "COOP", "source_ids": "S_MDN_COOP", "source_span": "MDN COOP directives; accessed copy lines 214-219", "semantic_obligation": "unsafe-none is the default COOP value and opts out of process isolation behavior.", "encoded_status": "encoded", "proof_obligation": "coop_default_boundary"},
    {"rule_id": "R_PERMISSIONS_POLICY_ALLOWLIST", "policy_family": "Permissions-Policy", "source_ids": "S_MDN_PERMISSIONS", "source_span": "MDN Permissions-Policy syntax; accessed copy lines 217-255", "semantic_obligation": "A directive allowlist controls whether a browser feature is available in top-level and nested contexts.", "encoded_status": "encoded", "proof_obligation": "allowlist_interpretation"},
    {"rule_id": "R_PERMISSIONS_POLICY_EMPTY_DISABLES", "policy_family": "Permissions-Policy", "source_ids": "S_MDN_PERMISSIONS", "source_span": "MDN Permissions-Policy allowlist values; accessed copy lines 240-245", "semantic_obligation": "An empty allowlist disables a feature in top-level and nested browsing contexts.", "encoded_status": "encoded", "proof_obligation": "feature_denial_soundness"},
    {"rule_id": "R_NEXT_NONCE_DYNAMIC_REQUIRED", "policy_family": "CSP/framework", "source_ids": "S_NEXT_CSP_DOC", "source_span": "Next.js CSP guide Dynamic Rendering Requirement; accessed copy lines 673-680", "semantic_obligation": "Nonce-based CSP in Next.js requires dynamic rendering; static optimization, ISR, CDN caching by default, and PPR are incompatible or disabled.", "encoded_status": "encoded", "proof_obligation": "framework_generation_precondition"},
    {"rule_id": "R_HELMET_CSP_DEFAULT_MERGE", "policy_family": "CSP/framework", "source_ids": "S_HELMET_DOC", "source_span": "Helmet reference; accessed copy lines 43-50 and 80-110", "semantic_obligation": "Helmet sets a default CSP and merges configured directives into defaults unless defaults are disabled.", "encoded_status": "planned_rule", "proof_obligation": "framework_header_generation"},
    {"rule_id": "R_HELMET_REPORT_ONLY", "policy_family": "CSP/framework", "source_ids": "S_HELMET_DOC", "source_span": "Helmet reference; accessed copy lines 112-124", "semantic_obligation": "Helmet can emit Content-Security-Policy-Report-Only when reportOnly is true.", "encoded_status": "planned_rule", "proof_obligation": "framework_disposition_generation"},
    {"rule_id": "R_HELMET_COEP_NOT_DEFAULT", "policy_family": "COEP/framework", "source_ids": "S_HELMET_DOC", "source_span": "Helmet reference; accessed copy lines 150-160", "semantic_obligation": "Helmet does not set COEP by default; it requires explicit crossOriginEmbedderPolicy configuration.", "encoded_status": "planned_rule", "proof_obligation": "framework_default_absence"},
    {"rule_id": "R_DJANGO_HSTS_HTTPS_ONLY", "policy_family": "HSTS/framework", "source_ids": "S_DJANGO_SECURITY", "source_span": "Django 5.2 middleware docs; accessed copy lines 185-200", "semantic_obligation": "Django SecurityMiddleware adds HSTS on HTTPS responses when SECURE_HSTS_SECONDS is nonzero; reverse proxies can prevent Django from recognizing secure connections.", "encoded_status": "planned_rule", "proof_obligation": "deployment_context_precondition"},
    {"rule_id": "R_SPRING_CSP_CONTEXT_REQUIRED", "policy_family": "CSP/framework", "source_ids": "S_SPRING_SECURITY_HEADERS", "source_span": "Spring Security headers docs; accessed copy lines 784-887", "semantic_obligation": "Spring Security does not add CSP by default because a reasonable default requires application context; authors must declare enforce or report-only policies.", "encoded_status": "planned_rule", "proof_obligation": "secure_default_context_boundary"},
    {"rule_id": "R_RAILS_REPORT_ONLY_MIGRATION", "policy_family": "CSP/framework", "source_ids": "S_RAILS_SECURITY", "source_span": "Rails Security Guide §9.3; accessed copy lines 1211-1223", "semantic_obligation": "Rails can set CSP report-only during migration to report without enforcing.", "encoded_status": "planned_rule", "proof_obligation": "migration_disposition_boundary"},
    {"rule_id": "R_RAILS_NONCE_CACHE_TRADEOFF", "policy_family": "CSP/framework", "source_ids": "S_RAILS_SECURITY", "source_span": "Rails Security Guide §9.3.2; accessed copy lines 1233-1278", "semantic_obligation": "Per-request CSP nonces can conflict with caching because changing nonces can create changing ETags or stale content risks.", "encoded_status": "planned_rule", "proof_obligation": "nonce_cache_precondition"},
    {"rule_id": "R_EXPRESS_CORS_REFLECT_ORIGIN", "policy_family": "CORS/framework", "source_ids": "S_EXPRESS_CORS", "source_span": "Express cors docs; accessed copy lines 527-538", "semantic_obligation": "Express cors origin=true reflects the request Origin and credentials=true emits ACAC.", "encoded_status": "encoded_as_reflected_origin_symbol", "proof_obligation": "middleware_generation_mapping"},
    {"rule_id": "R_EXPRESS_CORS_NOT_AUTHORIZATION", "policy_family": "CORS/framework", "source_ids": "S_EXPRESS_CORS", "source_span": "Express cors docs Common Misconceptions; accessed copy lines 555-566", "semantic_obligation": "CORS controls whether browser JavaScript can read a response; it is not server-side access control or API authorization.", "encoded_status": "planned_rule", "proof_obligation": "threat_boundary"},
    {"rule_id": "R_BASELINE_CSP_EVALUATOR_SCOPE", "policy_family": "baseline", "source_ids": "S_CSP_EVALUATOR", "source_span": "GitHub README/release; accessed copy lines 307-310 and 383-385", "semantic_obligation": "CSP Evaluator is scoped to reviewing CSP as an XSS mitigation and common bypasses, not cross-policy browser-effective intent drift.", "encoded_status": "baseline_scope_record", "proof_obligation": "wrapper_isolation"},
    {"rule_id": "R_BASELINE_OBSERVATORY_SCOPE", "policy_family": "baseline", "source_ids": "S_MDN_OBSERVATORY", "source_span": "GitHub README/release; accessed copy lines 310-312 and 503-505", "semantic_obligation": "MDN HTTP Observatory checks sites for security-relevant headers and is a header/configuration scanner baseline.", "encoded_status": "baseline_scope_record", "proof_obligation": "wrapper_isolation"},
    {"rule_id": "R_BASELINE_HSTSPRELOAD_SCOPE", "policy_family": "baseline", "source_ids": "S_HSTSPRELOAD", "source_span": "pkg.go.dev package metadata; accessed copy lines 106-115", "semantic_obligation": "Chromium hstspreload is a preload eligibility library and is not a general browser-policy intent oracle.", "encoded_status": "baseline_scope_record", "proof_obligation": "wrapper_isolation"},
]

claims = [
    ("CL_CSP_01", "S_CSP_SPEC", "normative", "CSP", "CSP report-only policies are monitoring policies rather than enforcing policies.", "enforce_script_restriction", "R_CSP_REPORT_ONLY_MONITOR", "positive", "CSP ED §3.2 lines 514-527"),
    ("CL_CSP_02", "S_CSP_SPEC", "normative", "CSP", "CSP default-src supplies fallback source lists for fetch directives that are not explicitly set.", "enforce_script_restriction", "R_CSP_DEFAULT_SRC_FALLBACK", "positive_and_negative", "CSP ED §6.1.3 lines 1414-1420"),
    ("CL_CSP_03", "S_CSP_SPEC", "normative", "CSP", "An explicit script-src controls script requests rather than inheriting default-src.", "enforce_script_restriction", "R_CSP_SCRIPT_SRC_OVERRIDES_DEFAULT", "negative_control", "CSP ED §6.1.3 lines 1416-1420"),
    ("CL_CSP_04", "S_CSP_SPEC", "normative", "CSP", "The script fetch fallback list includes script-src-elem, script-src, and default-src in order.", "enforce_script_restriction", "R_CSP_DEFAULT_SRC_FALLBACK", "positive_and_negative", "CSP ED §6.8.3 lines 2698-2709"),
    ("CL_CSP_05", "S_CSP_SPEC", "normative", "CSP", "Report-only CSP is not supported through meta delivery.", "enforce_script_restriction", "R_CSP_META_REPORT_ONLY_UNSUPPORTED", "planned", "CSP ED §3.3 lines 527-536"),
    ("CL_CSP_06", "S_CSP_SPEC", "normative", "CSP", "Nonce source expressions require fresh per-transmission values.", "nonce_based_strict_csp", "R_CSP_NONCE_UNIQUE_PER_TRANSMISSION", "positive", "CSP ED nonce guidance line 2771"),
    ("CL_CSP_07", "S_CSP_SPEC", "normative", "CSP", "Multiple enforced CSP policies compose restrictively.", "enforce_script_restriction", "R_CSP_MULTIPLE_POLICIES_RESTRICT", "planned", "CSP ED §8.1 lines 2853-2863"),
    ("CL_CORS_01", "S_FETCH_SPEC", "normative", "CORS", "ACAO wildcard is not shareable with credentials mode include.", "allow_credentialed_cors", "R_CORS_WILDCARD_CREDENTIALS_NOT_SHAREABLE", "positive", "Fetch CORS table lines 1848-1857"),
    ("CL_CORS_02", "S_FETCH_SPEC", "normative", "CORS", "A serialized request origin with ACAC exactly true can be shareable for credentials mode include.", "allow_credentialed_cors", "R_CORS_SPECIFIC_ORIGIN_CREDENTIALS_SHAREABLE", "negative_control", "Fetch CORS table lines 1848-1857"),
    ("CL_CORS_03", "S_FETCH_SPEC", "normative", "CORS", "ACAC true is byte-case-sensitive for the shareability table.", "allow_credentialed_cors", "R_CORS_SPECIFIC_ORIGIN_CREDENTIALS_SHAREABLE", "planned", "Fetch CORS table lines 1854-1856"),
    ("CL_CORS_04", "S_FETCH_SPEC", "normative", "CORS", "Dynamic ACAO responses have cache interactions that require distinguishing Origin-varying responses.", "allow_credentialed_cors", "R_CORS_DYNAMIC_ACAO_NEEDS_VARY", "planned", "Fetch CORS cache note lines 4838-4841"),
    ("CL_HSTS_01", "S_RFC6797", "normative", "HSTS", "STS headers received over insecure transport are ignored by user agents.", "enforce_https_only", "R_HSTS_IGNORE_INSECURE_TRANSPORT", "positive", "RFC 6797 §8.1 lines 1120-1123"),
    ("CL_HSTS_02", "S_RFC6797", "normative", "HSTS", "max-age=0 clears known HSTS host state including includeSubDomains.", "enforce_https_only", "R_HSTS_MAX_AGE_ZERO_CLEARS", "positive", "RFC 6797 §6.1.1 lines 960-1004"),
    ("CL_HSTS_03", "S_RFC6797", "normative", "HSTS", "Nonconforming STS header fields are ignored by user agents.", "enforce_https_only", "R_HSTS_INVALID_HEADER_IGNORED", "planned", "RFC 6797 §6.1 lines 925-930"),
    ("CL_COEP_01", "S_MDN_COEP", "developer_doc", "COEP/CORP/CORS", "COEP require-corp blocks no-cors cross-origin resources without compatible CORP.", "cross_origin_isolation_without_embed_breakage", "R_COEP_REQUIRE_CORP_NO_CORS", "positive", "MDN COEP lines 256-262"),
    ("CL_COEP_02", "S_MDN_COEP", "developer_doc", "COEP/CORP/CORS", "CORS mode can avoid COEP require-corp blockage when the resource supports CORS.", "cross_origin_isolation_without_embed_breakage", "R_COEP_CORS_MODE_COMPATIBLE", "negative_control", "MDN COEP lines 304-306"),
    ("CL_COOP_01", "S_MDN_COOP", "developer_doc", "COOP", "COOP same-origin is needed together with compatible COEP for cross-origin isolated features.", "enable_cross_origin_isolation", "R_COOP_SAME_ORIGIN_FOR_ISOLATION", "positive_and_negative", "MDN COOP lines 272-280"),
    ("CL_COOP_02", "S_MDN_COOP", "developer_doc", "COOP", "COOP unsafe-none is the default and opts out of process isolation.", "enable_cross_origin_isolation", "R_COOP_UNSAFE_NONE_DEFAULT", "positive", "MDN COOP lines 214-219"),
    ("CL_PERM_01", "S_MDN_PERMISSIONS", "developer_doc", "Permissions-Policy", "Permissions-Policy allowlists determine whether features are allowed or denied in top-level and nested contexts.", "allow_browser_feature", "R_PERMISSIONS_POLICY_ALLOWLIST", "positive_and_negative", "MDN Permissions-Policy lines 217-255"),
    ("CL_PERM_02", "S_MDN_PERMISSIONS", "developer_doc", "Permissions-Policy", "An empty Permissions-Policy allowlist disables the feature.", "allow_browser_feature", "R_PERMISSIONS_POLICY_EMPTY_DISABLES", "positive", "MDN Permissions-Policy lines 240-245"),
    ("CL_NEXT_01", "S_NEXT_CSP_DOC", "framework_doc", "CSP/framework", "Next.js nonce CSP requires dynamic rendering.", "nonce_based_strict_csp", "R_NEXT_NONCE_DYNAMIC_REQUIRED", "positive", "Next.js CSP guide lines 673-680"),
    ("CL_NEXT_02", "S_NEXT_CSP_DOC", "framework_doc", "CSP/framework", "Next.js nonce CSP disables or conflicts with static optimization, ISR, default CDN caching, and PPR.", "nonce_based_strict_csp", "R_NEXT_NONCE_DYNAMIC_REQUIRED", "positive", "Next.js CSP guide lines 675-680"),
    ("CL_HELMET_01", "S_HELMET_DOC", "framework_doc", "CSP/framework", "Helmet sets a default CSP header and the header usually needs app-specific configuration.", "enforce_script_restriction", "R_HELMET_CSP_DEFAULT_MERGE", "planned", "Helmet docs lines 43-51"),
    ("CL_HELMET_02", "S_HELMET_DOC", "framework_doc", "CSP/framework", "Helmet merges configured CSP directives into defaults unless defaults are disabled.", "enforce_script_restriction", "R_HELMET_CSP_DEFAULT_MERGE", "planned", "Helmet docs lines 80-110"),
    ("CL_HELMET_03", "S_HELMET_DOC", "framework_doc", "CSP/framework", "Helmet can emit CSP Report-Only through reportOnly=true.", "enforce_script_restriction", "R_HELMET_REPORT_ONLY", "planned", "Helmet docs lines 112-124"),
    ("CL_HELMET_04", "S_HELMET_DOC", "framework_doc", "COEP/framework", "Helmet does not set COEP by default.", "enable_cross_origin_isolation", "R_HELMET_COEP_NOT_DEFAULT", "planned", "Helmet docs lines 150-160"),
    ("CL_HELMET_05", "S_HELMET_DOC", "framework_doc", "baseline", "Helmet performs little CSP validation and points users to CSP checkers.", "baseline_scope", "R_BASELINE_CSP_EVALUATOR_SCOPE", "baseline", "Helmet docs line 139"),
    ("CL_DJANGO_01", "S_DJANGO_SECURITY", "framework_doc", "HSTS/framework", "Django SecurityMiddleware sets HSTS on HTTPS responses when SECURE_HSTS_SECONDS is nonzero.", "enforce_https_only", "R_DJANGO_HSTS_HTTPS_ONLY", "planned", "Django docs lines 185-189"),
    ("CL_DJANGO_02", "S_DJANGO_SECURITY", "framework_doc", "HSTS/framework", "Django may fail to add HSTS behind a load balancer or reverse proxy if secure-connection recognition is not configured.", "enforce_https_only", "R_DJANGO_HSTS_HTTPS_ONLY", "planned", "Django docs lines 199-200"),
    ("CL_SPRING_01", "S_SPRING_SECURITY_HEADERS", "framework_doc", "CSP/framework", "Spring Security does not add CSP by default because a reasonable default requires application context.", "enforce_script_restriction", "R_SPRING_CSP_CONTEXT_REQUIRED", "planned", "Spring docs lines 784-787"),
    ("CL_SPRING_02", "S_SPRING_SECURITY_HEADERS", "framework_doc", "CSP/framework", "Spring Security can configure CSP as enforced or report-only.", "enforce_script_restriction", "R_SPRING_CSP_CONTEXT_REQUIRED;R_CSP_REPORT_ONLY_MONITOR", "planned", "Spring docs lines 849-887"),
    ("CL_RAILS_01", "S_RAILS_SECURITY", "framework_doc", "CSP/framework", "Rails recommends defining CSP and provides a DSL to configure the response header.", "enforce_script_restriction", "R_RAILS_REPORT_ONLY_MIGRATION", "planned", "Rails guide lines 1166-1169"),
    ("CL_RAILS_02", "S_RAILS_SECURITY", "framework_doc", "CSP/framework", "Rails can set CSP report-only during legacy-content migration.", "enforce_script_restriction", "R_RAILS_REPORT_ONLY_MIGRATION;R_CSP_REPORT_ONLY_MONITOR", "planned", "Rails guide lines 1211-1223"),
    ("CL_RAILS_03", "S_RAILS_SECURITY", "framework_doc", "CSP/framework", "Rails per-request nonce generation has caching and ETag tradeoffs.", "nonce_based_strict_csp", "R_RAILS_NONCE_CACHE_TRADEOFF;R_CSP_NONCE_UNIQUE_PER_TRANSMISSION", "planned", "Rails guide lines 1233-1278"),
    ("CL_EXPRESS_01", "S_EXPRESS_CORS", "framework_doc", "CORS/framework", "Express cors origin=true reflects the request Origin.", "deny_public_credentialed_cors", "R_EXPRESS_CORS_REFLECT_ORIGIN", "positive", "Express cors docs lines 527-538"),
    ("CL_EXPRESS_02", "S_EXPRESS_CORS", "framework_doc", "CORS/framework", "Express cors credentials=true emits ACAC.", "deny_public_credentialed_cors", "R_EXPRESS_CORS_REFLECT_ORIGIN", "positive", "Express cors docs lines 484-493 and 537-538"),
    ("CL_EXPRESS_03", "S_EXPRESS_CORS", "framework_doc", "CORS/framework", "CORS is not API access control and does not stop the server from receiving requests.", "threat_boundary", "R_EXPRESS_CORS_NOT_AUTHORIZATION", "planned", "Express cors docs lines 555-566"),
    ("CL_BASE_01", "S_CSP_EVALUATOR", "tool_doc", "baseline", "CSP Evaluator reviews CSP as an XSS mitigation and common bypasses.", "baseline_scope", "R_BASELINE_CSP_EVALUATOR_SCOPE", "baseline", "CSP Evaluator README lines 307-310"),
    ("CL_BASE_02", "S_MDN_OBSERVATORY", "tool_doc", "baseline", "MDN HTTP Observatory checks security-relevant HTTP headers.", "baseline_scope", "R_BASELINE_OBSERVATORY_SCOPE", "baseline", "MDN Observatory README lines 310-312"),
    ("CL_BASE_03", "S_HSTSPRELOAD", "tool_doc", "baseline", "Chromium hstspreload is pinned as an HSTS preload eligibility library baseline.", "baseline_scope", "R_BASELINE_HSTSPRELOAD_SCOPE", "baseline", "pkg.go.dev lines 106-115"),
]


# Protocol-amended post-freeze expansion: retain the earlier denominator in the
# protocol amendment log, then add source-grounded composition/cache/scope
# families before any upgraded execution.  These rows are deliberately explicit
# so reproducibility checks can separate the original 82-fixture run from the expanded run.
rules.extend([
    {"rule_id": "R_CSP_CONJUNCTIVE_COMPOSITION", "policy_family": "Layered policy composition", "source_ids": "S_CSP_SPEC", "source_span": "CSP ED §8.1; multiple enforced policies restrict cumulatively", "semantic_obligation": "A required fetch allowed by one enforced CSP can still be blocked when another enforced CSP in the generated surface does not allow it.", "encoded_status": "encoded", "proof_obligation": "policy_meet_over_layers"},
    {"rule_id": "R_LAYERED_HEADER_SURFACE", "policy_family": "Layered policy composition", "source_ids": "S_HELMET_DOC;S_DJANGO_SECURITY;S_SPRING_SECURITY_HEADERS;S_RAILS_SECURITY", "source_span": "Framework documentation for generated security headers, middleware configuration, and report-only/header-generation APIs", "semantic_obligation": "The browser-effective header surface is the ordered result of framework, application, and deployment layers; a later remove/set operation can invalidate an earlier enforcement claim.", "encoded_status": "encoded", "proof_obligation": "layer_composition_determinism"},
    {"rule_id": "R_CORS_DYNAMIC_ORIGIN_VARY", "policy_family": "CORS/cache", "source_ids": "S_FETCH_SPEC;S_EXPRESS_CORS", "source_span": "Fetch Standard CORS/cache guidance and Express dynamic origin configuration examples", "semantic_obligation": "A dynamic credentialed ACAO surface should be distinguished by Origin in shared-cache contexts.", "encoded_status": "encoded", "proof_obligation": "cache_context_precondition"},
    {"rule_id": "R_HSTS_INCLUDE_SUBDOMAINS_SCOPE", "policy_family": "HSTS/framework", "source_ids": "S_RFC6797;S_DJANGO_SECURITY;S_SPRING_SECURITY_HEADERS", "source_span": "RFC 6797 includeSubDomains semantics and framework HSTS configuration documentation", "semantic_obligation": "An HSTS intent that covers subdomains requires includeSubDomains in the effective STS policy.", "encoded_status": "encoded", "proof_obligation": "hsts_scope_soundness"},
])

claims.extend([
    ("CL_CSP_08", "S_CSP_SPEC", "normative", "Layered policy composition", "Multiple enforced CSP policies restrict cumulatively, so a later layer can block a required script allowed by an earlier layer.", "allow_required_script_after_policy_composition", "R_CSP_CONJUNCTIVE_COMPOSITION;R_LAYERED_HEADER_SURFACE", "positive_and_negative", "CSP ED §8.1 multiple policy behavior"),
    ("CL_LAYER_01", "S_HELMET_DOC", "framework_doc", "Layered policy composition", "Framework security-header APIs are one layer in a generated response surface that can be changed by application or deployment middleware.", "preserve_enforced_policy_across_layers", "R_LAYERED_HEADER_SURFACE;R_CSP_REPORT_ONLY_MONITOR", "positive_and_negative", "Helmet header-generation documentation and reportOnly examples"),
    ("CL_CORS_05", "S_FETCH_SPEC", "normative", "CORS/cache", "Dynamic credentialed CORS responses need Origin-sensitive cache treatment.", "allow_credentialed_cors_cache_safe", "R_CORS_DYNAMIC_ORIGIN_VARY;R_CORS_SPECIFIC_ORIGIN_CREDENTIALS_SHAREABLE", "positive_and_negative", "Fetch Standard CORS cache guidance and dynamic ACAO behavior"),
    ("CL_HSTS_04", "S_RFC6797", "normative", "HSTS/framework", "HSTS subdomain protection requires includeSubDomains when the intended scope includes subdomains.", "enforce_https_only_subdomains", "R_HSTS_INCLUDE_SUBDOMAINS_SCOPE", "positive_and_negative", "RFC 6797 includeSubDomains directive semantics"),
    ("CL_HSTS_05", "S_HSTSPRELOAD", "tool_doc", "HSTS/preload", "An HSTS policy intended to be preload-ready must satisfy preload eligibility conditions such as sufficient max-age, includeSubDomains, and preload declaration.", "expect_hsts_preload", "R_BASELINE_HSTSPRELOAD_SCOPE;R_HSTS_INCLUDE_SUBDOMAINS_SCOPE", "positive_and_negative", "pkg.go.dev exported eligibility helpers and hstspreload documentation"),
])

claim_rows = []
for cid, sid, ctype, family, paraphrase, intent, rule_ids, bucket, span in claims:
    src = sources[sid]
    row = {
        "claim_id": cid,
        "source_id": sid,
        "source_name": src["name"],
        "policy_family": family,
        "claim_type": ctype,
        "source_url": src["url"],
        "source_version": src["version"],
        "source_span": span,
        "explicit_claim_paraphrase": paraphrase,
        "intent_class": intent,
        "semantic_rule_ids": rule_ids,
        "fixture_role": bucket,
        "included_in_denominator": "yes",
        "exclusion_reason": "",
        "verification_date": DATE,
        "claim_hash": "",
    }
    row["claim_hash"] = stable_hash({k: row[k] for k in row if k != "claim_hash"})[:16]
    claim_rows.append(row)

claim_fields = [
    "claim_id", "source_id", "source_name", "policy_family", "claim_type", "source_url", "source_version", "source_span",
    "explicit_claim_paraphrase", "intent_class", "semantic_rule_ids", "fixture_role", "included_in_denominator",
    "exclusion_reason", "verification_date", "claim_hash",
]
write_csv(DATA / "corpus_claims.csv", claim_rows, claim_fields)

rule_fields = ["rule_id", "policy_family", "source_ids", "source_span", "semantic_obligation", "encoded_status", "proof_obligation", "rule_hash"]
RULE_MATURITY_STATUS = {
    "R_CSP_META_REPORT_ONLY_UNSUPPORTED": "encoded_delivery_surface_boundary",
    "R_CSP_NONCE_UNIQUE_PER_TRANSMISSION": "encoded_framework_context_precondition",
    "R_CSP_MULTIPLE_POLICIES_RESTRICT": "encoded_policy_meet",
    "R_CORS_DYNAMIC_ACAO_NEEDS_VARY": "encoded_cache_context",
    "R_HSTS_INVALID_HEADER_IGNORED": "encoded_syntax_boundary",
    "R_HELMET_CSP_DEFAULT_MERGE": "encoded_generation_layer_contract",
    "R_HELMET_REPORT_ONLY": "encoded_report_only_generation",
    "R_HELMET_COEP_NOT_DEFAULT": "encoded_default_absence_boundary",
    "R_DJANGO_HSTS_HTTPS_ONLY": "encoded_deployment_context_precondition",
    "R_SPRING_CSP_CONTEXT_REQUIRED": "encoded_framework_context_boundary",
    "R_RAILS_REPORT_ONLY_MIGRATION": "encoded_report_only_migration",
    "R_RAILS_NONCE_CACHE_TRADEOFF": "encoded_nonce_cache_precondition",
    "R_EXPRESS_CORS_REFLECT_ORIGIN": "encoded_reflected_origin_symbol",
    "R_EXPRESS_CORS_NOT_AUTHORIZATION": "encoded_threat_boundary",
}
for r in rules:
    if r.get("rule_id") in RULE_MATURITY_STATUS:
        r["encoded_status"] = RULE_MATURITY_STATUS[str(r.get("rule_id"))]
    r["rule_hash"] = stable_hash({k: r[k] for k in r if k != "rule_hash"})[:16]
# Write every canonical ledger alias used by the artifact.  Earlier
# iterations only refreshed a subset of aliases, which allowed stale
# rule ledgers to survive after re-materialization.
for ledger_path in [
    METHOD / "rule_to_source_ledger.csv",
    METHOD / "source_rule_ledger.csv",
    DATA / "rule_to_source_ledger.csv",
    DATA / "rule_source_ledger.csv",
    ART / "rule_source_ledger.csv",
]:
    write_csv(ledger_path, rules, rule_fields)

snapshot_rows = []
for sid, src in sources.items():
    source_claims = [r["claim_id"] for r in claim_rows if r["source_id"] == sid]
    source_rules = [r["rule_id"] for r in rules if sid in str(r["source_ids"]).split(";") or sid in str(r["source_ids"]).split(",") or sid in str(r["source_ids"])]
    record = {
        "source_id": sid,
        "source_name": src["name"],
        "source_url": src["url"],
        "source_version": src["version"],
        "access_date": DATE,
        "local_snapshot_policy": "No full upstream source copy is stored; artifact records stable URLs, sections/line spans, paraphrased claims, and hashes of extracted records.",
        "claim_ids": ";".join(source_claims),
        "rule_ids": ";".join(source_rules),
        "snapshot_record_hash": "",
    }
    record["snapshot_record_hash"] = stable_hash(record)[:16]
    snapshot_rows.append(record)
write_csv(DATA / "source_snapshot_manifest.csv", snapshot_rows, ["source_id", "source_name", "source_url", "source_version", "access_date", "local_snapshot_policy", "claim_ids", "rule_ids", "snapshot_record_hash"])
write_csv(ART / "source_snapshot_manifest.csv", snapshot_rows, ["source_id", "source_name", "source_url", "source_version", "access_date", "local_snapshot_policy", "claim_ids", "rule_ids", "snapshot_record_hash"])

# Auxiliary source ledgers are derived from the same admitted-source universe as
# the source snapshot manifest.  Earlier releases kept older acquisition logs
# with fewer rows; regenerating them here keeps public-evidence traceability
# synchronized after materialization.
source_acquisition_rows = []
source_snapshot_ledger_rows = []
for row in snapshot_rows:
    source_acquisition_rows.append({
        "source_id": row["source_id"],
        "url": row["source_url"],
        "locator": row["claim_ids"] or row["rule_ids"],
        "source_type": "admitted_public_source",
        "access_date": row["access_date"],
        "snapshot_policy": row["local_snapshot_policy"],
        "status": "locked_admitted_source",
    })
    source_snapshot_ledger_rows.append({
        "source_id": row["source_id"],
        "url": row["source_url"],
        "access_date": row["access_date"],
        "snapshot_status": "stable_url_recorded_no_raw_copy_in_artifact",
        "anchor_hint": row["claim_ids"] or row["rule_ids"],
        "metadata_sha256": stable_hash(row),
    })
write_csv(DATA / "source_acquisition_log.csv", source_acquisition_rows, ["source_id", "url", "locator", "source_type", "access_date", "snapshot_policy", "status"])
write_csv(DATA / "source_snapshot_ledger.csv", source_snapshot_ledger_rows, ["source_id", "url", "access_date", "snapshot_status", "anchor_hint", "metadata_sha256"])


def h(name: str, value: str) -> Dict[str, str]:
    return {"name": name, "value": value}


def fixture(fid: str, family: str, claim_ids: List[str], intent_class: str, claim: str,
            context: Dict[str, object], headers: List[Dict[str, str]], expected: str,
            role: str = "positive", variant: str = "base") -> Dict[str, object]:
    return {
        "id": fid,
        "policy_family": family,
        "source_claim_ids": claim_ids,
        "public_source_id": claim_ids[0] if claim_ids else "",
        "intent": {"class": intent_class, "claim": claim},
        "context": context,
        "headers": headers,
        "expected_issue": expected,
        "fixture_role": role,
        "variant": variant,
    }

full: List[Dict[str, object]] = []
# CSP report-only positives.
for i, origin in enumerate(["https://evil.example", "https://cdn.bad", "https://tracker.invalid", "https://assets.other", "https://x.test", "https://untrusted.example"], 1):
    full.append(fixture(
        f"LF_CSP_RO_{i:02d}", "CSP", ["CL_CSP_01"], "enforce_script_restriction",
        "Block untrusted third-party script execution.",
        {"document_origin": "https://app.example", "resource_origin": origin, "resource_kind": "script", "scheme": "https"},
        [h("Content-Security-Policy-Report-Only", "script-src 'self'; report-uri /csp")],
        "csp_report_only_not_enforced", "positive", "report_only_only"))
# CSP fallback positives.
for i, policy in enumerate(["default-src *; object-src 'none'", "default-src https:; object-src 'none'", "default-src *; img-src 'self'", "default-src https://evil.example; object-src 'none'", "default-src *; frame-ancestors 'none'", "default-src https: data:; object-src 'none'", "default-src *; base-uri 'self'", "default-src http: https:; object-src 'none'"], 1):
    full.append(fixture(
        f"LF_CSP_FB_{i:02d}", "CSP", ["CL_CSP_02", "CL_CSP_04"], "enforce_script_restriction",
        "Restrict executable script to trusted origins.",
        {"document_origin": "https://app.example", "resource_origin": "https://evil.example", "resource_kind": "script", "scheme": "https"},
        [h("Content-Security-Policy", policy)],
        "csp_effective_script_allowance", "positive", "default_src_allows_script"))
# CSP nonce/static positives.
for i, mode in enumerate(["static_export", "static_optimization", "ISR", "CDN_cached_static", "partial_prerendering", "build_time_render"], 1):
    full.append(fixture(
        f"LF_CSP_NONCE_{i:02d}", "CSP/framework", ["CL_CSP_06", "CL_NEXT_01", "CL_NEXT_02"], "nonce_based_strict_csp",
        "Use nonce-based strict CSP while preserving static rendering or static caching.",
        {"document_origin": "https://app.example", "resource_origin": "https://app.example", "resource_kind": "script", "scheme": "https", "static_render": True, "rendering_variant": mode},
        [h("Content-Security-Policy", "script-src 'self' 'nonce-abc123' 'strict-dynamic'; object-src 'none'; base-uri 'none'")],
        "nonce_csp_static_render_incompatibility", "positive", mode))
# CORS positives.
for i, req_origin in enumerate(["https://frontend.example", "https://console.example", "https://admin.example", "https://partner.example", "https://app.test", "https://tenant.example"], 1):
    full.append(fixture(
        f"LF_CORS_WC_{i:02d}", "CORS", ["CL_CORS_01"], "allow_credentialed_cors",
        "Allow the credentialed frontend request to read the API response.",
        {"request_origin": req_origin, "document_origin": req_origin, "resource_origin": "https://api.example", "credentials_mode": "include", "scheme": "https"},
        [h("Access-Control-Allow-Origin", "*"), h("Access-Control-Allow-Credentials", "true")],
        "cors_intended_credentialed_share_blocked", "positive", "wildcard_credentials"))
for i, req_origin in enumerate(["https://attacker.example", "https://evil.example", "https://untrusted.example", "https://random.test", "https://tenant.bad", "https://origin.invalid"], 1):
    full.append(fixture(
        f"LF_CORS_REFLECT_{i:02d}", "CORS/framework", ["CL_EXPRESS_01", "CL_EXPRESS_02"], "deny_public_credentialed_cors",
        "Do not expose credentialed API responses to arbitrary origins.",
        {"request_origin": req_origin, "document_origin": req_origin, "resource_origin": "https://api.example", "credentials_mode": "include", "scheme": "https"},
        [h("Access-Control-Allow-Origin", "$ORIGIN"), h("Access-Control-Allow-Credentials", "true")],
        "cors_reflected_origin_with_credentials", "positive", "reflected_origin_credentials"))
# HSTS positives.
for i, host in enumerate(["app.example", "secure.example", "login.example", "admin.example", "tenant.example", "service.example"], 1):
    full.append(fixture(
        f"LF_HSTS_HTTP_{i:02d}", "HSTS", ["CL_HSTS_01"], "enforce_https_only",
        "Establish HSTS state for future visits.",
        {"document_origin": f"http://{host}", "scheme": "http"},
        [h("Strict-Transport-Security", "max-age=31536000; includeSubDomains")],
        "hsts_header_not_honored_over_http", "positive", "insecure_transport"))
for i, host in enumerate(["app.example", "secure.example", "login.example", "admin.example", "tenant.example", "service.example"], 1):
    full.append(fixture(
        f"LF_HSTS_ZERO_{i:02d}", "HSTS", ["CL_HSTS_02"], "enforce_https_only",
        "Keep HTTPS-only behavior active.",
        {"document_origin": f"https://{host}", "scheme": "https"},
        [h("Strict-Transport-Security", "max-age=0; includeSubDomains")],
        "hsts_policy_cleared_by_zero_max_age", "positive", "zero_max_age"))
# COEP/CORP positives.
for i, res_origin in enumerate(["https://cdn.other", "https://images.partner", "https://fonts.third", "https://video.other", "https://assets.invalid", "https://cdn2.example.net"], 1):
    full.append(fixture(
        f"LF_COEP_{i:02d}", "COEP/CORP/CORS", ["CL_COEP_01"], "cross_origin_isolation_without_embed_breakage",
        "Enable cross-origin isolation without blocking a required third-party no-cors asset.",
        {"document_origin": "https://app.example", "resource_origin": res_origin, "request_mode": "no-cors", "credentials_mode": "omit", "scheme": "https"},
        [h("Cross-Origin-Embedder-Policy", "require-corp")],
        "coep_require_corp_blocks_cross_origin_resource", "positive", "no_cors_missing_corp"))
# COOP isolation positives.
for i, headers in enumerate([
    [h("Cross-Origin-Embedder-Policy", "require-corp")],
    [h("Cross-Origin-Opener-Policy", "unsafe-none"), h("Cross-Origin-Embedder-Policy", "require-corp")],
    [h("Cross-Origin-Opener-Policy", "same-origin")],
    [h("Cross-Origin-Opener-Policy", "same-origin-allow-popups"), h("Cross-Origin-Embedder-Policy", "require-corp")],
    [h("Cross-Origin-Opener-Policy", "same-origin"), h("Cross-Origin-Embedder-Policy", "unsafe-none")],
    [h("Cross-Origin-Opener-Policy", "same-origin"), h("Cross-Origin-Embedder-Policy", "require-corp"), h("Permissions-Policy", "cross-origin-isolated=()")],
], 1):
    full.append(fixture(
        f"LF_COOP_ISO_{i:02d}", "COOP/COEP/Permissions-Policy", ["CL_COOP_01", "CL_COOP_02", "CL_PERM_02"], "enable_cross_origin_isolation",
        "Enable cross-origin isolation for APIs that require it.",
        {"document_origin": "https://app.example", "scheme": "https", "feature": "cross-origin-isolated"},
        headers,
        "cross_origin_isolation_incomplete", "positive", "missing_or_blocking_isolation_header"))
# Permissions positives.
for i, feature in enumerate(["geolocation", "camera", "microphone", "fullscreen", "payment", "usb"], 1):
    full.append(fixture(
        f"LF_PERM_DISABLED_{i:02d}", "Permissions-Policy", ["CL_PERM_01", "CL_PERM_02"], "allow_browser_feature",
        f"Allow the application to use {feature} in the current document.",
        {"document_origin": "https://app.example", "feature": feature, "scheme": "https"},
        [h("Permissions-Policy", f"{feature}=()")],
        "permissions_policy_feature_disabled", "positive", "empty_allowlist_disables"))
# Negative controls.
negative_specs = [
    ("NC_CSP_SELF", "CSP", ["CL_CSP_03"], "enforce_script_restriction", "Block third-party scripts.", {"document_origin": "https://app.example", "resource_origin": "https://evil.example", "resource_kind": "script", "scheme": "https"}, [h("Content-Security-Policy", "default-src 'none'; script-src 'self'")], "explicit_self_blocks"),
    ("NC_CSP_OVERRIDE", "CSP", ["CL_CSP_03"], "enforce_script_restriction", "Block third-party scripts even when default-src is broad.", {"document_origin": "https://app.example", "resource_origin": "https://evil.example", "resource_kind": "script", "scheme": "https"}, [h("Content-Security-Policy", "default-src *; script-src 'self'; object-src 'none'")], "script_src_overrides_default"),
    ("NC_CORS_SPECIFIC", "CORS", ["CL_CORS_02"], "allow_credentialed_cors", "Allow a credentialed frontend request to read the API response.", {"request_origin": "https://frontend.example", "document_origin": "https://frontend.example", "resource_origin": "https://api.example", "credentials_mode": "include", "scheme": "https"}, [h("Access-Control-Allow-Origin", "https://frontend.example"), h("Access-Control-Allow-Credentials", "true")], "specific_origin_credentials"),
    ("NC_CORS_WC_OMIT", "CORS", ["CL_CORS_01"], "allow_public_cors", "Allow a public credentialless response to be read cross-origin.", {"request_origin": "https://frontend.example", "document_origin": "https://frontend.example", "resource_origin": "https://api.example", "credentials_mode": "omit", "scheme": "https"}, [h("Access-Control-Allow-Origin", "*")], "wildcard_without_credentials"),
    ("NC_HSTS_HTTPS", "HSTS", ["CL_HSTS_01"], "enforce_https_only", "Establish HSTS state for future visits.", {"document_origin": "https://app.example", "scheme": "https"}, [h("Strict-Transport-Security", "max-age=31536000; includeSubDomains")], "https_positive"),
    ("NC_HSTS_POSITIVE", "HSTS", ["CL_HSTS_02"], "enforce_https_only", "Keep HTTPS-only behavior active.", {"document_origin": "https://app.example", "scheme": "https"}, [h("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")], "nonzero_max_age"),
    ("NC_COEP_CORP", "COEP/CORP/CORS", ["CL_COEP_01"], "cross_origin_isolation_without_embed_breakage", "Enable cross-origin isolation while loading a CORP-authorized asset.", {"document_origin": "https://app.example", "resource_origin": "https://cdn.other", "request_mode": "no-cors", "credentials_mode": "omit", "scheme": "https"}, [h("Cross-Origin-Embedder-Policy", "require-corp"), h("Cross-Origin-Resource-Policy", "cross-origin")], "corp_cross_origin"),
    ("NC_COEP_CORS", "COEP/CORP/CORS", ["CL_COEP_02"], "cross_origin_isolation_without_embed_breakage", "Enable cross-origin isolation while loading a CORS-authorized asset.", {"document_origin": "https://app.example", "resource_origin": "https://cdn.other", "request_mode": "cors", "credentials_mode": "omit", "scheme": "https"}, [h("Cross-Origin-Embedder-Policy", "require-corp"), h("Access-Control-Allow-Origin", "https://app.example")], "cors_mode_authorized"),
    ("NC_COOP_ISO", "COOP/COEP/Permissions-Policy", ["CL_COOP_01"], "enable_cross_origin_isolation", "Enable cross-origin isolation for APIs that require it.", {"document_origin": "https://app.example", "scheme": "https", "feature": "cross-origin-isolated"}, [h("Cross-Origin-Opener-Policy", "same-origin"), h("Cross-Origin-Embedder-Policy", "require-corp")], "coop_coep_positive"),
    ("NC_PERM_SELF", "Permissions-Policy", ["CL_PERM_01"], "allow_browser_feature", "Allow geolocation in the current same-origin document.", {"document_origin": "https://app.example", "feature": "geolocation", "scheme": "https"}, [h("Permissions-Policy", "geolocation=(self)")], "self_allows_top_level"),
]
for idx, (prefix, family, claim_ids, intent_class, claim, context, headers, variant) in enumerate(negative_specs, 1):
    for j in range(1, 3):
        ctx = dict(context)
        ctx["negative_control_variant_index"] = j
        full.append(fixture(f"LF_{prefix}_{j:02d}", family, claim_ids, intent_class, claim, ctx, headers, "none", "negative_control", variant))


# Expanded source-grounded workload families added under protocol amendment A006.
# These fixtures exercise browser-policy engineering phenomena that are not
# captured by single-header checklist examples: layer composition, conjunctive
# CSP surfaces, dynamic-origin cache context, and HSTS subdomain scope.
for i, cdn in enumerate(["https://cdn.example", "https://static.example", "https://assets.example", "https://scripts.partner", "https://widgets.example", "https://media.example", "https://cdn2.example", "https://bundle.example"], 1):
    lf = fixture(
        f"LF_CSP_COMPOSE_{i:02d}", "Layered policy composition", ["CL_CSP_08"], "allow_required_script_after_policy_composition",
        "Allow a required script after combining framework and deployment CSP layers.",
        {"document_origin": "https://app.example", "resource_origin": cdn, "resource_kind": "script", "scheme": "https"},
        [],
        "csp_conjunctive_policy_composition_blocks_required_script", "positive", "conjunctive_csp_blocks_required_script")
    lf["layers"] = [
        {"layer": "framework", "op": "append", "headers": [h("Content-Security-Policy", f"script-src 'self' {cdn}; object-src 'none'")]},
        {"layer": "proxy_default", "op": "append", "headers": [h("Content-Security-Policy", "script-src 'self'; object-src 'none'")]},
    ]
    full.append(lf)

for i, mode in enumerate(["legacy_middleware", "reverse_proxy", "edge_function", "route_override", "compatibility_filter", "cdn_rule"], 1):
    lf = fixture(
        f"LF_LAYER_DROP_{i:02d}", "Layered policy composition", ["CL_LAYER_01", "CL_CSP_01"], "preserve_enforced_policy_across_layers",
        "Preserve enforced CSP after application and deployment layers compose the response.",
        {"document_origin": "https://app.example", "resource_origin": "https://evil.example", "resource_kind": "script", "scheme": "https", "expected_enforced_csp": True},
        [],
        "layered_header_override_drops_enforcement", "positive", mode)
    lf["layers"] = [
        {"layer": "framework", "op": "append", "headers": [h("Content-Security-Policy", "script-src 'self'; object-src 'none'")]},
        {"layer": mode, "op": "remove", "headers": [h("Content-Security-Policy", "")]},
        {"layer": mode, "op": "append", "headers": [h("Content-Security-Policy-Report-Only", "script-src 'self'; report-uri /csp")]},
    ]
    full.append(lf)

for i, req_origin in enumerate(["https://tenant1.example", "https://tenant2.example", "https://console.example", "https://admin.example", "https://partner.example", "https://embedder.example"], 1):
    full.append(fixture(
        f"LF_CORS_VARY_{i:02d}", "CORS/cache", ["CL_CORS_05"], "allow_credentialed_cors_cache_safe",
        "Allow credentialed dynamic-origin CORS without cross-origin cache confusion.",
        {"request_origin": req_origin, "document_origin": req_origin, "resource_origin": "https://api.example", "credentials_mode": "include", "scheme": "https", "dynamic_origin": True},
        [h("Access-Control-Allow-Origin", req_origin), h("Access-Control-Allow-Credentials", "true")],
        "cors_dynamic_origin_missing_vary", "positive", "dynamic_acao_without_vary"))

for i, host in enumerate(["app.example", "login.example", "admin.example", "tenant.example", "shop.example", "pay.example"], 1):
    full.append(fixture(
        f"LF_HSTS_SUBDOMAIN_{i:02d}", "HSTS/framework", ["CL_HSTS_04"], "enforce_https_only_subdomains",
        "Keep HTTPS-only behavior active for the host and its subdomains.",
        {"document_origin": f"https://{host}", "scheme": "https", "subdomain_scope_required": True},
        [h("Strict-Transport-Security", "max-age=31536000")],
        "hsts_subdomain_scope_not_covered", "positive", "missing_include_subdomains"))

expanded_negative_specs = [
    ("NC_CSP_COMPOSE_ALLOW", "Layered policy composition", ["CL_CSP_08"], "allow_required_script_after_policy_composition", "Allow a required script after combining CSP layers.", {"document_origin": "https://app.example", "resource_origin": "https://cdn.example", "resource_kind": "script", "scheme": "https"}, [], "composition_allows_required", [
        {"layer": "framework", "op": "append", "headers": [h("Content-Security-Policy", "script-src 'self' https://cdn.example; object-src 'none'")]},
        {"layer": "proxy_default", "op": "append", "headers": [h("Content-Security-Policy", "script-src 'self' https://cdn.example; object-src 'none'")]},
    ]),
    ("NC_LAYER_PRESERVE", "Layered policy composition", ["CL_LAYER_01"], "preserve_enforced_policy_across_layers", "Preserve enforced CSP after response layers compose.", {"document_origin": "https://app.example", "resource_origin": "https://evil.example", "resource_kind": "script", "scheme": "https", "expected_enforced_csp": True}, [], "layer_preserves_enforced", [
        {"layer": "framework", "op": "append", "headers": [h("Content-Security-Policy", "script-src 'self'; object-src 'none'")]},
        {"layer": "proxy_default", "op": "append", "headers": [h("X-Content-Type-Options", "nosniff")]},
    ]),
    ("NC_CORS_VARY", "CORS/cache", ["CL_CORS_05"], "allow_credentialed_cors_cache_safe", "Allow dynamic-origin credentialed CORS with cache separation.", {"request_origin": "https://frontend.example", "document_origin": "https://frontend.example", "resource_origin": "https://api.example", "credentials_mode": "include", "scheme": "https", "dynamic_origin": True}, [h("Access-Control-Allow-Origin", "https://frontend.example"), h("Access-Control-Allow-Credentials", "true"), h("Vary", "Origin")], "dynamic_acao_with_vary", None),
    ("NC_HSTS_SUBDOMAIN", "HSTS/framework", ["CL_HSTS_04"], "enforce_https_only_subdomains", "Keep HTTPS-only behavior active for the host and its subdomains.", {"document_origin": "https://app.example", "scheme": "https", "subdomain_scope_required": True}, [h("Strict-Transport-Security", "max-age=31536000; includeSubDomains")], "include_subdomains_present", None),
]
for idx, (prefix, family, claim_ids, intent_class, claim, context, headers, variant, layers) in enumerate(expanded_negative_specs, 1):
    for j in range(1, 3):
        ctx = dict(context)
        ctx["negative_control_variant_index"] = j
        lf = fixture(f"LF_{prefix}_{j:02d}", family, claim_ids, intent_class, claim, ctx, headers, "none", "negative_control", variant)
        if layers:
            lf["layers"] = layers
        full.append(lf)

# Attach hashes.
for item in full:
    item["fixture_hash"] = stable_hash({k: item[k] for k in item if k != "fixture_hash"})[:16]
# Canonical locked denominator: keep the historical filenames used by the
# reproduction scripts as exact aliases of the same JSON payload.
write_json(DATA / "locked_full_fixtures.json", full)
write_json(DATA / "locked_fixtures.json", full)
write_json(DATA / "full_fixtures.json", full)

manifest = []
for item in full:
    manifest.append({
        "fixture_id": item["id"],
        "policy_family": item["policy_family"],
        "source_claim_ids": ";".join(item.get("source_claim_ids", [])),
        "intent_class": item["intent"]["class"],
        "expected_issue": item["expected_issue"],
        "fixture_role": item["fixture_role"],
        "variant": item["variant"],
        "header_count": len(item.get("headers", [])),
        "context_keys": ";".join(sorted(item.get("context", {}).keys())),
        "fixture_hash": item["fixture_hash"],
        "locked_status": "locked_pre_experiment",
    })
write_csv(DATA / "fixture_manifest.csv", manifest, ["fixture_id", "policy_family", "source_claim_ids", "intent_class", "expected_issue", "fixture_role", "variant", "header_count", "context_keys", "fixture_hash", "locked_status"])

# Denominator summary.
summary = {
    "date": DATE,
    "workload": "seed-lineage-base",
    "lineage_not_main_denominator": True,
    "main_workload": "BEP-Deep",
    "claims_total": len(claim_rows),
    "semantic_rules_total": len(rules),
    "sources_total": len(sources),
    "seed_fixtures_total": len(full),
    "locked_fixtures_total": len(full),
    "positive_fixtures": sum(1 for f in full if f["fixture_role"] == "positive"),
    "negative_control_fixtures": sum(1 for f in full if f["fixture_role"] == "negative_control"),
    "policy_families": sorted(set(str(f["policy_family"]) for f in full)),
    "expected_issue_labels": sorted(set(str(f["expected_issue"]) for f in full)),
    "corpus_claims_sha256": hashlib.sha256((DATA / "corpus_claims.csv").read_bytes()).hexdigest(),
    "locked_full_fixtures_sha256": hashlib.sha256((DATA / "locked_full_fixtures.json").read_bytes()).hexdigest(),
    "locked_fixtures_sha256": hashlib.sha256((DATA / "locked_fixtures.json").read_bytes()).hexdigest(),
    "full_fixtures_sha256": hashlib.sha256((DATA / "full_fixtures.json").read_bytes()).hexdigest(),
    "fixture_manifest_sha256": hashlib.sha256((DATA / "fixture_manifest.csv").read_bytes()).hexdigest(),
    "rule_to_source_ledger_sha256": hashlib.sha256((METHOD / "rule_to_source_ledger.csv").read_bytes()).hexdigest(),
}
write_json(RESULTS / "lineage" / "seed_denominator_lock_summary.json", summary)

# Protocol lock marker.
lock = {
    "date": DATE,
    "status": "seed_lineage_materialized",
    "scope": "seed-lineage materialization; the release BEP-Deep protocol lock is recorded separately",
    "main_workload": "BEP-Deep",
    "lineage_not_main_denominator": True,
    "locked_inputs": {
        "corpus_claims_csv": summary["corpus_claims_sha256"],
        "locked_full_fixtures_json": summary["locked_full_fixtures_sha256"],
        "locked_fixtures_json": summary["locked_fixtures_sha256"],
        "full_fixtures_json": summary["full_fixtures_sha256"],
        "fixture_manifest_csv": summary["fixture_manifest_sha256"],
        "rule_to_source_ledger_csv": summary["rule_to_source_ledger_sha256"],
    },
    "frozen_rqs": ["RQ1", "RQ2", "RQ3", "RQ4", "RQ5"],
    "amendment_policy": "Any change to release RQs, denominator, expected labels, metrics, negative controls, ablations, or baseline scope requires a recorded protocol amendment before execution.",
}
write_json(ART / "protocol_corpus_lock.json", lock)

# Print a scope-explicit status object rather than a denominator-shaped object,
# so a reproducer does not mistake the seed-lineage materialization for the
# main BEP-Deep denominator.
stdout_summary = {
    "status": "pass",
    "materialized_scope": "seed-lineage-base",
    "main_workload": "BEP-Deep",
    "lineage_not_main_denominator": True,
    "claims_total": len(claim_rows),
    "semantic_rules_total": len(rules),
    "seed_fixtures_total": len(full),
    "main_denominator_summary_preserved": (RESULTS / "denominator_lock_summary.json").exists(),
}
print(json.dumps(stdout_summary, sort_keys=True))
