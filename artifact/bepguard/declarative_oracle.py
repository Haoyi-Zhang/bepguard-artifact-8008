"""Declarative, label-free BEP obligation oracle.

This module is intentionally separate from ``scripts/bep_semantics.py`` and from
``scripts/decision_table_oracle.py``.  It implements the encoded policy fragment
as small guard clauses over normalized headers, intent class, and request
context.  It does not read benchmark labels, fixture roles, source identifiers,
fixture hashes, or certificate identifiers.  Audits may compare its output with
labels and other oracles, but the decision procedure itself is metadata-blind.
"""
from __future__ import annotations

import re
import sys
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlparse

sys.dont_write_bytecode = True
Header = Dict[str, str]


def canonical_header_name(name: str) -> str:
    return "-".join(part.capitalize() for part in str(name).strip().split("-"))


def header_values(headers: Iterable[Mapping[str, Any]], name: str) -> List[str]:
    wanted = canonical_header_name(name)
    return [str(h.get("value", "")) for h in headers if canonical_header_name(str(h.get("name", ""))) == wanted]


def parse_origin(origin: str) -> Tuple[str, str, int | None]:
    parsed = urlparse(str(origin))
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port
    if port is None and scheme == "https":
        port = 443
    if port is None and scheme == "http":
        port = 80
    return scheme, host, port


def same_origin(a: str, b: str) -> bool:
    return parse_origin(a) == parse_origin(b)


def site_key(host: str) -> str:
    labels = host.lower().split(".")
    if labels and labels[-1] in {"example", "invalid", "test", "localhost"}:
        return labels[-1]
    return ".".join(labels[-2:]) if len(labels) >= 2 else host.lower()


def same_site(a: str, b: str) -> bool:
    return site_key(parse_origin(a)[1]) == site_key(parse_origin(b)[1])


def parse_csp(value: str) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for raw in str(value).split(";"):
        parts = raw.strip().split()
        if parts:
            out[parts[0].lower()] = parts[1:]
    return out


def source_allows(token: str, resource_origin: str, document_origin: str) -> bool:
    source = str(token).strip()
    if source == "*":
        return True
    if source == "'none'":
        return False
    if source == "'self'":
        return same_origin(resource_origin, document_origin)
    if source.startswith("'nonce-") or source in {"'strict-dynamic'", "'unsafe-inline'", "'unsafe-eval'"}:
        return False
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*:", source):
        return parse_origin(resource_origin)[0] == source[:-1].lower()
    if source.startswith("http://") or source.startswith("https://"):
        return same_origin(resource_origin, source.rstrip("/"))
    if source.startswith("*."):
        return parse_origin(resource_origin)[1].endswith(source[1:].lower())
    return parse_origin(resource_origin)[1] == source.lower()


def effective_script_sources(policy: str) -> List[str]:
    directives = parse_csp(policy)
    for key in ("script-src-elem", "script-src", "default-src"):
        if key in directives:
            return directives[key]
    return ["*"]


def csp_allows(policy: str, document_origin: str, resource_origin: str) -> bool:
    sources = effective_script_sources(policy)
    return True if not sources else any(source_allows(s, resource_origin, document_origin) for s in sources)


def enforced_csp_allows(policies: Sequence[str], document_origin: str, resource_origin: str) -> bool:
    return all(csp_allows(p, document_origin, resource_origin) for p in policies) if policies else True


def has_directive(policy: str, directive: str) -> bool:
    return directive.lower() in parse_csp(policy)


def has_nonce(policy: str) -> bool:
    return bool(re.search(r"'nonce-[^']+'", str(policy)))


def parse_hsts(value: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {"max_age": None, "valid": False, "include_subdomains": False, "preload": False}
    for raw in str(value).split(";"):
        token = raw.strip()
        lower = token.lower()
        if lower.startswith("max-age"):
            _, _, raw_value = token.partition("=")
            raw_value = raw_value.strip().strip('"')
            if raw_value.isdigit():
                out["max_age"] = int(raw_value)
                out["valid"] = True
            else:
                out["max_age"] = None
                out["valid"] = False
        elif lower == "includesubdomains":
            out["include_subdomains"] = True
        elif lower == "preload":
            out["preload"] = True
    return out


def hsts_preload_ready(value: str) -> bool:
    parsed = parse_hsts(value)
    max_age = parsed.get("max_age")
    return bool(parsed.get("valid") and isinstance(max_age, int) and max_age >= 31536000 and parsed.get("include_subdomains") and parsed.get("preload"))


def cors_shareable(headers: Sequence[Mapping[str, Any]], request_origin: str, credentials_mode: str) -> bool:
    acao = [v.strip() for v in header_values(headers, "Access-Control-Allow-Origin")]
    if len(acao) != 1:
        return False
    acac = [v.strip() for v in header_values(headers, "Access-Control-Allow-Credentials")]
    if acao[0] == "*":
        return credentials_mode != "include"
    if acao[0] in {request_origin, "$ORIGIN"}:
        return credentials_mode != "include" or "true" in acac
    return False


def vary_has_origin(headers: Sequence[Mapping[str, Any]]) -> bool:
    for value in header_values(headers, "Vary"):
        if "origin" in [p.strip().lower() for p in value.split(",")]:
            return True
    return False


def parse_permissions(value: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for raw in str(value).split(","):
        if "=" not in raw:
            continue
        feature, _, allowlist = raw.partition("=")
        out[feature.strip().lower()] = allowlist.strip()
    return out


def permissions_disabled(headers: Sequence[Mapping[str, Any]], feature: str) -> bool:
    key = feature.strip().lower()
    return any(parse_permissions(v).get(key) == "()" for v in header_values(headers, "Permissions-Policy"))


def permissions_overallowed(headers: Sequence[Mapping[str, Any]], feature: str, target_origin: str) -> bool:
    key = feature.strip().lower()
    needle = target_origin.lower()
    for value in header_values(headers, "Permissions-Policy"):
        allowlist = parse_permissions(value).get(key)
        if allowlist is None:
            continue
        normalized = allowlist.replace("'", "").strip().lower()
        if normalized in {"*", "(*)"} or "*" in normalized or (needle and needle in normalized):
            return True
    return False


def corp_allows(value: Optional[str], document_origin: str, resource_origin: str) -> bool:
    if value is None:
        return False
    normalized = value.strip().lower()
    if normalized == "cross-origin":
        return True
    if normalized == "same-origin":
        return same_origin(document_origin, resource_origin)
    if normalized == "same-site":
        return same_site(document_origin, resource_origin)
    return False


def composed_headers(fixture: Mapping[str, Any]) -> List[Header]:
    headers: List[Header] = [dict(h) for h in fixture.get("headers", []) if isinstance(h, Mapping)]
    layers = fixture.get("layers", [])
    if not isinstance(layers, list):
        return headers
    for layer in layers:
        if not isinstance(layer, Mapping):
            continue
        op = str(layer.get("op", "append")).lower()
        layer_headers = layer.get("headers", [])
        if not isinstance(layer_headers, list):
            continue
        if op == "remove":
            remove = {canonical_header_name(str(h.get("name", ""))) for h in layer_headers if isinstance(h, Mapping)}
            headers = [h for h in headers if canonical_header_name(h.get("name", "")) not in remove]
            continue
        for raw in layer_headers:
            if not isinstance(raw, Mapping):
                continue
            h = {"name": str(raw.get("name", "")), "value": str(raw.get("value", ""))}
            if op == "set":
                wanted = canonical_header_name(h["name"])
                headers = [old for old in headers if canonical_header_name(old.get("name", "")) != wanted]
            headers.append(h)
    return headers


def declarative_issues(fixture: Mapping[str, Any]) -> Tuple[str, ...]:
    """Return the sorted issue set implied by headers, intent class, and context."""
    headers = composed_headers(fixture)
    ctx = fixture.get("context", {}) if isinstance(fixture.get("context", {}), Mapping) else {}
    intent = fixture.get("intent", {}) if isinstance(fixture.get("intent", {}), Mapping) else {}
    intent_class = str(intent.get("class", ""))
    document_origin = str(ctx.get("document_origin", "https://app.example"))
    resource_origin = str(ctx.get("resource_origin", "https://cdn.example"))
    request_origin = str(ctx.get("request_origin", document_origin))
    credentials_mode = str(ctx.get("credentials_mode", "omit"))
    request_mode = str(ctx.get("request_mode", "no-cors")).lower()
    scheme = str(ctx.get("scheme", parse_origin(document_origin)[0] or "https")).lower()
    feature = str(ctx.get("feature", "")) or "geolocation"
    out: List[str] = []

    csp = header_values(headers, "Content-Security-Policy")
    ro = header_values(headers, "Content-Security-Policy-Report-Only")
    if intent_class == "preserve_enforced_policy_across_layers":
        if bool(ctx.get("expected_enforced_csp", True)) and (not csp or (ro and not any(canonical_header_name(h.get("name", "")) == "Content-Security-Policy" for h in headers))):
            out.append("layered_header_override_drops_enforcement")
    if intent_class == "allow_required_script_after_policy_composition":
        if len(csp) > 1 and not enforced_csp_allows(csp, document_origin, resource_origin):
            out.append("csp_conjunctive_policy_composition_blocks_required_script")
    if intent_class == "enforce_script_restriction":
        if ro and not csp:
            out.append("csp_report_only_not_enforced")
        elif csp and enforced_csp_allows(csp, document_origin, resource_origin):
            out.append("csp_effective_script_allowance")
    if intent_class == "allow_trusted_script":
        if csp and not enforced_csp_allows(csp, document_origin, resource_origin):
            out.append("csp_multiple_policy_overblocks_trusted_script")
    if intent_class == "enforce_framing_protection":
        meta = header_values(headers, "Content-Security-Policy-Meta")
        if any(has_directive(v, "frame-ancestors") for v in ro) and not any(has_directive(v, "frame-ancestors") for v in csp):
            out.append("csp_frame_ancestors_report_only_not_enforced")
        if any(has_directive(v, "frame-ancestors") for v in meta) and not any(has_directive(v, "frame-ancestors") for v in csp):
            out.append("csp_frame_ancestors_meta_delivery_unsupported")
    if intent_class == "nonce_based_strict_csp" and bool(ctx.get("static_render", False)) and any(has_nonce(v) for v in csp):
        out.append("nonce_csp_static_render_incompatibility")

    acao = [v.strip() for v in header_values(headers, "Access-Control-Allow-Origin")]
    acac = [v.strip() for v in header_values(headers, "Access-Control-Allow-Credentials")]
    if intent_class == "allow_credentialed_cors":
        if len(acao) > 1:
            out.append("cors_duplicate_acao_not_shareable")
        elif acao and acao[0] in {request_origin, "$ORIGIN"} and credentials_mode == "include" and any(v.lower() == "true" and v != "true" for v in acac):
            out.append("cors_acac_case_sensitive_not_shareable")
        elif not cors_shareable(headers, request_origin, credentials_mode):
            out.append("cors_intended_credentialed_share_blocked")
    if intent_class == "deny_public_credentialed_cors" and credentials_mode == "include" and "$ORIGIN" in acao and "true" in acac:
        out.append("cors_reflected_origin_with_credentials")
    if intent_class == "partition_cors_cache_by_origin":
        if bool(ctx.get("shared_cache", False)) and "$ORIGIN" in acao and not vary_has_origin(headers):
            out.append("cors_dynamic_origin_without_vary")
    if intent_class == "allow_credentialed_cors_cache_safe":
        dynamic_origin = bool(ctx.get("dynamic_origin", False)) or "$ORIGIN" in acao or request_origin in acao
        if dynamic_origin and credentials_mode == "include" and "true" in acac and not vary_has_origin(headers):
            out.append("cors_dynamic_origin_missing_vary")

    hsts = header_values(headers, "Strict-Transport-Security")
    if intent_class == "enforce_https_only" and hsts:
        parsed = parse_hsts(hsts[0])
        if scheme != "https":
            out.append("hsts_header_not_honored_over_http")
        elif not parsed.get("valid"):
            out.append("hsts_invalid_max_age_ignored")
        elif parsed.get("max_age") == 0:
            out.append("hsts_policy_cleared_by_zero_max_age")
    if intent_class == "enforce_https_subdomains" and hsts:
        parsed = parse_hsts(hsts[0])
        if scheme == "https" and bool(ctx.get("subdomain_request", True)) and not parsed.get("include_subdomains"):
            out.append("hsts_missing_include_subdomains")
    if intent_class == "enforce_https_only_subdomains" and hsts:
        parsed = parse_hsts(hsts[0])
        if scheme == "https" and bool(ctx.get("subdomain_scope_required", True)) and parsed.get("valid") and not parsed.get("include_subdomains"):
            out.append("hsts_subdomain_scope_not_covered")
    if intent_class == "expect_hsts_preload" and hsts and not hsts_preload_ready(hsts[0]):
        out.append("hsts_preload_criteria_not_met")

    if intent_class == "cross_origin_isolation_without_embed_breakage":
        coep = [v.strip().lower() for v in header_values(headers, "Cross-Origin-Embedder-Policy")]
        corp = header_values(headers, "Cross-Origin-Resource-Policy")
        if "require-corp" in coep and request_mode == "no-cors" and not same_origin(document_origin, resource_origin):
            corp_ok = any(corp_allows(v, document_origin, resource_origin) for v in corp)
            cors_ok = request_mode == "cors" and cors_shareable(headers, document_origin, credentials_mode)
            if not corp_ok and not cors_ok:
                out.append("coep_require_corp_blocks_cross_origin_resource")
    if intent_class == "deny_cross_origin_embedding":
        corp = header_values(headers, "Cross-Origin-Resource-Policy")
        if not same_origin(document_origin, resource_origin) and same_site(document_origin, resource_origin) and any(v.strip().lower() == "same-site" for v in corp):
            out.append("corp_same_site_allows_cross_origin_same_site")
    if intent_class == "enable_cross_origin_isolation":
        coop = [v.strip().lower() for v in header_values(headers, "Cross-Origin-Opener-Policy")]
        coep = [v.strip().lower() for v in header_values(headers, "Cross-Origin-Embedder-Policy")]
        if not ("same-origin" in coop and any(v in {"require-corp", "credentialless"} for v in coep) and not permissions_disabled(headers, "cross-origin-isolated")):
            out.append("cross_origin_isolation_incomplete")

    if intent_class == "allow_browser_feature" and permissions_disabled(headers, feature):
        out.append("permissions_policy_feature_disabled")
    if intent_class == "deny_browser_feature" and permissions_overallowed(headers, feature, str(ctx.get("target_origin", "*"))):
        out.append("permissions_policy_feature_overallowed")

    return tuple(sorted(set(out)))
