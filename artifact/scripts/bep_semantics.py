#!/usr/bin/env python3
"""Executable core semantics for BEP semantic-witness experiments.

The model is deterministic and CPU-native. It covers the Browser-Enforced
Policy fragments used by the source-grounded workload: CSP delivery/fallback /
nonces / multiple-policy intersection / frame-ancestor delivery, CORS
shareability and cache-variant hazards, HSTS state transitions and preload
criteria, COEP/CORP/CORS embedding, COOP+COEP cross-origin isolation, and
Permissions-Policy allowlist denial/over-allowance. It performs no network
access.
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse
import json
import re

Header = Dict[str, str]
Context = Dict[str, object]


@dataclass(frozen=True)
class Finding:
    fixture_id: str
    issue: str
    severity: str
    policy_family: str
    intent_class: str
    explanation: str
    witness: Dict[str, object]


def canonical_header_name(name: str) -> str:
    return "-".join(part.capitalize() for part in name.strip().split("-"))


def header_values(headers: Iterable[Header], name: str) -> List[str]:
    wanted = canonical_header_name(name)
    return [str(h.get("value", "")) for h in headers if canonical_header_name(str(h.get("name", ""))) == wanted]


def has_header_token(headers: Iterable[Header], name: str, token: str) -> bool:
    wanted = token.strip().lower()
    return any(v.strip().lower() == wanted for v in header_values(headers, name))


def parse_csp(policy: str) -> Dict[str, List[str]]:
    directives: Dict[str, List[str]] = {}
    for raw_segment in str(policy).split(";"):
        segment = raw_segment.strip()
        if not segment:
            continue
        parts = segment.split()
        if not parts:
            continue
        directives[parts[0].lower()] = parts[1:]
    return directives


def parse_origin(origin: str) -> Tuple[str, str, Optional[int]]:
    parsed = urlparse(origin)
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port
    if port is None and scheme == "https":
        port = 443
    elif port is None and scheme == "http":
        port = 80
    return scheme, host, port


def same_origin(a: str, b: str) -> bool:
    return parse_origin(a) == parse_origin(b)


def _fixture_site_key(host: str) -> str:
    labels = host.lower().split(".")
    # The workload uses reserved fixture domains rather than a public suffix list.
    # Treat *.example as one deterministic site so app.example and cdn.example
    # exercise same-site/cross-origin behavior without external dependencies.
    if labels and labels[-1] in {"example", "invalid", "test", "localhost"}:
        return labels[-1]
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return host.lower()


def same_site(a: str, b: str) -> bool:
    """Small deterministic approximation for fixture hostnames."""
    return _fixture_site_key(parse_origin(a)[1]) == _fixture_site_key(parse_origin(b)[1])


def source_allows(source: str, resource_origin: str, document_origin: str) -> bool:
    s = source.strip()
    if s == "*":
        return True
    if s == "'none'":
        return False
    if s == "'self'":
        return same_origin(resource_origin, document_origin)
    if s.startswith("'nonce-") or s in {"'strict-dynamic'", "'unsafe-inline'", "'unsafe-eval'"}:
        # The locked script-load probe is a host/source-list question. Nonces and
        # keyword execution modes do not authorize a third-party URL by host.
        return False
    if s.endswith(":") and re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*:", s):
        return parse_origin(resource_origin)[0] == s[:-1].lower()
    if s.startswith("http://") or s.startswith("https://"):
        return same_origin(resource_origin, s.rstrip("/"))
    if s.startswith("*."):
        return parse_origin(resource_origin)[1].endswith(s[1:].lower())
    return parse_origin(resource_origin)[1] == s.lower()


def effective_script_sources(policy: str) -> List[str]:
    directives = parse_csp(policy)
    # The encoded script-element request fragment follows CSP3's fallback list:
    # script-src-elem, then script-src, then default-src.  Keeping the most
    # specific directive first matters for policies that intentionally refine
    # script-element loads separately from generic script execution sinks.
    if "script-src-elem" in directives:
        return directives["script-src-elem"]
    if "script-src" in directives:
        return directives["script-src"]
    if "default-src" in directives:
        return directives["default-src"]
    return ["*"]


def csp_policy_allows_script(policy: str, document_origin: str, resource_origin: str) -> bool:
    sources = effective_script_sources(policy)
    if not sources:
        return True
    return any(source_allows(src, resource_origin, document_origin) for src in sources)


def enforced_csp_allows_script(policies: List[str], document_origin: str, resource_origin: str) -> bool:
    # Multiple enforced CSP policies restrict conjunctively: a script load must
    # be allowed by every enforced policy. With no enforced CSP, the fragment's
    # default is allow.
    if not policies:
        return True
    return all(csp_policy_allows_script(policy, document_origin, resource_origin) for policy in policies)


def csp_has_nonce(policy: str) -> bool:
    return bool(re.search(r"'nonce-[^']+'", str(policy)))


def csp_has_directive(policy: str, directive: str) -> bool:
    return directive.lower() in parse_csp(policy)


def parse_hsts(value: str) -> Dict[str, object]:
    result: Dict[str, object] = {"max_age": None, "include_subdomains": False, "preload": False, "valid_max_age": False}
    for part in str(value).split(";"):
        token = part.strip()
        lower = token.lower()
        if lower.startswith("max-age"):
            _, _, raw_value = token.partition("=")
            raw_value = raw_value.strip().strip('"')
            if raw_value.isdigit():
                result["max_age"] = int(raw_value)
                result["valid_max_age"] = True
            else:
                result["max_age"] = None
                result["valid_max_age"] = False
        elif lower == "includesubdomains":
            result["include_subdomains"] = True
        elif lower == "preload":
            result["preload"] = True
    return result


def hsts_preload_ready(value: str) -> bool:
    """Return the encoded preload-eligibility predicate for an STS header.

    The predicate is intentionally narrower than general HSTS state creation: a
    header can establish HSTS state without being preload-ready.  Keeping this
    helper in the semantic core prevents the documented preload control from
    drifting into a general HSTS oracle.
    """
    parsed = parse_hsts(value)
    max_age = parsed.get("max_age")
    return bool(
        parsed.get("valid_max_age")
        and isinstance(max_age, int)
        and max_age >= 31536000
        and parsed.get("include_subdomains")
        and parsed.get("preload")
    )


def cors_shareable(headers: List[Header], request_origin: str, credentials_mode: str) -> bool:
    acao_values = [v.strip() for v in header_values(headers, "Access-Control-Allow-Origin")]
    if len(acao_values) != 1:
        return False
    acao = acao_values[0]
    # Fetch's ACAC success value is byte-case-sensitive: exactly "true".
    acac_values = [v.strip() for v in header_values(headers, "Access-Control-Allow-Credentials")]
    credentials_included = credentials_mode == "include"
    if acao == "*":
        return not credentials_included
    if acao in {request_origin, "$ORIGIN"}:
        return (not credentials_included) or ("true" in acac_values)
    return False


def cors_dynamic_origin_without_vary(headers: List[Header]) -> bool:
    acao_values = [v.strip() for v in header_values(headers, "Access-Control-Allow-Origin")]
    vary_values = [v.strip().lower() for v in header_values(headers, "Vary")]
    dynamic = any(v == "$ORIGIN" for v in acao_values)
    has_vary_origin = any("origin" in [part.strip() for part in v.split(",")] for v in vary_values)
    return dynamic and not has_vary_origin


def parse_permissions_policy(value: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for segment in str(value).split(","):
        part = segment.strip()
        if not part or "=" not in part:
            continue
        feature, _, allowlist = part.partition("=")
        result[feature.strip().lower()] = allowlist.strip()
    return result


def permissions_feature_disabled(headers: List[Header], feature: str) -> bool:
    feature_key = feature.strip().lower()
    for value in header_values(headers, "Permissions-Policy"):
        if parse_permissions_policy(value).get(feature_key) == "()":
            return True
    return False


def permissions_feature_overallowed(headers: List[Header], feature: str, target_origin: str = "*") -> bool:
    feature_key = feature.strip().lower()
    for value in header_values(headers, "Permissions-Policy"):
        allowlist = parse_permissions_policy(value).get(feature_key)
        if allowlist is None:
            continue
        normalized = allowlist.replace("'", "").strip().lower()
        if normalized in {"*", "(*)"} or "*" in normalized:
            return True
        if target_origin and target_origin.lower() in normalized:
            return True
    return False


def cross_origin_isolation_headers_ok(headers: List[Header]) -> bool:
    coop = [v.strip().lower() for v in header_values(headers, "Cross-Origin-Opener-Policy")]
    coep = [v.strip().lower() for v in header_values(headers, "Cross-Origin-Embedder-Policy")]
    return (
        "same-origin" in coop
        and any(v in {"require-corp", "credentialless"} for v in coep)
        and not permissions_feature_disabled(headers, "cross-origin-isolated")
    )


def corp_allows(corp_value: Optional[str], document_origin: str, resource_origin: str) -> bool:
    if corp_value is None:
        return False
    v = corp_value.strip().lower()
    if v == "cross-origin":
        return True
    if v == "same-origin":
        return same_origin(document_origin, resource_origin)
    if v == "same-site":
        return same_site(document_origin, resource_origin)
    return False


def _finding(fid: str, issue: str, severity: str, family: str, intent_class: str, explanation: str, witness: Dict[str, object]) -> Finding:
    return Finding(fid, issue, severity, family, intent_class, explanation, witness)


def effective_headers_from_layers(fixture: Dict[str, object]) -> Tuple[List[Header], List[Dict[str, object]]]:
    """Compose response headers from optional ordered generation layers.

    ``append`` preserves earlier fields, ``set`` replaces earlier fields with
    the same header name, and ``remove`` deletes earlier fields with the same
    header name.  Multiple CSP fields are preserved when appended, matching the
    encoded conjunctive-policy fragment.  The provenance trace is used only for
    explaining witnesses and does not affect oracle decisions.
    """
    base = fixture.get("headers", [])
    headers: List[Header] = list(base) if isinstance(base, list) else []  # type: ignore[list-item]
    provenance: List[Dict[str, object]] = [
        {"layer_index": 0, "layer_name": "flat_response", "op": "base", "header": h.get("name", "")}
        for h in headers
    ]
    layers = fixture.get("layers", [])
    if not isinstance(layers, list):
        return headers, provenance
    for li, layer in enumerate(layers):
        if not isinstance(layer, dict):
            continue
        op = str(layer.get("op", "append")).lower()
        lname = str(layer.get("layer", layer.get("name", f"layer{li}")))
        layer_headers = layer.get("headers", [])
        if not isinstance(layer_headers, list):
            continue
        if op == "remove":
            remove_names = {canonical_header_name(str(h.get("name", ""))) for h in layer_headers if isinstance(h, dict)}
            headers = [h for h in headers if canonical_header_name(str(h.get("name", ""))) not in remove_names]
            provenance.append({"layer_index": li, "layer_name": lname, "op": "remove", "header": ";".join(sorted(remove_names))})
            continue
        for header in layer_headers:
            if not isinstance(header, dict):
                continue
            new_header = {"name": str(header.get("name", "")), "value": str(header.get("value", ""))}
            wanted = canonical_header_name(new_header["name"])
            if op == "set":
                headers = [h for h in headers if canonical_header_name(str(h.get("name", ""))) != wanted]
            headers.append(new_header)
            provenance.append({"layer_index": li, "layer_name": lname, "op": op, "header": new_header["name"]})
    return headers, provenance


def analyze_fixture(fixture: Dict[str, object]) -> List[Finding]:
    fid = str(fixture.get("id", "unknown"))
    headers, layer_trace = effective_headers_from_layers(fixture)
    ctx: Context = dict(fixture.get("context", {})) if isinstance(fixture.get("context", {}), dict) else {}
    intent = dict(fixture.get("intent", {})) if isinstance(fixture.get("intent", {}), dict) else {}
    intent_class = str(intent.get("class", "unspecified"))
    findings: List[Finding] = []

    document_origin = str(ctx.get("document_origin", "https://app.example"))
    resource_origin = str(ctx.get("resource_origin", "https://cdn.example"))
    request_origin = str(ctx.get("request_origin", document_origin))
    credentials_mode = str(ctx.get("credentials_mode", "omit"))
    scheme = str(ctx.get("scheme", parse_origin(document_origin)[0] or "https")).lower()
    request_mode = str(ctx.get("request_mode", "no-cors")).lower()
    feature = str(ctx.get("feature", ""))

    csp_values = header_values(headers, "Content-Security-Policy")
    csp_ro_values = header_values(headers, "Content-Security-Policy-Report-Only")
    if intent_class == "preserve_enforced_policy_across_layers":
        if bool(ctx.get("expected_enforced_csp", True)) and not csp_values:
            findings.append(_finding(
                fid,
                "layered_header_override_drops_enforcement",
                "high",
                "Layered policy composition",
                intent_class,
                "The ordered policy-generation layers remove the enforced CSP required by the explicit intent.",
                {"headers": [], "layer_trace": layer_trace},
            ))
        elif bool(ctx.get("expected_enforced_csp", True)) and csp_ro_values and not any("Content-Security-Policy" == canonical_header_name(str(h.get("name", ""))) for h in headers):
            findings.append(_finding(
                fid,
                "layered_header_override_drops_enforcement",
                "high",
                "Layered policy composition",
                intent_class,
                "The composed surface leaves only report-only CSP where the explicit intent requires enforcement.",
                {"headers": [{"name": "Content-Security-Policy-Report-Only", "value": csp_ro_values[0]}], "layer_trace": layer_trace},
            ))

    if intent_class == "allow_required_script_after_policy_composition":
        if len(csp_values) > 1 and not enforced_csp_allows_script(csp_values, document_origin, resource_origin):
            findings.append(_finding(
                fid,
                "csp_conjunctive_policy_composition_blocks_required_script",
                "medium",
                "Layered policy composition",
                intent_class,
                "Multiple enforced CSP policies compose conjunctively, so a required script allowed by one layer is blocked by another layer's policy.",
                {"headers": [{"name": "Content-Security-Policy", "value": v} for v in csp_values], "attempt": {"document_origin": document_origin, "resource_origin": resource_origin}, "layer_trace": layer_trace},
            ))

    if intent_class == "enforce_script_restriction":
        if csp_ro_values and not csp_values:
            findings.append(_finding(
                fid,
                "csp_report_only_not_enforced",
                "high",
                "CSP",
                intent_class,
                "Only report-only CSP is delivered, so the browser reports violations but does not enforce script blocking.",
                {"headers": [{"name": "Content-Security-Policy-Report-Only", "value": csp_ro_values[0]}], "attempt": {"resource_kind": "script", "resource_origin": resource_origin}},
            ))
        elif csp_values and enforced_csp_allows_script(csp_values, document_origin, resource_origin):
            findings.append(_finding(
                fid,
                "csp_effective_script_allowance",
                "high",
                "CSP",
                intent_class,
                "The effective script source list permits the probed third-party script under script-src or default-src fallback.",
                {"headers": [{"name": "Content-Security-Policy", "value": v} for v in csp_values], "effective_sources": [effective_script_sources(v) for v in csp_values], "attempt": {"document_origin": document_origin, "resource_origin": resource_origin}},
            ))

    if intent_class == "allow_trusted_script":
        if csp_values and not enforced_csp_allows_script(csp_values, document_origin, resource_origin):
            findings.append(_finding(
                fid,
                "csp_multiple_policy_overblocks_trusted_script",
                "medium",
                "CSP/composition",
                intent_class,
                "The trusted script is blocked because multiple enforced CSP policies compose conjunctively in the encoded fragment.",
                {"headers": [{"name": "Content-Security-Policy", "value": v} for v in csp_values], "attempt": {"document_origin": document_origin, "resource_origin": resource_origin}},
            ))

    if intent_class == "enforce_framing_protection":
        meta_values = header_values(headers, "Content-Security-Policy-Meta")
        all_frame_sources = [v for v in csp_values if csp_has_directive(v, "frame-ancestors")]
        ro_frame_sources = [v for v in csp_ro_values if csp_has_directive(v, "frame-ancestors")]
        meta_frame_sources = [v for v in meta_values if csp_has_directive(v, "frame-ancestors")]
        if ro_frame_sources and not all_frame_sources:
            findings.append(_finding(
                fid,
                "csp_frame_ancestors_report_only_not_enforced",
                "high",
                "CSP/framing",
                intent_class,
                "Frame-ancestor restriction appears only in report-only CSP and therefore does not enforce the framing decision.",
                {"headers": [{"name": "Content-Security-Policy-Report-Only", "value": ro_frame_sources[0]}], "attempt": {"ancestor_origin": ctx.get("ancestor_origin", "https://embedder.example")}},
            ))
        if meta_frame_sources and not all_frame_sources:
            findings.append(_finding(
                fid,
                "csp_frame_ancestors_meta_delivery_unsupported",
                "high",
                "CSP/framing",
                intent_class,
                "The fixture encodes frame-ancestors through a meta-delivery surface, which is outside the modeled enforcing header delivery surface.",
                {"meta_policy": meta_frame_sources[0], "attempt": {"ancestor_origin": ctx.get("ancestor_origin", "https://embedder.example")}},
            ))

    if intent_class == "nonce_based_strict_csp" and bool(ctx.get("static_render", False)):
        for csp in csp_values:
            if csp_has_nonce(csp):
                findings.append(_finding(
                    fid,
                    "nonce_csp_static_render_incompatibility",
                    "medium",
                    "CSP/framework",
                    intent_class,
                    "A nonce-bearing CSP requires a per-request value, but the fixture context is statically rendered or statically cached.",
                    {"headers": [{"name": "Content-Security-Policy", "value": csp}], "rendering": ctx.get("rendering_variant", "static"), "required_value": "per-request nonce"},
                ))
                break

    if intent_class == "allow_credentialed_cors":
        acao_values = [v.strip() for v in header_values(headers, "Access-Control-Allow-Origin")]
        acac_values = [v.strip() for v in header_values(headers, "Access-Control-Allow-Credentials")]
        if len(acao_values) > 1:
            findings.append(_finding(
                fid,
                "cors_duplicate_acao_not_shareable",
                "medium",
                "CORS",
                intent_class,
                "Multiple Access-Control-Allow-Origin values are not a single valid credentialed CORS authorization in the encoded fragment.",
                {"acao_values": acao_values, "request_origin": request_origin, "credentials_mode": credentials_mode},
            ))
        elif acao_values and acao_values[0] in {request_origin, "$ORIGIN"} and credentials_mode == "include" and any(v.lower() == "true" and v != "true" for v in acac_values):
            findings.append(_finding(
                fid,
                "cors_acac_case_sensitive_not_shareable",
                "medium",
                "CORS",
                intent_class,
                "The credentialed CORS response uses a non-lowercase ACAC value, while the encoded success value is exactly true.",
                {"headers": [{"name": "Access-Control-Allow-Origin", "value": acao_values[0]}, {"name": "Access-Control-Allow-Credentials", "value": acac_values[0] if acac_values else ""}], "request_origin": request_origin},
            ))
        elif not cors_shareable(headers, request_origin, credentials_mode):
            findings.append(_finding(
                fid,
                "cors_intended_credentialed_share_blocked",
                "medium",
                "CORS",
                intent_class,
                "The response does not satisfy the CORS shareability conditions for a credentialed request.",
                {"headers": [{"name": "Access-Control-Allow-Origin", "value": v} for v in acao_values] + [{"name": "Access-Control-Allow-Credentials", "value": v} for v in acac_values], "request_origin": request_origin, "credentials_mode": credentials_mode},
            ))
    elif intent_class == "deny_public_credentialed_cors":
        acao_values = [v.strip() for v in header_values(headers, "Access-Control-Allow-Origin")]
        acac_values = [v.strip() for v in header_values(headers, "Access-Control-Allow-Credentials")]
        if credentials_mode == "include" and "$ORIGIN" in acao_values and "true" in acac_values:
            findings.append(_finding(
                fid,
                "cors_reflected_origin_with_credentials",
                "high",
                "CORS/framework",
                intent_class,
                "The policy reflects arbitrary request origins while enabling credentialed sharing.",
                {"headers": [{"name": "Access-Control-Allow-Origin", "value": "$ORIGIN"}, {"name": "Access-Control-Allow-Credentials", "value": "true"}], "request_origin": request_origin},
            ))
    elif intent_class == "partition_cors_cache_by_origin":
        if bool(ctx.get("shared_cache", False)) and cors_dynamic_origin_without_vary(headers):
            findings.append(_finding(
                fid,
                "cors_dynamic_origin_without_vary",
                "medium",
                "CORS/cache",
                intent_class,
                "A dynamically reflected ACAO surface is used in a shared-cache context without a Vary: Origin discriminator.",
                {"headers": [{"name": "Access-Control-Allow-Origin", "value": v} for v in header_values(headers, "Access-Control-Allow-Origin")] + [{"name": "Vary", "value": v} for v in header_values(headers, "Vary")], "shared_cache": True},
            ))

    elif intent_class == "allow_credentialed_cors_cache_safe":
        acao_values = [v.strip() for v in header_values(headers, "Access-Control-Allow-Origin")]
        acac_values = [v.strip() for v in header_values(headers, "Access-Control-Allow-Credentials")]
        vary_values = [v.strip().lower() for v in header_values(headers, "Vary")]
        has_vary_origin = any("origin" in [part.strip() for part in v.split(",")] for v in vary_values)
        dynamic_origin = bool(ctx.get("dynamic_origin", False)) or "$ORIGIN" in acao_values or request_origin in acao_values
        if dynamic_origin and credentials_mode == "include" and "true" in acac_values and not has_vary_origin:
            findings.append(_finding(
                fid,
                "cors_dynamic_origin_missing_vary",
                "medium",
                "CORS/cache",
                intent_class,
                "A dynamic credentialed CORS surface lacks Vary: Origin, so a shared cache may reuse the response outside the intended request-origin context.",
                {"headers": [{"name": "Access-Control-Allow-Origin", "value": v} for v in acao_values] + [{"name": "Access-Control-Allow-Credentials", "value": v} for v in acac_values], "missing": "Vary: Origin", "request_origin": request_origin},
            ))

    hsts_values = header_values(headers, "Strict-Transport-Security")
    if intent_class == "enforce_https_only" and hsts_values:
        first_hsts = hsts_values[0]
        parsed_hsts = parse_hsts(first_hsts)
        if scheme != "https":
            findings.append(_finding(
                fid,
                "hsts_header_not_honored_over_http",
                "high",
                "HSTS",
                intent_class,
                "An HSTS header received over insecure transport is ignored by the user agent.",
                {"headers": [{"name": "Strict-Transport-Security", "value": first_hsts}], "scheme": scheme},
            ))
        elif not parsed_hsts.get("valid_max_age"):
            findings.append(_finding(
                fid,
                "hsts_invalid_max_age_ignored",
                "high",
                "HSTS",
                intent_class,
                "The STS header does not contain a valid max-age directive in the encoded fragment, so it cannot establish the intended state.",
                {"headers": [{"name": "Strict-Transport-Security", "value": first_hsts}], "scheme": scheme},
            ))
        elif parsed_hsts.get("max_age") == 0:
            findings.append(_finding(
                fid,
                "hsts_policy_cleared_by_zero_max_age",
                "high",
                "HSTS",
                intent_class,
                "An HSTS max-age of zero clears the user agent's known-HSTS-host state.",
                {"headers": [{"name": "Strict-Transport-Security", "value": first_hsts}], "transition": "delete-known-hsts-host"},
            ))

    if intent_class == "enforce_https_subdomains" and hsts_values:
        parsed_hsts = parse_hsts(hsts_values[0])
        if scheme == "https" and bool(ctx.get("subdomain_request", True)) and not parsed_hsts.get("include_subdomains"):
            findings.append(_finding(
                fid,
                "hsts_missing_include_subdomains",
                "medium",
                "HSTS/subdomains",
                intent_class,
                "The policy is intended to cover subdomains, but the emitted STS header lacks includeSubDomains.",
                {"headers": [{"name": "Strict-Transport-Security", "value": hsts_values[0]}], "subdomain_request": ctx.get("subdomain_request", True)},
            ))

    if intent_class == "enforce_https_only_subdomains" and hsts_values:
        parsed_hsts = parse_hsts(hsts_values[0])
        if scheme == "https" and bool(ctx.get("subdomain_scope_required", True)) and parsed_hsts.get("valid_max_age") and not parsed_hsts.get("include_subdomains"):
            findings.append(_finding(
                fid,
                "hsts_subdomain_scope_not_covered",
                "medium",
                "HSTS/framework",
                intent_class,
                "The effective STS header establishes host state but omits includeSubDomains while the policy intent requires subdomain coverage.",
                {"headers": [{"name": "Strict-Transport-Security", "value": hsts_values[0]}], "required_scope": "includeSubDomains"},
            ))

    if intent_class == "expect_hsts_preload" and hsts_values:
        parsed_hsts = parse_hsts(hsts_values[0])
        if not hsts_preload_ready(hsts_values[0]):
            findings.append(_finding(
                fid,
                "hsts_preload_criteria_not_met",
                "medium",
                "HSTS/preload",
                intent_class,
                "The header does not satisfy the documented preload-oriented criterion encoded by the benchmark control.",
                {"headers": [{"name": "Strict-Transport-Security", "value": hsts_values[0]}], "criterion": "max-age>=31536000; includeSubDomains; preload"},
            ))

    if intent_class == "cross_origin_isolation_without_embed_breakage":
        coep_values = [v.strip().lower() for v in header_values(headers, "Cross-Origin-Embedder-Policy")]
        corp_values = header_values(headers, "Cross-Origin-Resource-Policy")
        has_require_corp = "require-corp" in coep_values
        same_doc_resource = same_origin(document_origin, resource_origin)
        if has_require_corp and request_mode == "no-cors" and not same_doc_resource:
            corp_ok = any(corp_allows(v, document_origin, resource_origin) for v in corp_values)
            cors_ok = request_mode == "cors" and cors_shareable(headers, document_origin, credentials_mode)
            if not corp_ok and not cors_ok:
                findings.append(_finding(
                    fid,
                    "coep_require_corp_blocks_cross_origin_resource",
                    "medium",
                    "COEP/CORP/CORS",
                    intent_class,
                    "COEP require-corp blocks the cross-origin no-cors resource because it has neither compatible CORP nor CORS authorization.",
                    {"headers": [{"name": "Cross-Origin-Embedder-Policy", "value": "require-corp"}] + ([{"name": "Cross-Origin-Resource-Policy", "value": corp_values[0]}] if corp_values else []), "request_mode": request_mode, "resource_origin": resource_origin},
                ))

    if intent_class == "deny_cross_origin_embedding":
        corp_values = header_values(headers, "Cross-Origin-Resource-Policy")
        if not same_origin(document_origin, resource_origin) and same_site(document_origin, resource_origin) and any(v.strip().lower() == "same-site" for v in corp_values):
            findings.append(_finding(
                fid,
                "corp_same_site_allows_cross_origin_same_site",
                "medium",
                "CORP",
                intent_class,
                "CORP same-site admits a same-site but cross-origin resource edge, contradicting the stricter same-origin intent.",
                {"headers": [{"name": "Cross-Origin-Resource-Policy", "value": "same-site"}], "document_origin": document_origin, "resource_origin": resource_origin},
            ))

    if intent_class == "enable_cross_origin_isolation":
        if not cross_origin_isolation_headers_ok(headers):
            findings.append(_finding(
                fid,
                "cross_origin_isolation_incomplete",
                "medium",
                "COOP/COEP/Permissions-Policy",
                intent_class,
                "The headers do not jointly satisfy the modeled cross-origin-isolation preconditions.",
                {"coop": header_values(headers, "Cross-Origin-Opener-Policy"), "coep": header_values(headers, "Cross-Origin-Embedder-Policy"), "permissions_policy": header_values(headers, "Permissions-Policy")},
            ))

    if intent_class == "allow_browser_feature":
        target_feature = feature or "geolocation"
        if permissions_feature_disabled(headers, target_feature):
            findings.append(_finding(
                fid,
                "permissions_policy_feature_disabled",
                "medium",
                "Permissions-Policy",
                intent_class,
                "The Permissions-Policy entry uses an empty allowlist for a feature the intent says should be available.",
                {"feature": target_feature, "headers": [{"name": "Permissions-Policy", "value": v} for v in header_values(headers, "Permissions-Policy")]},
            ))

    if intent_class == "deny_browser_feature":
        target_feature = feature or "geolocation"
        target_origin = str(ctx.get("target_origin", "*"))
        if permissions_feature_overallowed(headers, target_feature, target_origin):
            findings.append(_finding(
                fid,
                "permissions_policy_feature_overallowed",
                "medium",
                "Permissions-Policy",
                intent_class,
                "The Permissions-Policy allowlist admits a feature or origin that the intent says should be denied.",
                {"feature": target_feature, "target_origin": target_origin, "headers": [{"name": "Permissions-Policy", "value": v} for v in header_values(headers, "Permissions-Policy")]},
            ))

    return findings


def analyze_fixtures(fixtures: Iterable[Dict[str, object]]) -> List[Finding]:
    findings: List[Finding] = []
    for fixture in fixtures:
        findings.extend(analyze_fixture(fixture))
    return findings


def load_fixtures(path: str) -> List[Dict[str, object]]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, list):
        raise ValueError("fixture file must contain a JSON list")
    return data
