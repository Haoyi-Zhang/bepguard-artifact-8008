#!/usr/bin/env python3
"""Independent decision-table oracle for BEP-Deep fixture validation.

The script intentionally re-implements the covered semantic decisions as compact
rule tables rather than calling the executable witness generator.  It is used as
a redundancy check against accidental implementation coupling between the oracle,
workload, and repair controls.  It performs no network access and writes only
CSV/JSON audit artifacts.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True

import argparse, csv, json, itertools, re
from pathlib import Path
from urllib.parse import urlparse
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Operational oracle is imported only for cross-oracle comparison; the decision
# table below is otherwise self-contained.
from bep_semantics import analyze_fixture

Header = Dict[str, str]
Fixture = Dict[str, Any]

APP = "https://app.example"
CDN = "https://cdn.example"
EVIL = "https://evil.example"
OTHER = "https://cdn.other"
API = "https://api.example"


def cname(name: str) -> str:
    return "-".join(part.capitalize() for part in name.strip().split("-"))


def hvals(headers: Iterable[Header], name: str) -> List[str]:
    wanted = cname(name)
    return [str(h.get("value", "")) for h in headers if cname(str(h.get("name", ""))) == wanted]


def origin_tuple(origin: str) -> Tuple[str, str, int]:
    p = urlparse(origin)
    scheme = (p.scheme or "").lower()
    host = (p.hostname or "").lower()
    port = p.port if p.port is not None else (443 if scheme == "https" else 80)
    return scheme, host, port


def same_origin(a: str, b: str) -> bool:
    return origin_tuple(a) == origin_tuple(b)


def site_key(host: str) -> str:
    labels = host.lower().split(".")
    if labels and labels[-1] in {"example", "invalid", "test", "localhost"}:
        return labels[-1]
    return ".".join(labels[-2:]) if len(labels) >= 2 else host.lower()


def same_site(a: str, b: str) -> bool:
    return site_key(origin_tuple(a)[1]) == site_key(origin_tuple(b)[1])


def parse_csp(policy: str) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for seg in str(policy).split(";"):
        parts = seg.strip().split()
        if parts:
            out[parts[0].lower()] = parts[1:]
    return out


def source_allows(src: str, resource_origin: str, document_origin: str) -> bool:
    s = src.strip()
    if s == "*": return True
    if s == "'none'": return False
    if s == "'self'": return same_origin(resource_origin, document_origin)
    if s.startswith("'nonce-") or s in {"'strict-dynamic'", "'unsafe-inline'", "'unsafe-eval'"}: return False
    if s.endswith(":") and re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*:", s): return origin_tuple(resource_origin)[0] == s[:-1].lower()
    if s.startswith("http://") or s.startswith("https://"): return same_origin(resource_origin, s.rstrip("/"))
    if s.startswith("*."): return origin_tuple(resource_origin)[1].endswith(s[1:].lower())
    return origin_tuple(resource_origin)[1] == s.lower()


def effective_script_sources(policy: str) -> List[str]:
    d = parse_csp(policy)
    # CSP3 orders the script-element fallback chain from most specific to least
    # specific: script-src-elem, script-src, default-src.
    if "script-src-elem" in d: return d["script-src-elem"]
    if "script-src" in d: return d["script-src"]
    if "default-src" in d: return d["default-src"]
    return ["*"]


def csp_allows(policy: str, doc: str, res: str) -> bool:
    srcs = effective_script_sources(policy)
    return True if not srcs else any(source_allows(s, res, doc) for s in srcs)


def policies_allow_conj(policies: List[str], doc: str, res: str) -> bool:
    return True if not policies else all(csp_allows(p, doc, res) for p in policies)


def has_directive(policy: str, directive: str) -> bool:
    return directive.lower() in parse_csp(policy)


def has_nonce(policy: str) -> bool:
    return bool(re.search(r"'nonce-[^']+'", policy))


def parse_hsts(value: str) -> Dict[str, Any]:
    out = {"max_age": None, "valid": False, "include_subdomains": False, "preload": False}
    for raw in str(value).split(";"):
        token = raw.strip(); lower = token.lower()
        if lower.startswith("max-age"):
            _, _, v = token.partition("="); v = v.strip().strip('"')
            if v.isdigit():
                out["max_age"] = int(v); out["valid"] = True
            else:
                out["max_age"] = None; out["valid"] = False
        elif lower == "includesubdomains": out["include_subdomains"] = True
        elif lower == "preload": out["preload"] = True
    return out


def parse_permissions(value: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for seg in str(value).split(','):
        if '=' in seg:
            k, _, v = seg.partition('='); out[k.strip().lower()] = v.strip()
    return out


def feature_disabled(headers: List[Header], feature: str) -> bool:
    return any(parse_permissions(v).get(feature.lower()) == "()" for v in hvals(headers, "Permissions-Policy"))


def feature_overallowed(headers: List[Header], feature: str, target: str) -> bool:
    for v in hvals(headers, "Permissions-Policy"):
        allow = parse_permissions(v).get(feature.lower())
        if allow is None: continue
        norm = allow.replace("'", "").lower()
        if norm in {"*", "(*)"} or "*" in norm or (target and target.lower() in norm): return True
    return False


def cors_shareable(headers: List[Header], request_origin: str, credentials_mode: str) -> bool:
    acao = [v.strip() for v in hvals(headers, "Access-Control-Allow-Origin")]
    acac = [v.strip() for v in hvals(headers, "Access-Control-Allow-Credentials")]
    if len(acao) != 1: return False
    if acao[0] == "*": return credentials_mode != "include"
    if acao[0] in {request_origin, "$ORIGIN"}:
        return credentials_mode != "include" or "true" in acac
    return False


def dynamic_origin_without_vary(headers: List[Header]) -> bool:
    acao = [v.strip() for v in hvals(headers, "Access-Control-Allow-Origin")]
    vary = [v.strip().lower() for v in hvals(headers, "Vary")]
    has_vary = any("origin" in [p.strip() for p in v.split(',')] for v in vary)
    return "$ORIGIN" in acao and not has_vary


def corp_ok(corp_value: Optional[str], doc: str, res: str) -> bool:
    if corp_value is None: return False
    v = corp_value.strip().lower()
    if v == "cross-origin": return True
    if v == "same-origin": return same_origin(doc, res)
    if v == "same-site": return same_site(doc, res)
    return False


def compose_layers(fx: Fixture) -> List[Header]:
    headers = list(fx.get("headers", []) or [])
    layers = fx.get("layers", []) or []
    if not isinstance(layers, list): return headers
    for layer in layers:
        if not isinstance(layer, dict): continue
        op = str(layer.get("op", "append")).lower()
        lhs = layer.get("headers", []) or []
        if op == "remove":
            names = {cname(str(h.get("name", ""))) for h in lhs if isinstance(h, dict)}
            headers = [h for h in headers if cname(str(h.get("name", ""))) not in names]
        else:
            for hdr in lhs:
                if not isinstance(hdr, dict): continue
                nh = {"name": str(hdr.get("name", "")), "value": str(hdr.get("value", ""))}
                if op == "set":
                    n = cname(nh["name"]); headers = [h for h in headers if cname(str(h.get("name", ""))) != n]
                headers.append(nh)
    return headers


def decision_issues(fx: Fixture, mutant: str = "") -> List[str]:
    headers = compose_layers(fx)
    ctx = fx.get("context", {}) if isinstance(fx.get("context", {}), dict) else {}
    intent = fx.get("intent", {}) if isinstance(fx.get("intent", {}), dict) else {}
    ic = str(intent.get("class", ""))
    doc = str(ctx.get("document_origin", APP)); res = str(ctx.get("resource_origin", CDN)); req = str(ctx.get("request_origin", doc))
    creds = str(ctx.get("credentials_mode", "omit")); scheme = str(ctx.get("scheme", origin_tuple(doc)[0] or "https")).lower()
    mode = str(ctx.get("request_mode", "no-cors")).lower(); feature = str(ctx.get("feature", "geolocation"))
    csp = hvals(headers, "Content-Security-Policy"); ro = hvals(headers, "Content-Security-Policy-Report-Only")
    out: List[str] = []
    if ic == "preserve_enforced_policy_across_layers" and bool(ctx.get("expected_enforced_csp", True)):
        if (not csp or (ro and not csp)) and mutant != "layer_override_not_modeled": out.append("layered_header_override_drops_enforcement")
    if ic == "allow_required_script_after_policy_composition":
        allow = policies_allow_conj(csp, doc, res) if mutant != "csp_policies_compose_disjunctively" else (any(csp_allows(p, doc, res) for p in csp) if csp else True)
        if len(csp) > 1 and not allow: out.append("csp_conjunctive_policy_composition_blocks_required_script")
    if ic == "enforce_script_restriction":
        if ro and not csp and mutant != "report_only_enforces": out.append("csp_report_only_not_enforced")
        elif csp:
            allow = policies_allow_conj(csp, doc, res)
            if mutant == "csp_default_src_not_fallback":
                allow = any(("script-src" in parse_csp(p) and csp_allows(p, doc, res)) for p in csp)
            if allow: out.append("csp_effective_script_allowance")
    if ic == "allow_trusted_script":
        allow = policies_allow_conj(csp, doc, res) if mutant != "csp_policies_compose_disjunctively" else (any(csp_allows(p, doc, res) for p in csp) if csp else True)
        if csp and not allow: out.append("csp_multiple_policy_overblocks_trusted_script")
    if ic == "enforce_framing_protection":
        meta = hvals(headers, "Content-Security-Policy-Meta")
        enforced = [p for p in csp if has_directive(p, "frame-ancestors")]
        if [p for p in ro if has_directive(p, "frame-ancestors")] and not enforced and mutant != "frame_report_only_enforces": out.append("csp_frame_ancestors_report_only_not_enforced")
        if [p for p in meta if has_directive(p, "frame-ancestors")] and not enforced and mutant != "frame_meta_enforces": out.append("csp_frame_ancestors_meta_delivery_unsupported")
    if ic == "nonce_based_strict_csp" and bool(ctx.get("static_render", False)) and mutant != "nonce_static_is_fresh":
        if any(has_nonce(p) for p in csp): out.append("nonce_csp_static_render_incompatibility")
    if ic == "allow_credentialed_cors":
        acao = [v.strip() for v in hvals(headers, "Access-Control-Allow-Origin")]; acac = [v.strip() for v in hvals(headers, "Access-Control-Allow-Credentials")]
        if len(acao) > 1 and mutant != "cors_duplicate_acao_singletons": out.append("cors_duplicate_acao_not_shareable")
        elif acao and acao[0] in {req, "$ORIGIN"} and creds == "include" and any(v.lower() == "true" and v != "true" for v in acac) and mutant != "cors_acac_case_insensitive": out.append("cors_acac_case_sensitive_not_shareable")
        elif not cors_shareable(headers, req, creds):
            if not (mutant == "cors_wildcard_credentials_allowed" and acao == ["*"] and creds == "include"):
                out.append("cors_intended_credentialed_share_blocked")
    if ic == "deny_public_credentialed_cors":
        if creds == "include" and "$ORIGIN" in [v.strip() for v in hvals(headers, "Access-Control-Allow-Origin")] and "true" in [v.strip() for v in hvals(headers, "Access-Control-Allow-Credentials")] and mutant != "reflected_origin_safe": out.append("cors_reflected_origin_with_credentials")
    if ic == "partition_cors_cache_by_origin" and bool(ctx.get("shared_cache", False)) and dynamic_origin_without_vary(headers) and mutant != "cors_vary_not_required": out.append("cors_dynamic_origin_without_vary")
    if ic == "allow_credentialed_cors_cache_safe":
        acao = [v.strip() for v in hvals(headers, "Access-Control-Allow-Origin")]; acac = [v.strip() for v in hvals(headers, "Access-Control-Allow-Credentials")]
        vary = [v.strip().lower() for v in hvals(headers, "Vary")]
        has_vary = any("origin" in [p.strip() for p in v.split(',')] for v in vary)
        dynamic = bool(ctx.get("dynamic_origin", False)) or "$ORIGIN" in acao or req in acao
        if dynamic and creds == "include" and "true" in acac and not has_vary and mutant != "cors_vary_not_required": out.append("cors_dynamic_origin_missing_vary")
    hsts = hvals(headers, "Strict-Transport-Security")
    if ic == "enforce_https_only" and hsts:
        parsed = parse_hsts(hsts[0])
        if scheme != "https" and mutant != "hsts_http_honored": out.append("hsts_header_not_honored_over_http")
        elif not parsed["valid"] and mutant != "hsts_invalid_max_age_valid": out.append("hsts_invalid_max_age_ignored")
        elif parsed["max_age"] == 0 and mutant != "hsts_zero_preserves_state": out.append("hsts_policy_cleared_by_zero_max_age")
    if ic == "enforce_https_subdomains" and hsts:
        p = parse_hsts(hsts[0])
        if scheme == "https" and bool(ctx.get("subdomain_request", True)) and not p["include_subdomains"] and mutant != "hsts_subdomains_implicit": out.append("hsts_missing_include_subdomains")
    if ic == "enforce_https_only_subdomains" and hsts:
        p = parse_hsts(hsts[0])
        if scheme == "https" and bool(ctx.get("subdomain_scope_required", True)) and p["valid"] and not p["include_subdomains"] and mutant != "hsts_subdomains_implicit": out.append("hsts_subdomain_scope_not_covered")
    if ic == "expect_hsts_preload" and hsts:
        p = parse_hsts(hsts[0]); ma = p["max_age"]
        if not (isinstance(ma, int) and ma >= 31536000 and p["include_subdomains"] and p["preload"]) and mutant != "hsts_preload_weak_criterion": out.append("hsts_preload_criteria_not_met")
    if ic == "cross_origin_isolation_without_embed_breakage":
        coep = [v.strip().lower() for v in hvals(headers, "Cross-Origin-Embedder-Policy")]
        corp = hvals(headers, "Cross-Origin-Resource-Policy")
        if "require-corp" in coep and mode == "no-cors" and not same_origin(doc, res):
            ok = any(corp_ok(v, doc, res) for v in corp) or (mode == "cors" and cors_shareable(headers, doc, creds))
            if not ok and mutant != "coep_ignores_resource_optin": out.append("coep_require_corp_blocks_cross_origin_resource")
    if ic == "deny_cross_origin_embedding":
        if not same_origin(doc, res) and same_site(doc, res) and any(v.strip().lower() == "same-site" for v in hvals(headers, "Cross-Origin-Resource-Policy")) and mutant != "corp_same_site_is_same_origin": out.append("corp_same_site_allows_cross_origin_same_site")
    if ic == "enable_cross_origin_isolation":
        coop = [v.strip().lower() for v in hvals(headers, "Cross-Origin-Opener-Policy")]
        coep = [v.strip().lower() for v in hvals(headers, "Cross-Origin-Embedder-Policy")]
        ok = "same-origin" in coop and any(v in {"require-corp", "credentialless"} for v in coep) and not feature_disabled(headers, "cross-origin-isolated")
        if not ok and mutant != "isolation_coep_only": out.append("cross_origin_isolation_incomplete")
    if ic == "allow_browser_feature":
        if feature_disabled(headers, feature) and mutant != "permissions_empty_allows": out.append("permissions_policy_feature_disabled")
    if ic == "deny_browser_feature":
        if feature_overallowed(headers, feature, str(ctx.get("target_origin", "*"))) and mutant != "permissions_wildcard_safe": out.append("permissions_policy_feature_overallowed")
    return out


def load(path: str) -> List[Fixture]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, list): raise ValueError("fixture JSON must be a list")
    return data


def generate_finite_states() -> List[Fixture]:
    fixtures: List[Fixture] = []
    def fx(fid: str, ic: str, headers: List[Header], ctx: Dict[str, Any], fam: str) -> Fixture:
        return {"id": fid, "headers": headers, "context": ctx, "intent": {"class": ic}, "policy_family": fam}
    # Enumerate compact domains around every semantic hinge.  This is larger than
    # the human-readable proof-obligation sample and independent of labels.
    csp_policies = ["script-src 'self'", "default-src *", "default-src 'self'; script-src https://cdn.example", "script-src https://cdn.example", "script-src 'none'"]
    for i,p in enumerate(csp_policies):
        fixtures.append(fx(f"state_csp_enforce_{i}", "enforce_script_restriction", [{"name":"Content-Security-Policy","value":p}], {"document_origin":APP,"resource_origin":EVIL if i!=2 else CDN}, "CSP"))
        fixtures.append(fx(f"state_csp_report_{i}", "enforce_script_restriction", [{"name":"Content-Security-Policy-Report-Only","value":p}], {"document_origin":APP,"resource_origin":EVIL}, "CSP"))
    for acao, acac, creds in itertools.product(["*", APP, "$ORIGIN", "https://other.example"], ["true", "True", "false", ""], ["include", "omit"]):
        hs = [{"name":"Access-Control-Allow-Origin","value":acao}]
        if acac: hs.append({"name":"Access-Control-Allow-Credentials","value":acac})
        fixtures.append(fx(f"state_cors_{len(fixtures)}", "allow_credentialed_cors", hs, {"request_origin":APP,"credentials_mode":creds}, "CORS"))
    for value, scheme in itertools.product(["max-age=0", "max-age=abc", "max-age=31536000", "max-age=31536000; includeSubDomains", "max-age=31536000; includeSubDomains; preload"], ["http", "https"]):
        fixtures.append(fx(f"state_hsts_{len(fixtures)}", "enforce_https_only", [{"name":"Strict-Transport-Security","value":value}], {"scheme":scheme}, "HSTS"))
    for corp, mode, res in itertools.product([None, "same-origin", "same-site", "cross-origin"], ["no-cors", "cors"], [APP, CDN, OTHER]):
        hs = [{"name":"Cross-Origin-Embedder-Policy","value":"require-corp"}]
        if corp: hs.append({"name":"Cross-Origin-Resource-Policy","value":corp})
        if mode == "cors": hs.append({"name":"Access-Control-Allow-Origin","value":APP})
        fixtures.append(fx(f"state_embed_{len(fixtures)}", "cross_origin_isolation_without_embed_breakage", hs, {"document_origin":APP,"resource_origin":res,"request_mode":mode,"credentials_mode":"omit"}, "COEP/CORP/CORS"))
    for pp, ic in itertools.product(["geolocation=()", "geolocation=(self)", "geolocation=*", "camera=()"], ["allow_browser_feature", "deny_browser_feature"]):
        fixtures.append(fx(f"state_perm_{len(fixtures)}", ic, [{"name":"Permissions-Policy","value":pp}], {"feature":"geolocation","target_origin":CDN}, "Permissions-Policy"))

    # Framing, nonce, isolation, subdomain, preload and ordered-layer finite states.
    for delivery, pol in itertools.product(["enforced", "report", "meta", "none"], ["frame-ancestors 'none'", "default-src 'self'", "frame-ancestors https://embedder.example"]):
        hs: List[Header] = []
        if delivery == "enforced": hs = [{"name":"Content-Security-Policy","value":pol}]
        elif delivery == "report": hs = [{"name":"Content-Security-Policy-Report-Only","value":pol}]
        elif delivery == "meta": hs = [{"name":"Content-Security-Policy-Meta","value":pol}]
        fixtures.append(fx(f"state_frame_{len(fixtures)}", "enforce_framing_protection", hs, {"ancestor_origin":"https://embedder.example"}, "CSP/framing"))
    for csp_value, static in itertools.product(["script-src 'nonce-x'", "script-src 'self'", "script-src 'nonce-x' 'strict-dynamic'"], [True, False]):
        fixtures.append(fx(f"state_nonce_{len(fixtures)}", "nonce_based_strict_csp", [{"name":"Content-Security-Policy","value":csp_value}], {"static_render": static}, "CSP/framework"))
    for value, intent in itertools.product(["max-age=31536000", "max-age=31536000; includeSubDomains", "max-age=31536000; includeSubDomains; preload", "max-age=1000; preload"], ["enforce_https_subdomains", "enforce_https_only_subdomains", "expect_hsts_preload"]):
        fixtures.append(fx(f"state_hsts_scope_{len(fixtures)}", intent, [{"name":"Strict-Transport-Security","value":value}], {"scheme":"https","subdomain_request":True,"subdomain_scope_required":True}, "HSTS"))
    for coop, coep, pp in itertools.product([None, "same-origin", "unsafe-none"], [None, "require-corp", "credentialless"], [None, "cross-origin-isolated=()", "geolocation=()"]):
        hs: List[Header] = []
        if coop: hs.append({"name":"Cross-Origin-Opener-Policy","value":coop})
        if coep: hs.append({"name":"Cross-Origin-Embedder-Policy","value":coep})
        if pp: hs.append({"name":"Permissions-Policy","value":pp})
        fixtures.append(fx(f"state_iso_{len(fixtures)}", "enable_cross_origin_isolation", hs, {"feature":"cross-origin-isolated"}, "COOP/COEP/Permissions-Policy"))
    layer_templates = [
        ([{"layer":"framework","op":"append","headers":[{"name":"Content-Security-Policy","value":"script-src 'self' https://cdn.example"}]},{"layer":"proxy","op":"append","headers":[{"name":"Content-Security-Policy","value":"script-src 'self'"}]}], "allow_required_script_after_policy_composition"),
        ([{"layer":"framework","op":"append","headers":[{"name":"Content-Security-Policy","value":"script-src 'self'"}]},{"layer":"proxy","op":"remove","headers":[{"name":"Content-Security-Policy","value":""}]}], "preserve_enforced_policy_across_layers"),
        ([{"layer":"framework","op":"append","headers":[{"name":"Content-Security-Policy","value":"script-src https://cdn.example"}]},{"layer":"route","op":"append","headers":[{"name":"Content-Security-Policy","value":"script-src 'self'"}]}], "allow_trusted_script"),
    ]
    for layers, ic in layer_templates:
        obj = fx(f"state_layer_{len(fixtures)}", ic, [], {"document_origin":APP,"resource_origin":CDN,"expected_enforced_csp":True}, "Layered policy composition")
        obj["layers"] = layers; fixtures.append(obj)

    # Replicate the compact state grid with harmless origin/scheme variants to
    # exercise canonicalization and site/origin boundaries without new labels.
    expanded: List[Fixture] = []
    for base in fixtures:
        expanded.append(base)
        ctx = dict(base.get("context", {}))
        if "document_origin" in ctx or base.get("policy_family") in {"CSP", "CORS", "COEP/CORP/CORS", "CORP"}:
            for suffix, doc, res in [("same_origin", APP, APP), ("same_site", APP, CDN), ("other_site", APP, OTHER)]:
                clone = json.loads(json.dumps(base)); clone["id"] = f"{base['id']}__{suffix}"
                clone.setdefault("context", {})["document_origin"] = doc
                clone.setdefault("context", {})["resource_origin"] = res
                expanded.append(clone)
    return expanded


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixtures", default="artifact/data/deep_locked_fixtures.json")
    ap.add_argument("--out-dir", default="artifact/results/deep_locked")
    args = ap.parse_args()
    out = Path(args.out_dir); out.mkdir(parents=True, exist_ok=True)
    fixtures = load(args.fixtures)
    rows = []
    mismatches = []
    for fx in fixtures:
        op = sorted({f.issue for f in analyze_fixture(fx)})
        dt = sorted(set(decision_issues(fx)))
        expected = [] if fx.get("expected_issue") == "none" else [str(fx.get("expected_issue"))]
        ok = (op == dt == expected)
        row = {"fixture_id": fx.get("id"), "operational": ";".join(op) or "none", "decision_table": ";".join(dt) or "none", "expected": ";".join(expected) or "none", "status": "pass" if ok else "mismatch"}
        rows.append(row)
        if not ok: mismatches.append(row)
    finite = generate_finite_states()
    finite_mismatches = []
    for fx in finite:
        op = sorted({f.issue for f in analyze_fixture(fx)})
        dt = sorted(set(decision_issues(fx)))
        if op != dt:
            finite_mismatches.append({"fixture_id": fx["id"], "operational": ";".join(op) or "none", "decision_table": ";".join(dt) or "none"})
    with (out / "decision_table_oracle_audit.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["fixture_id","operational","decision_table","expected","status"]); w.writeheader(); w.writerows(rows)
    with (out / "decision_table_finite_mismatches.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["fixture_id","operational","decision_table"]); w.writeheader(); w.writerows(finite_mismatches)
    metrics = {
        "locked_fixtures_checked": len(fixtures),
        "locked_fixture_agreements": sum(1 for r in rows if r["status"] == "pass"),
        "locked_fixture_mismatches": len(mismatches),
        "finite_states_checked": len(finite),
        "finite_state_oracle_mismatches": len(finite_mismatches),
        "independent_decision_rules": 25,
        "interpretation": "Independent decision-table oracle cross-check; it validates the encoded fragment and workload labels, not full browser conformance.",
    }
    (out / "decision_table_oracle_metrics.json").write_text(json.dumps(metrics, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    print(json.dumps(metrics, sort_keys=True))
    if mismatches or finite_mismatches:
        sys.exit(1)

if __name__ == "__main__":
    main()
