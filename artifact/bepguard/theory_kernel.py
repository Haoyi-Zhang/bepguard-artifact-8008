"""Finite proof kernel for the BEPGuard semantic fragment.

The kernel checks small, source-grounded theorems over the executable BEP
semantics.  It is deliberately independent of the locked fixture labels: each
obligation enumerates finite policy/context states and verifies an invariant
that should hold for the semantic fragment regardless of the benchmark object.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Sequence, Tuple

sys.dont_write_bytecode = True


def _import_semantics(root: Path):
    scripts = root / "artifact" / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import bep_semantics  # type: ignore
    return bep_semantics


@dataclass(frozen=True)
class Obligation:
    name: str
    theorem: str
    states_checked: int
    counterexamples: Tuple[Mapping[str, Any], ...]
    proof_kind: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "theorem": self.theorem,
            "states_checked": self.states_checked,
            "counterexamples": [dict(c) for c in self.counterexamples],
            "counterexample_count": len(self.counterexamples),
            "proof_kind": self.proof_kind,
            "status": "pass" if not self.counterexamples else "fail",
        }


def _finding_issues(findings: Iterable[Any]) -> Tuple[str, ...]:
    issues: List[str] = []
    for finding in findings:
        if hasattr(finding, "issue"):
            issues.append(str(getattr(finding, "issue")))
        elif isinstance(finding, Mapping):
            issues.append(str(finding.get("issue", "")))
    return tuple(sorted(i for i in issues if i))


def _fixture(fid: str, intent_class: str, headers: List[Dict[str, str]], context: Dict[str, Any], expected_issue: str = "none", family: str = "theory") -> Dict[str, Any]:
    return {
        "id": fid,
        "fixture_role": "positive" if expected_issue != "none" else "negative_control",
        "expected_issue": expected_issue,
        "headers": headers,
        "intent": {"class": intent_class, "claim": f"finite proof obligation for {intent_class}"},
        "context": context,
        "policy_family": family,
        "source_claim_ids": ["THEORY_KERNEL"],
        "public_source_id": "THEORY_KERNEL",
        "variant": fid.lower(),
    }


def _check_csp_meet(root: Path) -> Obligation:
    sem = _import_semantics(root)
    origins = ["https://app.example", "https://admin.example", "https://shop.example", "https://docs.example", "https://portal.test"]
    resources = ["https://app.example", "https://cdn.example", "https://evil.example", "https://static.test", "https://shop.example", "https://docs.example", "http://cdn.example", "https://portal.test"]
    policies = [
        "script-src 'self'",
        "script-src *",
        "default-src 'self'",
        "default-src *",
        "script-src https://cdn.example",
        "script-src https://static.test",
        "script-src 'none'",
        "default-src 'none'; script-src 'self'",
        "default-src https:; script-src 'self' https://cdn.example",
        "script-src https:",
        "script-src *.example",
        "default-src 'none'; script-src https://portal.test",
        "script-src https://assets.example",
        "script-src https://alpha.example https://assets.example",
        "default-src https://cdn.example; script-src 'self'",
        "script-src 'self' https://evil.example",
        "script-src http:",
        "default-src *; script-src 'none'",
        "script-src https://docs.example https://shop.example",
        "default-src 'self'; script-src https://cdn.example",
    ]
    cex: List[Dict[str, Any]] = []
    states = 0
    for doc in origins:
        for res in resources:
            for p in policies:
                for q in policies:
                    states += 1
                    combined = sem.enforced_csp_allows_script([p, q], doc, res)
                    single_p = sem.enforced_csp_allows_script([p], doc, res)
                    single_q = sem.enforced_csp_allows_script([q], doc, res)
                    if combined and not (single_p and single_q):
                        cex.append({"document_origin": doc, "resource_origin": res, "p": p, "q": q, "violation": "meet expanded capability"})
                    if (not single_p or not single_q) and combined:
                        cex.append({"document_origin": doc, "resource_origin": res, "p": p, "q": q, "violation": "blocked component allowed by meet"})
    return Obligation("csp_policy_meet_nonexpansion", "Adding an enforced CSP policy cannot authorize a script edge that one enforced member blocks.", states, tuple(cex), "finite-product enumeration")


def _check_csp_fallback(root: Path) -> Obligation:
    sem = _import_semantics(root)
    cases = [
        ("script-src-elem *; script-src 'none'; default-src 'none'", ["*"]),
        ("script-src https://cdn.example; default-src 'none'", ["https://cdn.example"]),
        ("default-src 'self'", ["'self'"]),
        ("object-src 'none'", ["*"]),
        ("script-src-elem 'self'; default-src *", ["'self'"]),
        ("script-src 'none'; default-src *", ["'none'"]),
    ]
    cex: List[Dict[str, Any]] = []
    for policy, expected in cases:
        actual = sem.effective_script_sources(policy)
        if actual != expected:
            cex.append({"policy": policy, "expected": expected, "actual": actual})
    return Obligation("csp_directive_specificity", "Script-element source selection follows script-src-elem, then script-src, then default-src, then the uncovered default.", len(cases), tuple(cex), "case enumeration")


def _check_report_only(root: Path) -> Obligation:
    sem = _import_semantics(root)
    contexts = [
        {"document_origin": "https://app.example", "resource_origin": "https://evil.example", "resource_kind": "script", "scheme": "https"},
        {"document_origin": "https://admin.example", "resource_origin": "https://cdn.example", "resource_kind": "script", "scheme": "https"},
    ]
    policies = ["script-src 'self'", "default-src 'none'", "script-src 'none'; report-uri /csp"]
    cex: List[Dict[str, Any]] = []
    states = 0
    for idx, ctx in enumerate(contexts):
        for policy in policies:
            states += 1
            fixture = _fixture(f"TK_RO_{idx}_{states}", "enforce_script_restriction", [{"name": "Content-Security-Policy-Report-Only", "value": policy}], ctx, "csp_report_only_not_enforced", "CSP")
            issues = _finding_issues(sem.analyze_fixture(fixture))
            if issues != ("csp_report_only_not_enforced",):
                cex.append({"policy": policy, "context": ctx, "actual": issues})
    return Obligation("csp_report_only_monitor_only", "A report-only CSP surface yields monitoring conflict under an enforcement intent but no enforced block judgment.", states, tuple(cex), "executable witness enumeration")


def _check_cors_truth_table(root: Path) -> Obligation:
    sem = _import_semantics(root)
    req = "https://app.example"
    acao_values = ["*", req, "$ORIGIN", "https://other.example", ""]
    acac_values = ["true", "True", "false", ""]
    cred_modes = ["include", "omit"]
    cex: List[Dict[str, Any]] = []
    states = 0
    for acao in acao_values:
        for acac in acac_values:
            for mode in cred_modes:
                states += 1
                headers = [] if not acao else [{"name": "Access-Control-Allow-Origin", "value": acao}]
                if acac:
                    headers.append({"name": "Access-Control-Allow-Credentials", "value": acac})
                expected = False
                if acao == "*":
                    expected = mode != "include"
                elif acao in {req, "$ORIGIN"}:
                    expected = (mode != "include") or acac == "true"
                actual = sem.cors_shareable(headers, req, mode)
                if actual != expected:
                    cex.append({"acao": acao, "acac": acac, "mode": mode, "expected": expected, "actual": actual})
    return Obligation("cors_credentialed_shareability_table", "Credentialed CORS shareability is exact-origin plus byte-case-sensitive ACAC, and wildcard excludes credentials.", states, tuple(cex), "truth-table enumeration")


def _check_cors_cache(root: Path) -> Obligation:
    sem = _import_semantics(root)
    vary_values = ["", "Origin", "Accept-Encoding", "Accept-Encoding, Origin", "origin"]
    acao_values = ["$ORIGIN", "https://app.example", "*"]
    cex: List[Dict[str, Any]] = []
    states = 0
    for acao in acao_values:
        for vary in vary_values:
            states += 1
            headers = [{"name": "Access-Control-Allow-Origin", "value": acao}]
            if vary:
                headers.append({"name": "Vary", "value": vary})
            expected = acao == "$ORIGIN" and "origin" not in [p.strip().lower() for p in vary.split(",")]
            actual = sem.cors_dynamic_origin_without_vary(headers)
            if actual != expected:
                cex.append({"acao": acao, "vary": vary, "expected": expected, "actual": actual})
    return Obligation("cors_dynamic_origin_cache_partition", "Dynamic ACAO requires an Origin discriminator; unrelated Vary fields do not repair the cache obligation.", states, tuple(cex), "truth-table enumeration")


def _check_hsts_state(root: Path) -> Obligation:
    sem = _import_semantics(root)
    values = ["max-age=0", "max-age=31536000", "max-age=abc", "includeSubDomains", "max-age=63072000; includeSubDomains; preload"]
    schemes = ["http", "https"]
    cex: List[Dict[str, Any]] = []
    states = 0
    for scheme in schemes:
        for value in values:
            states += 1
            fixture = _fixture("TK_HSTS", "enforce_https_only", [{"name": "Strict-Transport-Security", "value": value}], {"document_origin": "https://app.example", "scheme": scheme}, "none", "HSTS")
            issues = _finding_issues(sem.analyze_fixture(fixture))
            if scheme == "http":
                expected = ("hsts_header_not_honored_over_http",)
            elif value == "max-age=0":
                expected = ("hsts_policy_cleared_by_zero_max_age",)
            elif "max-age=" not in value or "max-age=abc" in value:
                expected = ("hsts_invalid_max_age_ignored",)
            else:
                expected = tuple()
            if issues != expected:
                cex.append({"scheme": scheme, "value": value, "expected": expected, "actual": issues})
    return Obligation("hsts_state_transition_partition", "HSTS processing partitions into insecure-delivery ignore, invalid-header ignore, zero-age clear, and valid-state cases.", states, tuple(cex), "executable state partition")


def _check_coep_request_mode(root: Path) -> Obligation:
    sem = _import_semantics(root)
    modes = ["no-cors", "cors"]
    corp_values = [None, "same-origin", "same-site", "cross-origin"]
    acao_values = [None, "https://app.example"]
    cex: List[Dict[str, Any]] = []
    states = 0
    for mode in modes:
        for corp in corp_values:
            for acao in acao_values:
                states += 1
                headers = [{"name": "Cross-Origin-Embedder-Policy", "value": "require-corp"}]
                if corp is not None:
                    headers.append({"name": "Cross-Origin-Resource-Policy", "value": corp})
                if acao is not None:
                    headers.append({"name": "Access-Control-Allow-Origin", "value": acao})
                fixture = _fixture("TK_COEP", "cross_origin_isolation_without_embed_breakage", headers, {"document_origin": "https://app.example", "resource_origin": "https://other.example", "scheme": "https", "request_mode": mode}, "none", "COEP/CORP/CORS")
                issues = _finding_issues(sem.analyze_fixture(fixture))
                corp_ok = bool(corp is not None and sem.corp_allows(corp, "https://app.example", "https://other.example"))
                expected_block = mode == "no-cors" and not corp_ok
                expected = ("coep_require_corp_blocks_cross_origin_resource",) if expected_block else tuple()
                # The current fragment emits the COEP block for no-cors only when the resource lacks a compatible CORP opt-in.
                if issues != expected:
                    cex.append({"mode": mode, "corp": corp, "acao": acao, "expected": expected, "actual": issues})
    return Obligation("coep_cors_mode_separation", "CORS response headers alone do not repair a no-cors COEP resource edge; compatible CORP repairs the no-cors edge.", states, tuple(cex), "request-mode enumeration")


def _check_corp_scope(root: Path) -> Obligation:
    sem = _import_semantics(root)
    pairs = [("https://app.example", "https://cdn.example"), ("https://app.example", "https://app.example"), ("https://app.example", "https://evil.test")]
    values = ["same-origin", "same-site", "cross-origin", "invalid"]
    cex: List[Dict[str, Any]] = []
    states = 0
    for doc, res in pairs:
        for value in values:
            states += 1
            actual = sem.corp_allows(value, doc, res)
            expected = (value == "cross-origin") or (value == "same-origin" and sem.same_origin(doc, res)) or (value == "same-site" and sem.same_site(doc, res))
            if actual != expected:
                cex.append({"document": doc, "resource": res, "corp": value, "expected": expected, "actual": actual})
    return Obligation("corp_scope_lattice", "CORP scope is ordered same-origin <= same-site <= cross-origin over the fixture origin approximation.", states, tuple(cex), "finite scope enumeration")


def _check_permissions(root: Path) -> Obligation:
    sem = _import_semantics(root)
    values = ["geolocation=()", "geolocation=*", "geolocation=(self)", "camera=()", "geolocation=(https://evil.example)"]
    cex: List[Dict[str, Any]] = []
    states = 0
    for value in values:
        states += 1
        headers = [{"name": "Permissions-Policy", "value": value}]
        disabled = sem.permissions_feature_disabled(headers, "geolocation")
        over = sem.permissions_feature_overallowed(headers, "geolocation", "https://evil.example")
        expected_disabled = value == "geolocation=()"
        expected_over = value in {"geolocation=*", "geolocation=(https://evil.example)"}
        if disabled != expected_disabled or over != expected_over:
            cex.append({"value": value, "expected_disabled": expected_disabled, "actual_disabled": disabled, "expected_over": expected_over, "actual_over": over})
    return Obligation("permissions_allowlist_boundary", "Empty allowlists deny a feature and wildcard/explicit external entries over-allow a denied origin in the encoded fragment.", states, tuple(cex), "allowlist enumeration")


def _check_layer_composition(root: Path) -> Obligation:
    sem = _import_semantics(root)
    ops = ["append", "set", "remove"]
    base = [{"name": "Content-Security-Policy", "value": "script-src 'self'"}]
    layer_header = {"name": "Content-Security-Policy", "value": "script-src *"}
    cex: List[Dict[str, Any]] = []
    states = 0
    for op in ops:
        states += 1
        fixture = {"id": "TK_LAYER", "headers": base, "layers": [{"op": op, "layer": "test", "headers": [layer_header]}]}
        headers, trace = sem.effective_headers_from_layers(fixture)
        values = sem.header_values(headers, "Content-Security-Policy")
        expected_len = {"append": 2, "set": 1, "remove": 0}[op]
        if len(values) != expected_len:
            cex.append({"op": op, "expected_csp_fields": expected_len, "actual": values, "trace": trace})
    return Obligation("ordered_generation_layer_contract", "Append preserves fields, set replaces same-name fields, and remove deletes same-name fields before semantic evaluation.", states, tuple(cex), "operator enumeration")



def _check_csp_meet_commutativity_idempotence(root: Path) -> Obligation:
    sem = _import_semantics(root)
    origins = ["https://app.example", "https://admin.example", "https://shop.example", "https://docs.example", "https://portal.test"]
    resources = ["https://app.example", "https://cdn.example", "https://evil.example", "https://static.test", "https://shop.example", "https://docs.example", "http://cdn.example", "https://portal.test"]
    policies = [
        "script-src 'self'",
        "script-src *",
        "default-src 'self'",
        "default-src *",
        "script-src https://cdn.example",
        "script-src https://static.test",
        "script-src 'none'",
        "default-src 'none'; script-src 'self'",
        "default-src https:; script-src 'self' https://cdn.example",
        "script-src https:",
        "script-src *.example",
        "default-src 'none'; script-src https://portal.test",
        "script-src https://assets.example",
        "script-src https://alpha.example https://assets.example",
        "default-src https://cdn.example; script-src 'self'",
        "script-src 'self' https://evil.example",
        "script-src http:",
        "default-src *; script-src 'none'",
        "script-src https://docs.example https://shop.example",
        "default-src 'self'; script-src https://cdn.example",
    ]
    cex: List[Dict[str, Any]] = []
    states = 0
    for doc in origins:
        for res in resources:
            for p in policies:
                states += 1
                if sem.enforced_csp_allows_script([p, p], doc, res) != sem.enforced_csp_allows_script([p], doc, res):
                    cex.append({"document_origin": doc, "resource_origin": res, "p": p, "violation": "idempotence"})
                for q in policies:
                    states += 1
                    if sem.enforced_csp_allows_script([p, q], doc, res) != sem.enforced_csp_allows_script([q, p], doc, res):
                        cex.append({"document_origin": doc, "resource_origin": res, "p": p, "q": q, "violation": "commutativity"})
    return Obligation("csp_meet_commutativity_idempotence", "Enforced CSP-policy conjunction is commutative and idempotent over the encoded source-list fragment.", states, tuple(cex), "finite algebraic enumeration")


def _check_csp_source_monotonicity(root: Path) -> Obligation:
    sem = _import_semantics(root)
    docs = ["https://app.example", "https://shop.example"]
    resources = ["https://app.example", "https://cdn.example", "https://evil.example", "https://static.test", "http://cdn.example"]
    narrower = ["'none'", "'self'", "https://cdn.example"]
    broader = ["'self'", "https://cdn.example", "https:", "*"]
    cex: List[Dict[str, Any]] = []
    states = 0
    for doc in docs:
        for res in resources:
            for a in narrower:
                for b in broader:
                    states += 1
                    pa = f"script-src {a}"
                    pb = f"script-src {a} {b}"
                    if sem.csp_policy_allows_script(pa, doc, res) and not sem.csp_policy_allows_script(pb, doc, res):
                        cex.append({"document": doc, "resource": res, "smaller": pa, "larger": pb})
    return Obligation("csp_source_list_extension_monotonicity", "Adding a source expression to one source list cannot remove an allowed script edge before policy meet is applied.", states, tuple(cex), "finite source-list enumeration")


def _check_cors_duplicate_acao_rejection(root: Path) -> Obligation:
    sem = _import_semantics(root)
    reqs = ["https://app.example", "https://admin.example"]
    acao_pairs = [("*", "https://app.example"), ("https://app.example", "https://app.example"), ("$ORIGIN", "https://app.example"), ("https://admin.example", "https://app.example")]
    acac_values = ["true", "false", "True", ""]
    modes = ["include", "omit"]
    cex: List[Dict[str, Any]] = []
    states = 0
    for req in reqs:
        for a, b in acao_pairs:
            for acac in acac_values:
                for mode in modes:
                    states += 1
                    headers = [{"name": "Access-Control-Allow-Origin", "value": a}, {"name": "Access-Control-Allow-Origin", "value": b}]
                    if acac:
                        headers.append({"name": "Access-Control-Allow-Credentials", "value": acac})
                    actual = sem.cors_shareable(headers, req, mode)
                    if actual:
                        cex.append({"request_origin": req, "acao": [a, b], "acac": acac, "mode": mode, "violation": "duplicate ACAO shared"})
    return Obligation("cors_duplicate_acao_rejection", "A response with multiple ACAO values is not shareable in the encoded CORS fragment.", states, tuple(cex), "truth-table enumeration")


def _check_cors_vary_origin_tokenization(root: Path) -> Obligation:
    sem = _import_semantics(root)
    vary_values = ["Origin", "origin", "ORIGIN", "Accept-Encoding, Origin", "Origin, Accept-Encoding", "Accept-Encoding", "X-Origin", "Origin-Policy", ""]
    acao_values = ["$ORIGIN", "https://app.example"]
    cex: List[Dict[str, Any]] = []
    states = 0
    for acao in acao_values:
        for vary in vary_values:
            states += 1
            headers = [{"name": "Access-Control-Allow-Origin", "value": acao}]
            if vary:
                headers.append({"name": "Vary", "value": vary})
            actual = sem.cors_dynamic_origin_without_vary(headers)
            tokens = [x.strip().lower() for x in vary.split(",")]
            expected = acao == "$ORIGIN" and "origin" not in tokens
            if actual != expected:
                cex.append({"acao": acao, "vary": vary, "expected": expected, "actual": actual})
    return Obligation("cors_vary_origin_tokenization", "Only an Origin token, not a substring, repairs dynamic ACAO cache partitioning.", states, tuple(cex), "token enumeration")


def _check_hsts_preload_criterion(root: Path) -> Obligation:
    sem = _import_semantics(root)
    ages = [0, 1, 10886400, 15552000, 31535999, 31536000, 63072000]
    include_values = [False, True]
    preload_values = [False, True]
    cex: List[Dict[str, Any]] = []
    states = 0
    for age in ages:
        for include in include_values:
            for preload in preload_values:
                states += 1
                value = f"max-age={age}" + ("; includeSubDomains" if include else "") + ("; preload" if preload else "")
                expected = age >= 31536000 and include and preload
                actual = sem.hsts_preload_ready(value)
                if actual != expected:
                    cex.append({"value": value, "expected": expected, "actual": actual})
    return Obligation("hsts_preload_criterion_boundary", "The documented preload-control predicate is exactly max-age>=31536000 plus includeSubDomains plus preload in the encoded fragment.", states, tuple(cex), "boundary enumeration")


def _check_coop_coep_isolation_partition(root: Path) -> Obligation:
    sem = _import_semantics(root)
    coop_values = [None, "same-origin", "same-origin-allow-popups", "unsafe-none"]
    coep_values = [None, "require-corp", "credentialless", "unsafe-none"]
    perm_values = [None, "cross-origin-isolated=()", "geolocation=()"]
    cex: List[Dict[str, Any]] = []
    states = 0
    for coop in coop_values:
        for coep in coep_values:
            for perm in perm_values:
                states += 1
                headers: List[Dict[str, str]] = []
                if coop:
                    headers.append({"name": "Cross-Origin-Opener-Policy", "value": coop})
                if coep:
                    headers.append({"name": "Cross-Origin-Embedder-Policy", "value": coep})
                if perm:
                    headers.append({"name": "Permissions-Policy", "value": perm})
                actual = sem.cross_origin_isolation_headers_ok(headers)
                expected = coop == "same-origin" and coep in {"require-corp", "credentialless"} and perm != "cross-origin-isolated=()"
                if actual != expected:
                    cex.append({"coop": coop, "coep": coep, "permissions": perm, "expected": expected, "actual": actual})
    return Obligation("coop_coep_isolation_partition", "Cross-origin isolation preconditions require the encoded COOP/COEP pair and are disabled by an explicit Permissions-Policy denial.", states, tuple(cex), "finite product enumeration")


def _check_permissions_feature_independence(root: Path) -> Obligation:
    sem = _import_semantics(root)
    features = ["geolocation", "camera", "microphone", "cross-origin-isolated"]
    allowlists = ["()", "*", "(self)", "(https://evil.example)"]
    target = "https://evil.example"
    cex: List[Dict[str, Any]] = []
    states = 0
    for configured in features:
        for queried in features:
            for allowlist in allowlists:
                states += 1
                headers = [{"name": "Permissions-Policy", "value": f"{configured}={allowlist}"}]
                disabled = sem.permissions_feature_disabled(headers, queried)
                overallowed = sem.permissions_feature_overallowed(headers, queried, target)
                expected_disabled = configured == queried and allowlist == "()"
                expected_over = configured == queried and allowlist in {"*", "(https://evil.example)"}
                if disabled != expected_disabled or overallowed != expected_over:
                    cex.append({"configured": configured, "queried": queried, "allowlist": allowlist, "disabled": disabled, "expected_disabled": expected_disabled, "overallowed": overallowed, "expected_overallowed": expected_over})
    return Obligation("permissions_feature_independence", "A Permissions-Policy directive affects only its named feature in the encoded fragment.", states, tuple(cex), "feature-product enumeration")


def _check_layer_remove_set_absorption(root: Path) -> Obligation:
    sem = _import_semantics(root)
    names = ["Content-Security-Policy", "Strict-Transport-Security", "Permissions-Policy"]
    ops = ["append", "set", "remove"]
    cex: List[Dict[str, Any]] = []
    states = 0
    for name in names:
        base = [{"name": name, "value": "base"}, {"name": "X-Other", "value": "keep"}]
        layer_header = {"name": name.lower(), "value": "layer"}
        for op1 in ops:
            for op2 in ops:
                states += 1
                fixture = {"id": "TK_LAYER2", "headers": base, "layers": [{"op": op1, "headers": [layer_header]}, {"op": op2, "headers": [layer_header]}]}
                headers, _ = sem.effective_headers_from_layers(fixture)
                other = sem.header_values(headers, "X-Other")
                if other != ["keep"]:
                    cex.append({"name": name, "op1": op1, "op2": op2, "violation": "unrelated header changed", "headers": headers})
                if op2 == "remove" and sem.header_values(headers, name):
                    cex.append({"name": name, "op1": op1, "op2": op2, "violation": "release remove not absorbing", "headers": headers})
                if op2 == "set" and sem.header_values(headers, name) != ["layer"]:
                    cex.append({"name": name, "op1": op1, "op2": op2, "violation": "release set not replacing", "headers": headers})
    return Obligation("ordered_layer_remove_set_absorption", "A release remove absorbs same-name fields, a release set replaces same-name fields, and unrelated fields are preserved.", states, tuple(cex), "operator-product enumeration")


def _check_corp_same_site_approximation(root: Path) -> Obligation:
    sem = _import_semantics(root)
    docs = ["https://app.example", "https://shop.example", "https://app.test", "https://a.invalid"]
    resources = ["https://cdn.example", "https://app.example", "https://evil.test", "https://b.invalid", "https://shop.example"]
    cex: List[Dict[str, Any]] = []
    states = 0
    for doc in docs:
        for res in resources:
            states += 1
            actual = sem.corp_allows("same-site", doc, res)
            expected = sem.same_site(doc, res)
            if actual != expected:
                cex.append({"document": doc, "resource": res, "expected": expected, "actual": actual})
    return Obligation("corp_same_site_consistency", "CORP same-site delegates exactly to the fixture same-site approximation.", states, tuple(cex), "origin-pair enumeration")


def _check_unknown_free_known_fragments(root: Path) -> Obligation:
    sem = _import_semantics(root)
    fixture_templates = [
        ("enforce_script_restriction", [{"name": "Content-Security-Policy", "value": "script-src 'self'"}], {"document_origin": "https://app.example", "resource_origin": "https://evil.example", "scheme": "https"}),
        ("allow_credentialed_cors", [{"name": "Access-Control-Allow-Origin", "value": "https://app.example"}, {"name": "Access-Control-Allow-Credentials", "value": "true"}], {"request_origin": "https://app.example", "credentials_mode": "include"}),
        ("enforce_https_only", [{"name": "Strict-Transport-Security", "value": "max-age=31536000"}], {"scheme": "https"}),
        ("enable_cross_origin_isolation", [{"name": "Cross-Origin-Opener-Policy", "value": "same-origin"}, {"name": "Cross-Origin-Embedder-Policy", "value": "require-corp"}], {"scheme": "https"}),
        ("allow_browser_feature", [{"name": "Permissions-Policy", "value": "geolocation=(self)"}], {"feature": "geolocation", "target_origin": "https://evil.example"}),
    ]
    cex: List[Dict[str, Any]] = []
    states = 0
    for idx, (intent, headers, ctx) in enumerate(fixture_templates):
        for extra in [{}, {"unobserved": "noise"}, {"document_origin": "https://app.example", **ctx}]:
            states += 1
            fixture = _fixture(f"TK_KNOWN_{idx}_{states}", intent, headers, {**ctx, **extra}, "none", "known-fragment")
            try:
                sem.analyze_fixture(fixture)
            except Exception as exc:  # pragma: no cover - collected as counterexample
                cex.append({"intent": intent, "headers": headers, "context": {**ctx, **extra}, "exception": str(exc)})
    return Obligation("known_fragment_totality", "Known encoded fragments execute without exception under irrelevant context extensions.", states, tuple(cex), "execution-totality enumeration")



def _check_header_name_canonicalization(root: Path) -> Obligation:
    sem = _import_semantics(root)
    names = ["content-security-policy", "CONTENT-SECURITY-POLICY", "Content-Security-Policy", "strict-transport-security", "ACCESS-CONTROL-ALLOW-ORIGIN", "permissions-policy"]
    cex: List[Dict[str, Any]] = []
    states = 0
    for name in names:
        states += 1
        first = sem.canonical_header_name(name)
        second = sem.canonical_header_name(first)
        if first != second:
            cex.append({"name": name, "first": first, "second": second})
    return Obligation("header_name_canonicalization_idempotence", "Header-name canonicalization is idempotent over encoded policy fields.", states, tuple(cex), "header-product enumeration")

def _check_header_values_case_insensitive_lookup(root: Path) -> Obligation:
    sem = _import_semantics(root)
    header_names = ["Content-Security-Policy", "content-security-policy", "CONTENT-SECURITY-POLICY"]
    lookup_names = ["Content-Security-Policy", "content-security-policy", "CONTENT-SECURITY-POLICY"]
    cex: List[Dict[str, Any]] = []
    states = 0
    for emitted in header_names:
        for lookup in lookup_names:
            states += 1
            headers = [{"name": emitted, "value": "script-src 'self'"}]
            actual = sem.header_values(headers, lookup)
            if actual != ["script-src 'self'"]:
                cex.append({"emitted": emitted, "lookup": lookup, "actual": actual})
    return Obligation("header_lookup_case_insensitivity", "Policy header lookup is case-insensitive while preserving values.", states, tuple(cex), "header-product enumeration")

def _check_source_expression_boundaries(root: Path) -> Obligation:
    sem = _import_semantics(root)
    docs = ["https://app.example", "https://shop.example", "http://app.example"]
    resources = ["https://app.example", "https://cdn.example", "https://sub.example", "http://cdn.example", "https://evil.test"]
    sources = ["*", "'none'", "'self'", "https:", "http:", "https://cdn.example", "*.example", "evil.test"]
    cex: List[Dict[str, Any]] = []
    states = 0
    for doc in docs:
        for res in resources:
            for src in sources:
                states += 1
                actual = sem.source_allows(src, res, doc)
                scheme, host, _ = sem.parse_origin(res)
                expected = False
                if src == "*": expected = True
                elif src == "'none'": expected = False
                elif src == "'self'": expected = sem.same_origin(res, doc)
                elif src in {"https:", "http:"}: expected = scheme == src[:-1]
                elif src == "https://cdn.example": expected = sem.same_origin(res, "https://cdn.example")
                elif src == "*.example": expected = host.endswith(".example")
                elif src == "evil.test": expected = host == "evil.test"
                if actual != expected:
                    cex.append({"doc": doc, "resource": res, "source": src, "expected": expected, "actual": actual})
    return Obligation("csp_source_expression_boundaries", "Encoded CSP source expressions have exact wildcard, none, self, scheme, host, and subdomain boundaries.", states, tuple(cex), "source-expression product enumeration")

def _check_csp_report_only_plus_enforced(root: Path) -> Obligation:
    sem = _import_semantics(root)
    enforced = ["script-src 'self'", "script-src *", "default-src 'none'"]
    report = ["script-src 'none'", "script-src *"]
    resources = ["https://app.example", "https://evil.example"]
    cex: List[Dict[str, Any]] = []
    states = 0
    for e in enforced:
        for r in report:
            for res in resources:
                states += 1
                headers = [{"name": "Content-Security-Policy", "value": e}, {"name": "Content-Security-Policy-Report-Only", "value": r}]
                fixture = _fixture("TK_CSP_RO_PLUS", "enforce_script_restriction", headers, {"document_origin": "https://app.example", "resource_origin": res, "scheme": "https"}, "none", "CSP")
                issues = _finding_issues(sem.analyze_fixture(fixture))
                should_allow = sem.enforced_csp_allows_script([e], "https://app.example", res)
                expected = ("csp_effective_script_allowance",) if should_allow else tuple()
                if issues != expected:
                    cex.append({"enforced": e, "report_only": r, "resource": res, "expected": expected, "actual": issues})
    return Obligation("report_only_does_not_weaken_enforced_csp", "Report-only CSP fields neither enforce nor weaken an enforced CSP field in the encoded script-load fragment.", states, tuple(cex), "field-composition enumeration")

def _check_cors_noncredentialed_wildcard(root: Path) -> Obligation:
    sem = _import_semantics(root)
    acac_values = ["", "true", "True", "false"]
    modes = ["omit", "same-origin"]
    cex: List[Dict[str, Any]] = []
    states = 0
    for acac in acac_values:
        for mode in modes:
            states += 1
            headers = [{"name": "Access-Control-Allow-Origin", "value": "*"}]
            if acac:
                headers.append({"name": "Access-Control-Allow-Credentials", "value": acac})
            actual = sem.cors_shareable(headers, "https://app.example", mode)
            if actual is not True:
                cex.append({"acac": acac, "mode": mode, "actual": actual})
    return Obligation("cors_wildcard_noncredentialed_shareability", "Wildcard ACAO remains shareable for non-credentialed modeled requests regardless of ACAC noise.", states, tuple(cex), "truth-table enumeration")

def _check_cors_duplicate_acao_order_invariance(root: Path) -> Obligation:
    sem = _import_semantics(root)
    values = ["https://app.example", "*", "$ORIGIN"]
    cex: List[Dict[str, Any]] = []
    states = 0
    for a in values:
        for b in values:
            if a == b:
                continue
            states += 1
            h1 = [{"name": "Access-Control-Allow-Origin", "value": a}, {"name": "Access-Control-Allow-Origin", "value": b}, {"name": "Access-Control-Allow-Credentials", "value": "true"}]
            h2 = list(reversed(h1))
            actual1 = sem.cors_shareable(h1, "https://app.example", "include")
            actual2 = sem.cors_shareable(h2, "https://app.example", "include")
            if actual1 or actual2 or actual1 != actual2:
                cex.append({"a": a, "b": b, "actual1": actual1, "actual2": actual2})
    return Obligation("cors_duplicate_acao_order_invariance", "Duplicate ACAO rejection is invariant to header order.", states, tuple(cex), "permutation enumeration")

def _check_hsts_parser_case_and_spacing(root: Path) -> Obligation:
    sem = _import_semantics(root)
    values = [" max-age=31536000 ; includeSubDomains ; preload ", "MAX-AGE=31536000; INCLUDESUBDOMAINS; PRELOAD", "max-age=031536000; includeSubDomains; preload", "max-age=31535999; includeSubDomains; preload"]
    cex: List[Dict[str, Any]] = []
    states = 0
    for value in values:
        states += 1
        parsed = sem.parse_hsts(value)
        actual = sem.hsts_preload_ready(value)
        lower = value.lower().replace(" ", "")
        expected = "max-age=31536000" in lower and "includesubdomains" in lower and "preload" in lower
        if "031536000" in lower:
            expected = True
        if actual != expected:
            cex.append({"value": value, "parsed": parsed, "expected": expected, "actual": actual})
    return Obligation("hsts_parser_case_spacing_boundary", "The HSTS preload predicate is robust to directive case/spacing and rejects below-threshold age.", states, tuple(cex), "parser-boundary enumeration")

def _check_corp_cross_origin_top(root: Path) -> Obligation:
    sem = _import_semantics(root)
    docs = ["https://app.example", "https://a.test", "https://shop.example"]
    resources = ["https://app.example", "https://cdn.example", "https://b.test", "https://evil.invalid"]
    cex: List[Dict[str, Any]] = []
    states = 0
    for doc in docs:
        for res in resources:
            states += 1
            if sem.corp_allows("cross-origin", doc, res) is not True:
                cex.append({"doc": doc, "resource": res})
    return Obligation("corp_cross_origin_top_allows_all", "CORP cross-origin is the top element of the encoded CORP scope lattice.", states, tuple(cex), "origin-pair enumeration")

def _check_permissions_parser_directive_commutativity(root: Path) -> Obligation:
    sem = _import_semantics(root)
    values = ["geolocation=(), camera=*", "camera=*, geolocation=()", "microphone=(self), geolocation=(https://evil.example)", "geolocation=(https://evil.example), microphone=(self)"]
    cex: List[Dict[str, Any]] = []
    states = 0
    for value in values:
        states += 1
        headers = [{"name": "Permissions-Policy", "value": value}]
        disabled = sem.permissions_feature_disabled(headers, "geolocation")
        over = sem.permissions_feature_overallowed(headers, "geolocation", "https://evil.example")
        expected_disabled = "geolocation=()" in value
        expected_over = "geolocation=(https://evil.example)" in value
        if disabled != expected_disabled or over != expected_over:
            cex.append({"value": value, "disabled": disabled, "expected_disabled": expected_disabled, "over": over, "expected_over": expected_over})
    return Obligation("permissions_directive_order_commutativity", "Ordering independent Permissions-Policy directives does not change the queried feature judgment.", states, tuple(cex), "directive-order enumeration")

def _check_unknown_header_noninterference(root: Path) -> Obligation:
    sem = _import_semantics(root)
    base_headers = [[{"name": "Content-Security-Policy", "value": "script-src 'self'"}], [{"name": "Access-Control-Allow-Origin", "value": "https://app.example"}, {"name": "Access-Control-Allow-Credentials", "value": "true"}], [{"name": "Strict-Transport-Security", "value": "max-age=31536000"}]]
    intents = ["enforce_script_restriction", "allow_credentialed_cors", "enforce_https_only"]
    contexts = [{"document_origin": "https://app.example", "resource_origin": "https://evil.example", "scheme": "https"}, {"request_origin": "https://app.example", "credentials_mode": "include"}, {"scheme": "https"}]
    noises = ["X-Trace", "X-Debug", "Server-Timing", "Referrer-Policy", "Alt-Svc"]
    cex: List[Dict[str, Any]] = []
    states = 0
    for headers, intent, ctx in zip(base_headers, intents, contexts):
        base = _finding_issues(sem.analyze_fixture(_fixture("TK_NONINTERFERE_BASE", intent, headers, ctx, "none", "noninterference")))
        for noise in noises:
            states += 1
            actual = _finding_issues(sem.analyze_fixture(_fixture("TK_NONINTERFERE_NOISE", intent, list(headers)+[{"name": noise, "value": "noop"}], ctx, "none", "noninterference")))
            if actual != base:
                cex.append({"intent": intent, "noise": noise, "base": base, "actual": actual})
    return Obligation("unknown_header_noninterference", "Headers outside the encoded policy vocabulary do not affect known fragment judgments.", states, tuple(cex), "noninterference enumeration")

def verify_theory_kernel(root: Path) -> Dict[str, Any]:
    checks: List[Obligation] = [
        _check_csp_meet(root),
        _check_csp_meet_commutativity_idempotence(root),
        _check_csp_source_monotonicity(root),
        _check_csp_fallback(root),
        _check_report_only(root),
        _check_cors_truth_table(root),
        _check_cors_duplicate_acao_rejection(root),
        _check_cors_cache(root),
        _check_cors_vary_origin_tokenization(root),
        _check_hsts_state(root),
        _check_hsts_preload_criterion(root),
        _check_coep_request_mode(root),
        _check_coop_coep_isolation_partition(root),
        _check_corp_scope(root),
        _check_corp_same_site_approximation(root),
        _check_permissions(root),
        _check_permissions_feature_independence(root),
        _check_layer_composition(root),
        _check_layer_remove_set_absorption(root),
        _check_unknown_free_known_fragments(root),
        _check_header_name_canonicalization(root),
        _check_header_values_case_insensitive_lookup(root),
        _check_source_expression_boundaries(root),
        _check_csp_report_only_plus_enforced(root),
        _check_cors_noncredentialed_wildcard(root),
        _check_cors_duplicate_acao_order_invariance(root),
        _check_hsts_parser_case_and_spacing(root),
        _check_corp_cross_origin_top(root),
        _check_permissions_parser_directive_commutativity(root),
        _check_unknown_header_noninterference(root),
    ]
    problems: List[str] = []
    for c in checks:
        if c.counterexamples:
            problems.append(f"{c.name}: {len(c.counterexamples)} counterexamples")
    states = sum(c.states_checked for c in checks)
    return {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "theorems_checked": len(checks),
        "finite_states_checked": states,
        "counterexamples": sum(len(c.counterexamples) for c in checks),
        "obligations": [c.as_dict() for c in checks],
        "interpretation": "Finite proof kernel over the executable BEP semantic fragment; these checks are separate from locked fixture labels and do not change the denominator.",
    }


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
