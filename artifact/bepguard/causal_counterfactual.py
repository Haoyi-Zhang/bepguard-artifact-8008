"""Causal counterfactual audits for BEPGuard.

The paired-repair controls show that known positives can be repaired.  This
module checks the complementary direction: clean controls that are inside an
encoded fragment can be pushed across the semantic boundary by a small targeted
counterfactual edit, and the same oracle must then emit the expected issue.  The
audit is deliberately metadata-independent: it constructs fresh fixture ids and
compares only semantic issue signatures.
"""
from __future__ import annotations

import copy
import csv
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

sys.dont_write_bytecode = True


def _import_semantics(root: Path):
    scripts = root / "artifact" / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import bep_semantics  # type: ignore
    return bep_semantics


def _signature(findings: Iterable[Any]) -> Tuple[str, ...]:
    issues: List[str] = []
    for finding in findings:
        if hasattr(finding, "issue"):
            issues.append(str(getattr(finding, "issue")))
        elif isinstance(finding, Mapping):
            issues.append(str(finding.get("issue", "")))
    return tuple(sorted(i for i in issues if i))


def _expected(fixture: Mapping[str, Any]) -> Tuple[str, ...]:
    issue = str(fixture.get("expected_issue", "none"))
    return tuple() if issue in {"", "none"} else (issue,)


def _digest(obj: Mapping[str, Any]) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()[:16]


def _headers(*pairs: Tuple[str, str]) -> List[Dict[str, str]]:
    return [{"name": name, "value": value} for name, value in pairs]


def _fresh(base: Mapping[str, Any], suffix: str) -> Dict[str, Any]:
    out = copy.deepcopy(dict(base))
    for k in ["fixture_hash", "expected_issue", "fixture_role", "source_claim_ids", "public_source_id", "variant"]:
        out.pop(k, None)
    out["id"] = f"CAUSAL_{suffix}_{_digest(out)}"
    out["fixture_role"] = "counterfactual_activation"
    return out


def _activate_clean_control(control: Mapping[str, Any]) -> Optional[Tuple[Dict[str, Any], str, str]]:
    """Return a targeted activation fixture, expected issue, and operator name.

    The transformation keeps the intent class and context family stable whenever
    possible.  It avoids adding new semantic rules: every expected issue must be
    emitted by the released BEP semantic oracle.
    """
    intent_class = str(control.get("intent", {}).get("class", "")) if isinstance(control.get("intent"), Mapping) else ""
    out = _fresh(control, intent_class.upper()[:12] or "GEN")
    ctx = dict(out.get("context", {})) if isinstance(out.get("context"), Mapping) else {}

    if intent_class == "enforce_script_restriction":
        out["headers"] = _headers(("Content-Security-Policy-Report-Only", "script-src 'self'; report-uri /csp"))
        return out, "csp_report_only_not_enforced", "enforced_to_report_only"
    if intent_class == "allow_credentialed_cors":
        out["headers"] = _headers(("Access-Control-Allow-Origin", "https://other.example"), ("Access-Control-Allow-Credentials", "true"))
        ctx["credentials_mode"] = "include"; ctx.setdefault("request_origin", "https://frontend.example")
        out["context"] = ctx
        return out, "cors_intended_credentialed_share_blocked", "credentialed_cors_origin_mismatch"
    if intent_class == "enforce_https_only":
        out["headers"] = _headers(("Strict-Transport-Security", "max-age=abc; includeSubDomains"))
        ctx["scheme"] = "https"; out["context"] = ctx
        return out, "hsts_invalid_max_age_ignored", "hsts_invalid_max_age"
    if intent_class == "cross_origin_isolation_without_embed_breakage":
        out["headers"] = _headers(("Cross-Origin-Embedder-Policy", "require-corp"))
        ctx["request_mode"] = "no-cors"; ctx.setdefault("document_origin", "https://app.example"); ctx.setdefault("resource_origin", "https://cdn.other.example")
        out["context"] = ctx
        return out, "coep_require_corp_blocks_cross_origin_resource", "remove_resource_opt_in"
    if intent_class == "enable_cross_origin_isolation":
        out["headers"] = _headers(("Cross-Origin-Opener-Policy", "same-origin"))
        return out, "cross_origin_isolation_incomplete", "drop_coep_half"
    if intent_class == "allow_browser_feature":
        feature = str(ctx.get("feature", "geolocation")) or "geolocation"
        out["headers"] = _headers(("Permissions-Policy", f"{feature}=()"))
        out["context"] = ctx
        return out, "permissions_policy_feature_disabled", "disable_required_feature"
    if intent_class == "allow_required_script_after_policy_composition":
        ctx.setdefault("document_origin", "https://app.example"); ctx.setdefault("resource_origin", "https://cdn.example")
        out["headers"] = _headers(("Content-Security-Policy", "script-src https://cdn.example"), ("Content-Security-Policy", "default-src 'self'; script-src 'self'"))
        out["context"] = ctx
        return out, "csp_conjunctive_policy_composition_blocks_required_script", "add_conjunctive_blocking_policy"
    if intent_class == "preserve_enforced_policy_across_layers":
        out["headers"] = []
        ctx["expected_enforced_csp"] = True
        out["context"] = ctx
        out["layers"] = [{"layer": "counterfactual", "op": "append", "headers": [{"name": "Content-Security-Policy-Report-Only", "value": "script-src 'self'"}]}]
        return out, "layered_header_override_drops_enforcement", "enforced_layer_to_report_only"
    if intent_class == "allow_credentialed_cors_cache_safe":
        out["headers"] = _headers(("Access-Control-Allow-Origin", "$ORIGIN"), ("Access-Control-Allow-Credentials", "true"))
        ctx["credentials_mode"] = "include"; ctx["dynamic_origin"] = True
        out["context"] = ctx
        return out, "cors_dynamic_origin_missing_vary", "drop_vary_origin"
    if intent_class == "enforce_https_only_subdomains":
        out["headers"] = _headers(("Strict-Transport-Security", "max-age=31536000"))
        ctx["scheme"] = "https"; ctx["subdomain_scope_required"] = True
        out["context"] = ctx
        return out, "hsts_subdomain_scope_not_covered", "drop_include_subdomains"
    if intent_class == "allow_trusted_script":
        ctx.setdefault("document_origin", "https://app.example"); ctx.setdefault("resource_origin", "https://cdn.example")
        out["headers"] = _headers(("Content-Security-Policy", "script-src https://cdn.example"), ("Content-Security-Policy", "script-src 'self'"))
        out["context"] = ctx
        return out, "csp_multiple_policy_overblocks_trusted_script", "add_overblocking_csp"
    if intent_class == "expect_hsts_preload":
        out["headers"] = _headers(("Strict-Transport-Security", "max-age=31536000; includeSubDomains"))
        ctx["scheme"] = "https"; out["context"] = ctx
        return out, "hsts_preload_criteria_not_met", "drop_preload_token"
    if intent_class == "deny_cross_origin_embedding":
        ctx["document_origin"] = "https://app.example"; ctx["resource_origin"] = "https://cdn.example"
        out["headers"] = _headers(("Cross-Origin-Resource-Policy", "same-site"))
        out["context"] = ctx
        return out, "corp_same_site_allows_cross_origin_same_site", "weaken_corp_same_origin_to_same_site"
    if intent_class == "deny_browser_feature":
        feature = str(ctx.get("feature", "geolocation")) or "geolocation"
        ctx.setdefault("target_origin", "https://cdn.example")
        out["headers"] = _headers(("Permissions-Policy", f"{feature}=*"))
        out["context"] = ctx
        return out, "permissions_policy_feature_overallowed", "wildcard_denied_feature"
    if intent_class == "enforce_framing_protection":
        out["headers"] = _headers(("Content-Security-Policy-Report-Only", "frame-ancestors 'none'"))
        return out, "csp_frame_ancestors_report_only_not_enforced", "frame_ancestors_report_only"
    if intent_class == "nonce_based_strict_csp":
        ctx["static_render"] = True; ctx["rendering_variant"] = "static_rendered"
        out["headers"] = _headers(("Content-Security-Policy", "script-src 'self' 'nonce-abc123' 'strict-dynamic'; object-src 'none'"))
        out["context"] = ctx
        return out, "nonce_csp_static_render_incompatibility", "make_nonce_static_rendered"
    if intent_class == "deny_public_credentialed_cors":
        out["headers"] = _headers(("Access-Control-Allow-Origin", "$ORIGIN"), ("Access-Control-Allow-Credentials", "true"))
        ctx["credentials_mode"] = "include"
        out["context"] = ctx
        return out, "cors_reflected_origin_with_credentials", "reflect_origin_with_credentials"
    if intent_class == "partition_cors_cache_by_origin":
        out["headers"] = _headers(("Access-Control-Allow-Origin", "$ORIGIN"), ("Access-Control-Allow-Credentials", "true"))
        ctx["shared_cache"] = True; ctx["credentials_mode"] = "include"
        out["context"] = ctx
        return out, "cors_dynamic_origin_without_vary", "drop_cache_vary_origin"
    if intent_class == "enforce_https_subdomains":
        out["headers"] = _headers(("Strict-Transport-Security", "max-age=31536000"))
        ctx["scheme"] = "https"; ctx["subdomain_request"] = True
        out["context"] = ctx
        return out, "hsts_missing_include_subdomains", "drop_subdomain_scope"
    # allow_public_cors is a clean control-only intent in the locked fragment;
    # it does not have a positive branch in the released semantic oracle.
    return None


def run_causal_activation_audit(root: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    sem = _import_semantics(root)
    fixtures = json.loads((root / "artifact" / "data" / "deep_locked_fixtures.json").read_text(encoding="utf-8"))
    positives = {str(f.get("id")): f for f in fixtures if _expected(f)}
    rows: List[Dict[str, Any]] = []
    problems: List[Dict[str, Any]] = []
    skipped = 0
    for control in [f for f in fixtures if not _expected(f)]:
        if str(control.get("fixture_role")) == "paired_repair_negative_control":
            positive = positives.get(str(control.get("paired_positive_fixture_id", "")))
            if positive is None:
                row = {"control_id": control.get("id"), "operator": "paired_positive_lookup", "activated": False, "problem": "missing paired positive"}
                rows.append(row); problems.append(row); continue
            expected_issue = tuple(str(x) for x in _expected(positive))
            activation = copy.deepcopy(positive)
            activation["id"] = f"CAUSAL_REVERSE_{_digest(activation)}"
            operator = "paired_repair_reverse_activation"
        else:
            maybe = _activate_clean_control(control)
            if maybe is None:
                skipped += 1
                rows.append({"control_id": control.get("id"), "operator": "not_applicable_in_locked_oracle", "activated": "not_applicable", "intent_class": control.get("intent", {}).get("class", "") if isinstance(control.get("intent"), Mapping) else ""})
                continue
            activation, issue, operator = maybe
            expected_issue = (issue,)
        before = _signature(sem.analyze_fixture(copy.deepcopy(control)))
        after = _signature(sem.analyze_fixture(copy.deepcopy(activation)))
        row = {
            "control_id": str(control.get("id", "")),
            "activation_id": str(activation.get("id", "")),
            "operator": operator,
            "intent_class": control.get("intent", {}).get("class", "") if isinstance(control.get("intent"), Mapping) else "",
            "control_signature": list(before),
            "expected_activation_issue": list(expected_issue),
            "activation_signature": list(after),
            "activated": before == tuple() and after == expected_issue,
        }
        rows.append(row)
        if not row["activated"]:
            problems.append(row)
    required = [r for r in rows if r.get("activated") != "not_applicable"]
    by_operator = Counter(str(r.get("operator", "")) for r in required)
    by_intent = Counter(str(r.get("intent_class", "")) for r in required)
    return rows, {
        "schema": "BEPGuardCausalCounterfactualActivation/v1",
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems[:25],
        "clean_controls_seen": sum(1 for f in fixtures if not _expected(f)),
        "required_activations": len(required),
        "activated_controls": sum(1 for r in required if r.get("activated") is True),
        "not_applicable_controls": skipped,
        "operators": dict(sorted(by_operator.items())),
        "intent_classes": len(by_intent),
        "interpretation": "Causal activation starts from clean controls, applies a small targeted semantic edit, and requires the same oracle to cross the boundary and emit the expected issue. Paired repairs are checked by reversing to their paired positive; clean controls whose intent has no positive branch in the locked oracle are recorded as not-applicable rather than relabeled.",
    }


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: List[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("\n", encoding="utf-8"); return
    fieldnames = sorted({k for r in rows for k in r.keys()})
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: json.dumps(v, sort_keys=True) if isinstance(v, (list, dict, tuple)) else v for k, v in row.items()})
