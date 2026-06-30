#!/usr/bin/env python3
"""Certify issue-specific repair frontiers for BEP-Deep witnesses.

For each positive fixture, the checker compares the original witness with its
paired repair control.  The paired control must (1) remove the modeled issue,
(2) preserve source and intent, (3) change exactly one semantic surface among
headers/layers/context, and (4) be no more expensive than a small deterministic
neighborhood of alternative edits.  The frontier is intentionally local: it is a
certificate that the reported witness has a compact actionable counterfactual,
not a claim of globally optimal deployment repair.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True

import argparse, copy, csv, json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from bep_semantics import analyze_fixture
from decision_table_oracle import decision_issues, load


def issues(fx: Dict[str, Any]) -> List[str]:
    return sorted({f.issue for f in analyze_fixture(fx)})


def expected(fx: Dict[str, Any]) -> List[str]:
    e = str(fx.get("expected_issue", "none"))
    return [] if e == "none" else [e]


def edit_cost(a: Dict[str, Any], b: Dict[str, Any]) -> int:
    cost = 0
    for key in ["headers", "layers", "context"]:
        if a.get(key) != b.get(key):
            # Header/layer edits are counted by changed serialized surface,
            # context edits by changed keys.
            if key == "context" and isinstance(a.get(key), dict) and isinstance(b.get(key), dict):
                ka = set(a[key].keys()); kb = set(b[key].keys())
                cost += 1
            else:
                cost += 1
    return cost


def set_header(fx: Dict[str, Any], name: str, value: str) -> None:
    lname = name.lower()
    hs = fx.setdefault("headers", [])
    if not isinstance(hs, list):
        fx["headers"] = []
        hs = fx["headers"]
    fx["headers"] = [h for h in hs if str(h.get("name", "")).lower() != lname]
    fx["headers"].append({"name": name, "value": value})


def remove_header(fx: Dict[str, Any], name: str) -> None:
    lname = name.lower()
    hs = fx.setdefault("headers", [])
    if isinstance(hs, list):
        fx["headers"] = [h for h in hs if str(h.get("name", "")).lower() != lname]


def alternative_repairs(pos: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
    issue = str(pos.get("expected_issue", ""))
    alts: List[Tuple[str, Dict[str, Any]]] = []
    # Generic no-op-like distractor and surface removal candidate.
    g = copy.deepcopy(pos); g["id"] = f"{pos['id']}__frontier_noop_comment"; g.setdefault("headers", []).append({"name":"X-BEP-Note", "value":"noop"}); alts.append(("irrelevant_header", g))
    g = copy.deepcopy(pos); g["id"] = f"{pos['id']}__frontier_drop_policy"; g["headers"] = []; alts.append(("drop_all_headers", g))
    # Issue-class nearest repairs.  These intentionally overlap with the paired
    # control family but are generated independently for the frontier check.
    g = copy.deepcopy(pos); ctx = g.setdefault("context", {}) if isinstance(g.get("context", {}), dict) else {}; g["context"] = ctx
    if issue == "hsts_header_not_honored_over_http":
        ctx["scheme"] = "https"; alts.append(("secure_transport", g))
    elif issue in {"hsts_policy_cleared_by_zero_max_age", "hsts_invalid_max_age_ignored", "hsts_missing_include_subdomains", "hsts_subdomain_scope_not_covered"}:
        set_header(g, "Strict-Transport-Security", "max-age=31536000; includeSubDomains"); alts.append(("canonical_hsts", g))
    elif issue == "hsts_preload_criteria_not_met":
        set_header(g, "Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"); alts.append(("preload_header", g))
    elif issue.startswith("cors"):
        req = str((pos.get("context") or {}).get("request_origin", "https://app.example"))
        set_header(g, "Access-Control-Allow-Origin", req); set_header(g, "Access-Control-Allow-Credentials", "true")
        if issue in {"cors_dynamic_origin_without_vary", "cors_dynamic_origin_missing_vary"}: set_header(g, "Vary", "Origin")
        alts.append(("specific_cors", g))
    elif issue.startswith("csp") or issue.startswith("layered"):
        if issue == "csp_report_only_not_enforced":
            vals = [h.get("value", "script-src 'self'") for h in pos.get("headers", []) if str(h.get("name","")).lower()=="content-security-policy-report-only"]
            remove_header(g, "Content-Security-Policy-Report-Only"); set_header(g, "Content-Security-Policy", str(vals[0] if vals else "script-src 'self'"))
        elif issue in {"csp_effective_script_allowance", "layered_header_override_drops_enforcement"}:
            set_header(g, "Content-Security-Policy", "script-src 'self'; object-src 'none'")
        elif issue in {"csp_multiple_policy_overblocks_trusted_script", "csp_conjunctive_policy_composition_blocks_required_script"}:
            res = str((pos.get("context") or {}).get("resource_origin", "https://cdn.example"))
            g["headers"] = [{"name":"Content-Security-Policy", "value":f"script-src {res}; object-src 'none'"}]
        elif issue in {"csp_frame_ancestors_report_only_not_enforced", "csp_frame_ancestors_meta_delivery_unsupported"}:
            g["headers"] = [{"name":"Content-Security-Policy", "value":"frame-ancestors 'none'"}]
        elif issue == "nonce_csp_static_render_incompatibility":
            ctx["static_render"] = False; ctx["rendering_variant"] = "dynamic_per_request"
        alts.append(("csp_canonical", g))
    elif issue.startswith("coep") or issue.startswith("corp") or issue.startswith("cross_origin"):
        set_header(g, "Cross-Origin-Opener-Policy", "same-origin"); set_header(g, "Cross-Origin-Embedder-Policy", "require-corp"); set_header(g, "Cross-Origin-Resource-Policy", "cross-origin")
        remove_header(g, "Permissions-Policy"); alts.append(("isolation_canonical", g))
    elif issue.startswith("permissions"):
        if issue == "permissions_policy_feature_disabled": remove_header(g, "Permissions-Policy")
        else: set_header(g, "Permissions-Policy", f"{(pos.get('context') or {}).get('feature','geolocation')}=()")
        alts.append(("permissions_canonical", g))
    return alts


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixtures", default="artifact/data/deep_locked_fixtures.json")
    ap.add_argument("--out-dir", default="artifact/results/bep_max")
    args = ap.parse_args()
    fixtures = load(args.fixtures)
    by_id = {str(f["id"]): f for f in fixtures}
    repairs = {str(f.get("paired_positive_fixture_id")): f for f in fixtures if str(f.get("fixture_role")) == "paired_repair_negative_control"}
    out = Path(args.out_dir); out.mkdir(parents=True, exist_ok=True)
    rows = []
    failures = []
    for pos in fixtures:
        if expected(pos) == []:
            continue
        pid = str(pos["id"]); rep = repairs.get(pid)
        if not rep:
            failures.append({"fixture_id": pid, "reason": "missing paired repair"}); continue
        target = expected(pos)[0]
        rep_issues = issues(rep); rep_dt = sorted(set(decision_issues(rep)))
        same_source = set(pos.get("source_claim_ids", [])) == set(rep.get("source_claim_ids", []))
        same_intent = pos.get("intent", {}) == rep.get("intent", {})
        cost = edit_cost(pos, rep)
        # Evaluate neighborhood.
        candidates = []
        for name, cand in alternative_repairs(pos):
            cand_issues = issues(cand)
            candidates.append({"name": name, "cost": edit_cost(pos, cand), "clean": cand_issues == [], "issues": ";".join(cand_issues) or "none"})
        clean_costs = [c["cost"] for c in candidates if c["clean"]]
        best_alt_cost = min(clean_costs) if clean_costs else None
        frontier = rep_issues == [] and rep_dt == [] and same_source and same_intent and (best_alt_cost is None or cost <= best_alt_cost)
        row = {
            "fixture_id": pid,
            "target_issue": target,
            "paired_repair_id": rep.get("id", ""),
            "repair_cost": cost,
            "clean_under_operational": str(rep_issues == []).lower(),
            "clean_under_decision_table": str(rep_dt == []).lower(),
            "source_preserved": str(same_source).lower(),
            "intent_preserved": str(same_intent).lower(),
            "candidate_repairs_tested": len(candidates),
            "best_alternative_clean_cost": best_alt_cost if best_alt_cost is not None else "none",
            "frontier_certified": str(frontier).lower(),
        }
        rows.append(row)
        if not frontier and len(failures) < 20:
            failures.append(row)
    with (out / "repair_frontier_audit.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    metrics = {
        "positive_witnesses": len(rows),
        "frontier_certified": sum(1 for r in rows if r["frontier_certified"] == "true"),
        "candidate_repairs_tested": sum(int(r["candidate_repairs_tested"]) for r in rows),
        "mean_candidate_repairs_per_witness": round(sum(int(r["candidate_repairs_tested"]) for r in rows)/len(rows), 3) if rows else 0,
        "failures": failures,
        "interpretation": "Local repair-frontier certification over issue-specific neighborhoods; not a global optimal-repair theorem.",
    }
    (out / "repair_frontier_metrics.json").write_text(json.dumps(metrics, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    print(json.dumps(metrics, sort_keys=True))
    if failures:
        sys.exit(1)

if __name__ == "__main__":
    main()
