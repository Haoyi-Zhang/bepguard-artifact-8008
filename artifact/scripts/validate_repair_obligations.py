#!/usr/bin/env python3
"""Validate counterfactual repair obligations beyond target removal.

A target issue disappearing is not enough: a repair could drop all headers,
change the claim, or hide the fixture.  This validator checks that repaired
fixtures are paired with their positive parents, keep the intent identity and
context scope, remove all modeled issues under the same oracle, and modify only
an issue-class-specific surface.
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import csv
import json
from pathlib import Path
from typing import Dict, List, Set

from bep_semantics import analyze_fixture

ALLOWED_FIELDS: Dict[str, Set[str]] = {
    "csp_report_only_not_enforced": {"headers", "layers"},
    "csp_effective_script_allowance": {"headers", "layers"},
    "csp_multiple_policy_overblocks_trusted_script": {"headers", "layers"},
    "csp_conjunctive_policy_composition_blocks_required_script": {"headers", "layers"},
    "layered_header_override_drops_enforcement": {"headers", "layers"},
    "csp_frame_ancestors_report_only_not_enforced": {"headers", "layers"},
    "csp_frame_ancestors_meta_delivery_unsupported": {"headers", "layers"},
    "nonce_csp_static_render_incompatibility": {"headers", "context"},
    "cors_intended_credentialed_share_blocked": {"headers"},
    "cors_duplicate_acao_not_shareable": {"headers"},
    "cors_acac_case_sensitive_not_shareable": {"headers"},
    "cors_reflected_origin_with_credentials": {"headers"},
    "cors_dynamic_origin_without_vary": {"headers"},
    "cors_dynamic_origin_missing_vary": {"headers"},
    "hsts_header_not_honored_over_http": {"context"},
    "hsts_invalid_max_age_ignored": {"headers"},
    "hsts_policy_cleared_by_zero_max_age": {"headers"},
    "hsts_missing_include_subdomains": {"headers"},
    "hsts_subdomain_scope_not_covered": {"headers"},
    "hsts_preload_criteria_not_met": {"headers"},
    "coep_require_corp_blocks_cross_origin_resource": {"headers"},
    "corp_same_site_allows_cross_origin_same_site": {"headers", "context"},
    "cross_origin_isolation_incomplete": {"headers"},
    "permissions_policy_feature_disabled": {"headers"},
    "permissions_policy_feature_overallowed": {"headers"},
}

META_KEYS = {"id", "fixture_hash", "locked_status", "variant", "mutation_operator", "mutation_operator_class", "mutation_parent", "fixture_role", "interpretation", "expected_issue"}


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def issue_list(f: Dict[str, object]) -> List[str]:
    return sorted(x.issue for x in analyze_fixture(f))


def changed_top_keys(parent: Dict[str, object], fixed: Dict[str, object]) -> Set[str]:
    keys = set(parent) | set(fixed)
    out = set()
    for k in keys:
        if k in META_KEYS:
            continue
        if parent.get(k) != fixed.get(k):
            out.add(k)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixtures", default="artifact/data/extended_fixtures.json")
    ap.add_argument("--repaired", default="artifact/results/extended_locked/repaired_positive_fixtures.json")
    ap.add_argument("--csv", default="artifact/results/deep_locked/repair_obligation_audit.csv")
    ap.add_argument("--json", default="artifact/results/deep_locked/repair_obligation_metrics.json")
    args = ap.parse_args()
    fixtures = {str(f["id"]): f for f in load(Path(args.fixtures))}
    repaired = load(Path(args.repaired))
    rows: List[Dict[str, object]] = []
    for fixed in repaired:
        rid = str(fixed.get("id", ""))
        parent_id = rid.removesuffix("__repair")
        parent = fixtures.get(parent_id)
        if parent is None:
            parent_id = str(fixed.get("mutation_parent", parent_id))
            parent = fixtures.get(parent_id)
        target = str(fixed.get("expected_issue", "none"))
        before = issue_list(parent) if parent else []
        after = issue_list(fixed)
        allowed = ALLOWED_FIELDS.get(target, {"headers", "context", "layers"})
        changed = changed_top_keys(parent or {}, fixed)
        rows.append({
            "repaired_fixture_id": rid,
            "parent_fixture_id": parent_id,
            "target_issue": target,
            "parent_found": parent is not None,
            "parent_triggers_target": target in before,
            "target_removed": target not in after,
            "all_modeled_issues_removed": len(after) == 0,
            "intent_preserved": (parent or {}).get("intent") == fixed.get("intent"),
            "source_preserved": (parent or {}).get("public_source_id") == fixed.get("public_source_id"),
            "changed_top_keys": ";".join(sorted(changed)) if changed else "none",
            "allowed_change_scope": ";".join(sorted(allowed)),
            "change_scope_ok": changed.issubset(allowed),
            "issues_before": ";".join(before) if before else "none",
            "issues_after": ";".join(after) if after else "none",
        })
    out_csv = Path(args.csv); out_csv.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["repaired_fixture_id", "parent_fixture_id", "target_issue", "parent_found", "parent_triggers_target", "target_removed", "all_modeled_issues_removed", "intent_preserved", "source_preserved", "changed_top_keys", "allowed_change_scope", "change_scope_ok", "issues_before", "issues_after"]
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames); w.writeheader(); w.writerows(rows)
    failures = [r for r in rows if not (r["parent_found"] and r["parent_triggers_target"] and r["target_removed"] and r["all_modeled_issues_removed"] and r["intent_preserved"] and r["source_preserved"] and r["change_scope_ok"])]
    metrics = {
        "repair_pairs_checked": len(rows),
        "parent_triggers_target": sum(1 for r in rows if r["parent_triggers_target"]),
        "target_removed": sum(1 for r in rows if r["target_removed"]),
        "all_modeled_issues_removed": sum(1 for r in rows if r["all_modeled_issues_removed"]),
        "intent_preserved": sum(1 for r in rows if r["intent_preserved"]),
        "source_preserved": sum(1 for r in rows if r["source_preserved"]),
        "change_scope_ok": sum(1 for r in rows if r["change_scope_ok"]),
        "failures": failures,
        "interpretation": "Repair validation checks target removal, all-modeled-issue removal, intent/source preservation, and issue-specific change scope; it is not deployment advice.",
    }
    Path(args.json).write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(metrics, sort_keys=True))
    if failures:
        sys.exit(1)


if __name__ == "__main__":
    main()
