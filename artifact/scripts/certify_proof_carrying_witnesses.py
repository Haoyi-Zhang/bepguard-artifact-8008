#!/usr/bin/env python3
"""Generate and verify proof-carrying witness certificates for BEP-Deep.

The certificate layer is intentionally separate from witness generation.  It
checks that every positive witness is linked to (1) a locked fixture and public
source claim, (2) an encoded semantic rule, (3) agreement by the independent
decision-table oracle, (4) a paired repair negative control, and (5) a
minimality certificate.  The output is a deterministic audit artifact; it does
not contact external services.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True

import argparse, csv, hashlib, json
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Import the independent oracle, not the operational witness generator.
from decision_table_oracle import decision_issues, load

ISSUE_RULES: Dict[str, List[str]] = {
    "csp_report_only_not_enforced": ["R_CSP_REPORT_ONLY_MONITOR"],
    "csp_effective_script_allowance": ["R_CSP_DEFAULT_SRC_FALLBACK", "R_CSP_SCRIPT_SRC_OVERRIDES_DEFAULT"],
    "nonce_csp_static_render_incompatibility": ["R_CSP_NONCE_UNIQUE_PER_TRANSMISSION", "R_NEXT_NONCE_DYNAMIC_REQUIRED"],
    "csp_conjunctive_policy_composition_blocks_required_script": ["R_CSP_CONJUNCTIVE_COMPOSITION"],
    "csp_multiple_policy_overblocks_trusted_script": ["R_CSP_CONJUNCTIVE_COMPOSITION"],
    "csp_frame_ancestors_report_only_not_enforced": ["R_CSP_REPORT_ONLY_MONITOR", "R_CSP_META_REPORT_ONLY_UNSUPPORTED"],
    "csp_frame_ancestors_meta_delivery_unsupported": ["R_CSP_META_REPORT_ONLY_UNSUPPORTED"],
    "layered_header_override_drops_enforcement": ["R_LAYERED_HEADER_SURFACE", "R_CSP_CONJUNCTIVE_COMPOSITION"],
    "cors_intended_credentialed_share_blocked": ["R_CORS_WILDCARD_CREDENTIALS_NOT_SHAREABLE", "R_CORS_SPECIFIC_ORIGIN_CREDENTIALS_SHAREABLE"],
    "cors_reflected_origin_with_credentials": ["R_EXPRESS_CORS_REFLECT_ORIGIN"],
    "cors_duplicate_acao_not_shareable": ["R_CORS_SPECIFIC_ORIGIN_CREDENTIALS_SHAREABLE"],
    "cors_acac_case_sensitive_not_shareable": ["R_CORS_SPECIFIC_ORIGIN_CREDENTIALS_SHAREABLE"],
    "cors_dynamic_origin_without_vary": ["R_CORS_DYNAMIC_ACAO_NEEDS_VARY", "R_CORS_DYNAMIC_ORIGIN_VARY"],
    "cors_dynamic_origin_missing_vary": ["R_CORS_DYNAMIC_ACAO_NEEDS_VARY", "R_CORS_DYNAMIC_ORIGIN_VARY"],
    "hsts_header_not_honored_over_http": ["R_HSTS_IGNORE_INSECURE_TRANSPORT", "R_DJANGO_HSTS_HTTPS_ONLY"],
    "hsts_policy_cleared_by_zero_max_age": ["R_HSTS_MAX_AGE_ZERO_CLEARS"],
    "hsts_invalid_max_age_ignored": ["R_HSTS_INVALID_HEADER_IGNORED"],
    "hsts_subdomain_scope_not_covered": ["R_HSTS_INCLUDE_SUBDOMAINS_SCOPE"],
    "hsts_missing_include_subdomains": ["R_HSTS_INCLUDE_SUBDOMAINS_SCOPE"],
    "hsts_preload_criteria_not_met": ["R_BASELINE_HSTSPRELOAD_SCOPE", "R_HSTS_INCLUDE_SUBDOMAINS_SCOPE"],
    "coep_require_corp_blocks_cross_origin_resource": ["R_COEP_REQUIRE_CORP_NO_CORS", "R_COEP_CORS_MODE_COMPATIBLE"],
    "corp_same_site_allows_cross_origin_same_site": ["R_COEP_REQUIRE_CORP_NO_CORS"],
    "cross_origin_isolation_incomplete": ["R_COOP_SAME_ORIGIN_FOR_ISOLATION", "R_COOP_UNSAFE_NONE_DEFAULT", "R_PERMISSIONS_POLICY_EMPTY_DISABLES"],
    "permissions_policy_feature_disabled": ["R_PERMISSIONS_POLICY_ALLOWLIST", "R_PERMISSIONS_POLICY_EMPTY_DISABLES"],
    "permissions_policy_feature_overallowed": ["R_PERMISSIONS_POLICY_ALLOWLIST"],
}


def stable_hash(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()[:20]


def read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixtures", default="artifact/data/deep_locked_fixtures.json")
    ap.add_argument("--witnesses", default="artifact/results/deep_locked/full_witnesses.json")
    ap.add_argument("--minimized", default="artifact/results/deep_locked/minimized_witnesses.json")
    ap.add_argument("--paired-controls", default="artifact/data/paired_repair_controls.json")
    ap.add_argument("--rule-ledger", default="artifact/rule_source_ledger.csv")
    ap.add_argument("--claim-ledger", default="artifact/data/corpus_claims.csv")
    ap.add_argument("--minimality-csv", default="artifact/results/deep_locked/minimality_certificates.csv")
    ap.add_argument("--repair-csv", default="artifact/results/deep_locked/repair_obligation_audit.csv")
    ap.add_argument("--out-dir", default="artifact/results/deep_locked")
    args = ap.parse_args()

    fixtures = {fx["id"]: fx for fx in load(args.fixtures)}
    positives = {fid: fx for fid, fx in fixtures.items() if fx.get("expected_issue") != "none"}
    witnesses = {w["fixture_id"]: w for w in load(args.witnesses)}
    minimized = {m["fixture_id"]: m for m in load(args.minimized)}
    paired = {p.get("paired_positive_fixture_id"): p for p in load(args.paired_controls)}
    rules = {r["rule_id"]: r for r in read_csv(Path(args.rule_ledger))}
    claims = {r.get("claim_id") or r.get("id") or r.get("source_claim_id"): r for r in read_csv(Path(args.claim_ledger))}
    min_rows = {r["fixture_id"]: r for r in read_csv(Path(args.minimality_csv))}
    repair_rows = {r["parent_fixture_id"]: r for r in read_csv(Path(args.repair_csv))}

    certs: List[Dict[str, Any]] = []
    audit_rows: List[Dict[str, Any]] = []
    failures: List[Tuple[str, str]] = []

    for fid, fx in sorted(positives.items()):
        issue = str(fx.get("expected_issue"))
        rule_ids = ISSUE_RULES.get(issue, [])
        source_claim_ids = fx.get("source_claim_ids") or ([fx.get("public_source_id")] if fx.get("public_source_id") else [])
        decision = sorted(set(decision_issues(fx)))
        paired_fx = paired.get(fid)
        paired_decision = sorted(set(decision_issues(paired_fx))) if paired_fx else ["__missing_paired_control__"]
        min_row = min_rows.get(fid, {})
        rep_row = repair_rows.get(fid, {})
        witness_present = fid in witnesses
        minimized_present = fid in minimized
        rules_present = all(rid in rules for rid in rule_ids)
        claims_present = all(cid in claims for cid in source_claim_ids)
        decision_supports = decision == [issue]
        paired_clean = paired_fx is not None and paired_decision == [] and paired_fx.get("expected_issue") == "none"
        minimality_ok = min_row.get("one_deletion_minimal") == "True" and min_row.get("exact_header_subset_minimal") == "True"
        repair_ok = rep_row.get("target_removed") == "True" and rep_row.get("all_modeled_issues_removed") == "True" and rep_row.get("intent_preserved") == "True" and rep_row.get("source_preserved") == "True"
        obligations = {
            "locked_fixture_present": fid in fixtures,
            "witness_present": witness_present,
            "minimized_witness_present": minimized_present,
            "rule_ids_present": rules_present,
            "source_claims_present": claims_present,
            "decision_table_supports_issue": decision_supports,
            "paired_repair_control_clean": paired_clean,
            "minimality_certificate_ok": minimality_ok,
            "repair_obligation_ok": repair_ok,
        }
        ok = all(obligations.values())
        if not ok:
            failures.append((fid, ";".join(k for k, v in obligations.items() if not v)))
        cert_payload = {
            "fixture_id": fid,
            "issue": issue,
            "policy_family": fx.get("policy_family"),
            "source_claim_ids": source_claim_ids,
            "rule_ids": rule_ids,
            "fixture_hash": fx.get("fixture_hash", stable_hash(fx)),
            "decision_table_issues": decision,
            "paired_repair_control_id": paired_fx.get("id") if paired_fx else None,
            "paired_repair_control_issues": paired_decision,
            "minimality": {
                "one_deletion_minimal": min_row.get("one_deletion_minimal") == "True",
                "exact_header_subset_minimal": min_row.get("exact_header_subset_minimal") == "True",
            },
            "repair_obligation": {
                "target_removed": rep_row.get("target_removed") == "True",
                "all_modeled_issues_removed": rep_row.get("all_modeled_issues_removed") == "True",
                "intent_preserved": rep_row.get("intent_preserved") == "True",
                "source_preserved": rep_row.get("source_preserved") == "True",
            },
            "obligations": obligations,
        }
        cert_payload["certificate_id"] = "PCW-" + stable_hash(cert_payload)
        certs.append(cert_payload)
        audit_rows.append({
            "fixture_id": fid,
            "issue": issue,
            "certificate_id": cert_payload["certificate_id"],
            "rules": ";".join(rule_ids),
            "source_claims": ";".join(source_claim_ids),
            "decision_table_supports_issue": str(decision_supports),
            "paired_repair_control_clean": str(paired_clean),
            "minimality_certificate_ok": str(minimality_ok),
            "repair_obligation_ok": str(repair_ok),
            "certificate_ok": str(ok),
        })

    out = Path(args.out_dir); out.mkdir(parents=True, exist_ok=True)
    (out / "proof_carrying_witness_certificates.json").write_text(json.dumps(certs, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    with (out / "proof_carrying_witness_audit.csv").open("w", newline="", encoding="utf-8") as fh:
        fieldnames = list(audit_rows[0].keys()) if audit_rows else ["fixture_id"]
        w = csv.DictWriter(fh, fieldnames=fieldnames); w.writeheader(); w.writerows(audit_rows)
    metrics = {
        "positive_witnesses": len(positives),
        "certificates_generated": len(certs),
        "certificates_verified": sum(1 for r in audit_rows if r["certificate_ok"] == "True"),
        "decision_table_backed": sum(1 for r in audit_rows if r["decision_table_supports_issue"] == "True"),
        "paired_repair_backed": sum(1 for r in audit_rows if r["paired_repair_control_clean"] == "True"),
        "minimality_backed": sum(1 for r in audit_rows if r["minimality_certificate_ok"] == "True"),
        "repair_obligation_backed": sum(1 for r in audit_rows if r["repair_obligation_ok"] == "True"),
        "failures": [{"fixture_id": fid, "failed_obligations": why} for fid, why in failures],
        "interpretation": "Proof-carrying witness certificates bind each positive witness to source claims, semantic rules, independent decision-table support, a paired repair negative control, minimality, and repair obligations.",
    }
    (out / "proof_carrying_witness_metrics.json").write_text(json.dumps(metrics, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    print(json.dumps(metrics, sort_keys=True))
    if failures:
        sys.exit(1)

if __name__ == "__main__":
    main()
