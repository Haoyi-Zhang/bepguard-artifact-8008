#!/usr/bin/env python3
"""Semantic mutation adequacy audit for BEP-Deep.

Each mutant weakens or distorts one encoded semantic hinge in the independent
decision-table oracle.  BEP-Deep is adequate for the hinge when the mutant is
"killed": at least one locked fixture or paired control no longer matches the
locked expected result.  This does not prove complete browser conformance; it
checks that the workload is not only a positive-path oracle smoke test.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True

import argparse, csv, json
from pathlib import Path
from typing import Any, Dict, List

from decision_table_oracle import decision_issues, load

MUTANTS = [
    ("report_only_enforces", "Treat report-only CSP as enforcing."),
    ("csp_default_src_not_fallback", "Ignore default-src as script fallback."),
    ("csp_policies_compose_disjunctively", "Compose multiple enforced CSPs by union instead of intersection."),
    ("frame_report_only_enforces", "Treat report-only frame-ancestors as enforcing."),
    ("frame_meta_enforces", "Treat meta-delivered frame-ancestors as enforcing."),
    ("nonce_static_is_fresh", "Assume static rendering can provide fresh per-request nonces."),
    ("cors_duplicate_acao_singletons", "Accept duplicate ACAO values as a singleton authorization."),
    ("cors_acac_case_insensitive", "Treat Access-Control-Allow-Credentials as case-insensitive."),
    ("cors_wildcard_credentials_allowed", "Allow wildcard ACAO on credentialed requests."),
    ("reflected_origin_safe", "Treat origin reflection with credentials as safe."),
    ("cors_vary_not_required", "Ignore Vary: Origin obligations for dynamic CORS."),
    ("hsts_http_honored", "Honor HSTS delivered over insecure transport."),
    ("hsts_invalid_max_age_valid", "Accept invalid HSTS max-age values."),
    ("hsts_zero_preserves_state", "Do not clear HSTS state on max-age=0."),
    ("hsts_subdomains_implicit", "Treat host HSTS as covering subdomains by default."),
    ("hsts_preload_weak_criterion", "Treat weak preload-shaped HSTS headers as preload-ready."),
    ("coep_ignores_resource_optin", "Ignore cross-origin resource opt-in under COEP require-corp."),
    ("corp_same_site_is_same_origin", "Treat CORP same-site as same-origin for stricter embedding intent."),
    ("isolation_coep_only", "Treat COEP alone as cross-origin isolation."),
    ("permissions_empty_allows", "Treat empty Permissions-Policy allowlist as allowing the feature."),
    ("permissions_wildcard_safe", "Treat wildcard Permissions-Policy allowlist as not over-allowing."),
    ("layer_override_not_modeled", "Ignore ordered layer drops of enforced CSP."),
    ("over_csp_header_presence", "Over-report CSP conflicts whenever any CSP header is present."),
    ("over_cors_acao_presence", "Over-report CORS drift whenever ACAO is present."),
    ("over_hsts_header_presence", "Over-report HSTS drift whenever an STS header is present."),
    ("over_coep_header_presence", "Over-report embedding drift whenever COEP is present."),
    ("over_permissions_header_presence", "Over-report Permissions-Policy drift whenever the header is present."),
    ("over_layer_presence", "Over-report layer-composition drift whenever layers exist."),
]


def expected_issues(fx: Dict[str, Any]) -> List[str]:
    e = str(fx.get("expected_issue", "none"))
    return [] if e == "none" else [e]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixtures", default="artifact/data/deep_locked_fixtures.json")
    ap.add_argument("--out-dir", default="artifact/results/deep_locked")
    args = ap.parse_args()
    fixtures = load(args.fixtures)
    out = Path(args.out_dir); out.mkdir(parents=True, exist_ok=True)
    rows = []
    for mutant, desc in MUTANTS:
        killed_by_positive = 0; killed_by_negative = 0; killed_by_paired_repair = 0; failures = []
        for fx in fixtures:
            expected = expected_issues(fx)
            actual = sorted(set(decision_issues(fx, mutant=mutant)))
            # Aggressive over-reporting mutants exercise the negative-control side
            # of the workload.  They simulate checklist-style oracles that treat
            # presence of a surface as evidence of a conflict.
            headers = fx.get("headers", []) or []
            layers = fx.get("layers", []) or []
            def has(name: str) -> bool:
                n = name.lower()
                return any(str(h.get("name", "")).lower() == n for h in headers if isinstance(h, dict))
            if mutant == "over_csp_header_presence" and (has("Content-Security-Policy") or has("Content-Security-Policy-Report-Only")):
                actual = sorted(set(actual + ["over_reported_csp_conflict"]))
            elif mutant == "over_cors_acao_presence" and has("Access-Control-Allow-Origin"):
                actual = sorted(set(actual + ["over_reported_cors_conflict"]))
            elif mutant == "over_hsts_header_presence" and has("Strict-Transport-Security"):
                actual = sorted(set(actual + ["over_reported_hsts_conflict"]))
            elif mutant == "over_coep_header_presence" and has("Cross-Origin-Embedder-Policy"):
                actual = sorted(set(actual + ["over_reported_embedding_conflict"]))
            elif mutant == "over_permissions_header_presence" and has("Permissions-Policy"):
                actual = sorted(set(actual + ["over_reported_permissions_conflict"]))
            elif mutant == "over_layer_presence" and layers:
                actual = sorted(set(actual + ["over_reported_layer_conflict"]))
            if actual != expected:
                role = str(fx.get("control_role", fx.get("fixture_role", "")))
                if expected: killed_by_positive += 1
                else: killed_by_negative += 1
                if "paired" in role or str(fx.get("id", "")).endswith("__repair_control"):
                    killed_by_paired_repair += 1
                if len(failures) < 5:
                    failures.append(str(fx.get("id")))
        killed = killed_by_positive + killed_by_negative > 0
        rows.append({
            "mutant": mutant,
            "description": desc,
            "killed": str(killed).lower(),
            "killed_by_positive_fixtures": killed_by_positive,
            "killed_by_negative_controls": killed_by_negative,
            "killed_by_paired_repair_controls": killed_by_paired_repair,
            "example_killing_fixtures": ";".join(failures) or "none",
        })
    with (out / "semantic_mutation_adequacy.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    metrics = {
        "semantic_mutants": len(rows),
        "killed_mutants": sum(1 for r in rows if r["killed"] == "true"),
        "surviving_mutants": [r["mutant"] for r in rows if r["killed"] != "true"],
        "mutants_killed_by_negative_controls": sum(1 for r in rows if int(r["killed_by_negative_controls"]) > 0),
        "mutants_killed_by_paired_repair_controls": sum(1 for r in rows if int(r["killed_by_paired_repair_controls"]) > 0),
        "interpretation": "Semantic mutation adequacy for encoded BEP-IR hinges; not a completeness proof for the web platform.",
    }
    (out / "semantic_mutation_adequacy.json").write_text(json.dumps(metrics, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    print(json.dumps(metrics, sort_keys=True))
    if metrics["surviving_mutants"]:
        sys.exit(1)

if __name__ == "__main__":
    main()
