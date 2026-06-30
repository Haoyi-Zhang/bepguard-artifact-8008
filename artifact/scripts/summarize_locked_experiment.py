#!/usr/bin/env python3
"""Summarize locked full-experiment outputs without changing the oracle."""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List

from bep_semantics import analyze_fixtures, load_fixtures

COMPONENTS = {
    "csp_delivery_report_only": {"csp_report_only_not_enforced"},
    "csp_fallback_source_list": {"csp_effective_script_allowance"},
    "rendering_context_nonce": {"nonce_csp_static_render_incompatibility"},
    "cors_credentials_shareability": {"cors_intended_credentialed_share_blocked", "cors_reflected_origin_with_credentials", "cors_duplicate_acao_not_shareable", "cors_acac_case_sensitive_not_shareable"},
    "cors_cache_context": {"cors_dynamic_origin_without_vary", "cors_dynamic_origin_missing_vary"},
    "hsts_state_transition": {"hsts_header_not_honored_over_http", "hsts_policy_cleared_by_zero_max_age", "hsts_invalid_max_age_ignored"},
    "hsts_scope_context": {"hsts_missing_include_subdomains", "hsts_subdomain_scope_not_covered", "hsts_preload_criteria_not_met"},
    "coep_corp_cors_embedding": {"coep_require_corp_blocks_cross_origin_resource"},
    "coop_coep_permissions_isolation": {"cross_origin_isolation_incomplete"},
    "permissions_policy_allowlist": {"permissions_policy_feature_disabled", "permissions_policy_feature_overallowed"},
    "corp_scope_semantics": {"corp_same_site_allows_cross_origin_same_site"},
    "csp_framing_delivery": {"csp_frame_ancestors_report_only_not_enforced", "csp_frame_ancestors_meta_delivery_unsupported"},
    "layered_policy_composition": {"csp_multiple_policy_overblocks_trusted_script", "csp_conjunctive_policy_composition_blocks_required_script", "layered_header_override_drops_enforcement"},
}


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_csv(path: Path, rows: List[Dict[str, object]], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader(); writer.writerows(rows)


def confusion(rows: Iterable[Dict[str, object]], flag_field: str = "flagged") -> Dict[str, int]:
    tp=fp=tn=fn=0
    for row in rows:
        flagged = bool(row.get(flag_field))
        positive = bool(row.get("semantic_positive"))
        if flagged and positive: tp += 1
        elif flagged and not positive: fp += 1
        elif (not flagged) and not positive: tn += 1
        else: fn += 1
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", default="artifact/data/locked_full_fixtures.json")
    parser.add_argument("--result-dir", default="artifact/results/locked82")
    args = parser.parse_args()

    result_dir = Path(args.result_dir)
    fixtures = load_fixtures(args.fixtures)
    full_metrics = read_json(result_dir / "full_metrics.json")
    full_witnesses = read_json(result_dir / "full_witnesses.json")
    minimization = read_json(result_dir / "minimization_metrics.json")
    header_presence = read_json(result_dir / "header_presence_baseline.json")
    hsts_preload = read_json(result_dir / "hsts_preload_criterion.json")
    external = read_json(result_dir / "external_baseline_fixture_probe.json")["results"]
    availability = read_json(result_dir / "external_baseline_availability.json")

    issue_counts = Counter(w["issue"] for w in full_witnesses)
    fixture_family_counts = Counter(str(f.get("policy_family", "mixed")) for f in fixtures)
    fixture_variant_counts = Counter(str(f.get("variant", "base")) for f in fixtures)
    expected_counts = Counter(str(f.get("expected_issue", "none")) for f in fixtures)

    # Baseline comparison rows.
    baseline_rows: List[Dict[str, object]] = []
    hp_conf = confusion(header_presence)
    baseline_rows.append({
        "baseline": "conservative_header_presence",
        "applicable_fixtures": len(header_presence),
        "ran_or_flagged": sum(1 for r in header_presence if r.get("flagged")),
        "not_applicable": 0,
        "unavailable": 0,
        "tp": hp_conf["tp"], "fp": hp_conf["fp"], "tn": hp_conf["tn"], "fn": hp_conf["fn"],
        "notes": "Internal negative-control baseline; checks presence/obvious markers, not effective browser semantics.",
    })
    hsts_rows = []
    for r in hsts_preload:
        if not r.get("applicable"):
            continue
        hsts_rows.append({"semantic_positive": r.get("expected_issue") != "none", "flagged": not bool(r.get("criterion_pass"))})
    h_conf = confusion(hsts_rows)
    baseline_rows.append({
        "baseline": "documented_hsts_preload_criterion",
        "applicable_fixtures": len(hsts_rows),
        "ran_or_flagged": sum(1 for r in hsts_rows if r.get("flagged")),
        "not_applicable": len(hsts_preload) - len(hsts_rows),
        "unavailable": 0,
        "tp": h_conf["tp"], "fp": h_conf["fp"], "tn": h_conf["tn"], "fn": h_conf["fn"],
        "notes": "Local documented criterion baseline for HSTS preload-style headers; not Chromium helper execution.",
    })
    by_external = defaultdict(Counter)
    for r in external:
        by_external[str(r.get("baseline"))][str(r.get("status"))] += 1
    for baseline, counts in sorted(by_external.items()):
        baseline_rows.append({
            "baseline": baseline,
            "applicable_fixtures": counts.get("available", 0) + counts.get("unavailable", 0) + counts.get("error", 0),
            "ran_or_flagged": counts.get("available", 0),
            "not_applicable": counts.get("not_applicable", 0),
            "unavailable": counts.get("unavailable", 0),
            "tp": "", "fp": "", "tn": "", "fn": "",
            "notes": "; ".join(f"{k}={v}" for k, v in sorted(counts.items())) + "; external wrapper output not remapped into semantic TP/FP without a declared oracle mapping.",
        })
    write_csv(result_dir / "full_baseline_comparison.csv", baseline_rows, ["baseline", "applicable_fixtures", "ran_or_flagged", "not_applicable", "unavailable", "tp", "fp", "tn", "fn", "notes"])

    # Ablation by component: remove each component's issue labels from the finding set and count losses.
    positives = [f for f in fixtures if f.get("expected_issue", "none") != "none"]
    ablation_rows: List[Dict[str, object]] = []
    for component, issues in COMPONENTS.items():
        component_pos = [f for f in positives if str(f.get("expected_issue")) in issues]
        missed = len(component_pos)
        ablation_rows.append({
            "component_removed": component,
            "mapped_issue_labels": ";".join(sorted(issues)),
            "positive_fixtures_dependent_on_component": len(component_pos),
            "expected_findings_after_ablation": full_metrics["expected_findings_detected"] - missed,
            "detection_loss": missed,
            "interpretation": "Dependency ablation over locked issue-to-component map; no metric or denominator changes.",
        })
    write_csv(result_dir / "full_ablation_metrics.csv", ablation_rows, ["component_removed", "mapped_issue_labels", "positive_fixtures_dependent_on_component", "expected_findings_after_ablation", "detection_loss", "interpretation"])

    # Robustness groups over locked variants and negative controls.
    actual_by_fixture = defaultdict(list)
    for w in full_witnesses:
        actual_by_fixture[str(w["fixture_id"])].append(str(w["issue"]))
    robustness_rows: List[Dict[str, object]] = []
    for variant, total in sorted(fixture_variant_counts.items()):
        var_fixtures = [f for f in fixtures if str(f.get("variant", "base")) == variant]
        positives_var = [f for f in var_fixtures if f.get("expected_issue", "none") != "none"]
        negatives_var = [f for f in var_fixtures if f.get("expected_issue", "none") == "none"]
        detected = sum(1 for f in positives_var if str(f.get("expected_issue")) in actual_by_fixture[str(f["id"])])
        clean = sum(1 for f in negatives_var if not actual_by_fixture[str(f["id"])])
        robustness_rows.append({
            "robustness_group": f"variant:{variant}",
            "fixtures": total,
            "positive_fixtures": len(positives_var),
            "expected_detected": detected,
            "negative_controls": len(negatives_var),
            "negative_controls_clean": clean,
        })
    write_csv(result_dir / "full_robustness_metrics.csv", robustness_rows, ["robustness_group", "fixtures", "positive_fixtures", "expected_detected", "negative_controls", "negative_controls_clean"])

    # Scalability: deterministic replicated workloads.
    scalability_rows: List[Dict[str, object]] = []
    for multiplier in [1, 2, 4, 8, 16, 32]:
        replicated = []
        for m in range(multiplier):
            for f in fixtures:
                g = dict(f)
                g["id"] = f"{f['id']}__rep{m:03d}"
                replicated.append(g)
        findings = analyze_fixtures(replicated)
        scalability_rows.append({
            "multiplier": multiplier,
            "fixtures": len(replicated),
            "findings": len(findings),
            "oracle_evaluations": len(replicated),
            "replication_label": f"x{multiplier}",
        })
    write_csv(result_dir / "full_scalability_metrics.csv", scalability_rows, ["multiplier", "fixtures", "findings", "oracle_evaluations", "replication_label"])

    optional_repair = read_json(result_dir / "repair_synthesis_metrics.json") if (result_dir / "repair_synthesis_metrics.json").exists() else None
    optional_metamorphic = read_json(result_dir / "metamorphic_metrics.json") if (result_dir / "metamorphic_metrics.json").exists() else None

    summary = {
        "locked_denominator": {
            "fixtures": len(fixtures),
            "positive_fixtures": sum(1 for f in fixtures if f.get("expected_issue", "none") != "none"),
            "negative_controls": sum(1 for f in fixtures if f.get("expected_issue", "none") == "none"),
            "families": dict(sorted(fixture_family_counts.items())),
            "expected_issue_counts": dict(sorted(expected_counts.items())),
        },
        "semantic_execution": full_metrics,
        "issue_counts": dict(sorted(issue_counts.items())),
        "minimization": minimization,
        "baseline_confusion": {
            "conservative_header_presence": hp_conf,
            "documented_hsts_preload_criterion": h_conf,
        },
        "external_baseline_status_counts": {k: dict(v) for k, v in sorted(by_external.items())},
        "external_baseline_availability": availability,
        "repair_synthesis": optional_repair,
        "metamorphic_workload": optional_metamorphic,
        "interpretation": "Expanded locked experiment over deterministic source-grounded fixtures; not a live-web prevalence study.",
    }
    (result_dir / "full_experiment_metrics.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"fixtures": len(fixtures), "semantic_passed": full_metrics["expected_findings_detected"] == full_metrics["expected_positive_fixtures"] and full_metrics["negative_controls_clean"] == full_metrics["negative_controls"], "result_dir": str(result_dir)}, sort_keys=True))


if __name__ == "__main__":
    main()
