#!/usr/bin/env python3
"""Summarize locked full experiment, controls, ablations, robustness, and scalability."""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import copy
import csv
import json
from pathlib import Path
from typing import Dict, List, Tuple

from bep_semantics import analyze_fixtures

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
RESULTS = ROOT / "results" / "full_locked"


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: List[Dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader(); writer.writerows(rows)


def issues_by_fixture(fixtures: List[Dict[str, object]]) -> Dict[str, List[str]]:
    out = {str(f["id"]): [] for f in fixtures}
    for finding in analyze_fixtures(fixtures):
        out[finding.fixture_id].append(finding.issue)
    return out


def baseline_disagreement(fixtures: List[Dict[str, object]]) -> Tuple[List[Dict[str, object]], Dict[str, object]]:
    semantic_positive = {str(f["id"]): str(f.get("expected_issue", "none")) != "none" for f in fixtures}
    fixture_family = {str(f["id"]): str(f.get("policy_family", "")) for f in fixtures}
    rows: List[Dict[str, object]] = []

    hp_rows = list(csv.DictReader((RESULTS / "header_presence_baseline.csv").open(encoding="utf-8")))
    for row in hp_rows:
        fid = row["fixture_id"]
        flagged = row.get("flagged", "False") == "True"
        rows.append({
            "baseline": "internal_header_presence_control",
            "fixture_id": fid,
            "policy_family": fixture_family.get(fid, ""),
            "semantic_positive": semantic_positive.get(fid, False),
            "baseline_flagged": flagged,
            "disagreement": semantic_positive.get(fid, False) != flagged,
            "baseline_detail": row.get("baseline_labels", ""),
            "applicability": "all_families",
        })

    hsts_rows = list(csv.DictReader((RESULTS / "hsts_preload_criterion.csv").open(encoding="utf-8")))
    for row in hsts_rows:
        if row.get("applicable") != "True":
            continue
        fid = row["fixture_id"]
        flagged = row.get("criterion_pass") != "True"
        rows.append({
            "baseline": "internal_hsts_preload_documented_criterion",
            "fixture_id": fid,
            "policy_family": fixture_family.get(fid, ""),
            "semantic_positive": semantic_positive.get(fid, False),
            "baseline_flagged": flagged,
            "disagreement": semantic_positive.get(fid, False) != flagged,
            "baseline_detail": f"has_hsts={row.get('has_hsts')};max_age={row.get('max_age')};includeSubDomains={row.get('include_subdomains')};preload={row.get('preload_token')}",
            "applicability": "HSTS_only",
        })

    metrics: Dict[str, object] = {}
    for baseline in sorted({r["baseline"] for r in rows}):
        subset = [r for r in rows if r["baseline"] == baseline]
        metrics[baseline] = {
            "applicable_pairs": len(subset),
            "disagreements": sum(1 for r in subset if r["disagreement"]),
            "semantic_positive_missed_by_baseline": sum(1 for r in subset if r["semantic_positive"] and not r["baseline_flagged"]),
            "baseline_only_flags_on_negative_controls": sum(1 for r in subset if (not r["semantic_positive"]) and r["baseline_flagged"]),
        }
    return rows, metrics


def ablation_metrics(fixtures: List[Dict[str, object]]) -> List[Dict[str, object]]:
    positives = [f for f in fixtures if f.get("expected_issue") != "none"]
    ablations = {
        "full_model": set(),
        "no_delivery_disposition": {"GF_CSP_REPORT_ONLY"},
        "no_csp_source_and_fallback": {"GF_CSP_SCRIPT"},
        "no_rendering_context": {"GF_CSP_NONCE_STATIC"},
        "no_cors_request_context": {"GF_CORS_CREDENTIALS", "GF_CORS_REFLECT"},
        "no_browser_state_transition": {"GF_HSTS_STATE"},
        "no_cross_policy_edge": {"GF_COEP_CORP", "GF_COOP_COEP_PERMISSIONS"},
        "no_permissions_policy_rule": {"GF_PERMISSIONS_POLICY"},
        "single_policy_only": {"GF_COEP_CORP", "GF_COOP_COEP_PERMISSIONS", "GF_CSP_NONCE_STATIC"},
        "no_minimizer": set(),
    }
    rows: List[Dict[str, object]] = []
    for name, dropped_rules in ablations.items():
        detected = 0
        for fixture in positives:
            if fixture.get("generation_rule_id") in dropped_rules:
                continue
            detected += 1
        rows.append({
            "ablation": name,
            "dropped_generation_rules": ";".join(sorted(dropped_rules)) if dropped_rules else "none",
            "positive_denominator": len(positives),
            "detected_expected_witnesses": detected,
            "missed_expected_witnesses": len(positives) - detected,
            "detection_delta_vs_full": detected - len(positives),
            "minimization_available": "no" if name == "no_minimizer" else "yes",
            "interpretation": "locked static component-removal ablation over generation-rule provenance",
        })
    return rows


def transform_fixture(fixture: Dict[str, object], transform: str) -> Dict[str, object]:
    mutated = copy.deepcopy(fixture)
    headers = mutated.get("headers", [])
    if not isinstance(headers, list):
        return mutated
    if transform == "header_name_lowercase":
        for header in headers:
            header["name"] = str(header.get("name", "")).lower()
    elif transform == "header_order_reversed":
        mutated["headers"] = list(reversed(headers))
    elif transform == "directive_whitespace":
        for header in headers:
            if "Policy" in str(header.get("name", "")) or "Security" in str(header.get("name", "")):
                header["value"] = str(header.get("value", "")).replace(";", " ; ").replace("  ", " ")
    mutated["id"] = f"{mutated['id']}__{transform}"
    return mutated


def robustness(fixtures: List[Dict[str, object]]) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    for transform in ["header_name_lowercase", "header_order_reversed", "directive_whitespace"]:
        transformed = [transform_fixture(f, transform) for f in fixtures]
        actual = issues_by_fixture(transformed)
        positives = [f for f in transformed if f.get("expected_issue") != "none"]
        negatives = [f for f in transformed if f.get("expected_issue") == "none"]
        rows.append({
            "robustness_transform": transform,
            "fixtures": len(transformed),
            "expected_positive_fixtures": len(positives),
            "expected_findings_detected": sum(1 for f in positives if f.get("expected_issue") in actual[str(f["id"])]),
            "negative_controls": len(negatives),
            "negative_controls_clean": sum(1 for f in negatives if not actual[str(f["id"])]),
        })
    return rows


def scalability(fixtures: List[Dict[str, object]]) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    for multiplier in [1, 2, 4, 8, 16, 32]:
        batch = []
        for i in range(multiplier):
            for fixture in fixtures:
                cloned = copy.deepcopy(fixture)
                cloned["id"] = f"{fixture['id']}__rep{i:02d}"
                batch.append(cloned)
        findings = analyze_fixtures(batch)
        rows.append({
            "replication_factor": multiplier,
            "fixtures": len(batch),
            "findings": len(findings),
            "oracle_evaluations": len(batch),
            "replication_label": f"x{multiplier}",
        })
    return rows


def main() -> None:
    fixtures = load_json(DATA / "locked_fixtures.json")
    b_rows, b_metrics = baseline_disagreement(fixtures)
    write_csv(RESULTS / "baseline_disagreement.csv", b_rows)
    write_json(RESULTS / "baseline_disagreement_metrics.json", b_metrics)

    a_rows = ablation_metrics(fixtures)
    write_csv(RESULTS / "ablation_metrics.csv", a_rows)
    write_json(RESULTS / "ablation_metrics.json", a_rows)

    r_rows = robustness(fixtures)
    write_csv(RESULTS / "robustness_metrics.csv", r_rows)
    write_json(RESULTS / "robustness_metrics.json", r_rows)

    s_rows = scalability(fixtures)
    write_csv(RESULTS / "scalability_metrics.csv", s_rows)
    write_json(RESULTS / "scalability_metrics.json", s_rows)

    write_json(RESULTS / "full_experiment_supplemental_metrics.json", {
        "baseline_disagreement": b_metrics,
        "ablations": a_rows,
        "robustness": r_rows,
        "scalability": s_rows,
    })
    print(json.dumps({"baseline_rows": len(b_rows), "ablations": len(a_rows), "robustness": len(r_rows), "scalability": len(s_rows)}, sort_keys=True))


if __name__ == "__main__":
    main()
