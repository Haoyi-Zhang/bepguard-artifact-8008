#!/usr/bin/env python3
"""Analyze the protocol-amended extended workload results."""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Tuple


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def read_csv(path: Path) -> List[Dict[str, str]]:
    return list(csv.DictReader(path.open(encoding="utf-8")))


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: List[Dict[str, object]], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        for row in rows:
            w.writerow({k: row.get(k, "") for k in fieldnames})


def issue_map(summary_rows: List[Dict[str, str]]) -> Dict[str, List[str]]:
    return {r["fixture_id"]: ([] if r.get("actual_issues") in {"", "none"} else r.get("actual_issues", "").split(";")) for r in summary_rows}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixtures", default="artifact/data/extended_fixtures.json")
    ap.add_argument("--result-dir", default="artifact/results/extended_locked")
    args = ap.parse_args()
    fixtures = read_json(Path(args.fixtures))
    result_dir = Path(args.result_dir)
    summary_rows = read_csv(result_dir / "full_summary.csv")
    actual = issue_map(summary_rows)

    by_id = {str(f["id"]): f for f in fixtures}
    issue_counts = Counter()
    family_counts: Dict[str, Counter] = defaultdict(Counter)
    mutation_counts: Dict[str, Counter] = defaultdict(Counter)
    status_counts = Counter()
    for row in summary_rows:
        fid = row["fixture_id"]
        fixture = by_id[fid]
        expected = str(fixture.get("expected_issue", "none"))
        op_class = str(fixture.get("mutation_operator_class", "locked_seed"))
        family = str(fixture.get("policy_family", "mixed"))
        status = row.get("status", "")
        status_counts[status] += 1
        mutation_counts[op_class][status] += 1
        family_counts[family][status] += 1
        if expected != "none":
            issue_counts[expected] += 1

    hp_rows = read_csv(result_dir / "header_presence_baseline.csv")
    hp_by_id = {r["fixture_id"]: r for r in hp_rows}
    disagreement_rows: List[Dict[str, object]] = []
    for f in fixtures:
        fid = str(f["id"])
        expected_positive = f.get("expected_issue", "none") != "none"
        flagged = hp_by_id.get(fid, {}).get("flagged", "False") == "True"
        disagreement_rows.append({
            "baseline": "internal_header_presence_control",
            "fixture_id": fid,
            "policy_family": f.get("policy_family", ""),
            "mutation_operator_class": f.get("mutation_operator_class", "locked_seed"),
            "semantic_positive": expected_positive,
            "baseline_flagged": flagged,
            "disagreement": expected_positive != flagged,
            "expected_issue": f.get("expected_issue", "none"),
            "baseline_labels": hp_by_id.get(fid, {}).get("baseline_labels", ""),
        })
    hsts_rows = read_csv(result_dir / "hsts_preload_criterion.csv")
    hsts_disagreement_rows: List[Dict[str, object]] = []
    for row in hsts_rows:
        if row.get("applicable") != "True":
            continue
        fid = row["fixture_id"]
        f = by_id[fid]
        expected_positive = f.get("expected_issue", "none") != "none"
        flagged = row.get("criterion_pass") != "True"
        hsts_disagreement_rows.append({
            "baseline": "internal_hsts_preload_documented_criterion",
            "fixture_id": fid,
            "policy_family": f.get("policy_family", ""),
            "mutation_operator_class": f.get("mutation_operator_class", "locked_seed"),
            "semantic_positive": expected_positive,
            "baseline_flagged": flagged,
            "disagreement": expected_positive != flagged,
            "expected_issue": f.get("expected_issue", "none"),
            "baseline_labels": f"max_age={row.get('max_age')};includeSubDomains={row.get('include_subdomains')};preload={row.get('preload_token')}",
        })
    all_disagreements = disagreement_rows + hsts_disagreement_rows
    write_csv(result_dir / "extended_baseline_disagreement.csv", all_disagreements, [
        "baseline", "fixture_id", "policy_family", "mutation_operator_class", "semantic_positive", "baseline_flagged", "disagreement", "expected_issue", "baseline_labels",
    ])

    baseline_metrics: Dict[str, Dict[str, int]] = {}
    for baseline in sorted({str(r["baseline"]) for r in all_disagreements}):
        subset = [r for r in all_disagreements if r["baseline"] == baseline]
        baseline_metrics[baseline] = {
            "applicable_pairs": len(subset),
            "disagreements": sum(1 for r in subset if r["disagreement"]),
            "semantic_positive_missed_by_baseline": sum(1 for r in subset if r["semantic_positive"] and not r["baseline_flagged"]),
            "baseline_only_flags_on_negative_controls": sum(1 for r in subset if (not r["semantic_positive"]) and r["baseline_flagged"]),
        }

    # Mutation robustness: every semantic-preserving variant should preserve its parent's expected label.
    mutation_rows: List[Dict[str, object]] = []
    for f in fixtures:
        if f.get("mutation_operator_class") != "semantic_preserving":
            continue
        fid = str(f["id"])
        parent = str(f.get("mutation_parent", ""))
        parent_expected = by_id[parent].get("expected_issue", "none") if parent in by_id else "missing_parent"
        expected = f.get("expected_issue", "none")
        actual_issues = actual.get(fid, [])
        mutation_rows.append({
            "fixture_id": fid,
            "parent_fixture_id": parent,
            "operator": f.get("mutation_operator", ""),
            "parent_expected_issue": parent_expected,
            "expected_issue": expected,
            "actual_issues": ";".join(actual_issues) if actual_issues else "none",
            "preserved_expected_label": expected == parent_expected,
            "oracle_preserved_positive": (expected == "none" and not actual_issues) or (expected in actual_issues),
        })
    write_csv(result_dir / "mutation_preservation_audit.csv", mutation_rows, [
        "fixture_id", "parent_fixture_id", "operator", "parent_expected_issue", "expected_issue", "actual_issues", "preserved_expected_label", "oracle_preserved_positive",
    ])

    mutation_operator_metrics: Dict[str, Dict[str, int]] = {}
    for op in sorted({str(r["operator"]) for r in mutation_rows}):
        subset = [r for r in mutation_rows if r["operator"] == op]
        mutation_operator_metrics[op] = {
            "fixtures": len(subset),
            "label_preserved": sum(1 for r in subset if r["preserved_expected_label"] is True),
            "oracle_preserved": sum(1 for r in subset if r["oracle_preserved_positive"] is True),
        }

    metrics = {
        "fixtures": len(fixtures),
        "expected_positive_fixtures": sum(1 for f in fixtures if f.get("expected_issue") != "none"),
        "negative_controls": sum(1 for f in fixtures if f.get("expected_issue") == "none"),
        "status_counts": dict(status_counts),
        "issue_counts": dict(sorted(issue_counts.items())),
        "family_status_counts": {k: dict(v) for k, v in sorted(family_counts.items())},
        "mutation_operator_class_status_counts": {k: dict(v) for k, v in sorted(mutation_counts.items())},
        "baseline_disagreement": baseline_metrics,
        "semantic_preserving_mutation_metrics": mutation_operator_metrics,
        "interpretation": "Protocol-amended deterministic stress-workload analysis; not live-web prevalence.",
    }
    write_json(result_dir / "extended_analysis_metrics.json", metrics)
    print(json.dumps(metrics, sort_keys=True))


if __name__ == "__main__":
    main()
