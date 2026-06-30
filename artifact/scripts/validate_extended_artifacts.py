#!/usr/bin/env python3
"""Validate protocol-amended extended workload artifacts."""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import csv
import json
from collections import Counter
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "artifact" / "data"
RESULTS = ROOT / "artifact" / "results" / "extended_locked"


def read_csv(path: Path) -> List[Dict[str, str]]:
    return list(csv.DictReader(path.open(encoding="utf-8")))


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_csv(path: Path, rows: List[Dict[str, object]], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader(); w.writerows(rows)


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    fixtures = read_json(DATA / "extended_fixtures.json")
    manifest = read_csv(DATA / "extended_fixture_manifest.csv")
    summary = read_csv(RESULTS / "full_summary.csv")
    metrics = read_json(RESULTS / "full_metrics.json")
    analysis = read_json(RESULTS / "extended_analysis_metrics.json")
    repair = read_json(RESULTS / "repair_synthesis_metrics.json")
    graph = read_json(RESULTS / "effective_exposure_graph_metrics.json")
    mutation = read_csv(RESULTS / "mutation_preservation_audit.csv")
    workload_summary = read_json(RESULTS / "extended_workload_summary.json")

    checks = []
    def add(name: str, passed: bool, observed, expected) -> None:
        checks.append({"check": name, "status": "pass" if passed else "fail", "observed": observed, "expected": expected})

    ids = [str(f["id"]) for f in fixtures]
    positives = [f for f in fixtures if f.get("expected_issue") != "none"]
    negatives = [f for f in fixtures if f.get("expected_issue") == "none"]
    add("extended_fixture_count", len(fixtures) == workload_summary.get("extended_fixtures"), len(fixtures), workload_summary.get("extended_fixtures"))
    add("unique_fixture_ids", len(set(ids)) == len(ids), len(set(ids)), len(ids))
    add("manifest_rows", len(manifest) == len(fixtures), len(manifest), len(fixtures))
    add("summary_rows", len(summary) == len(fixtures), len(summary), len(fixtures))
    add("positive_count", len(positives) == workload_summary.get("expected_positive_fixtures"), len(positives), workload_summary.get("expected_positive_fixtures"))
    add("negative_count", len(negatives) == workload_summary.get("negative_controls"), len(negatives), workload_summary.get("negative_controls"))
    add("semantic_positive_detection", metrics.get("expected_findings_detected") == len(positives), metrics.get("expected_findings_detected"), len(positives))
    add("negative_controls_clean", metrics.get("negative_controls_clean") == len(negatives), metrics.get("negative_controls_clean"), len(negatives))
    add("all_rows_pass", Counter(r.get("status") for r in summary) == {"pass": len(fixtures)}, dict(Counter(r.get("status") for r in summary)), {"pass": len(fixtures)})
    add("semantic_preserving_mutations", all(r.get("oracle_preserved_positive") == "True" for r in mutation), sum(1 for r in mutation if r.get("oracle_preserved_positive") == "True"), len(mutation))
    add("repair_target_removed", repair.get("target_issue_removed") == len(positives), repair.get("target_issue_removed"), len(positives))
    add("repair_all_issues_removed", repair.get("all_issues_removed") == len(positives), repair.get("all_issues_removed"), len(positives))
    add("exposure_graph_has_issue_nodes", graph.get("issue_node_count", 0) >= 21, graph.get("issue_node_count"), ">=21")
    add("exposure_graph_has_claim_paths", graph.get("claim_to_issue_paths", 0) > 0, graph.get("claim_to_issue_paths"), ">0")
    add("baseline_disagreement_recorded", "internal_header_presence_control" in analysis.get("baseline_disagreement", {}), sorted(analysis.get("baseline_disagreement", {}).keys()), "internal_header_presence_control present")

    status = "pass" if all(c["status"] == "pass" for c in checks) else "fail"
    write_csv(RESULTS / "extended_validation_report.csv", checks, ["check", "status", "observed", "expected"])
    write_json(RESULTS / "extended_validation_summary.json", {"status": status, "checks": len(checks), "failures": [c for c in checks if c["status"] != "pass"]})
    print(json.dumps({"status": status, "checks": len(checks)}, sort_keys=True))
    if status != "pass":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
