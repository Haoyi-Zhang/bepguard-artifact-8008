#!/usr/bin/env python3
"""Run the locked full fixture experiment for BEP semantic witnesses."""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import csv
import json
from dataclasses import asdict
from pathlib import Path
from typing import Dict, List

from bep_semantics import analyze_fixtures, load_fixtures


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the locked full BEP semantic witness experiment.")
    parser.add_argument("--fixtures", default="artifact/data/locked_full_fixtures.json")
    parser.add_argument("--out-dir", default="artifact/results")
    args = parser.parse_args()

    fixtures_path = Path(args.fixtures)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    fixtures = load_fixtures(str(fixtures_path))
    findings = analyze_fixtures(fixtures)

    finding_rows = [asdict(f) for f in findings]
    (out_dir / "full_witnesses.json").write_text(json.dumps(finding_rows, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    actual_by_fixture: Dict[str, List[str]] = {str(f["id"]): [] for f in fixtures}
    for finding in findings:
        actual_by_fixture[finding.fixture_id].append(finding.issue)

    summary_rows = []
    for fixture in fixtures:
        fid = str(fixture["id"])
        expected = str(fixture.get("expected_issue", "none"))
        actual = actual_by_fixture.get(fid, [])
        if expected == "none":
            status = "pass" if not actual else "unexpected_finding"
        else:
            status = "pass" if expected in actual else "missing_expected_finding"
        summary_rows.append({
            "fixture_id": fid,
            "policy_family": fixture.get("policy_family", "mixed"),
            "source_id": fixture.get("public_source_id", "unknown"),
            "expected_issue": expected,
            "actual_issues": ";".join(actual) if actual else "none",
            "status": status,
            "finding_count": len(actual),
        })

    with (out_dir / "full_summary.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(summary_rows[0].keys()))
        writer.writeheader(); writer.writerows(summary_rows)

    positives = [f for f in fixtures if f.get("expected_issue", "none") != "none"]
    negatives = [f for f in fixtures if f.get("expected_issue", "none") == "none"]
    family_counts: Dict[str, Dict[str, int]] = {}
    for row in summary_rows:
        fam = str(row["policy_family"])
        family_counts.setdefault(fam, {"fixtures": 0, "positives": 0, "detected": 0, "negative_controls": 0, "negative_clean": 0})
        family_counts[fam]["fixtures"] += 1
        if row["expected_issue"] == "none":
            family_counts[fam]["negative_controls"] += 1
            if row["status"] == "pass":
                family_counts[fam]["negative_clean"] += 1
        else:
            family_counts[fam]["positives"] += 1
            if row["status"] == "pass":
                family_counts[fam]["detected"] += 1
    metrics = {
        "fixtures": len(fixtures),
        "expected_positive_fixtures": len(positives),
        "expected_findings_detected": sum(1 for f in positives if str(f.get("expected_issue")) in actual_by_fixture[str(f["id"])]),
        "negative_controls": len(negatives),
        "negative_controls_clean": sum(1 for f in negatives if not actual_by_fixture[str(f["id"])]),
        "findings": len(findings),
        "family_counts": family_counts,
        "execution_profile": "deterministic-counts-only",
        "interpretation": "Locked local full-corpus oracle run; not a public-web prevalence claim.",
    }
    (out_dir / "full_metrics.json").write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(metrics, sort_keys=True))


if __name__ == "__main__":
    main()
