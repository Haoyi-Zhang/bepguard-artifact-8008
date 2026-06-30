#!/usr/bin/env python3
"""Audit release-level validation reports and lineage scope markers.

This gate catches inconsistencies that can survive when a project evolves from
seed fixtures to a deeper release workload: stale claim-validation reports,
auxiliary source ledgers that no longer describe the admitted-source universe,
and lineage result directories that are present without explicit scope markers.
It does not change labels, metrics, or denominator counts.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True

import argparse, csv, json
from pathlib import Path
from typing import Dict, List, Set

EXPECT = {"claims": 45, "fixtures": 972, "rules": 35}


def read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def ids(rows: List[Dict[str, str]], key: str) -> Set[str]:
    return {r.get(key, "") for r in rows if r.get(key, "")}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--out", default="artifact/results/validation_report_consistency_audit.json")
    args = ap.parse_args()
    root = Path(args.root).resolve()
    problems: List[str] = []

    claims = read_csv(root / "artifact/data/corpus_claims.csv")
    data_claim_report = read_csv(root / "artifact/data/coding_validation_claims.csv")
    release_report = read_csv(root / "artifact/results/coding_validation_report.csv")
    summary = read_json(root / "artifact/results/coding_validation_summary.json")

    claim_ids = ids(claims, "claim_id")
    data_report_ids = ids(data_claim_report, "claim_id")
    release_report_ids = ids(release_report, "claim_id")

    if len(claims) != EXPECT["claims"]:
        problems.append(f"corpus_claims.csv has {len(claims)} rows, expected {EXPECT['claims']}")
    if len(data_claim_report) != EXPECT["claims"] or data_report_ids != claim_ids:
        problems.append("data/coding_validation_claims.csv is not synchronized with corpus_claims.csv")
    if len(release_report) != EXPECT["claims"] or release_report_ids != claim_ids:
        problems.append("results/coding_validation_report.csv is not synchronized with corpus_claims.csv")
    bad_release_rows = [r.get("claim_id", "") for r in release_report if r.get("validation_status") != "validated"]
    if bad_release_rows:
        problems.append(f"release coding validation report has non-validated rows: {bad_release_rows[:10]}")
    if summary.get("claim_rows") != EXPECT["claims"] or summary.get("fixture_rows") != EXPECT["fixtures"] or summary.get("rule_rows") != EXPECT["rules"]:
        problems.append("coding_validation_summary.json does not match the release 45/972/35 counts")

    root_sources = read_csv(root / "artifact/source_snapshot_manifest.csv")
    data_sources = read_csv(root / "artifact/data/source_snapshot_manifest.csv")
    source_ids = ids(root_sources, "source_id")
    if source_ids != ids(data_sources, "source_id"):
        problems.append("root and data source_snapshot_manifest.csv files disagree")

    auxiliary_ledgers = {
        "artifact/data/source_acquisition_log.csv": "source_id",
        "artifact/data/source_snapshot_ledger.csv": "source_id",
    }
    auxiliary_counts = {}
    for rel, key in auxiliary_ledgers.items():
        rows = read_csv(root / rel)
        auxiliary_counts[rel] = len(rows)
        if ids(rows, key) != source_ids:
            problems.append(f"{rel} does not match the admitted-source snapshot universe")

    lineage_claim_audit = root / "artifact/results/full_locked/claim_adjudication_audit.csv"
    if lineage_claim_audit.exists():
        rows = read_csv(lineage_claim_audit)
        if len(rows) != EXPECT["claims"] or ids(rows, "claim_id") != claim_ids:
            problems.append("seed-lineage claim_adjudication_audit.csv is not synchronized with the 45 admitted claims")
    lineage_coding_report = root / "artifact/results/full_locked/coding_validation_report.csv"
    if lineage_coding_report.exists():
        rows = read_csv(lineage_coding_report)
        claim_rows = [r for r in rows if r.get("check") == "claim_rows"]
        unique_rows = [r for r in rows if r.get("check") == "unique_claim_ids"]
        if not claim_rows or claim_rows[0].get("observed") != "45" or claim_rows[0].get("expected") != "45":
            problems.append("seed-lineage coding_validation_report.csv has stale claim_rows cardinality")
        if not unique_rows or unique_rows[0].get("observed") != "45" or unique_rows[0].get("expected") != "45":
            problems.append("seed-lineage coding_validation_report.csv has stale unique_claim_ids cardinality")

    lineage_expect = {
        "artifact/results/full_locked/lineage_scope.json": {"scope": "seed-lineage", "main_workload": "BEP-Deep", "lineage_not_main_denominator": True, "fixtures": 116},
        "artifact/results/extended_locked/lineage_scope.json": {"scope": "bep-stress-lineage", "main_workload": "BEP-Deep", "lineage_not_main_denominator": True, "fixtures": 554},
    }
    lineage = {}
    for rel, expected in lineage_expect.items():
        p = root / rel
        if not p.exists():
            problems.append(f"missing explicit lineage scope marker: {rel}")
            continue
        obj = read_json(p)
        lineage[rel] = obj
        for key, value in expected.items():
            if obj.get(key) != value:
                problems.append(f"{rel} has {key}={obj.get(key)!r}, expected {value!r}")

    result = {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "claim_rows": len(claims),
        "release_coding_validation_rows": len(release_report),
        "data_coding_validation_rows": len(data_claim_report),
        "source_snapshot_rows": len(root_sources),
        "auxiliary_source_ledger_rows": auxiliary_counts,
        "lineage_scope_markers": lineage,
        "interpretation": "Release validation-report consistency audit: coding reports, auxiliary source ledgers, and lineage result directories must be synchronized with the release admitted-source and BEP-Deep validation state.",
    }
    write_json(root / args.out, result)
    print(json.dumps({"status": result["status"], "problem_count": len(problems), "release_coding_validation_rows": len(release_report), "source_snapshot_rows": len(root_sources)}, sort_keys=True))
    if problems:
        raise SystemExit(2)

if __name__ == "__main__":
    main()
