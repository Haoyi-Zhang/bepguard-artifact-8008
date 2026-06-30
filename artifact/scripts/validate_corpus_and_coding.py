#!/usr/bin/env python3
"""Validate the locked source-grounded corpus and coding traceability.

This audit is deterministic: it checks internal consistency of the locked
claim table, rule-source ledger, fixture manifest, and full fixture workload.
It does not infer prevalence and does not substitute for a human agreement
study. The output is meant to support a traceability/validation claim for the
source-grounded fixture experiment.
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, MutableMapping


def stable_hash(obj: object) -> str:
    payload = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def write_csv(path: Path, rows: List[Dict[str, object]], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def check_unique(rows: Iterable[Mapping[str, str]], key: str) -> Dict[str, int]:
    counts = Counter(row.get(key, "") for row in rows)
    return {k: v for k, v in counts.items() if v != 1}


def split_semicolon(value: str) -> List[str]:
    return [x.strip() for x in value.replace(",", ";").split(";") if x.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate locked corpus/coding traceability.")
    parser.add_argument("--root", default=".", help="project root containing artifact/")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    art = root / "artifact"
    data = art / "data"
    results = art / "results"

    claims = read_csv(data / "corpus_claims.csv")
    rules = read_csv(data / "rule_to_source_ledger.csv")
    # release paper delivery validation uses the main BEP-Deep denominator when it is
    # present.  The smaller seed fixture set is retained only as lineage.
    fixture_manifest_path = data / "deep_fixture_manifest.csv"
    if not fixture_manifest_path.exists():
        fixture_manifest_path = data / "fixture_manifest.csv"
    fixtures_manifest = read_csv(fixture_manifest_path)
    source_manifest = read_csv(data / "source_snapshot_manifest.csv")
    fixture_path = data / "deep_locked_fixtures.json"
    if not fixture_path.exists():
        fixture_path = data / "locked_full_fixtures.json"
    fixtures = json.loads(fixture_path.read_text(encoding="utf-8"))

    claim_ids = {r["claim_id"] for r in claims}
    rule_ids = {r["rule_id"] for r in rules}
    source_ids = {r.get("source_id", r.get("source_ids", "")) for r in source_manifest}
    fixture_by_id = {f["id"]: f for f in fixtures}
    manifest_by_id = {r["fixture_id"]: r for r in fixtures_manifest}

    claim_fixture_count: MutableMapping[str, int] = defaultdict(int)
    fixture_validation_rows: List[Dict[str, object]] = []
    for f in fixtures:
        fid = f["id"]
        problems: List[str] = []
        expected_hash = stable_hash({k: f[k] for k in f if k != "fixture_hash"})[:16]
        if f.get("fixture_hash") != expected_hash:
            problems.append("fixture_hash_mismatch")
        if fid not in manifest_by_id:
            problems.append("missing_manifest_row")
        else:
            m = manifest_by_id[fid]
            if m.get("fixture_hash") != f.get("fixture_hash"):
                problems.append("manifest_hash_mismatch")
            if m.get("expected_issue") != f.get("expected_issue"):
                problems.append("manifest_expected_issue_mismatch")
            if m.get("fixture_role") != f.get("fixture_role"):
                problems.append("manifest_role_mismatch")
        for cid in f.get("source_claim_ids", []):
            claim_fixture_count[cid] += 1
            if cid not in claim_ids:
                problems.append(f"unknown_claim:{cid}")
        role = f.get("fixture_role")
        expected_issue = f.get("expected_issue")
        if role == "positive" and expected_issue == "none":
            problems.append("positive_fixture_expected_none")
        if role == "negative_control" and expected_issue != "none":
            problems.append("negative_control_has_expected_issue")
        # Some paired-repair negative controls intentionally remove the only
        # policy header (e.g., disabling Permissions-Policy) to validate that
        # the oracle stops emitting the target issue.  Positives and ordinary
        # controls must still expose a policy surface.
        if not f.get("headers") and not f.get("layers") and role != "paired_repair_negative_control":
            problems.append("fixture_without_headers_or_layers")
        fixture_validation_rows.append({
            "fixture_id": fid,
            "policy_family": f.get("policy_family", ""),
            "fixture_role": role,
            "expected_issue": expected_issue,
            "source_claim_ids": ";".join(f.get("source_claim_ids", [])),
            "hash_valid": "yes" if f.get("fixture_hash") == expected_hash else "no",
            "manifest_consistent": "yes" if not [p for p in problems if p.startswith("manifest_") or p == "missing_manifest_row"] else "no",
            "validation_status": "validated" if not problems else "needs_action",
            "problems": ";".join(problems),
        })

    claim_validation_rows: List[Dict[str, object]] = []
    for row in claims:
        problems: List[str] = []
        expected_hash = stable_hash({k: row[k] for k in row if k != "claim_hash"})[:16]
        if row.get("claim_hash") != expected_hash:
            problems.append("claim_hash_mismatch")
        if not row.get("source_url", "").startswith("http"):
            problems.append("missing_or_non_http_source_url")
        if not row.get("source_span"):
            problems.append("missing_source_span")
        if not row.get("explicit_claim_paraphrase"):
            problems.append("missing_explicit_claim_paraphrase")
        if not row.get("intent_class"):
            problems.append("missing_intent_class")
        if row.get("included_in_denominator") != "yes":
            problems.append("not_in_denominator")
        coverage_required_roles = {"positive", "negative_control", "positive_and_negative"}
        if row.get("fixture_role") in coverage_required_roles and claim_fixture_count[row["claim_id"]] == 0:
            problems.append("no_fixture_coverage")
        missing_rules = [rid for rid in split_semicolon(row.get("semantic_rule_ids", "")) if rid not in rule_ids]
        if missing_rules:
            problems.append("unknown_rule:" + ",".join(missing_rules))
        # Source manifests use source_id. If a project adds a new source only in a claim,
        # this catches it before interpretation.
        if row.get("source_id") not in source_ids:
            problems.append("source_not_in_snapshot_manifest")
        claim_validation_rows.append({
            "claim_id": row["claim_id"],
            "source_id": row.get("source_id", ""),
            "policy_family": row.get("policy_family", ""),
            "claim_type": row.get("claim_type", ""),
            "fixture_role": row.get("fixture_role", ""),
            "intent_class": row.get("intent_class", ""),
            "semantic_rule_ids": row.get("semantic_rule_ids", ""),
            "fixture_coverage_count": claim_fixture_count[row["claim_id"]],
            "hash_valid": "yes" if row.get("claim_hash") == expected_hash else "no",
            "validation_status": "validated" if not problems else "needs_action",
            "problems": ";".join(problems),
        })

    # Rule validation: every encoded rule should have a source span and at least one supporting source.
    rule_rows: List[Dict[str, object]] = []
    for r in rules:
        problems: List[str] = []
        if not r.get("source_span"):
            problems.append("missing_source_span")
        if not r.get("semantic_obligation"):
            problems.append("missing_semantic_obligation")
        if not r.get("proof_obligation"):
            problems.append("missing_proof_obligation")
        for sid in split_semicolon(r.get("source_ids", "")):
            if sid not in source_ids:
                problems.append(f"source_not_in_snapshot_manifest:{sid}")
        rule_rows.append({
            "rule_id": r.get("rule_id", ""),
            "policy_family": r.get("policy_family", ""),
            "encoded_status": r.get("encoded_status", ""),
            "proof_obligation": r.get("proof_obligation", ""),
            "validation_status": "validated" if not problems else "needs_action",
            "problems": ";".join(problems),
        })

    validation_fields = ["claim_id", "source_id", "policy_family", "claim_type", "fixture_role", "intent_class", "semantic_rule_ids", "fixture_coverage_count", "hash_valid", "validation_status", "problems"]
    write_csv(data / "coding_validation_claims.csv", claim_validation_rows, validation_fields)
    # The public validation report is a release-level artifact and must be
    # regenerated from the same release denominator as the machine-readable
    # claim validation table.  Keeping this report synchronized prevents a
    # stale seed-era report from contradicting the 45-claim BEP-Deep audit.
    write_csv(results / "coding_validation_report.csv", claim_validation_rows, validation_fields)
    write_csv(data / "fixture_validation_audit.csv", fixture_validation_rows,
              ["fixture_id", "policy_family", "fixture_role", "expected_issue", "source_claim_ids", "hash_valid", "manifest_consistent", "validation_status", "problems"])
    write_csv(data / "rule_validation_audit.csv", rule_rows,
              ["rule_id", "policy_family", "encoded_status", "proof_obligation", "validation_status", "problems"])

    summary = {
        "date": "2026-06-20",
        "interpretation": "Deterministic traceability audit for source-grounded fixture construction; no human inter-rater agreement or prevalence claim is implied.",
        "claim_rows": len(claims),
        "fixture_rows": len(fixtures),
        "fixture_manifest_rows": len(fixtures_manifest),
        "rule_rows": len(rules),
        "source_snapshot_rows": len(source_manifest),
        "unique_id_violations": {
            "claims": check_unique(claims, "claim_id"),
            "fixtures": check_unique(({"fixture_id": f["id"]} for f in fixtures), "fixture_id"),
            "rules": check_unique(rules, "rule_id"),
        },
        "validated_claims": sum(1 for r in claim_validation_rows if r["validation_status"] == "validated"),
        "claims_needing_action": sum(1 for r in claim_validation_rows if r["validation_status"] != "validated"),
        "validated_fixtures": sum(1 for r in fixture_validation_rows if r["validation_status"] == "validated"),
        "fixtures_needing_action": sum(1 for r in fixture_validation_rows if r["validation_status"] != "validated"),
        "validated_rules": sum(1 for r in rule_rows if r["validation_status"] == "validated"),
        "rules_needing_action": sum(1 for r in rule_rows if r["validation_status"] != "validated"),
        "claim_fixture_coverage_min_all_claims": min(claim_fixture_count[c["claim_id"]] for c in claims) if claims else 0,
        "claim_fixture_coverage_max_all_claims": max(claim_fixture_count[c["claim_id"]] for c in claims) if claims else 0,
        "fixture_backed_claims": sum(1 for c in claims if claim_fixture_count[c["claim_id"]] > 0),
        "source_context_claims_without_fixture_coverage": sum(1 for c in claims if claim_fixture_count[c["claim_id"]] == 0 and c.get("fixture_role") == "source_context"),
        "baseline_claims_without_fixture_coverage": sum(1 for c in claims if claim_fixture_count[c["claim_id"]] == 0 and c.get("fixture_role") == "baseline"),
        "unresolved_planned_claims": sum(1 for c in claims if c.get("fixture_role") == "planned"),
        "status": "pass" if all(r["validation_status"] == "validated" for r in claim_validation_rows + fixture_validation_rows + rule_rows) else "needs_action",
    }
    write_json(results / "coding_validation_summary.json", summary)
    print(json.dumps({"status": summary["status"], "claims": len(claims), "fixtures": len(fixtures), "rules": len(rules)}, sort_keys=True))
    if summary["status"] != "pass":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
