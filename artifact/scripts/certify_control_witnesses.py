#!/usr/bin/env python3
"""Certify negative controls for the BEP-Deep workload.

The positive witnesses in this artifact are proof-carrying. This companion audit
turns the negative side into proof-carrying evidence as well: every ordinary
negative control and every paired repair control must be clean under both the
operational oracle and the independently written decision-table oracle, have a
valid fixture hash, and resolve to an admitted source claim. Paired repair
controls additionally have to name the positive fixture and target issue they
neutralize.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True

import csv, hashlib, json
from pathlib import Path
from typing import Any, Dict, List

from bep_semantics import analyze_fixture
from decision_table_oracle import decision_issues

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
RESULTS = ROOT / "results" / "deep_locked"


def stable_hash(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def write_csv(path: Path, rows: List[Dict[str, Any]], fields: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fields})


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> None:
    fixtures = json.loads((DATA / "deep_locked_fixtures.json").read_text(encoding="utf-8"))
    claims = {r["claim_id"] for r in read_csv(DATA / "corpus_claims.csv")}
    positives = {f["id"]: f for f in fixtures if f.get("fixture_role") == "positive"}
    rows: List[Dict[str, Any]] = []
    failures: List[Dict[str, Any]] = []
    for f in fixtures:
        role = f.get("fixture_role")
        if role not in {"negative_control", "paired_repair_negative_control"}:
            continue
        fid = f["id"]
        op = [x.issue for x in analyze_fixture(f)]
        dt = decision_issues(f)
        expected_hash = stable_hash({k: f[k] for k in f if k != "fixture_hash"})[:16]
        source_ok = all(cid in claims for cid in f.get("source_claim_ids", []))
        paired_ok = True
        if role == "paired_repair_negative_control":
            paired_ok = bool(f.get("paired_positive_fixture_id") in positives and f.get("paired_target_issue"))
        status = (
            f.get("expected_issue") == "none"
            and not op
            and not dt
            and f.get("fixture_hash") == expected_hash
            and source_ok
            and paired_ok
        )
        row = {
            "fixture_id": fid,
            "fixture_role": role,
            "policy_family": f.get("policy_family", ""),
            "source_claim_ids": ";".join(f.get("source_claim_ids", [])),
            "operational_clean": "yes" if not op else "no",
            "decision_table_clean": "yes" if not dt else "no",
            "hash_valid": "yes" if f.get("fixture_hash") == expected_hash else "no",
            "source_claims_known": "yes" if source_ok else "no",
            "paired_relation_valid": "yes" if paired_ok else "no",
            "certificate_status": "verified" if status else "failed",
            "operational_issues": ";".join(op),
            "decision_table_issues": ";".join(dt),
        }
        rows.append(row)
        if not status:
            failures.append(row)
    ordinary = [r for r in rows if r["fixture_role"] == "negative_control"]
    paired = [r for r in rows if r["fixture_role"] == "paired_repair_negative_control"]
    metrics = {
        "interpretation": "Negative-control certificates complement proof-carrying positive witnesses; they certify clean controls under both operational and decision-table oracles.",
        "negative_controls_certified": sum(1 for r in ordinary if r["certificate_status"] == "verified"),
        "ordinary_negative_controls": len(ordinary),
        "paired_repair_controls_certified": sum(1 for r in paired if r["certificate_status"] == "verified"),
        "paired_repair_controls": len(paired),
        "all_control_certificates": len(rows),
        "verified_control_certificates": sum(1 for r in rows if r["certificate_status"] == "verified"),
        "failures": failures,
        "status": "pass" if not failures else "fail",
    }
    fields = ["fixture_id", "fixture_role", "policy_family", "source_claim_ids", "operational_clean", "decision_table_clean", "hash_valid", "source_claims_known", "paired_relation_valid", "certificate_status", "operational_issues", "decision_table_issues"]
    write_csv(RESULTS / "control_certificate_audit.csv", rows, fields)
    write_json(RESULTS / "control_certificate_metrics.json", metrics)
    print(json.dumps({"status": metrics["status"], "verified_control_certificates": metrics["verified_control_certificates"], "all_control_certificates": metrics["all_control_certificates"]}, sort_keys=True))
    if failures:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
