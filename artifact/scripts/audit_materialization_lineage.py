#!/usr/bin/env python3
"""Audit materialization-lineage state for the release artifact release.

The artifact retains a seed-lineage materializer for reproducibility, while the
main paper reports the BEP-Deep denominator.  This gate checks that the lineage
lock and ledger aliases make that distinction explicit and cannot be confused
with the main denominator after a reproducer runs the materializer.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True

import csv, hashlib, json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load_json(rel: str):
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


def load_csv(rel: str):
    with (ROOT / rel).open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def sha(rel: str) -> str:
    return hashlib.sha256((ROOT / rel).read_bytes()).hexdigest()


def main() -> None:
    problems: list[str] = []

    corpus_lock = load_json("artifact/protocol_corpus_lock.json")
    if corpus_lock.get("status") != "seed_lineage_materialized":
        problems.append("protocol_corpus_lock status is not seed_lineage_materialized")
    if corpus_lock.get("lineage_not_main_denominator") is not True:
        problems.append("protocol_corpus_lock does not explicitly mark lineage_not_main_denominator")
    if corpus_lock.get("main_workload") != "BEP-Deep":
        problems.append("protocol_corpus_lock does not point to BEP-Deep as main workload")
    if "full_experiment_allowed" in corpus_lock or "full_experiment_blocker" in corpus_lock:
        problems.append("protocol_corpus_lock still contains obsolete full-experiment gate fields")

    seed = load_json("artifact/results/lineage/seed_denominator_lock_summary.json")
    if seed.get("workload") != "seed-lineage-base" or seed.get("lineage_not_main_denominator") is not True:
        problems.append("seed lineage summary is not explicitly marked as non-main denominator")
    if seed.get("seed_fixtures_total") != 116 or seed.get("positive_fixtures") != 88 or seed.get("negative_control_fixtures") != 28:
        problems.append("seed lineage summary counts are unexpected")

    denom = load_json("artifact/results/denominator_lock_summary.json")
    if denom.get("workload") != "BEP-Deep" or denom.get("locked_fixtures_total") != 972:
        problems.append("release denominator summary is not preserved as BEP-Deep 972")

    alias_paths = [
        "artifact/rule_source_ledger.csv",
        "artifact/data/rule_source_ledger.csv",
        "artifact/data/rule_to_source_ledger.csv",
        "artifact/method/rule_to_source_ledger.csv",
        "artifact/method/source_rule_ledger.csv",
    ]
    alias_hashes = {p: sha(p) for p in alias_paths}
    if len(set(alias_hashes.values())) != 1:
        problems.append("canonical rule-ledger aliases are not byte-identical")
    for p in alias_paths:
        rows = load_csv(p)
        if len(rows) != 35:
            problems.append(f"{p} has {len(rows)} rows, expected 35")

    out = {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "protocol_corpus_lock_status": corpus_lock.get("status"),
        "seed_lineage_fixtures": seed.get("seed_fixtures_total", seed.get("locked_fixtures_total")),
        "main_workload": denom.get("workload"),
        "main_fixtures": denom.get("locked_fixtures_total"),
        "rule_ledger_aliases_checked": alias_paths,
        "interpretation": "Materialization-lineage audit: seed materialization is retained for lineage, while the release BEP-Deep denominator remains the main workload and duplicate rule ledgers are kept synchronized.",
    }
    target = ROOT / "artifact/results/materialization_lineage_audit.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": out["status"], "problem_count": out["problem_count"], "rule_ledger_aliases": len(alias_paths)}, sort_keys=True))
    if problems:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
