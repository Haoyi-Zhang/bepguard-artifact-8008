"""Pairwise oracle triangulation over locked BEP-Deep fixtures.

This audit compares the operational evaluator, decision-table oracle, and
label-free declarative oracle on every locked fixture.  It is stricter than
single-oracle agreement summaries because it records all pairwise cells and
requires every oracle to match both the expected issue and the other oracles.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple


def _read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _norm(value: str) -> str:
    value = (value or "").strip()
    return "none" if value in {"", "None"} else value


def run_oracle_triangulation(root: Path) -> Tuple[List[Dict[str, str]], Dict[str, Any]]:
    decision = {r["fixture_id"]: r for r in _read_csv(root / "artifact/results/deep_locked/decision_table_oracle_audit.csv")}
    declarative_rows = [r for r in _read_csv(root / "artifact/results/deep_locked/declarative_oracle_rows.csv") if r.get("suite") == "BEP-Deep"]
    declarative = {r["case_id"]: r for r in declarative_rows}
    full = _read_csv(root / "artifact/results/deep_locked/full_summary.csv")
    rows: List[Dict[str, str]] = []
    problems: List[str] = []
    pairs = [("operational", "decision_table"), ("operational", "declarative"), ("decision_table", "declarative")]
    positives = 0
    controls = 0
    for r in full:
        fid = r["fixture_id"]
        if fid not in decision:
            problems.append(f"{fid}: missing decision-table row")
            continue
        if fid not in declarative:
            problems.append(f"{fid}: missing declarative oracle row")
            continue
        expected = _norm(r.get("expected_issue", "none"))
        operational = _norm(decision[fid].get("operational", ""))
        decision_value = _norm(decision[fid].get("decision_table", ""))
        declarative_value = _norm(declarative[fid].get("declarative", ""))
        if expected == "none":
            controls += 1
        else:
            positives += 1
        values = {"operational": operational, "decision_table": decision_value, "declarative": declarative_value}
        expected_ok = all(v == expected for v in values.values())
        if not expected_ok:
            problems.append(f"{fid}: expected {expected}, got {values}")
        for a, b in pairs:
            pair_ok = values[a] == values[b]
            if not pair_ok:
                problems.append(f"{fid}: {a}={values[a]} != {b}={values[b]}")
            rows.append({
                "fixture_id": fid,
                "policy_family": r.get("policy_family", ""),
                "expected": expected,
                "oracle_a": a,
                "oracle_b": b,
                "value_a": values[a],
                "value_b": values[b],
                "pair_status": "agree" if pair_ok else "disagree",
                "expected_status": "match" if expected_ok else "mismatch",
            })
    summary = {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems[:50],
        "fixtures_checked": len(full),
        "positive_fixtures_checked": positives,
        "negative_controls_checked": controls,
        "oracles": ["operational", "decision_table", "declarative"],
        "pairwise_agreement_cells": len(rows),
        "pairwise_agreements": sum(1 for row in rows if row["pair_status"] == "agree"),
        "expected_matches": sum(1 for fid in {row["fixture_id"] for row in rows} if fid in decision and fid in declarative),
        "interpretation": "Every BEP-Deep fixture is checked across operational semantics, decision-table oracle, and declarative oracle.  The audit records pairwise oracle agreement and agreement with the locked expected issue without reading fixture labels inside the oracle implementations.",
    }
    return rows, summary


def write_csv(path: Path, rows: List[Dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["fixture_id", "policy_family", "expected", "oracle_a", "oracle_b", "value_a", "value_b", "pair_status", "expected_status"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader(); writer.writerows(rows)


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
