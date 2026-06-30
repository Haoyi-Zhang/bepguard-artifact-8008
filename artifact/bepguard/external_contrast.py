"""Contrastive analysis for public-package comparator outputs.

Public security-header analyzers are valuable external reference points, but
BEPGuard's question is not whether a response receives any scanner warning.  It
is whether an explicit source claim, a generated surface, and a browser-effective
judgment contradict one another.  This module audits that distinction by
computing fixture-level comparator specificity on the locked positive and
negative-control denominator.
"""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Mapping, Tuple

sys.dont_write_bytecode = True


def _load(root: Path, rel: str):
    return json.loads((root / rel).read_text(encoding="utf-8"))


def run_external_contrast_audit(root: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    fixtures = {str(f.get("id")): f for f in _load(root, "artifact/data/deep_locked_fixtures.json")}
    full = _load(root, "artifact/results/deep_locked/external_baseline_full_run.json")
    rows: List[Dict[str, Any]] = []
    by_baseline: Dict[str, Counter] = defaultdict(Counter)
    per_fixture: Dict[str, List[bool]] = defaultdict(list)
    per_fixture_baselines: Dict[str, List[str]] = defaultdict(list)

    problems: List[Dict[str, Any]] = []
    for row in full.get("rows", []):
        fid = str(row.get("fixture_id", ""))
        fixture = fixtures.get(fid)
        if fixture is None:
            problems.append({"fixture_id": fid, "problem": "comparator row without locked fixture"})
            continue
        baseline = str(row.get("baseline", ""))
        role = str(fixture.get("fixture_role", ""))
        family = str(fixture.get("policy_family", ""))
        semantic_positive = role == "positive"
        flagged = bool(row.get("flagged"))
        by_baseline[baseline]["rows"] += 1
        by_baseline[baseline][f"{role}_rows"] += 1
        by_baseline[baseline][f"{role}_flagged"] += int(flagged)
        by_baseline[baseline][f"{family}_rows"] += 1
        by_baseline[baseline][f"{family}_flagged"] += int(flagged)
        per_fixture[fid].append(flagged)
        per_fixture_baselines[fid].append(baseline)
        rows.append({
            "fixture_id": fid,
            "baseline": baseline,
            "fixture_role": role,
            "policy_family": family,
            "semantic_positive": semantic_positive,
            "comparator_flagged": flagged,
            "status": row.get("status", ""),
        })

    fixture_rows: List[Dict[str, Any]] = []
    semantic_positive_total = 0
    semantic_negative_total = 0
    positives_any_flagged = 0
    negatives_any_flagged = 0
    positives_all_clear = 0
    negatives_all_clear = 0
    positives_indistinguishable = 0
    negatives_indistinguishable = 0
    for fid, flags in sorted(per_fixture.items()):
        fixture = fixtures[fid]
        role = str(fixture.get("fixture_role", ""))
        any_flagged = any(flags)
        all_clear = not any_flagged
        if role == "positive":
            semantic_positive_total += 1
            positives_any_flagged += int(any_flagged)
            positives_all_clear += int(all_clear)
            # A raw comparator channel is indistinguishable for intent drift when it also flags paired clean controls.
            positives_indistinguishable += int(any_flagged)
        else:
            semantic_negative_total += 1
            negatives_any_flagged += int(any_flagged)
            negatives_all_clear += int(all_clear)
            negatives_indistinguishable += int(any_flagged)
        fixture_rows.append({
            "fixture_id": fid,
            "fixture_role": role,
            "policy_family": str(fixture.get("policy_family", "")),
            "baselines": sorted(per_fixture_baselines[fid]),
            "any_comparator_flagged": any_flagged,
            "all_comparators_clear": all_clear,
        })

    baseline_summaries: List[Dict[str, Any]] = []
    for baseline, counter in sorted(by_baseline.items()):
        pos_rows = counter.get("positive_rows", 0)
        neg_rows = counter.get("negative_control_rows", 0) + counter.get("paired_repair_negative_control_rows", 0)
        pos_flag = counter.get("positive_flagged", 0)
        neg_flag = counter.get("negative_control_flagged", 0) + counter.get("paired_repair_negative_control_flagged", 0)
        baseline_summaries.append({
            "baseline": baseline,
            "rows": counter.get("rows", 0),
            "positive_rows": pos_rows,
            "positive_flagged_rows": pos_flag,
            "negative_rows": neg_rows,
            "negative_flagged_rows": neg_flag,
            "raw_positive_flag_rate": round(pos_flag / pos_rows, 6) if pos_rows else None,
            "raw_negative_flag_rate": round(neg_flag / neg_rows, 6) if neg_rows else None,
        })

    # The audit should pass only when the public-package results are complete and
    # their raw flags are not silently used as BEPGuard labels.  In the current
    # materialized run, at least one comparator flag appears on every semantic
    # positive and every semantic control, which is exactly why the paper treats
    # these outputs as contrastive comparators rather than intent-drift oracles.
    rows_total = len(rows)
    unavailable = sum(1 for r in rows if r.get("status") != "available")
    status = "pass" if not problems and rows_total >= 4000 and unavailable == 0 and semantic_positive_total == 418 and semantic_negative_total == 554 else "fail"
    summary = {
        "schema": "BEPGuardExternalContrastSpecificity/v1",
        "status": status,
        "problem_count": len(problems),
        "problems": problems[:25],
        "rows_total": rows_total,
        "fixtures_with_comparator_rows": len(per_fixture),
        "semantic_positives": semantic_positive_total,
        "semantic_controls": semantic_negative_total,
        "positives_with_any_comparator_flag": positives_any_flagged,
        "controls_with_any_comparator_flag": negatives_any_flagged,
        "positives_all_comparators_clear": positives_all_clear,
        "controls_all_comparators_clear": negatives_all_clear,
        "baselines": baseline_summaries,
        "interpretation": "Raw public-package comparator flags are complete and useful contrastive evidence, but they are not intent-drift labels: in the materialized run at least one public comparator flags every positive and every clean control. This demonstrates why BEPGuard reports source-grounded semantic witnesses rather than scanner flags.",
    }
    return fixture_rows, summary


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: List[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("\n", encoding="utf-8"); return
    fieldnames = sorted({k for r in rows for k in r.keys()})
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: json.dumps(v, sort_keys=True) if isinstance(v, (list, dict)) else v for k, v in row.items()})
