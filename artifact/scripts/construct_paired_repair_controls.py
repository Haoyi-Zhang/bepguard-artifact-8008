#!/usr/bin/env python3
"""Create paired negative controls from validated repair counterfactuals.

Each positive BEP-Stress fixture already has a deterministic repair candidate.
This script converts the repaired fixtures into paired negative controls and
merges them with the stress workload.  The controls are adversarial near-misses:
they preserve the original claim/context/provenance as much as the repair
allows, but the target semantic issue must disappear under the same oracle.
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import csv
import json
import hashlib
from pathlib import Path
from typing import Dict, List

from bep_semantics import analyze_fixture


def stable_hash(obj: object) -> str:
    payload = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixtures", default="artifact/data/extended_fixtures.json")
    ap.add_argument("--repaired", default="artifact/results/extended_locked/repaired_positive_fixtures.json")
    ap.add_argument("--out", default="artifact/data/deep_locked_fixtures.json")
    ap.add_argument("--controls", default="artifact/data/paired_repair_controls.json")
    ap.add_argument("--audit", default="artifact/results/deep_locked/paired_repair_controls_audit.csv")
    ap.add_argument("--metrics", default="artifact/results/deep_locked/paired_repair_controls_metrics.json")
    args = ap.parse_args()
    fixtures: List[Dict[str, object]] = load(Path(args.fixtures))
    repaired: List[Dict[str, object]] = load(Path(args.repaired))
    controls: List[Dict[str, object]] = []
    rows: List[Dict[str, object]] = []
    for r in repaired:
        parent_id = str(r.get("id", "")).removesuffix("__repair")
        target = str(r.get("expected_issue", "none"))
        c = json.loads(json.dumps(r))
        c["id"] = f"{r.get('id')}__paired_negative"
        c["expected_issue"] = "none"
        c["fixture_role"] = "paired_repair_negative_control"
        c["mutation_operator_class"] = "paired_repair_negative_control"
        c["paired_positive_fixture_id"] = parent_id
        c["paired_target_issue"] = target
        c["interpretation"] = "Repaired near-miss negative control; validates that the same oracle stops emitting the target issue after the declared counterfactual repair."
        c.pop("fixture_hash", None)
        c["fixture_hash"] = stable_hash(c)[:16]
        actual = [x.issue for x in analyze_fixture(c)]
        controls.append(c)
        rows.append({
            "control_id": c["id"],
            "paired_positive_fixture_id": parent_id,
            "paired_target_issue": target,
            "actual_issues_after_repair": ";".join(actual) if actual else "none",
            "target_removed": target not in actual,
            "clean_control": len(actual) == 0,
        })
    merged = fixtures + controls
    out = Path(args.out); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(merged, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    Path(args.controls).write_text(json.dumps(controls, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest_path = Path("artifact/data/deep_fixture_manifest.csv")
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_fields = ["fixture_id", "policy_family", "source_claim_ids", "intent_class", "expected_issue", "fixture_role", "variant", "header_count", "context_keys", "generation_rule_id", "mutation_parent", "mutation_operator", "mutation_operator_class", "fixture_hash", "locked_status"]
    with manifest_path.open("w", newline="", encoding="utf-8") as mf:
        mw = csv.DictWriter(mf, fieldnames=manifest_fields)
        mw.writeheader()
        for item in merged:
            mw.writerow({
                "fixture_id": item.get("id", ""),
                "policy_family": item.get("policy_family", ""),
                "source_claim_ids": ";".join(item.get("source_claim_ids", [])),
                "intent_class": item.get("intent_class", ""),
                "expected_issue": item.get("expected_issue", ""),
                "fixture_role": item.get("fixture_role", ""),
                "variant": item.get("variant", ""),
                "header_count": len(item.get("headers", [])),
                "context_keys": ";".join(sorted(item.get("context", {}).keys())),
                "generation_rule_id": item.get("generation_rule_id", ""),
                "mutation_parent": item.get("mutation_parent", item.get("paired_positive_fixture_id", "")),
                "mutation_operator": item.get("mutation_operator", item.get("paired_target_issue", "")),
                "mutation_operator_class": item.get("mutation_operator_class", ""),
                "fixture_hash": item.get("fixture_hash", ""),
                "locked_status": item.get("locked_status", "locked_deep_denominator"),
            })
    audit = Path(args.audit); audit.parent.mkdir(parents=True, exist_ok=True)
    with audit.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["control_id", "paired_positive_fixture_id", "paired_target_issue", "actual_issues_after_repair", "target_removed", "clean_control"])
        w.writeheader(); w.writerows(rows)
    metrics = {
        "base_stress_fixtures": len(fixtures),
        "paired_repair_negative_controls": len(controls),
        "deep_locked_fixtures": len(merged),
        "target_removed": sum(1 for r in rows if r["target_removed"]),
        "clean_controls": sum(1 for r in rows if r["clean_control"]),
        "failures": [r for r in rows if not r["clean_control"]],
        "interpretation": "Paired repaired fixtures are negative controls, not new public-web observations.",
    }
    Path(args.metrics).write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(metrics, sort_keys=True))
    if metrics["failures"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
