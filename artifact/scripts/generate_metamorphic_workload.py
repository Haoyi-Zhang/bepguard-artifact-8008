#!/usr/bin/env python3
"""Generate and evaluate semantics-preserving metamorphic policy workloads.

The transforms are designed to preserve the intended oracle label: header-name
case normalization, header-order changes within a surface/layer, harmless policy
whitespace, and irrelevant response-header injection.  The script validates that
expected positives and negative controls remain stable under those transforms.
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import copy
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Dict, List

from bep_semantics import analyze_fixtures, load_fixtures


def add_irrelevant_header(headers: List[Dict[str, str]]) -> None:
    headers.append({"name": "X-Policy-Fixture-Marker", "value": "irrelevant"})


def mutate_headers(headers: List[Dict[str, str]], transform: str) -> List[Dict[str, str]]:
    out = copy.deepcopy(headers)
    if transform == "header_name_lowercase":
        for h in out:
            h["name"] = str(h.get("name", "")).lower()
    elif transform == "header_order_reversed":
        out = list(reversed(out))
    elif transform == "policy_whitespace":
        for h in out:
            name = str(h.get("name", "")).lower()
            if "policy" in name or name == "strict-transport-security":
                h["value"] = str(h.get("value", "")).replace(";", " ; ").replace(",", " , ")
    elif transform == "irrelevant_header_injected":
        add_irrelevant_header(out)
    return out


def transform_fixture(fixture: Dict[str, object], transform: str) -> Dict[str, object]:
    f = copy.deepcopy(fixture)
    f["id"] = f"{fixture['id']}__MT_{transform}"
    f["metamorphic_transform"] = transform
    headers = f.get("headers", [])
    if isinstance(headers, list):
        f["headers"] = mutate_headers(headers, transform)
    layers = f.get("layers", [])
    if isinstance(layers, list):
        for layer in layers:
            if isinstance(layer, dict) and isinstance(layer.get("headers", []), list):
                # Do not reorder layers; only mutate header lists within a layer.
                layer["headers"] = mutate_headers(layer.get("headers", []), transform)  # type: ignore[arg-type]
    return f


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate metamorphic invariance for locked fixtures.")
    parser.add_argument("--fixtures", default="artifact/data/locked_full_fixtures.json")
    parser.add_argument("--out", default="artifact/results/full_locked/metamorphic_workload.json")
    parser.add_argument("--summary", default="artifact/results/full_locked/metamorphic_summary.csv")
    parser.add_argument("--metrics", default="artifact/results/full_locked/metamorphic_metrics.json")
    args = parser.parse_args()

    base = load_fixtures(args.fixtures)
    transforms = ["header_name_lowercase", "header_order_reversed", "policy_whitespace", "irrelevant_header_injected"]
    workload: List[Dict[str, object]] = []
    for transform in transforms:
        workload.extend(transform_fixture(f, transform) for f in base)
    findings = analyze_fixtures(workload)
    by_id: Dict[str, List[str]] = {str(f["id"]): [] for f in workload}
    for finding in findings:
        by_id[finding.fixture_id].append(finding.issue)

    rows: List[Dict[str, object]] = []
    for f in workload:
        expected = str(f.get("expected_issue", "none"))
        actual = by_id[str(f["id"])]
        if expected == "none":
            stable = not actual
        else:
            stable = expected in actual
        rows.append({
            "fixture_id": f["id"],
            "base_fixture_id": str(f["id"]).split("__MT_")[0],
            "transform": f.get("metamorphic_transform", ""),
            "policy_family": f.get("policy_family", ""),
            "expected_issue": expected,
            "actual_issues": ";".join(actual) if actual else "none",
            "stable": stable,
        })

    stable_by_transform = {}
    for transform in transforms:
        subset = [r for r in rows if r["transform"] == transform]
        stable_by_transform[transform] = {
            "fixtures": len(subset),
            "stable": sum(1 for r in subset if r["stable"]),
            "unstable": sum(1 for r in subset if not r["stable"]),
        }
    metrics = {
        "base_fixtures": len(base),
        "transforms": transforms,
        "metamorphic_fixtures": len(workload),
        "stable_fixtures": sum(1 for r in rows if r["stable"]),
        "unstable_fixtures": sum(1 for r in rows if not r["stable"]),
        "stable_by_transform": stable_by_transform,
        "expected_issue_counts": dict(sorted(Counter(str(f.get("expected_issue", "none")) for f in workload).items())),
        "interpretation": "Semantics-preserving metamorphic workload over locked fixtures; not new public-web observations.",
    }

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(workload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with Path(args.summary).open("w", newline="", encoding="utf-8") as fh:
        fieldnames = ["fixture_id", "base_fixture_id", "transform", "policy_family", "expected_issue", "actual_issues", "stable"]
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader(); writer.writerows(rows)
    Path(args.metrics).write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(metrics, sort_keys=True))


if __name__ == "__main__":
    main()
