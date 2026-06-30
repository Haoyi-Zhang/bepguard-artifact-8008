#!/usr/bin/env python3
"""Produce auditable minimality certificates for minimized witnesses.

The original minimizer guarantees one-deletion minimality over declared edit
operators.  This checker validates that claim and adds an exact finite
certificate for header-subset minimality on the returned minimized witnesses.
It does not change witnesses or labels.
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import copy
import csv
import itertools
import json
from pathlib import Path
from typing import Dict, List

from bep_semantics import analyze_fixture


def issues(fixture: Dict[str, object]) -> List[str]:
    return [f.issue for f in analyze_fixture(fixture)]


def parse_csp(value: str) -> List[List[str]]:
    return [seg.strip().split() for seg in value.split(";") if seg.strip().split()]


def fmt_csp(segs: List[List[str]]) -> str:
    return "; ".join(" ".join(s) for s in segs if s)


def header_candidates(fixture: Dict[str, object]) -> List[Dict[str, object]]:
    headers = fixture.get("headers", [])
    if not isinstance(headers, list):
        return []
    out: List[Dict[str, object]] = []
    for i in range(len(headers)):
        if len(headers) > 1:
            cand = copy.deepcopy(fixture)
            del cand["headers"][i]
            out.append({"op": f"delete_header[{i}]", "fixture": cand})
        name = str(headers[i].get("name", "")).lower()
        value = str(headers[i].get("value", ""))
        if name in {"content-security-policy", "content-security-policy-report-only"}:
            segs = parse_csp(value)
            for di in range(len(segs)):
                if len(segs) > 1:
                    trial = segs[:di] + segs[di+1:]
                    cand = copy.deepcopy(fixture)
                    cand["headers"][i]["value"] = fmt_csp(trial)
                    out.append({"op": f"delete_csp_directive[{i},{di}]", "fixture": cand})
                for ti in range(1, len(segs[di])):
                    if len(segs[di]) > 2:
                        trial = copy.deepcopy(segs)
                        trial[di] = trial[di][:ti] + trial[di][ti+1:]
                        cand = copy.deepcopy(fixture)
                        cand["headers"][i]["value"] = fmt_csp(trial)
                        out.append({"op": f"delete_csp_token[{i},{di},{ti}]", "fixture": cand})
        elif name == "strict-transport-security":
            parts = [x.strip() for x in value.split(";") if x.strip()]
            for pi in range(len(parts)):
                if len(parts) > 1:
                    trial = parts[:pi] + parts[pi+1:]
                    cand = copy.deepcopy(fixture)
                    cand["headers"][i]["value"] = "; ".join(trial)
                    out.append({"op": f"delete_hsts_part[{i},{pi}]", "fixture": cand})
    return out


def exact_header_subset_minimal(fixture: Dict[str, object], issue: str) -> bool:
    headers = fixture.get("headers", [])
    if not isinstance(headers, list) or len(headers) <= 1:
        return True
    n = len(headers)
    for k in range(0, n):
        for idxs in itertools.combinations(range(n), k):
            cand = copy.deepcopy(fixture)
            cand["headers"] = [headers[i] for i in idxs]
            if issue in issues(cand):
                return False
    return True


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--minimized", default="artifact/results/deep_locked/minimized_witnesses.json")
    ap.add_argument("--csv", default="artifact/results/deep_locked/minimality_certificates.csv")
    ap.add_argument("--json", default="artifact/results/deep_locked/minimality_certificates.json")
    args = ap.parse_args()
    rows_in = json.loads(Path(args.minimized).read_text(encoding="utf-8"))
    rows: List[Dict[str, object]] = []
    for row in rows_in:
        if row.get("status") != "minimized":
            continue
        issue = str(row["issue"])
        mf = copy.deepcopy(row["minimized_fixture"])
        if not isinstance(mf, dict):
            continue
        # Reconstruct enough fixture metadata for analysis.
        mf["id"] = str(row["fixture_id"]) + "__mincert"
        if "expected_issue" not in mf:
            mf["expected_issue"] = issue
        base_issues = issues(mf)
        one_del_survivors = []
        for cand in header_candidates(mf):
            if issue in issues(cand["fixture"]):
                one_del_survivors.append(str(cand["op"]))
        exact_header = exact_header_subset_minimal(mf, issue)
        rows.append({
            "fixture_id": row["fixture_id"],
            "issue": issue,
            "base_still_triggers_issue": issue in base_issues,
            "declared_one_deletion_survivors": ";".join(one_del_survivors) if one_del_survivors else "none",
            "one_deletion_minimal": len(one_del_survivors) == 0,
            "exact_header_subset_minimal": exact_header,
            "minimized_header_count": len(mf.get("headers", [])) if isinstance(mf.get("headers", []), list) else 0,
            "base_issues": ";".join(base_issues) if base_issues else "none",
        })
    out_csv = Path(args.csv); out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        fieldnames = ["fixture_id", "issue", "base_still_triggers_issue", "declared_one_deletion_survivors", "one_deletion_minimal", "exact_header_subset_minimal", "minimized_header_count", "base_issues"]
        w = csv.DictWriter(fh, fieldnames=fieldnames); w.writeheader(); w.writerows(rows)
    metrics = {
        "certified_witnesses": len(rows),
        "base_still_triggers_issue": sum(1 for r in rows if r["base_still_triggers_issue"]),
        "one_deletion_minimal": sum(1 for r in rows if r["one_deletion_minimal"]),
        "exact_header_subset_minimal": sum(1 for r in rows if r["exact_header_subset_minimal"]),
        "one_deletion_failures": [r for r in rows if not r["one_deletion_minimal"]],
        "exact_header_subset_failures": [r for r in rows if not r["exact_header_subset_minimal"]],
        "interpretation": "Minimality certificates for returned minimized witnesses; exactness is over header subsets, while directive/token checks are one-deletion based.",
    }
    Path(args.json).write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(metrics, sort_keys=True))
    if metrics["one_deletion_failures"] or metrics["exact_header_subset_failures"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
