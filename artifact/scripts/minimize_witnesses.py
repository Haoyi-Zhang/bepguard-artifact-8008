#!/usr/bin/env python3
"""Minimize semantic conflict witnesses.

The minimizer is intentionally conservative. It preserves the target issue and
attempts deletion-based minimization over response headers and, for CSP/HSTS
values, over directive segments and directive tokens. The guarantee is
1-minimality with respect to the implemented deletion operators, not global
minimality over all possible policy strings.
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import copy
import json
from dataclasses import asdict
from pathlib import Path
from typing import Dict, Iterable, List

from bep_semantics import analyze_fixture, load_fixtures


def _issues(fixture: Dict[str, object]) -> List[str]:
    return [finding.issue for finding in analyze_fixture(fixture)]


def _keeps_issue(fixture: Dict[str, object], issue: str) -> bool:
    return issue in _issues(fixture)


def _set_header_value(fixture: Dict[str, object], index: int, value: str) -> Dict[str, object]:
    candidate = copy.deepcopy(fixture)
    headers = candidate.get("headers", [])
    if not isinstance(headers, list):
        return candidate
    headers[index]["value"] = value
    return candidate


def _format_csp(directives: List[List[str]]) -> str:
    return "; ".join(" ".join(part for part in directive if part) for directive in directives if directive)


def _parse_csp_segments(value: str) -> List[List[str]]:
    segments: List[List[str]] = []
    for raw in value.split(";"):
        parts = raw.strip().split()
        if parts:
            segments.append(parts)
    return segments


def _minimize_csp_value(fixture: Dict[str, object], header_index: int, issue: str) -> str:
    headers = fixture.get("headers", [])
    value = str(headers[header_index].get("value", ""))  # type: ignore[index]
    segments = _parse_csp_segments(value)

    # Delete whole directives first.
    i = 0
    while i < len(segments):
        trial = segments[:i] + segments[i + 1:]
        if trial and _keeps_issue(_set_header_value(fixture, header_index, _format_csp(trial)), issue):
            segments = trial
        else:
            i += 1

    # Then delete source tokens inside each remaining directive.
    for di in range(len(segments)):
        ti = 1
        while ti < len(segments[di]):
            trial_segments = copy.deepcopy(segments)
            trial_segments[di] = trial_segments[di][:ti] + trial_segments[di][ti + 1:]
            if len(trial_segments[di]) > 1 and _keeps_issue(
                _set_header_value(fixture, header_index, _format_csp(trial_segments)), issue
            ):
                segments = trial_segments
            else:
                ti += 1
    return _format_csp(segments)


def _minimize_hsts_value(fixture: Dict[str, object], header_index: int, issue: str) -> str:
    headers = fixture.get("headers", [])
    parts = [p.strip() for p in str(headers[header_index].get("value", "")).split(";") if p.strip()]  # type: ignore[index]
    i = 0
    while i < len(parts):
        trial = parts[:i] + parts[i + 1:]
        if trial and _keeps_issue(_set_header_value(fixture, header_index, "; ".join(trial)), issue):
            parts = trial
        else:
            i += 1
    return "; ".join(parts)


def minimize_fixture_for_issue(fixture: Dict[str, object], issue: str) -> Dict[str, object]:
    candidate = copy.deepcopy(fixture)
    headers = candidate.get("headers", [])
    if not isinstance(headers, list):
        return candidate

    # Header-level deletion.
    i = 0
    while i < len(headers):
        trial = copy.deepcopy(candidate)
        trial_headers = trial.get("headers", [])
        del trial_headers[i]
        if trial_headers and _keeps_issue(trial, issue):
            candidate = trial
            headers = candidate.get("headers", [])
        else:
            i += 1

    # Header-value deletion for modeled policy syntaxes.
    headers = candidate.get("headers", [])
    for idx, header in enumerate(headers):
        name = str(header.get("name", "")).lower()
        if name in {"content-security-policy", "content-security-policy-report-only"}:
            candidate = _set_header_value(candidate, idx, _minimize_csp_value(candidate, idx, issue))
        elif name == "strict-transport-security":
            candidate = _set_header_value(candidate, idx, _minimize_hsts_value(candidate, idx, issue))
    return candidate


def main() -> None:
    parser = argparse.ArgumentParser(description="Minimize semantic conflict witnesses.")
    parser.add_argument("--fixtures", default="artifact/data/locked_full_fixtures.json")
    parser.add_argument("--out", default="artifact/results/full_locked/minimized_witnesses.json")
    parser.add_argument("--metrics", default="artifact/results/minimization_metrics.json")
    args = parser.parse_args()

    fixtures = load_fixtures(args.fixtures)
    rows = []
    for fixture in fixtures:
        expected = fixture.get("expected_issue", "none")
        if expected == "none":
            continue
        expected_issue = str(expected)
        if not _keeps_issue(fixture, expected_issue):
            rows.append({
                "fixture_id": fixture.get("id"),
                "issue": expected_issue,
                "status": "target_issue_not_detected",
                "minimized_fixture": None,
            })
            continue
        minimized = minimize_fixture_for_issue(fixture, expected_issue)
        rows.append({
            "fixture_id": fixture.get("id"),
            "issue": expected_issue,
            "status": "minimized",
            "original_header_count": len(fixture.get("headers", [])),
            "minimized_header_count": len(minimized.get("headers", [])),
            "original_header_bytes": len(json.dumps(fixture.get("headers", []), sort_keys=True)),
            "minimized_header_bytes": len(json.dumps(minimized.get("headers", []), sort_keys=True)),
            "minimized_fixture": {
                "id": minimized.get("id", fixture.get("id")),
                "policy_family": minimized.get("policy_family", fixture.get("policy_family", "mixed")),
                "public_source_id": minimized.get("public_source_id", fixture.get("public_source_id", "unknown")),
                "source_claim_ids": minimized.get("source_claim_ids", fixture.get("source_claim_ids", [])),
                "expected_issue": expected_issue,
                "context": minimized.get("context", {}),
                "headers": minimized.get("headers", []),
                "layers": minimized.get("layers", []),
                "intent": minimized.get("intent", {}),
            },
            "remaining_issues": [asdict(f) for f in analyze_fixture(minimized)],
        })

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    minimized_count = sum(1 for r in rows if r["status"] == "minimized")
    total_before = sum(int(r.get("original_header_bytes", 0)) for r in rows)
    total_after = sum(int(r.get("minimized_header_bytes", 0)) for r in rows)
    metrics = {
        "positive_fixtures": len(rows),
        "minimized": minimized_count,
        "total_header_bytes_before": total_before,
        "total_header_bytes_after": total_after,
        "byte_reduction": total_before - total_after,
    }
    Path(args.metrics).write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(metrics, sort_keys=True))


if __name__ == "__main__":
    main()
