#!/usr/bin/env python3
"""Deterministic internal header-presence baseline used as a scoped negative control.

This baseline intentionally checks only explicit header presence and never
substitutes for browser-effective BEP semantics or external tools.
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import csv
import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from bep_semantics import effective_headers_from_layers


def load_fixtures(path: Path) -> List[Dict[str, object]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("fixture file must contain a JSON list")
    return data


def get_header(headers: Iterable[Dict[str, str]], name: str) -> Optional[str]:
    lname = name.lower()
    for h in headers:
        if h.get("name", "").lower() == lname:
            return h.get("value", "")
    return None


def analyze_fixture(fixture: Dict[str, object]) -> Dict[str, object]:
    headers, _ = effective_headers_from_layers(fixture)
    family = str(fixture.get("policy_family", ""))
    fid = str(fixture.get("id", "unknown"))
    labels: List[str] = []

    csp = get_header(headers, "Content-Security-Policy")
    csp_ro = get_header(headers, "Content-Security-Policy-Report-Only")
    acao = get_header(headers, "Access-Control-Allow-Origin")
    acac = get_header(headers, "Access-Control-Allow-Credentials")
    hsts = get_header(headers, "Strict-Transport-Security")
    coep = get_header(headers, "Cross-Origin-Embedder-Policy")
    corp = get_header(headers, "Cross-Origin-Resource-Policy")

    if family == "CSP":
        if not csp and csp_ro:
            labels.append("missing_enforced_csp")
        elif not csp and not csp_ro:
            labels.append("missing_csp")
        if csp and "'unsafe-inline'" in csp:
            labels.append("csp_contains_unsafe_inline")
    elif family == "CORS":
        if acao == "*" and str(acac).lower() == "true":
            labels.append("cors_wildcard_with_credentials_marker")
        elif acao is None:
            labels.append("missing_acao")
    elif family == "HSTS":
        if not hsts:
            labels.append("missing_hsts")
        elif "max-age=0" in hsts.replace(" ", "").lower():
            labels.append("hsts_zero_max_age_marker")
    elif family in {"COEP_CORP_CORS", "COEP/CORP/CORS"}:
        if coep == "require-corp" and not corp and acao is None:
            labels.append("coep_without_local_corp_or_cors_marker")

    return {
        "fixture_id": fid,
        "family": family,
        "baseline_labels": labels,
        "flagged": bool(labels),
        "expected_issue": fixture.get("expected_issue", "none"),
        "semantic_positive": fixture.get("expected_issue", "none") != "none",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a conservative header-presence baseline on fixture JSON.")
    parser.add_argument("--fixtures", default="artifact/data/locked_full_fixtures.json")
    parser.add_argument("--json-out", default="artifact/results/header_presence_baseline.json")
    parser.add_argument("--csv-out", default="artifact/results/header_presence_baseline.csv")
    args = parser.parse_args()
    fixtures = load_fixtures(Path(args.fixtures))
    rows = [analyze_fixture(f) for f in fixtures]
    Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.json_out).write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with Path(args.csv_out).open("w", newline="", encoding="utf-8") as fh:
        fieldnames = ["fixture_id", "family", "semantic_positive", "expected_issue", "flagged", "baseline_labels"]
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            out = dict(row)
            out["baseline_labels"] = ";".join(row["baseline_labels"])
            writer.writerow(out)
    print(json.dumps({"fixtures": len(rows), "flagged": sum(1 for r in rows if r["flagged"])}))


if __name__ == "__main__":
    main()
