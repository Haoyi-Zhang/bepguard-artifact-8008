#!/usr/bin/env python3
"""Deterministic internal HSTS preload-criterion baseline.

The script encodes the documented preload header criterion as a scoped baseline
control and does not perform domain lookups, network checks, or preload-list
queries.
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import csv
import json
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from bep_semantics import effective_headers_from_layers


def get_header(headers: Iterable[Dict[str, str]], name: str) -> Optional[str]:
    lname = name.lower()
    for h in headers:
        if h.get("name", "").lower() == lname:
            return h.get("value", "")
    return None


def max_age(value: str) -> Optional[int]:
    m = re.search(r"max-age\s*=\s*(\d+)", value, flags=re.I)
    return int(m.group(1)) if m else None


def check_hsts_preload(value: Optional[str]) -> Dict[str, object]:
    if not value:
        return {"has_hsts": False, "max_age": None, "include_subdomains": False, "preload_token": False, "criterion_pass": False}
    lower = value.lower()
    ma = max_age(value)
    return {
        "has_hsts": True,
        "max_age": ma,
        "include_subdomains": "includesubdomains" in lower,
        "preload_token": "preload" in lower,
        "criterion_pass": bool(ma is not None and ma >= 31536000 and "includesubdomains" in lower and "preload" in lower),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate local HSTS preload documented-criterion baseline on fixtures.")
    parser.add_argument("--fixtures", default="artifact/data/locked_full_fixtures.json")
    parser.add_argument("--json-out", default="artifact/results/hsts_preload_criterion.json")
    parser.add_argument("--csv-out", default="artifact/results/hsts_preload_criterion.csv")
    args = parser.parse_args()
    fixtures = json.loads(Path(args.fixtures).read_text(encoding="utf-8"))
    rows: List[Dict[str, object]] = []
    for fixture in fixtures:
        headers, _ = effective_headers_from_layers(fixture)
        value = get_header(headers, "Strict-Transport-Security")
        result = check_hsts_preload(value)
        result.update({
            "fixture_id": fixture.get("id", "unknown"),
            "family": fixture.get("policy_family", ""),
            "expected_issue": fixture.get("expected_issue", "none"),
            "applicable": fixture.get("policy_family") == "HSTS",
        })
        rows.append(result)
    Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.json_out).write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with Path(args.csv_out).open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["fixture_id", "family", "applicable", "expected_issue", "has_hsts", "max_age", "include_subdomains", "preload_token", "criterion_pass"])
        writer.writeheader(); writer.writerows(rows)
    print(json.dumps({"fixtures": len(rows), "applicable": sum(1 for r in rows if r["applicable"])}))


if __name__ == "__main__":
    main()
