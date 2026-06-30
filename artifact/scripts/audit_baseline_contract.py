#!/usr/bin/env python3
"""Audit baseline-wrapper status contracts and scope separation.

The artifact distinguishes external baselines from project-internal controls.
This audit prevents three common reproducibility failures: non-canonical wrapper
status values, missing BEP-Deep fixture-level baseline probes, and accidental
substitution of project logic when an external package is unavailable.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List

sys.dont_write_bytecode = True

try:
    from common_paths import package_root
except ImportError:  # pragma: no cover
    package_root = None  # type: ignore[assignment]

CANONICAL_STATUSES = {"available", "unavailable", "not_applicable", "unsupported", "error", "excluded"}
EXTERNAL_BASELINES = {"csp_evaluator", "mdn_http_observatory", "mdn_http_observatory_csp", "mdn_http_observatory_cors", "mdn_http_observatory_corp", "webhint_strict_transport_security", "chromium_hstspreload"}
INTERNAL_CONTROLS = {"conservative_header_presence", "documented_hsts_preload_criterion", "internal_header_presence_control", "internal_hsts_preload_documented_criterion"}
PROBE_FILES = [
    "artifact/results/full_locked/external_baseline_fixture_probe.json",
    "artifact/results/extended_locked/external_baseline_fixture_probe.json",
    "artifact/results/deep_locked/external_baseline_fixture_probe.json",
]
AVAILABILITY_FILES = [
    "artifact/results/full_locked/external_baseline_availability.json",
    "artifact/results/extended_locked/external_baseline_availability.json",
    "artifact/results/deep_locked/external_baseline_availability.json",
]
BASELINE_COMPARISON_FILES = [
    "artifact/results/full_locked/full_baseline_comparison.csv",
    "artifact/results/extended_locked/full_baseline_comparison.csv",
    "artifact/results/deep_locked/full_baseline_comparison.csv",
]


def root_from_arg(value: str | None) -> Path:
    if value:
        return Path(value).resolve()
    if package_root is not None:
        return package_root(__file__)
    return Path.cwd().resolve()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def status_rows(obj: Any) -> List[Dict[str, Any]]:
    if isinstance(obj, dict) and isinstance(obj.get("results"), list):
        return [r for r in obj["results"] if isinstance(r, dict)]
    return []


def main() -> None:
    ap = argparse.ArgumentParser(description="Audit external-baseline wrapper status contract.")
    ap.add_argument("--root", default=None)
    ap.add_argument("--out", default="artifact/results/baseline_contract_audit.json")
    args = ap.parse_args()

    root = root_from_arg(args.root)
    problems: List[str] = []
    status_counts: Dict[str, Dict[str, int]] = {}
    applicable_counts: Dict[str, Dict[str, int]] = {}
    files_checked: List[str] = []

    for rel in PROBE_FILES:
        path = root / rel
        if not path.exists():
            problems.append(f"missing fixture-level external baseline probe: {rel}")
            continue
        files_checked.append(rel)
        rows = status_rows(read_json(path))
        if not rows:
            problems.append(f"baseline probe has no result rows: {rel}")
            continue
        by_baseline: Dict[str, Counter[str]] = defaultdict(Counter)
        for idx, row in enumerate(rows):
            baseline = str(row.get("baseline", ""))
            status = str(row.get("status", ""))
            if baseline not in EXTERNAL_BASELINES:
                problems.append(f"{rel} row {idx} uses non-external baseline id {baseline!r}")
            if status not in CANONICAL_STATUSES:
                problems.append(f"{rel} row {idx} uses non-canonical status {status!r}")
            text = " ".join(str(row.get(k, "")) for k in ("stdout", "stderr", "notes")).lower()
            if status in {"unavailable", "unsupported", "excluded", "error"} and "fallback substituted" in text and "no" not in text:
                problems.append(f"{rel} row {idx} appears to substitute project logic for unavailable baseline")
            if status == "available" and not str(row.get("stdout", "")) and not row.get("raw") and "flagged" not in row:
                problems.append(f"{rel} row {idx} is available but has neither raw stdout nor structured public-package output")
            by_baseline[baseline][status] += 1
        status_counts[rel] = {f"{b}:{s}": c for b, counter in sorted(by_baseline.items()) for s, c in sorted(counter.items())}
        applicable_counts[rel] = {b: counter.get("available", 0) + counter.get("unavailable", 0) + counter.get("error", 0) for b, counter in sorted(by_baseline.items())}

    for rel in AVAILABILITY_FILES:
        path = root / rel
        if not path.exists():
            problems.append(f"missing external baseline availability probe: {rel}")
            continue
        files_checked.append(rel)
        obj = read_json(path)
        packages = obj.get("packages", {}) if isinstance(obj, dict) else {}
        for baseline in ("csp_evaluator", "mdn_http_observatory", "chromium_hstspreload"):
            if baseline not in packages:
                # hstspreload availability may also be represented by tools_available.
                if baseline == "chromium_hstspreload" and isinstance(obj, dict) and "hstspreload_header_helper" in obj.get("tools_available", {}):
                    continue
                problems.append(f"{rel} lacks availability record for {baseline}")

    for rel in BASELINE_COMPARISON_FILES:
        path = root / rel
        if not path.exists():
            problems.append(f"missing baseline comparison table: {rel}")
            continue
        files_checked.append(rel)
        rows = read_csv(path)
        seen = {r.get("baseline", "") for r in rows}
        for baseline in ("csp_evaluator", "mdn_http_observatory", "chromium_hstspreload"):
            if baseline not in seen:
                problems.append(f"{rel} omits external baseline {baseline}")
        for row in rows:
            baseline = str(row.get("baseline", ""))
            notes = str(row.get("notes", "")).lower()
            if baseline in EXTERNAL_BASELINES and any(field in row and row[field] not in {"", None} for field in ("tp", "fp", "tn", "fn")):
                problems.append(f"{rel} maps external baseline {baseline} into semantic confusion counts without a declared oracle mapping")
            if baseline in EXTERNAL_BASELINES and "not remapped" not in notes:
                problems.append(f"{rel} external baseline {baseline} lacks scope-separation note")
            if baseline in INTERNAL_CONTROLS and "internal" not in notes.lower() and "criterion" not in baseline:
                problems.append(f"{rel} internal control {baseline} is not explicitly labeled as internal")

    result = {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "canonical_statuses": sorted(CANONICAL_STATUSES),
        "external_baselines": sorted(EXTERNAL_BASELINES),
        "files_checked": files_checked,
        "status_counts": status_counts,
        "applicable_counts": applicable_counts,
        "interpretation": "Checks that external baselines are wrapped under a canonical status contract, are probed at BEP-Deep scope, and are not replaced by project-internal logic when unavailable.",
    }
    out = root / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "problem_count": len(problems), "files_checked": len(files_checked)}, sort_keys=True))
    if problems:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
