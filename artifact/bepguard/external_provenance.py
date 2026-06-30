"""Strict external-comparator provenance and cache-exclusion audit."""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping

sys.dont_write_bytecode = True

FORBIDDEN_PARTS = {"node_modules", ".npm", ".cache", "npm-cache", "external_workdir", ".pnpm-store"}
FORBIDDEN_SUFFIXES = {".tgz", ".zip", ".tar", ".gz"}
TRANSIENT_TOKENS = {"_tmp", ".tmp", "cache", "node_modules"}


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def audit_external_provenance(root: Path) -> Dict[str, Any]:
    artifact = root / "artifact"
    problems: List[str] = []
    full = _read_json(artifact / "results" / "deep_locked" / "external_baseline_full_run.json")
    summary = _read_json(artifact / "results" / "external_baseline_full_run_audit.json")
    lock = _read_json(artifact / "external_baseline_package_lock.json")
    manifest = _read_csv(artifact / "external_package_manifest.csv")
    rows = full.get("rows", []) if isinstance(full, Mapping) else []
    if summary.get("rows_total") != len(rows):
        problems.append("external full-run summary row count does not match materialized rows")
    if summary.get("fixtures_evaluated") != 972:
        problems.append("external comparator does not cover all 972 fixtures")
    if summary.get("error_rows") != 0 or summary.get("unavailable_rows") != 0:
        problems.append("external comparator contains error or unavailable rows")
    if lock.get("node_modules_packaged") is not False or lock.get("cache_packaged") is not False or lock.get("node_workdir_packaged") is not False:
        problems.append("external package lock does not prove cache/node_modules exclusion")
    packages = lock.get("packages", [])
    if not isinstance(packages, list) or len(packages) < 3:
        problems.append("external package lock records fewer than three public packages")
    package_names = {str(p.get("package", p.get("name", ""))) for p in packages if isinstance(p, Mapping)}
    tools = {str(r.get("comparator", r.get("tool", r.get("baseline", "")))) for r in rows if isinstance(r, Mapping)}
    if len(tools) < 5:
        problems.append("external full run covers fewer than five comparator tasks")
    for i, row in enumerate(rows[:10]):
        if not any(k in row for k in ["comparator", "tool", "baseline"]):
            problems.append(f"external row {i} lacks comparator/tool/baseline field")
        if not any(k in row for k in ["fixture_id", "fixture", "id"]):
            problems.append(f"external row {i} lacks fixture identifier field")
    # Release-tree cache scan.  This is intentionally stricter than the clean
    # package check because dependency caches are easy to miss in artifact zips.
    cache_hits: List[str] = []
    for path in root.rglob("*"):
        rel = str(path.relative_to(root)).replace("\\", "/")
        parts = set(Path(rel).parts)
        if parts & FORBIDDEN_PARTS:
            cache_hits.append(rel)
        elif path.is_file() and any(path.name.endswith(s) for s in FORBIDDEN_SUFFIXES) and "paper" not in parts:
            cache_hits.append(rel)
    tmp_hits: List[str] = []
    for path in root.rglob("*"):
        if path.is_file():
            rel = str(path.relative_to(root)).replace("\\", "/")
            if any(tok in path.name.lower() for tok in TRANSIENT_TOKENS):
                tmp_hits.append(rel)
    if cache_hits:
        problems.append(f"dependency cache/package artifacts present: {cache_hits[:10]}")
    if tmp_hits:
        problems.append(f"transient/cache-named files present: {tmp_hits[:10]}")
    manifest_packages = {r.get("package", "") for r in manifest}
    if package_names and not any(name in manifest_packages for name in package_names):
        problems.append("external package manifest does not overlap package lock")
    return {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "rows_checked": len(rows),
        "fixtures_evaluated": summary.get("fixtures_evaluated"),
        "comparator_families": sorted(tools),
        "packages_locked": len(packages) if isinstance(packages, list) else 0,
        "manifest_rows": len(manifest),
        "cache_hits": cache_hits[:25],
        "transient_hits": tmp_hits[:25],
        "node_modules_packaged": lock.get("node_modules_packaged"),
        "cache_packaged": lock.get("cache_packaged"),
        "node_workdir_packaged": lock.get("node_workdir_packaged"),
        "interpretation": "Strict provenance audit for the materialized full public-package comparator execution; it verifies rows, package locks, caller-supplied package-workdir status, and absence of packaged dependency caches or transient probe files.",
    }


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
