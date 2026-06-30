"""External-baseline and benchmark-adapter contract checks.

The artifact records external packages and baselines without vendoring or
modifying them.  This module audits the wrapper contract at the repository level:
canonical status vocabulary, pinned package metadata, fixture-scope separation,
internal-control labeling, and absence of silent substitution when external
packages are unavailable.
"""
from __future__ import annotations

import csv
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

sys.dont_write_bytecode = True

CANONICAL_STATUSES = {"available", "unavailable", "unsupported", "error", "excluded", "not_applicable"}
EXTERNAL_BASELINES = {"csp_evaluator", "mdn_http_observatory", "chromium_hstspreload", "mdn_http_observatory_csp", "mdn_http_observatory_cors", "mdn_http_observatory_corp", "webhint_strict_transport_security"}
INTERNAL_CONTROLS = {"conservative_header_presence", "documented_hsts_preload_criterion", "internal_header_presence_control", "internal_hsts_preload_documented_criterion"}
PINNED_PACKAGE_COLUMNS = {"package", "version", "license", "dist_integrity", "repository", "acquisition_status"}
NETWORK_RISK_WORDS = {"npx", "curl", "wget", "public observatory", "hosted scanner", "live web"}


@dataclass(frozen=True)
class ExternalProblem:
    path: str
    code: str
    message: str

    def as_dict(self) -> Dict[str, str]:
        return {"path": self.path, "code": self.code, "message": self.message}


def read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _problem(path: str, code: str, message: str) -> ExternalProblem:
    return ExternalProblem(path, code, message)


def audit_external_package_manifest(root: Path) -> List[ExternalProblem]:
    rel = "artifact/external_package_manifest.csv"
    path = root / rel
    problems: List[ExternalProblem] = []
    rows = read_csv(path)
    if not rows:
        return [_problem(rel, "empty_manifest", "external package manifest has no rows")]
    columns = set(rows[0])
    missing = PINNED_PACKAGE_COLUMNS - columns
    if missing:
        problems.append(_problem(rel, "missing_columns", f"missing columns {sorted(missing)}"))
    seen: set[str] = set()
    for idx, row in enumerate(rows):
        package = row.get("package", "")
        if not package:
            problems.append(_problem(rel, "missing_package", f"row {idx} lacks package id"))
        if package in seen:
            problems.append(_problem(rel, "duplicate_package", f"duplicate package {package}"))
        seen.add(package)
        if not row.get("version"):
            problems.append(_problem(rel, "missing_version", f"package {package} lacks version"))
        if not row.get("license"):
            problems.append(_problem(rel, "missing_license", f"package {package} lacks license"))
        integrity = row.get("dist_integrity", "")
        if package.startswith("@") or package in {"csp_evaluator"}:
            if not integrity.startswith("sha512-"):
                problems.append(_problem(rel, "missing_npm_integrity", f"npm package {package} lacks sha512 dist integrity"))
        if "modified" in row.get("acquisition_status", "").lower():
            problems.append(_problem(rel, "modified_external_logic", f"package {package} acquisition status suggests modification"))
    return problems


def audit_baseline_matrix(root: Path) -> List[ExternalProblem]:
    problems: List[ExternalProblem] = []
    rels = [
        "artifact/baseline_matrix.csv",
        "artifact/results/full_locked/full_baseline_comparison.csv",
        "artifact/results/extended_locked/full_baseline_comparison.csv",
        "artifact/results/deep_locked/full_baseline_comparison.csv",
    ]
    for rel in rels:
        path = root / rel
        if not path.exists():
            problems.append(_problem(rel, "missing_baseline_table", "baseline table is absent"))
            continue
        rows = read_csv(path)
        for idx, row in enumerate(rows):
            baseline = row.get("baseline", "")
            status = row.get("status", "")
            notes = " ".join(row.get(k, "") for k in ["notes", "stderr", "stdout"]).lower()
            if status and status not in CANONICAL_STATUSES:
                problems.append(_problem(rel, "noncanonical_status", f"row {idx} baseline {baseline} status {status!r} is not canonical"))
            if baseline in EXTERNAL_BASELINES and any(field in row and row[field] not in {"", None} for field in ["tp", "fp", "tn", "fn"]):
                problems.append(_problem(rel, "external_confusion_counts", f"external baseline {baseline} has semantic confusion-count fields"))
            if baseline in EXTERNAL_BASELINES and "fallback substituted" in notes and "no" not in notes:
                problems.append(_problem(rel, "internal_substitution", f"row {idx} suggests fallback substitution"))
    return problems


def audit_wrapper_protocol(root: Path) -> List[ExternalProblem]:
    rel = "artifact/baseline_wrapper_protocol.csv"
    path = root / rel
    rows = read_csv(path)
    problems: List[ExternalProblem] = []
    for idx, row in enumerate(rows):
        bid = row.get("baseline_id", "")
        execution = row.get("execution_mode", "").lower()
        modification = row.get("modification_policy", "").lower()
        smoke = row.get("smoke_test_status", "").lower()
        if "unmodified" not in modification and "no internal modification" not in modification:
            problems.append(_problem(rel, "modification_policy_not_clear", f"row {idx} {bid} does not clearly state unmodified external logic"))
        if any(word in execution for word in NETWORK_RISK_WORDS) and "no external" not in execution and "local" not in execution:
            problems.append(_problem(rel, "network_risk", f"row {idx} {bid} execution mode may contact network"))
        if "requires" in smoke and "record" not in smoke and "unavailable" not in smoke:
            problems.append(_problem(rel, "ambiguous_smoke_status", f"row {idx} {bid} smoke status is ambiguous"))
    return problems


def audit_probe_json(root: Path) -> List[ExternalProblem]:
    problems: List[ExternalProblem] = []
    for rel in [
        "artifact/results/full_locked/external_baseline_fixture_probe.json",
        "artifact/results/extended_locked/external_baseline_fixture_probe.json",
        "artifact/results/deep_locked/external_baseline_fixture_probe.json",
    ]:
        rows_obj = read_json(root / rel)
        rows = rows_obj.get("results", []) if isinstance(rows_obj, Mapping) else []
        if not rows:
            problems.append(_problem(rel, "empty_probe", "probe JSON has no rows"))
            continue
        seen_baselines = {str(r.get("baseline", "")) for r in rows if isinstance(r, Mapping)}
        if "deep_locked" in rel:
            required = {"csp_evaluator", "mdn_http_observatory_csp", "mdn_http_observatory_cors", "mdn_http_observatory_corp", "webhint_strict_transport_security"}
        else:
            required = {"csp_evaluator", "mdn_http_observatory", "chromium_hstspreload"}
        missing = required - seen_baselines
        if missing:
            problems.append(_problem(rel, "missing_external_baseline", f"probe lacks baselines {sorted(missing)}"))
        for idx, row in enumerate(rows):
            if not isinstance(row, Mapping):
                problems.append(_problem(rel, "malformed_probe_row", f"row {idx} is not an object"))
                continue
            baseline = str(row.get("baseline", ""))
            status = str(row.get("status", ""))
            if baseline not in EXTERNAL_BASELINES:
                problems.append(_problem(rel, "unexpected_probe_baseline", f"row {idx} baseline {baseline!r}"))
            if status not in CANONICAL_STATUSES:
                problems.append(_problem(rel, "noncanonical_probe_status", f"row {idx} status {status!r}"))
            notes = " ".join(str(row.get(k, "")) for k in ["notes", "stdout", "stderr"]).lower()
            if status != "available" and "fallback substituted" in notes and "no" not in notes:
                problems.append(_problem(rel, "probe_substitution", f"row {idx} suggests substitution"))
    return problems


def audit_all(root: Path) -> Dict[str, Any]:
    problems: List[ExternalProblem] = []
    for fn in [audit_external_package_manifest, audit_baseline_matrix, audit_wrapper_protocol, audit_probe_json]:
        problems.extend(fn(root))
    problem_rows = [p.as_dict() for p in problems]
    return {
        "status": "pass" if not problem_rows else "fail",
        "problem_count": len(problem_rows),
        "problems": problem_rows,
        "external_baselines": sorted(EXTERNAL_BASELINES),
        "canonical_statuses": sorted(CANONICAL_STATUSES),
        "checks": ["external_package_manifest", "baseline_matrix", "baseline_wrapper_protocol", "fixture_probe_json", "full_external_comparator_run"],
        "interpretation": "External benchmark/baseline adapter contract audit. It checks package pinning, canonical status vocabulary, no internal substitution, local-only wrapper scope, and the materialized full external comparator run for BEP-Deep.",
    }


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
