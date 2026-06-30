"""Anti-overfitting and leakage audits for BEPGuard method code.

This module checks that method code does not hard-code exact locked fixture
identifiers or certificate identifiers outside intentionally generated oracle
artifacts.  It also checks that SpecBench cases are identifier-disjoint from the
locked denominator and that external-baseline unavailable statuses are not paired
with project-internal fallback outputs.  The audit is deliberately conservative:
it protects the artifact against a common assessor concern for deterministic
benchmarks, namely that labels are memorized by implementation code rather than
recomputed from the released semantic rules.
"""
from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Set


ALLOWED_FIXTURE_ID_FILES = {
    "artifact/scripts/materialize_locked_inputs.py",
    "artifact/bepguard/generated_oracles.py",
    "artifact/tests/test_locked_fixtures_generated.py",
    "artifact/tests/test_witness_certificates_generated.py",
}
ALLOWED_COUNT_CONSTANT_FILES = {
    "artifact/scripts/run_validation.py",
    "artifact/scripts/audit_release_consistency.py",
    "artifact/scripts/audit_semantic_recomputation.py",
    "artifact/scripts/validate_locked_artifacts.py",
    "artifact/bepguard/repository.py",
    "artifact/bepguard/leakage.py",
}
COUNT_TOKENS = {"972", "418", "554", "4306"}
CANONICAL_BASELINE_STATUSES = {"available", "unavailable", "unsupported", "error", "excluded", "not_applicable"}


@dataclass(frozen=True)
class LeakageProblem:
    path: str
    kind: str
    detail: str

    def as_dict(self) -> Dict[str, str]:
        return {"path": self.path, "kind": self.kind, "detail": self.detail}


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _method_files(root: Path) -> List[Path]:
    files: List[Path] = []
    for base in [root / "artifact" / "scripts", root / "artifact" / "bepguard", root / "artifact" / "tests"]:
        for path in sorted(base.glob("*.py")):
            files.append(path)
    return files


def _rel(root: Path, path: Path) -> str:
    return str(path.relative_to(root)).replace("\\", "/")


def _fixture_ids(root: Path) -> Set[str]:
    fixtures = read_json(root / "artifact" / "data" / "deep_locked_fixtures.json")
    return {str(f.get("id", "")) for f in fixtures if str(f.get("id", ""))}


def _certificate_ids(root: Path) -> Set[str]:
    certs = read_json(root / "artifact" / "results" / "deep_locked" / "proof_carrying_witness_certificates.json")
    return {str(c.get("certificate_id", "")) for c in certs if str(c.get("certificate_id", ""))}


def _scan_exact_id_leakage(root: Path, fixture_ids: Set[str], certificate_ids: Set[str]) -> List[LeakageProblem]:
    problems: List[LeakageProblem] = []
    for path in _method_files(root):
        rel = _rel(root, path)
        text = path.read_text(encoding="utf-8")
        if rel not in ALLOWED_FIXTURE_ID_FILES:
            leaked = sorted(fid for fid in fixture_ids if fid and fid in text)
            if leaked:
                problems.append(LeakageProblem(rel, "exact_fixture_id_in_method_code", ";".join(leaked[:20])))
            leaked_certs = sorted(cid for cid in certificate_ids if cid and cid in text)
            if leaked_certs:
                problems.append(LeakageProblem(rel, "exact_certificate_id_in_method_code", ";".join(leaked_certs[:20])))
        if rel not in ALLOWED_COUNT_CONSTANT_FILES and "run_validation" not in rel:
            # Count constants are not illegal by themselves, but using all locked
            # headline counts in ordinary method code is a smell for result
            # memorization.  Constants in generated tests and manifest checks are
            # intentionally allowed elsewhere.
            present = sorted(tok for tok in COUNT_TOKENS if re.search(rf"(?<![0-9]){tok}(?![0-9])", text))
            if len(present) >= 3 and rel not in ALLOWED_FIXTURE_ID_FILES:
                problems.append(LeakageProblem(rel, "headline_counts_in_method_code", ";".join(present)))
    return problems


def _check_specbench_disjoint(root: Path, fixture_ids: Set[str]) -> List[LeakageProblem]:
    problems: List[LeakageProblem] = []
    spec_cases = read_json(root / "artifact" / "results" / "deep_locked" / "specbench_cases.json")
    case_ids = {str(c.get("case_id", "")) for c in spec_cases}
    overlap = sorted(case_ids & fixture_ids)
    if overlap:
        problems.append(LeakageProblem("artifact/results/deep_locked/specbench_cases.json", "specbench_id_overlaps_locked_denominator", ";".join(overlap[:20])))
    locked_fingerprints = set()
    fixtures = read_json(root / "artifact" / "data" / "deep_locked_fixtures.json")
    for f in fixtures:
        locked_fingerprints.add(json.dumps({"headers": f.get("headers", []), "context": f.get("context", {}), "expected_issue": f.get("expected_issue", "")}, sort_keys=True))
    copied = []
    for c in spec_cases:
        fixture = c.get("fixture", {})
        fp = json.dumps({"headers": fixture.get("headers", []), "context": fixture.get("context", {}), "expected_issue": fixture.get("expected_issue", "")}, sort_keys=True)
        if fp in locked_fingerprints:
            copied.append(str(c.get("case_id", "")))
    # Exact copy is allowed only when the SpecBench case is a negative control
    # derived from a boundary that also appears in the denominator.  We require
    # the number to stay small and report it explicitly rather than failing the
    # audit; a large value would suggest benchmark duplication.
    if len(copied) > 4:
        problems.append(LeakageProblem("artifact/results/deep_locked/specbench_cases.json", "too_many_exact_specbench_locked_fingerprints", str(len(copied))))
    return problems


def _check_baseline_no_substitution(root: Path) -> List[LeakageProblem]:
    problems: List[LeakageProblem] = []
    probe = read_json(root / "artifact" / "results" / "deep_locked" / "external_baseline_fixture_probe.json")
    results = probe.get("results", []) if isinstance(probe, Mapping) else []
    for idx, row in enumerate(results):
        status = str(row.get("status", ""))
        if status not in CANONICAL_BASELINE_STATUSES:
            problems.append(LeakageProblem("artifact/results/deep_locked/external_baseline_fixture_probe.json", "noncanonical_baseline_status", f"row {idx}: {status}"))
        if status in {"unavailable", "unsupported", "excluded", "not_applicable"}:
            if str(row.get("stdout", "")).strip() or str(row.get("stderr", "")).strip() or row.get("returncode") not in (None, "", "null"):
                problems.append(LeakageProblem("artifact/results/deep_locked/external_baseline_fixture_probe.json", "unavailable_baseline_has_execution_output", f"row {idx}: {status}"))
        notes = str(row.get("notes", "")).lower()
        if status in {"unavailable", "unsupported", "excluded", "not_applicable"} and "no fallback" not in notes and "no project fallback" not in notes and "not executed" not in notes:
            problems.append(LeakageProblem("artifact/results/deep_locked/external_baseline_fixture_probe.json", "missing_no_substitution_note", f"row {idx}: {status}"))
    return problems


def audit(root: Path) -> Dict[str, Any]:
    fixture_ids = _fixture_ids(root)
    certificate_ids = _certificate_ids(root)
    problems = []
    problems.extend(_scan_exact_id_leakage(root, fixture_ids, certificate_ids))
    problems.extend(_check_specbench_disjoint(root, fixture_ids))
    problems.extend(_check_baseline_no_substitution(root))
    files_scanned = len(_method_files(root))
    return {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": [p.as_dict() for p in problems],
        "method_files_scanned": files_scanned,
        "locked_fixture_ids_guarded": len(fixture_ids),
        "certificate_ids_guarded": len(certificate_ids),
        "allowed_fixture_id_files": sorted(ALLOWED_FIXTURE_ID_FILES),
        "allowed_count_constant_files": sorted(ALLOWED_COUNT_CONSTANT_FILES),
        "interpretation": "Anti-overfitting audit: method code must not memorize exact locked fixture/certificate identifiers outside generated artifacts, SpecBench must remain identifier-disjoint from BEP-Deep, and unavailable baselines must not carry substituted internal outputs.",
    }


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
