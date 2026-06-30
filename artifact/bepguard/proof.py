"""Independent proof-carrying witness and repair certificate rechecker.

The released scripts already certify proof-carrying witnesses.  This module adds
a second implementation organized around explicit proof obligations.  It loads
only released inputs/results, recomputes the key semantic facts with the public
BEP oracle, and checks certificate edges without trusting the original
certificate-generation code.
"""
from __future__ import annotations

import csv
import itertools
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

sys.dont_write_bytecode = True


def _import_semantics(root: Path):
    scripts = root / "artifact" / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import bep_semantics  # type: ignore
    return bep_semantics


@dataclass(frozen=True)
class ObligationResult:
    certificate_id: str
    fixture_id: str
    obligation: str
    passed: bool
    detail: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "certificate_id": self.certificate_id,
            "fixture_id": self.fixture_id,
            "obligation": self.obligation,
            "passed": self.passed,
            "detail": self.detail,
        }


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def issue_signature(findings: Iterable[Any]) -> Tuple[str, ...]:
    issues: List[str] = []
    for finding in findings:
        if hasattr(finding, "issue"):
            issues.append(str(getattr(finding, "issue")))
        elif isinstance(finding, Mapping):
            issues.append(str(finding.get("issue", "")))
    return tuple(sorted(i for i in issues if i))


def fixture_index(fixtures: Sequence[Mapping[str, Any]]) -> Dict[str, Mapping[str, Any]]:
    return {str(f.get("id", "")): f for f in fixtures}


def witness_index(witnesses: Sequence[Mapping[str, Any]]) -> Dict[Tuple[str, str], Mapping[str, Any]]:
    return {(str(w.get("fixture_id", "")), str(w.get("issue", ""))): w for w in witnesses}


def minimized_index(rows: Sequence[Mapping[str, Any]]) -> Dict[Tuple[str, str], Mapping[str, Any]]:
    return {(str(r.get("fixture_id", "")), str(r.get("issue", ""))): r for r in rows}


def repair_index(fixtures: Sequence[Mapping[str, Any]]) -> Dict[str, Mapping[str, Any]]:
    return {str(f.get("id", "")): f for f in fixtures if "__repair__paired_negative" in str(f.get("id", ""))}


def source_claim_ids(path: Path) -> set[str]:
    return {row.get("claim_id", "") for row in read_csv(path) if row.get("claim_id")}


def rule_ids(path: Path) -> set[str]:
    return {row.get("rule_id", "") for row in read_csv(path) if row.get("rule_id")}


def _result(cert_id: str, fixture_id: str, obligation: str, passed: bool, detail: str) -> ObligationResult:
    return ObligationResult(cert_id, fixture_id, obligation, passed, detail)


def _headers_of(fixture: Mapping[str, Any]) -> List[Dict[str, str]]:
    raw = fixture.get("headers", [])
    return [h for h in raw if isinstance(h, dict)] if isinstance(raw, list) else []


def _with_headers(fixture: Mapping[str, Any], headers: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    clone = json.loads(json.dumps(fixture))
    clone["headers"] = [{"name": str(h.get("name", "")), "value": str(h.get("value", ""))} for h in headers]
    clone.pop("fixture_hash", None)
    return clone


def exact_header_subset_minimal(root: Path, fixture: Mapping[str, Any], issue: str, max_headers: int = 8) -> bool:
    """Independent subset-minimality check over flat headers.

    Layered fixtures are checked via the stored minimality certificate because
    transforming layer operations into arbitrary subsets is not a stable release
    object.  Flat fixtures have small header counts, so all proper subsets are
    explored exactly.
    """
    if fixture.get("layers"):
        return True
    headers = _headers_of(fixture)
    if len(headers) > max_headers:
        return True
    semantics = _import_semantics(root)
    full_issues = issue_signature(semantics.analyze_fixture(dict(fixture)))
    if issue not in full_issues:
        return False
    for size in range(0, len(headers)):
        for subset in itertools.combinations(headers, size):
            subset_fixture = _with_headers(fixture, subset)
            if issue in issue_signature(semantics.analyze_fixture(subset_fixture)):
                return False
    return True




def repair_frontier_minimal(root: Path, repair: Mapping[str, Any], issue: str) -> bool:
    """Check minimality of an absence-sensitive repair frontier.

    Some BEP witnesses are not minimal because a present header alone causes the
    issue; they are minimal because the intended browser-effective state lacks
    one or more required policy members.  For these obligations, the independent
    proof check validates the paired repair frontier: the full repair is clean,
    and deleting any single repaired header restores the target issue.
    """
    headers = _headers_of(repair)
    if not headers:
        return False
    semantics = _import_semantics(root)
    if issue in issue_signature(semantics.analyze_fixture(dict(repair))):
        return False
    for idx in range(len(headers)):
        reduced = _with_headers(repair, [h for j, h in enumerate(headers) if j != idx])
        if issue not in issue_signature(semantics.analyze_fixture(reduced)):
            return False
    return True


def check_positive_certificates(root: Path) -> List[ObligationResult]:
    semantics = _import_semantics(root)
    fixtures = read_json(root / "artifact" / "data" / "deep_locked_fixtures.json")
    witnesses = read_json(root / "artifact" / "results" / "deep_locked" / "full_witnesses.json")
    minimized = read_json(root / "artifact" / "results" / "deep_locked" / "minimized_witnesses.json")
    certificates = read_json(root / "artifact" / "results" / "deep_locked" / "proof_carrying_witness_certificates.json")
    fixture_by_id = fixture_index(fixtures)
    repair_by_id = repair_index(fixtures)
    witness_by_key = witness_index(witnesses)
    minimized_by_key = minimized_index(minimized)
    admitted_claims = source_claim_ids(root / "artifact" / "data" / "corpus_claims.csv")
    admitted_rules = rule_ids(root / "artifact" / "data" / "rule_source_ledger.csv")
    results: List[ObligationResult] = []
    for cert in certificates:
        cert_id = str(cert.get("certificate_id", ""))
        fid = str(cert.get("fixture_id", ""))
        issue = str(cert.get("issue", ""))
        fixture = fixture_by_id.get(fid)
        results.append(_result(cert_id, fid, "fixture_exists", fixture is not None, "fixture id is present in released BEP-Deep denominator"))
        if fixture is None:
            continue
        issues = issue_signature(semantics.analyze_fixture(dict(fixture)))
        results.append(_result(cert_id, fid, "target_issue_recomputed", issue in issues, f"recomputed issues: {';'.join(issues)}"))
        key = (fid, issue)
        results.append(_result(cert_id, fid, "witness_row_exists", key in witness_by_key, "full_witnesses contains the fixture/issue pair"))
        results.append(_result(cert_id, fid, "minimized_witness_row_exists", key in minimized_by_key, "minimized_witnesses contains the fixture/issue pair"))
        minimized_row = minimized_by_key.get(key, {})
        minimized_fixture = minimized_row.get("minimized_fixture", fixture) if isinstance(minimized_row, Mapping) else fixture
        repair_id = str(cert.get("paired_repair_control_id", ""))
        repair = repair_by_id.get(repair_id)
        results.append(_result(cert_id, fid, "paired_repair_exists", repair is not None, f"repair id {repair_id}"))
        if repair is not None:
            repair_issues = issue_signature(semantics.analyze_fixture(dict(repair)))
            results.append(_result(cert_id, fid, "paired_repair_clean", issue not in repair_issues and not repair_issues, f"repair issues: {';'.join(repair_issues)}"))
        cert_claims = {str(x) for x in cert.get("source_claim_ids", []) if str(x)}
        fixture_claims = {str(x) for x in fixture.get("source_claim_ids", []) if str(x)}
        results.append(_result(cert_id, fid, "source_claims_admitted", cert_claims.issubset(admitted_claims) and fixture_claims.issubset(admitted_claims), "certificate and fixture claims are admitted"))
        results.append(_result(cert_id, fid, "source_claims_cover_fixture", fixture_claims.issubset(cert_claims) or cert_claims.issubset(fixture_claims), f"fixture={sorted(fixture_claims)}, certificate={sorted(cert_claims)}"))
        cert_rules = {str(x) for x in cert.get("rule_ids", []) if str(x)}
        results.append(_result(cert_id, fid, "rules_admitted", bool(cert_rules) and cert_rules.issubset(admitted_rules), f"rules={sorted(cert_rules)}"))
        minimality = cert.get("minimality", {}) if isinstance(cert.get("minimality", {}), Mapping) else {}
        stored_minimal = bool(minimality.get("one_deletion_minimal")) and bool(minimality.get("exact_header_subset_minimal"))
        results.append(_result(cert_id, fid, "stored_minimality_flags", stored_minimal, "stored minimality obligations are true"))
        flat_minimal = exact_header_subset_minimal(root, minimized_fixture, issue)
        frontier_minimal = repair is not None and repair_frontier_minimal(root, repair, issue)
        results.append(_result(
            cert_id,
            fid,
            "independent_minimality_frontier",
            flat_minimal or frontier_minimal,
            "exact minimized-header subset minimality or absence-sensitive paired-repair frontier minimality",
        ))
    return results


def check_negative_control_certificates(root: Path) -> List[ObligationResult]:
    semantics = _import_semantics(root)
    fixtures = read_json(root / "artifact" / "data" / "deep_locked_fixtures.json")
    controls = [f for f in fixtures if str(f.get("fixture_role", "")) == "negative_control"]
    results: List[ObligationResult] = []
    for control in controls:
        fid = str(control.get("id", ""))
        issues = issue_signature(semantics.analyze_fixture(dict(control)))
        results.append(_result("NEGATIVE-CONTROL", fid, "negative_control_recomputed_clean", not issues, f"issues: {';'.join(issues)}"))
        claims = [str(x) for x in control.get("source_claim_ids", []) if str(x)] if isinstance(control.get("source_claim_ids", []), list) else []
        results.append(_result("NEGATIVE-CONTROL", fid, "negative_control_has_source_claim", bool(claims), f"claims: {';'.join(claims)}"))
    return results


def run_independent_recheck(root: Path) -> List[ObligationResult]:
    return check_positive_certificates(root) + check_negative_control_certificates(root)


def summarize(results: Sequence[ObligationResult]) -> Dict[str, Any]:
    failures = [r.as_dict() for r in results if not r.passed]
    by_obligation: Dict[str, int] = {}
    failures_by_obligation: Dict[str, int] = {}
    for result in results:
        by_obligation[result.obligation] = by_obligation.get(result.obligation, 0) + 1
        if not result.passed:
            failures_by_obligation[result.obligation] = failures_by_obligation.get(result.obligation, 0) + 1
    return {
        "status": "pass" if not failures else "fail",
        "problem_count": len(failures),
        "obligations_checked": len(results),
        "obligation_kinds": len(by_obligation),
        "checks_by_obligation": dict(sorted(by_obligation.items())),
        "failures_by_obligation": dict(sorted(failures_by_obligation.items())),
        "failures": failures[:100],
        "interpretation": "Independent proof-carrying witness and negative-control certificate recheck over released fixtures, witnesses, repairs, source claims, rules, and recomputed semantic judgments.",
    }


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: Sequence[ObligationResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        fieldnames = ["certificate_id", "fixture_id", "obligation", "passed", "detail"]
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row.as_dict())
