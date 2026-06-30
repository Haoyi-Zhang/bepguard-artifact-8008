"""Metamorphic relations for BEP semantic-witness validation.

The locked workload verifies individual fixtures.  This module raises the audit
level by checking relations between fixtures: transformations that should
preserve semantic judgments, transformations that should repair specific issue
classes, and transformations that should remain inside the source/intent
boundary.  These checks are deterministic and generated from released inputs.
"""
from __future__ import annotations

import copy
import csv
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

sys.dont_write_bytecode = True


def _import_semantics(root: Path):
    scripts = root / "artifact" / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import bep_semantics  # type: ignore
    return bep_semantics


@dataclass(frozen=True)
class Relation:
    relation_id: str
    description: str
    kind: str
    transform: Callable[[Mapping[str, Any]], Mapping[str, Any]]
    applicable: Callable[[Mapping[str, Any]], bool]
    expected: Callable[[Tuple[str, ...], Tuple[str, ...]], bool]


@dataclass(frozen=True)
class RelationResult:
    relation_id: str
    fixture_id: str
    kind: str
    before_issues: Tuple[str, ...]
    after_issues: Tuple[str, ...]
    passed: bool
    description: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "relation_id": self.relation_id,
            "fixture_id": self.fixture_id,
            "kind": self.kind,
            "before_issues": list(self.before_issues),
            "after_issues": list(self.after_issues),
            "passed": self.passed,
            "description": self.description,
        }


def issue_signature(findings: Iterable[Any]) -> Tuple[str, ...]:
    issues: List[str] = []
    for finding in findings:
        if hasattr(finding, "issue"):
            issues.append(str(getattr(finding, "issue")))
        elif isinstance(finding, Mapping):
            issues.append(str(finding.get("issue", "")))
    return tuple(sorted(i for i in issues if i))


def _copy_fixture(fixture: Mapping[str, Any]) -> Dict[str, Any]:
    result = copy.deepcopy(dict(fixture))
    result.pop("fixture_hash", None)
    result["id"] = str(result.get("id", "fixture")) + "__MR"
    return result


def _headers(fixture: MutableMapping[str, Any]) -> List[Dict[str, str]]:
    headers = fixture.get("headers", [])
    if not isinstance(headers, list):
        fixture["headers"] = []
        return fixture["headers"]  # type: ignore[return-value]
    return headers  # type: ignore[return-value]


def lower_header_names(fixture: Mapping[str, Any]) -> Mapping[str, Any]:
    clone = _copy_fixture(fixture)
    for header in _headers(clone):
        header["name"] = str(header.get("name", "")).lower()
    for layer in clone.get("layers", []) if isinstance(clone.get("layers", []), list) else []:
        if isinstance(layer, dict):
            for header in layer.get("headers", []) if isinstance(layer.get("headers", []), list) else []:
                if isinstance(header, dict):
                    header["name"] = str(header.get("name", "")).lower()
    return clone


def add_ignored_header(fixture: Mapping[str, Any]) -> Mapping[str, Any]:
    clone = _copy_fixture(fixture)
    _headers(clone).append({"name": "X-BEPGuard-Ignored", "value": "1"})
    return clone


def add_reporting_header(fixture: Mapping[str, Any]) -> Mapping[str, Any]:
    clone = _copy_fixture(fixture)
    _headers(clone).append({"name": "Report-To", "value": "{\"group\":\"default\",\"max_age\":60,\"endpoints\":[]}"})
    return clone


def reorder_flat_headers(fixture: Mapping[str, Any]) -> Mapping[str, Any]:
    clone = _copy_fixture(fixture)
    headers = _headers(clone)
    clone["headers"] = list(reversed(headers))
    return clone


def normalize_context_order(fixture: Mapping[str, Any]) -> Mapping[str, Any]:
    clone = _copy_fixture(fixture)
    ctx = clone.get("context", {})
    if isinstance(ctx, dict):
        clone["context"] = {k: ctx[k] for k in sorted(ctx)}
    return clone


def add_vary_origin_for_cache(fixture: Mapping[str, Any]) -> Mapping[str, Any]:
    clone = _copy_fixture(fixture)
    _headers(clone).append({"name": "Vary", "value": "Origin"})
    return clone


def enforce_report_only_csp(fixture: Mapping[str, Any]) -> Mapping[str, Any]:
    clone = _copy_fixture(fixture)
    headers = _headers(clone)
    for header in headers:
        if str(header.get("name", "")).lower() == "content-security-policy-report-only":
            header["name"] = "Content-Security-Policy"
    return clone


def add_corp_cross_origin(fixture: Mapping[str, Any]) -> Mapping[str, Any]:
    clone = _copy_fixture(fixture)
    _headers(clone).append({"name": "Cross-Origin-Resource-Policy", "value": "cross-origin"})
    return clone


def complete_hsts_preload(fixture: Mapping[str, Any]) -> Mapping[str, Any]:
    clone = _copy_fixture(fixture)
    headers = _headers(clone)
    found = False
    for header in headers:
        if str(header.get("name", "")).lower() == "strict-transport-security":
            header["value"] = "max-age=63072000; includeSubDomains; preload"
            found = True
    if not found:
        headers.append({"name": "Strict-Transport-Security", "value": "max-age=63072000; includeSubDomains; preload"})
    return clone


def make_permissions_specific(fixture: Mapping[str, Any]) -> Mapping[str, Any]:
    clone = _copy_fixture(fixture)
    for header in _headers(clone):
        if str(header.get("name", "")).lower() == "permissions-policy":
            header["value"] = "geolocation=(self)"
    return clone


def always(_: Mapping[str, Any]) -> bool:
    return True


def has_issue(issue: str) -> Callable[[Mapping[str, Any]], bool]:
    def _pred(fixture: Mapping[str, Any]) -> bool:
        return str(fixture.get("expected_issue", "")) == issue
    return _pred


def has_intent(intent: str) -> Callable[[Mapping[str, Any]], bool]:
    def _pred(fixture: Mapping[str, Any]) -> bool:
        raw = fixture.get("intent", {})
        return isinstance(raw, Mapping) and str(raw.get("class", "")) == intent
    return _pred


def same(before: Tuple[str, ...], after: Tuple[str, ...]) -> bool:
    return before == after


def removes(issue: str) -> Callable[[Tuple[str, ...], Tuple[str, ...]], bool]:
    def _expected(before: Tuple[str, ...], after: Tuple[str, ...]) -> bool:
        return issue in before and issue not in after
    return _expected


def no_new_issues(before: Tuple[str, ...], after: Tuple[str, ...]) -> bool:
    return set(after).issubset(set(before))


def default_relations() -> List[Relation]:
    return [
        Relation("MR_PRESERVE_HEADER_NAME_CASE", "HTTP header-name case is canonicalized before semantic lookup", "preservation", lower_header_names, always, same),
        Relation("MR_PRESERVE_IRRELEVANT_HEADER", "Unknown non-security headers do not change modeled BEP decisions", "preservation", add_ignored_header, always, same),
        Relation("MR_PRESERVE_REPORTING_HEADER", "Report-To metadata is not an enforcement surface in the encoded fragment", "preservation", add_reporting_header, always, same),
        Relation("MR_PRESERVE_CONTEXT_KEY_ORDER", "Context object key order is not semantic", "preservation", normalize_context_order, always, same),
        Relation("MR_REPAIR_REPORT_ONLY_TO_ENFORCED", "Changing report-only CSP to enforced CSP removes report-only nonenforcement witness", "repair", enforce_report_only_csp, has_issue("csp_report_only_not_enforced"), removes("csp_report_only_not_enforced")),
        Relation("MR_REPAIR_CORS_CACHE_VARY", "Adding Vary: Origin removes dynamic CORS cache drift", "repair", add_vary_origin_for_cache, has_issue("cors_dynamic_origin_without_vary"), removes("cors_dynamic_origin_without_vary")),
        Relation("MR_REPAIR_COEP_CORP", "Adding CORP cross-origin opts resource into COEP require-corp", "repair", add_corp_cross_origin, has_issue("coep_require_corp_blocks_cross_origin_resource"), removes("coep_require_corp_blocks_cross_origin_resource")),
        Relation("MR_REPAIR_HSTS_PRELOAD", "Completing preload-oriented STS header removes preload-criterion witness", "repair", complete_hsts_preload, has_issue("hsts_preload_criteria_not_met"), removes("hsts_preload_criteria_not_met")),
        Relation("MR_REPAIR_PERMISSIONS_SPECIFIC", "Replacing wildcard Permissions-Policy with self-scoped allowlist removes overallowance witness", "repair", make_permissions_specific, has_issue("permissions_policy_feature_overallowed"), removes("permissions_policy_feature_overallowed")),
    ]


def run_relations(root: Path, fixtures: Sequence[Mapping[str, Any]], limit_per_relation: Optional[int] = None) -> List[RelationResult]:
    semantics = _import_semantics(root)
    results: List[RelationResult] = []
    for relation in default_relations():
        checked = 0
        for fixture in fixtures:
            if not relation.applicable(fixture):
                continue
            before = issue_signature(semantics.analyze_fixture(dict(fixture)))
            transformed = relation.transform(fixture)
            after = issue_signature(semantics.analyze_fixture(dict(transformed)))
            passed = relation.expected(before, after)
            results.append(RelationResult(
                relation_id=relation.relation_id,
                fixture_id=str(fixture.get("id", "")),
                kind=relation.kind,
                before_issues=before,
                after_issues=after,
                passed=passed,
                description=relation.description,
            ))
            checked += 1
            if limit_per_relation is not None and checked >= limit_per_relation:
                break
    return results


def summarize(results: Sequence[RelationResult]) -> Dict[str, Any]:
    failures = [r.as_dict() for r in results if not r.passed]
    by_relation: Dict[str, int] = {}
    by_kind: Dict[str, int] = {}
    for r in results:
        by_relation[r.relation_id] = by_relation.get(r.relation_id, 0) + 1
        by_kind[r.kind] = by_kind.get(r.kind, 0) + 1
    return {
        "status": "pass" if not failures else "fail",
        "problem_count": len(failures),
        "relations": len(by_relation),
        "checks": len(results),
        "passed_checks": sum(1 for r in results if r.passed),
        "checks_by_kind": dict(sorted(by_kind.items())),
        "checks_by_relation": dict(sorted(by_relation.items())),
        "failures": failures[:50],
        "interpretation": "Metamorphic validation over released BEP-Deep fixtures. Preservation relations check oracle invariances; repair relations check targeted semantic counterfactuals without changing the locked denominator.",
    }


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: Sequence[RelationResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        fieldnames = ["relation_id", "fixture_id", "kind", "before_issues", "after_issues", "passed", "description"]
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for result in rows:
            row = result.as_dict()
            row["before_issues"] = ";".join(result.before_issues)
            row["after_issues"] = ";".join(result.after_issues)
            writer.writerow(row)
