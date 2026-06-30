"""Rule-maturity and source-obligation closure audit for BEPGuard."""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Set

sys.dont_write_bytecode = True

ALLOWED_STATUS_PREFIXES = ("encoded", "baseline_scope_record")
LEDGER_ALIASES = [
    "artifact/data/rule_source_ledger.csv",
    "artifact/data/rule_to_source_ledger.csv",
    "artifact/method/rule_to_source_ledger.csv",
    "artifact/method/source_rule_ledger.csv",
    "artifact/rule_source_ledger.csv",
]

# SpecBench uses more specific proof-obligation names for several source-ledger rules.
SPECBENCH_ALIASES = {
    "R_CSP_REPORT_ONLY_MONITOR": {"R_CSP_REPORT_ONLY_MONITOR"},
    "R_CSP_DEFAULT_SRC_FALLBACK": {"R_CSP_DEFAULT_SRC_FALLBACK"},
    "R_CSP_SCRIPT_SRC_OVERRIDES_DEFAULT": {"R_CSP_SCRIPT_SRC_OVERRIDES_DEFAULT"},
    "R_CSP_NONCE_UNIQUE_PER_TRANSMISSION": {"R_CSP_NONCE_PER_REQUEST"},
    "R_CSP_MULTIPLE_POLICIES_RESTRICT": {"R_CSP_MULTIPLE_POLICY_INTERSECTION"},
    "R_CORS_WILDCARD_CREDENTIALS_NOT_SHAREABLE": {"R_CORS_CREDENTIALS_WILDCARD"},
    "R_CORS_SPECIFIC_ORIGIN_CREDENTIALS_SHAREABLE": {"R_CORS_CREDENTIALS_EXACT_ORIGIN", "R_CORS_ACAC_CASE_SENSITIVE"},
    "R_CORS_DYNAMIC_ACAO_NEEDS_VARY": {"R_CORS_DYNAMIC_ORIGIN_VARY"},
    "R_HSTS_IGNORE_INSECURE_TRANSPORT": {"R_HSTS_HTTPS_ONLY_PROCESSING"},
    "R_HSTS_MAX_AGE_ZERO_CLEARS": {"R_HSTS_ZERO_MAX_AGE_CLEARS"},
    "R_HSTS_INVALID_HEADER_IGNORED": {"R_HSTS_MAX_AGE_PARSE"},
    "R_COEP_REQUIRE_CORP_NO_CORS": {"R_COEP_REQUIRE_CORP_NO_CORS"},
    "R_COEP_CORS_MODE_COMPATIBLE": {"R_COEP_CORS_MODED_OPT_IN"},
    "R_COOP_SAME_ORIGIN_FOR_ISOLATION": {"R_COOP_COEP_ISOLATION_JOINT"},
    "R_COOP_UNSAFE_NONE_DEFAULT": {"R_COOP_COEP_ISOLATION_JOINT"},
    "R_PERMISSIONS_POLICY_ALLOWLIST": {"R_PERMISSIONS_POLICY_FEATURE_SPECIFIC"},
    "R_PERMISSIONS_POLICY_EMPTY_DISABLES": {"R_PERMISSIONS_POLICY_EMPTY_ALLOWLIST"},
    "R_EXPRESS_CORS_REFLECT_ORIGIN": {"R_CORS_REFLECTED_ORIGIN_CREDENTIALS"},
    "R_CSP_CONJUNCTIVE_COMPOSITION": {"R_CSP_MULTIPLE_POLICY_INTERSECTION"},
    "R_LAYERED_HEADER_SURFACE": {"R_CSP_MULTIPLE_POLICY_INTERSECTION"},
    "R_CORS_DYNAMIC_ORIGIN_VARY": {"R_CORS_DYNAMIC_ORIGIN_VARY"},
    "R_HSTS_INCLUDE_SUBDOMAINS_SCOPE": {"R_HSTS_INCLUDE_SUBDOMAINS_SCOPE", "R_HSTS_PRELOAD_CRITERION"},
}

FRAMEWORK_RULE_GROUPS = {
    "R_HELMET_CSP_DEFAULT_MERGE": "layered_policy_composition",
    "R_HELMET_REPORT_ONLY": "csp_report_only_not_enforced",
    "R_HELMET_COEP_NOT_DEFAULT": "cross_origin_isolation_incomplete",
    "R_DJANGO_HSTS_HTTPS_ONLY": "hsts_header_not_honored_over_http",
    "R_SPRING_CSP_CONTEXT_REQUIRED": "csp_report_only_not_enforced",
    "R_RAILS_REPORT_ONLY_MIGRATION": "csp_report_only_not_enforced",
    "R_RAILS_NONCE_CACHE_TRADEOFF": "nonce_csp_static_render_incompatibility",
    "R_EXPRESS_CORS_NOT_AUTHORIZATION": "cors_reflected_origin_with_credentials",
}


def read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _split_rule_ids(value: str) -> Set[str]:
    return {part.strip() for part in value.replace(",", ";").split(";") if part.strip()}


def audit_rule_closure(root: Path) -> Dict[str, Any]:
    problems: List[str] = []
    ledgers = {rel: read_csv(root / rel) for rel in LEDGER_ALIASES}
    canonical = ledgers["artifact/data/rule_source_ledger.csv"]
    canonical_ids = [r.get("rule_id", "") for r in canonical]
    if len(canonical_ids) != len(set(canonical_ids)):
        problems.append("canonical rule ledger has duplicate rule identifiers")
    canonical_by_id = {r.get("rule_id", ""): r for r in canonical}
    for rel, rows in ledgers.items():
        ids = [r.get("rule_id", "") for r in rows]
        if set(ids) != set(canonical_ids):
            problems.append(f"rule ledger alias mismatch: {rel}")
        for rid in set(ids) & set(canonical_ids):
            if next(r for r in rows if r.get("rule_id") == rid).get("encoded_status") != canonical_by_id[rid].get("encoded_status"):
                problems.append(f"encoded_status alias mismatch for {rid} in {rel}")
    status_counts = Counter(r.get("encoded_status", "") for r in canonical)
    for r in canonical:
        status = r.get("encoded_status", "")
        rid = r.get("rule_id", "")
        if not status.startswith(ALLOWED_STATUS_PREFIXES):
            problems.append(f"unresolved rule maturity status for {rid}: {status}")
        if "planned" in status.lower():
            problems.append(f"planned rule remains in release ledger: {rid}")
    claims = read_csv(root / "artifact/data/corpus_claims.csv")
    claim_rule_ids: Set[str] = set()
    for row in claims:
        claim_rule_ids.update(_split_rule_ids(row.get("semantic_rule_ids", "")))
    fixture_rows = read_json(root / "artifact/data/deep_locked_fixtures.json")
    issue_counts = Counter(str(f.get("expected_issue", "none")) for f in fixture_rows if str(f.get("expected_issue", "none")) != "none")
    spec_cases = read_json(root / "artifact/results/deep_locked/specbench_cases.json")
    spec_ids = {str(c.get("rule_id", "")) for c in spec_cases}
    covered_rows: List[Dict[str, Any]] = []
    for r in canonical:
        rid = r.get("rule_id", "")
        status = r.get("encoded_status", "")
        if status == "baseline_scope_record":
            coverage = "baseline-scope-contract"
        elif rid in claim_rule_ids:
            coverage = "claim-ledger"
        else:
            coverage = "semantic-ledger"
        spec_aliases = SPECBENCH_ALIASES.get(rid, set())
        spec_covered = sorted(spec_aliases & spec_ids)
        framework_issue = FRAMEWORK_RULE_GROUPS.get(rid, "")
        fixture_covered = issue_counts.get(framework_issue, 0) if framework_issue else 0
        if status != "baseline_scope_record" and not spec_covered and fixture_covered == 0 and rid not in claim_rule_ids:
            problems.append(f"no executable or claim-linked coverage evidence for rule {rid}")
        covered_rows.append({
            "rule_id": rid,
            "encoded_status": status,
            "coverage_class": coverage,
            "specbench_aliases": spec_covered,
            "fixture_issue_class": framework_issue,
            "fixture_issue_count": fixture_covered,
        })
    return {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "rules_checked": len(canonical),
        "status_counts": dict(sorted(status_counts.items())),
        "ledger_aliases_checked": len(LEDGER_ALIASES),
        "rules_with_planned_status": sum(1 for r in canonical if "planned" in r.get("encoded_status", "").lower()),
        "specbench_rule_aliases_observed": len(spec_ids),
        "positive_issue_classes_observed": len(issue_counts),
        "coverage_rows": covered_rows,
        "interpretation": "Rule maturity closure: no release denominator rule may remain as a future-plan marker; every non-baseline rule is linked to claim, fixture, SpecBench, or explicit framework-boundary coverage.",
    }


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
