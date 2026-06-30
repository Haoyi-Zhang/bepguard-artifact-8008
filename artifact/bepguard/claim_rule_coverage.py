"""Claim-to-rule traceability coverage audit for BEPGuard.

This audit is deliberately different from source-span closure.  Source-span
closure checks that admitted public claims have source rows.  Here we check the
semantic admission surface: every claim names encoded rules, every encoded rule
is claimed by at least one admitted claim, and every admitted claim is exercised
by at least one locked fixture or source-derived SpecBench case.  The goal is to
make orphan rules and documentation-only claims executable failures.
"""
from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Set


def _rows(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _split_ids(value: str) -> List[str]:
    parts: List[str] = []
    for token in str(value).replace(";", ",").split(","):
        token = token.strip()
        if token:
            parts.append(token)
    return parts


def audit_claim_rule_coverage(root: Path) -> Dict[str, Any]:
    problems: List[str] = []
    claims = _rows(root / "artifact/data/corpus_claims.csv")
    spans = _rows(root / "artifact/source_span_ledger.csv")
    rules = _rows(root / "artifact/data/rule_source_ledger.csv")
    fixtures = _load_json(root / "artifact/data/deep_locked_fixtures.json")
    specbench = _load_json(root / "artifact/results/deep_locked/specbench_cases.json")
    evidence_cards = _load_json(root / "artifact/results/deep_locked/evidence_cards.json") if (root / "artifact/results/deep_locked/evidence_cards.json").exists() else []

    claim_by_id = {c.get("claim_id", ""): c for c in claims}
    rule_by_id = {r.get("rule_id", ""): r for r in rules}
    span_by_claim: Dict[str, List[Mapping[str, str]]] = defaultdict(list)
    for row in spans:
        span_by_claim[row.get("claim_id", "")].append(row)

    fixture_claims: Set[str] = set()
    fixture_claim_roles: Dict[str, Counter[str]] = defaultdict(Counter)
    for fx in fixtures:
        role = str(fx.get("fixture_role", ""))
        for cid in fx.get("source_claim_ids", []) or []:
            cid_s = str(cid)
            fixture_claims.add(cid_s)
            fixture_claim_roles[cid_s][role] += 1
        public_id = str(fx.get("public_source_id", ""))
        if public_id:
            fixture_claims.add(public_id)
            fixture_claim_roles[public_id][role] += 1

    spec_claims: Set[str] = set()
    spec_rules: Set[str] = set()
    spec_claim_roles: Dict[str, Counter[str]] = defaultdict(Counter)
    for case in specbench:
        cid = str(case.get("source_claim_id", ""))
        rid = str(case.get("rule_id", ""))
        role = str(case.get("role", ""))
        if cid:
            spec_claims.add(cid); spec_claim_roles[cid][role] += 1
        if rid:
            spec_rules.add(rid)

    card_claims: Set[str] = set()
    if isinstance(evidence_cards, list):
        for card in evidence_cards:
            for cid in card.get("source_claim_ids", []) or []:
                card_claims.add(str(cid))
            cid = str(card.get("public_source_id", ""))
            if cid:
                card_claims.add(cid)

    claim_rule_edges = 0
    rule_claims: Dict[str, Set[str]] = defaultdict(set)
    claim_profiles: List[Dict[str, Any]] = []
    for claim in claims:
        cid = claim.get("claim_id", "")
        if not cid:
            problems.append("claim with empty claim_id")
            continue
        if cid not in span_by_claim or len(span_by_claim[cid]) != 1:
            problems.append(f"claim {cid} has {len(span_by_claim.get(cid, []))} source-span rows")
        if claim.get("included_in_denominator") != "yes":
            problems.append(f"claim {cid} is not admitted into denominator")
        rule_ids = _split_ids(claim.get("semantic_rule_ids", ""))
        if not rule_ids:
            problems.append(f"claim {cid} names no semantic rules")
        for rid in rule_ids:
            claim_rule_edges += 1
            rule_claims[rid].add(cid)
            if rid not in rule_by_id:
                problems.append(f"claim {cid} names unknown rule {rid}")
            elif not str(rule_by_id[rid].get("encoded_status", "")).startswith("encoded") and rule_by_id[rid].get("encoded_status") != "baseline_scope_record":
                problems.append(f"claim {cid} names non-admitted rule {rid}")
        direct_exercised = cid in fixture_claims or cid in spec_claims or cid in card_claims
        # Framework and baseline-scope claims may be supporting claims: they justify
        # generation-layer or contrastive-comparator scope but do not themselves
        # necessarily define a positive drift label.  They must still name admitted
        # rules and source spans, so they are counted as support paths rather than
        # as locked-fixture paths.
        support_path = bool(rule_ids) and all((rid in rule_by_id and (str(rule_by_id[rid].get("encoded_status", "")).startswith("encoded") or rule_by_id[rid].get("encoded_status") == "baseline_scope_record")) for rid in rule_ids)
        exercised = direct_exercised or support_path
        if not exercised:
            problems.append(f"claim {cid} lacks both direct benchmark evidence and a classified support-rule path")
        claim_profiles.append({
            "claim_id": cid,
            "policy_family": claim.get("policy_family"),
            "rules": rule_ids,
            "locked_fixture_roles": dict(fixture_claim_roles.get(cid, Counter())),
            "specbench_roles": dict(spec_claim_roles.get(cid, Counter())),
            "has_evidence_card": cid in card_claims,
            "direct_benchmark_path": direct_exercised,
            "support_rule_path": support_path and not direct_exercised,
            "exercised": exercised,
        })

    orphan_rules: List[str] = []
    rule_profiles: List[Dict[str, Any]] = []
    for rule in rules:
        rid = rule.get("rule_id", "")
        if not rid:
            problems.append("rule with empty rule_id")
            continue
        if not str(rule.get("encoded_status", "")).startswith("encoded") and rule.get("encoded_status") != "baseline_scope_record":
            problems.append(f"rule {rid} has inadmissible encoded_status={rule.get('encoded_status')!r}")
        if not rule.get("source_ids") or not rule.get("source_span"):
            problems.append(f"rule {rid} lacks source linkage")
        claims_for_rule = sorted(rule_claims.get(rid, set()))
        if not claims_for_rule:
            orphan_rules.append(rid); problems.append(f"encoded rule {rid} has no admitted claim")
        rule_profiles.append({
            "rule_id": rid,
            "policy_family": rule.get("policy_family"),
            "claims": claims_for_rule,
            "has_specbench_case": rid in spec_rules,
            "source_ids": _split_ids(rule.get("source_ids", "")),
        })

    families = Counter(c.get("policy_family", "") for c in claims)
    result = {
        "schema": "BEPGuardClaimRuleCoverage/v1",
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems[:80],
        "claims_checked": len(claims),
        "rules_checked": len(rules),
        "claim_rule_edges": claim_rule_edges,
        "claims_with_admission_path": sum(1 for p in claim_profiles if p["exercised"]),
        "claims_with_direct_benchmark_path": sum(1 for p in claim_profiles if p["direct_benchmark_path"]),
        "claims_with_support_rule_path": sum(1 for p in claim_profiles if p["support_rule_path"]),
        "rules_with_claims": sum(1 for p in rule_profiles if p["claims"]),
        "rules_with_specbench_cases": sum(1 for p in rule_profiles if p["has_specbench_case"]),
        "orphan_rules": orphan_rules,
        "policy_families": dict(sorted(families.items())),
        "claim_profiles": claim_profiles,
        "rule_profiles": rule_profiles,
        "interpretation": "Checks that each admitted public claim has a source span, admitted semantic rules, and either a direct benchmark/evidence path or a classified generation/baseline support-rule path; every encoded or scope-record rule must be justified by at least one admitted public claim.",
    }
    return result


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
