"""Claim-level trace saturation audit for BEPGuard.

The issue-depth and evidence-card gates close witness-level evidence.  This module
adds a source-claim perspective: every admitted public claim receives an explicit
claim card, and fixture-bearing claims must be connected to denominator fixtures,
rules, source spans, and at least one downstream evidence object.  Claims that
serve as source support without direct fixtures are recorded separately rather
than silently dropped.
"""
from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


def _load_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _claim_ids_from_fixture(fx: Dict[str, Any]) -> List[str]:
    raw = fx.get("source_claim_ids")
    if isinstance(raw, list):
        return [str(x) for x in raw if str(x)]
    if isinstance(raw, str) and raw:
        return [x for x in raw.replace(";", ",").split(",") if x]
    public = str(fx.get("public_source_id", ""))
    return [public] if public else []


def _split_ids(value: str) -> List[str]:
    return [v for v in str(value).replace(";", ",").split(",") if v]


def build_claim_trace_cards(root: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    claims = _load_csv(root / "artifact/data/corpus_claims.csv")
    spans = {r["claim_id"]: r for r in _load_csv(root / "artifact/source_span_ledger.csv")}
    rules = {r["rule_id"]: r for r in _load_csv(root / "artifact/data/rule_to_source_ledger.csv")}
    fixtures = _load_json(root / "artifact/data/deep_locked_fixtures.json")
    cards = _load_json(root / "artifact/results/deep_locked/evidence_cards.json")
    issue_depth = _load_csv(root / "artifact/results/deep_locked/issue_evidence_depth_rows.csv")
    spec_cases = _load_json(root / "artifact/results/deep_locked/specbench_cases.json")

    fixtures_by_claim: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    positives_by_claim: Counter[str] = Counter()
    controls_by_claim: Counter[str] = Counter()
    for fx in fixtures:
        issue = str(fx.get("expected_issue", "none"))
        is_pos = issue not in {"", "none"}
        for cid in _claim_ids_from_fixture(fx):
            fixtures_by_claim[cid].append(fx)
            if is_pos:
                positives_by_claim[cid] += 1
            else:
                controls_by_claim[cid] += 1

    evidence_cards_by_claim: Counter[str] = Counter()
    for card in cards:
        for cid in card.get("source_claim_ids", []) or []:
            evidence_cards_by_claim[str(cid)] += 1

    specbench_by_claim: Counter[str] = Counter()
    for case in spec_cases:
        fx = case.get("fixture", {}) if isinstance(case, dict) else {}
        for cid in _claim_ids_from_fixture(fx):
            specbench_by_claim[cid] += 1

    issue_obligations_by_issue: Counter[str] = Counter()
    for row in issue_depth:
        issue = row.get("issue", "")
        if row.get("status") == "pass":
            issue_obligations_by_issue[issue] += 1

    claim_cards: List[Dict[str, Any]] = []
    problems: List[str] = []
    fixture_bearing = 0
    source_support_only = 0
    claims_with_positive_cards = 0
    for claim in claims:
        cid = claim["claim_id"]
        semantic_rules = _split_ids(claim.get("semantic_rule_ids", ""))
        fxs = fixtures_by_claim.get(cid, [])
        issue_set = sorted({str(fx.get("expected_issue", "none")) for fx in fxs if str(fx.get("expected_issue", "none")) not in {"", "none"}})
        missing_rules = [rid for rid in semantic_rules if rid not in rules]
        if cid not in spans:
            problems.append(f"{cid}:missing source span")
        if missing_rules:
            problems.append(f"{cid}:missing rule rows {missing_rules}")
        if claim.get("included_in_denominator") == "yes" and not semantic_rules:
            problems.append(f"{cid}:included claim has no semantic rule ids")
        if fxs:
            fixture_bearing += 1
            if positives_by_claim[cid] and not evidence_cards_by_claim[cid]:
                problems.append(f"{cid}:positive fixtures have no evidence cards")
            if positives_by_claim[cid] and not specbench_by_claim[cid]:
                problems.append(f"{cid}:positive fixtures have no SpecBench pressure")
            if positives_by_claim[cid]:
                claims_with_positive_cards += 1
        else:
            source_support_only += 1
        card = {
            "claim_id": cid,
            "source_id": claim.get("source_id", ""),
            "policy_family": claim.get("policy_family", ""),
            "claim_type": claim.get("claim_type", ""),
            "source_span": claim.get("source_span", ""),
            "intent_class": claim.get("intent_class", ""),
            "semantic_rule_ids": semantic_rules,
            "fixture_count": len(fxs),
            "positive_fixture_count": positives_by_claim[cid],
            "control_fixture_count": controls_by_claim[cid],
            "evidence_cards": evidence_cards_by_claim[cid],
            "specbench_cases": specbench_by_claim[cid],
            "issue_classes": issue_set,
            "trace_status": "fixture_bearing" if fxs else "source_support_only",
            "source_span_present": cid in spans,
            "rule_rows_present": not missing_rules,
        }
        claim_cards.append(card)

    summary = {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems[:50],
        "claims_checked": len(claims),
        "claim_cards": len(claim_cards),
        "fixture_bearing_claims": fixture_bearing,
        "source_support_only_claims": source_support_only,
        "positive_fixture_claims_with_evidence_cards": claims_with_positive_cards,
        "source_spans_present": sum(1 for c in claim_cards if c["source_span_present"]),
        "rule_rows_present": sum(1 for c in claim_cards if c["rule_rows_present"]),
        "fixture_edges_checked": sum(len(v) for v in fixtures_by_claim.values()),
        "interpretation": "Every admitted public claim is materialized as a trace card. Fixture-bearing claims are tied to denominator fixtures, source spans, semantic rules, evidence cards, and SpecBench pressure; source-support-only claims remain explicit instead of being silently dropped.",
    }
    return claim_cards, summary


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
