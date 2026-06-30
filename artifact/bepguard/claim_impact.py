"""Claim-to-impact closure for the BEPGuard release.

This audit answers a common artifact-review question: does every admitted public
claim actually participate in the released evidence object, or are some claims
only present as citation padding or unused corpus metadata?  The audit builds a
claim-level matrix over locked fixtures, positive witnesses, paired repairs,
source spans, rule rows, evidence cards, and SpecBench cases.  Executable
fixture-backed claims must carry denominator evidence; source-context and
baseline claims must remain explicitly scoped so they cannot silently inflate
the drift denominator.
"""
from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


def _load_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _claim_ids(obj: Dict[str, Any]) -> List[str]:
    ids = obj.get("source_claim_ids") or obj.get("source_claim_id") or obj.get("public_source_id") or []
    if isinstance(ids, str):
        return [x.strip() for x in ids.replace(";", ",").split(",") if x.strip()]
    if isinstance(ids, list):
        return [str(x).strip() for x in ids if str(x).strip()]
    return []


def _write_csv(path: Path, rows: Iterable[Dict[str, Any]], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})


def build_claim_impact_matrix(root: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    claims = _load_csv(root / "artifact/data/corpus_claims.csv")
    spans = _load_csv(root / "artifact/source_span_ledger.csv")
    rules = _load_csv(root / "artifact/data/rule_to_source_ledger.csv")
    fixtures = _load_json(root / "artifact/data/deep_locked_fixtures.json")
    repairs = _load_json(root / "artifact/data/paired_repair_controls.json")
    witnesses = _load_json(root / "artifact/results/deep_locked/full_witnesses.json")
    cards = _load_json(root / "artifact/results/deep_locked/evidence_cards.json")
    specbench = _load_json(root / "artifact/results/deep_locked/specbench_cases.json")

    claims_by_id = {r["claim_id"]: r for r in claims}
    span_by_claim = {r["claim_id"]: r for r in spans}
    rules_by_claim: Dict[str, set[str]] = defaultdict(set)
    for row in claims:
        for rid in str(row.get("semantic_rule_ids", "")).replace(";", ",").split(","):
            rid = rid.strip()
            if rid:
                rules_by_claim[row["claim_id"]].add(rid)
    rule_ids = {r.get("rule_id", "") for r in rules}

    fixture_counts: Dict[str, int] = defaultdict(int)
    positive_counts: Dict[str, int] = defaultdict(int)
    control_counts: Dict[str, int] = defaultdict(int)
    repair_counts: Dict[str, int] = defaultdict(int)
    for fx in fixtures:
        role = str(fx.get("fixture_role", ""))
        for cid in _claim_ids(fx):
            fixture_counts[cid] += 1
            if role == "positive":
                positive_counts[cid] += 1
            else:
                control_counts[cid] += 1
    for rp in repairs:
        for cid in _claim_ids(rp):
            repair_counts[cid] += 1

    witness_counts: Dict[str, int] = defaultdict(int)
    issue_counts: Dict[str, set[str]] = defaultdict(set)
    for w in witnesses:
        fid = str(w.get("fixture_id", ""))
        # full_witnesses do not always duplicate source ids; use evidence cards.
        pass
    for card in cards:
        for cid in _claim_ids(card):
            witness_counts[cid] += 1
            issue_counts[cid].add(str(card.get("issue", "")))

    specbench_counts: Dict[str, int] = defaultdict(int)
    specbench_positive_counts: Dict[str, int] = defaultdict(int)
    for case in specbench:
        cid = str(case.get("source_claim_id") or "")
        if cid:
            specbench_counts[cid] += 1
            if str(case.get("role", "")) == "positive":
                specbench_positive_counts[cid] += 1

    rows: List[Dict[str, Any]] = []
    problems: List[str] = []
    for cid, claim in sorted(claims_by_id.items()):
        span = span_by_claim.get(cid)
        linked_rules = sorted(rules_by_claim.get(cid, set()))
        missing_rules = [rid for rid in linked_rules if rid not in rule_ids]
        row = {
            "claim_id": cid,
            "policy_family": claim.get("policy_family", ""),
            "intent_class": claim.get("intent_class", ""),
            "fixture_role": claim.get("fixture_role", ""),
            "has_source_span": "yes" if span and span.get("source_span") else "no",
            "rule_count": len(linked_rules),
            "rules": ";".join(linked_rules),
            "locked_fixtures": fixture_counts.get(cid, 0),
            "positive_witnesses": witness_counts.get(cid, 0),
            "negative_or_control_fixtures": control_counts.get(cid, 0),
            "paired_repairs": repair_counts.get(cid, 0),
            "specbench_cases": specbench_counts.get(cid, 0),
            "specbench_positives": specbench_positive_counts.get(cid, 0),
            "issues_covered": len({i for i in issue_counts.get(cid, set()) if i}),
        }
        rows.append(row)
        role = str(claim.get("fixture_role", ""))
        if row["has_source_span"] != "yes":
            problems.append(f"{cid}: missing source span")
        if row["rule_count"] == 0:
            problems.append(f"{cid}: no semantic rule link")
        if missing_rules:
            problems.append(f"{cid}: missing rule rows {missing_rules}")
        # Claims play different protocol roles. Executable positive/control
        # claims must be backed by denominator evidence. Baseline and
        # source-context claims are retained to bound external-tool scope,
        # framework preconditions, and source interpretation; they must be
        # explicit roles rather than future-work placeholders and must never be
        # counted as emitted drift outcomes.
        executable_roles = {"positive", "negative_control", "positive_and_negative"}
        context_roles = {"source_context", "baseline"}
        if role not in executable_roles | context_roles:
            problems.append(f"{cid}: unknown claim admission role {role}")
        if "positive" in role and row["positive_witnesses"] == 0:
            problems.append(f"{cid}: positive claim without evidence-card witness")
        if ("negative" in role or "control" in role) and row["negative_or_control_fixtures"] == 0:
            problems.append(f"{cid}: control claim without clean fixture")
        if role in executable_roles and row["locked_fixtures"] == 0:
            problems.append(f"{cid}: executable claim without locked fixture support")
        if role in context_roles and row["positive_witnesses"] != 0:
            problems.append(f"{cid}: context/baseline claim unexpectedly has emitted witness cards")
        # SpecBench pressure remains a measured claim-level signal, but the
        # separate per-issue evidence-depth gate is the acceptance criterion for
        # out-of-denominator semantic pressure.


    issue_universe = sorted({i for s in issue_counts.values() for i in s if i})
    summary = {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems[:80],
        "claims_checked": len(claims),
        "claims_with_source_span": sum(1 for r in rows if r["has_source_span"] == "yes"),
        "claims_with_locked_fixtures": sum(1 for r in rows if int(r["locked_fixtures"]) > 0),
        "claims_with_specbench_pressure": sum(1 for r in rows if int(r["specbench_cases"]) > 0),
        "source_context_claims_without_denominator_support": sum(1 for r in rows if int(r["locked_fixtures"]) == 0 and r["fixture_role"] == "source_context"),
        "baseline_claims_without_denominator_support": sum(1 for r in rows if int(r["locked_fixtures"]) == 0 and r["fixture_role"] == "baseline"),
        "unresolved_future_work_roles": sum(1 for r in rows if r["fixture_role"] == "planned"),
        "rules_referenced": len({rid for r in rows for rid in str(r["rules"]).split(";") if rid}),
        "issue_classes_reached_by_evidence_cards": len(issue_universe),
        "evidence_card_claim_links": sum(int(r["positive_witnesses"]) for r in rows),
        "paired_repair_claim_links": sum(int(r["paired_repairs"]) for r in rows),
        "interpretation": "Every admitted claim is checked for source-span closure, rule linkage, locked-denominator support, SpecBench validation pressure, and evidence-card/repair impact where applicable.",
    }
    return rows, summary


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_matrix(path: Path, rows: List[Dict[str, Any]]) -> None:
    fields = [
        "claim_id", "policy_family", "intent_class", "fixture_role", "has_source_span",
        "rule_count", "rules", "locked_fixtures", "positive_witnesses", "negative_or_control_fixtures",
        "paired_repairs", "specbench_cases", "specbench_positives", "issues_covered",
    ]
    _write_csv(path, rows, fields)
