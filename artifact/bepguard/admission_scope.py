"""Admission-scope audit for public claims and release roles.

The project admits public source claims for different purposes: some are backed by
locked BEP-Deep fixtures, some bound framework/source interpretation, and some
record contrastive external-tool scope.  This audit makes that stratification
executable so that source-context material cannot be mistaken for unimplemented
future work or counted as additional detected drift.
"""
from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

EXECUTABLE_ROLES = {"positive", "negative_control", "positive_and_negative"}
CONTEXT_ROLES = {"source_context", "baseline"}
EXPECTED_ROLE_COUNTS = {
    "positive": 12,
    "negative_control": 3,
    "positive_and_negative": 11,
    "source_context": 15,
    "baseline": 4,
}


def _read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def audit_admission_scope(root: Path) -> Dict[str, Any]:
    art = root / "artifact"
    claims = _read_csv(art / "data/corpus_claims.csv")
    coding = _read_csv(art / "data/coding_validation_claims.csv")
    spans = _read_csv(art / "source_span_ledger.csv")
    fixtures = _read_json(art / "data/deep_locked_fixtures.json")
    cards = _read_json(art / "results/deep_locked/evidence_cards.json")
    problems: List[str] = []
    role_counts = Counter(c.get("fixture_role", "") for c in claims)
    if dict(role_counts) != EXPECTED_ROLE_COUNTS:
        problems.append(f"claim admission role counts changed: {dict(role_counts)}")
    if any(c.get("fixture_role") == "planned" for c in claims):
        problems.append("unresolved fixture_role=planned appears in claim ledger")
    if any(c.get("fixture_role") == "planned" for c in coding):
        problems.append("unresolved fixture_role=planned appears in coding validation")
    span_roles = Counter(s.get("fixture_role", "") for s in spans)
    if any(role == "planned" for role in span_roles):
        problems.append("unresolved fixture_role=planned appears in source-span ledger")
    claim_by_id = {c["claim_id"]: c for c in claims}
    fixture_support: Dict[str, int] = defaultdict(int)
    witness_support: Dict[str, int] = defaultdict(int)
    for fx in fixtures:
        for cid in fx.get("source_claim_ids", []) or [fx.get("public_source_id")]:
            if cid:
                fixture_support[str(cid)] += 1
    for card in cards:
        for cid in card.get("source_claim_ids", []) or [card.get("public_source_id")]:
            if cid:
                witness_support[str(cid)] += 1
    executable_claims = 0
    context_claims = 0
    for cid, claim in claim_by_id.items():
        role = claim.get("fixture_role", "")
        if role in EXECUTABLE_ROLES:
            executable_claims += 1
            if fixture_support.get(cid, 0) == 0:
                problems.append(f"{cid}: executable role lacks locked fixture support")
            if "positive" in role and witness_support.get(cid, 0) == 0:
                problems.append(f"{cid}: positive executable role lacks evidence-card witness support")
        elif role in CONTEXT_ROLES:
            context_claims += 1
            if witness_support.get(cid, 0) != 0:
                problems.append(f"{cid}: context/baseline role unexpectedly has positive evidence-card witness")
        else:
            problems.append(f"{cid}: unknown admission role {role}")
    return {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems[:80],
        "claims_checked": len(claims),
        "executable_fixture_backed_claims": executable_claims,
        "source_context_claims": role_counts.get("source_context", 0),
        "baseline_scope_claims": role_counts.get("baseline", 0),
        "role_counts": dict(role_counts),
        "source_span_roles": dict(span_roles),
        "claims_with_locked_fixture_support": sum(1 for c in claims if fixture_support.get(c["claim_id"], 0) > 0),
        "claims_with_positive_witness_cards": sum(1 for c in claims if witness_support.get(c["claim_id"], 0) > 0),
        "unresolved_future_work_placeholders": 0 if not any(c.get("fixture_role") == "planned" for c in claims) else 1,
        "interpretation": "Admitted source claims are partitioned into executable fixture-backed claims, source-context claims, and baseline-scope claims. The audit prevents context evidence from masquerading as unimplemented future work or as emitted drift findings.",
    }


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
