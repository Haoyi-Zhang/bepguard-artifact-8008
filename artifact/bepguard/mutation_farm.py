"""Semantic mutation farm for BEPGuard.

The original mutation gate checks a compact set of hand-written semantic mutants.
This module adds a larger deterministic mutation farm whose mutants are defined
at the policy-obligation level: omitted obligations, confused issue classes,
family over-generalization, and intent over-generalization.  A mutant is killed
only when the locked expected oracle and the mutant oracle disagree on at least
one concrete fixture.  The gate therefore measures whether the workload and
certificate corpus distinguish common semantic regression families without
changing the locked denominator.
"""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

sys.dont_write_bytecode = True


def expected_signature(fixture: Mapping[str, Any]) -> Tuple[str, ...]:
    issue = str(fixture.get("expected_issue", "none"))
    return tuple() if issue == "none" else (issue,)


def family_of(fixture: Mapping[str, Any]) -> str:
    return str(fixture.get("policy_family", "unknown")).split("/")[0]


def intent_of(fixture: Mapping[str, Any]) -> str:
    intent = fixture.get("intent", {})
    if isinstance(intent, Mapping):
        return str(intent.get("class", "unknown"))
    return "unknown"


@dataclass(frozen=True)
class Mutant:
    mutant_id: str
    fault_model: str
    target_issue: str
    family: str
    intent_class: str
    replacement_issue: str = ""

    def predict(self, fixture: Mapping[str, Any]) -> Tuple[str, ...]:
        base = list(expected_signature(fixture))
        if self.fault_model == "drop_issue":
            return tuple(i for i in base if i != self.target_issue)
        if self.fault_model == "confuse_issue":
            return tuple(self.replacement_issue if i == self.target_issue else i for i in base)
        if self.fault_model == "family_overgeneralization":
            if not base and family_of(fixture) == self.family:
                return (self.target_issue,)
            return tuple(base)
        if self.fault_model == "intent_overgeneralization":
            if not base and intent_of(fixture) == self.intent_class:
                return (self.target_issue,)
            return tuple(base)
        if self.fault_model == "family_drop":
            if family_of(fixture) == self.family:
                return tuple(i for i in base if i != self.target_issue)
            return tuple(base)
        if self.fault_model == "intent_drop":
            if intent_of(fixture) == self.intent_class:
                return tuple(i for i in base if i != self.target_issue)
            return tuple(base)
        if self.fault_model == "negative_control_injection":
            if not base and str(fixture.get("fixture_role", "")) == "negative_control":
                return (self.target_issue,)
            return tuple(base)
        if self.fault_model == "same_claim_overgeneralization":
            claims = fixture.get("source_claim_ids", [])
            claim_text = ";".join(str(c) for c in claims) if isinstance(claims, list) else str(claims)
            if not base and self.replacement_issue and self.replacement_issue in claim_text:
                return (self.target_issue,)
            return tuple(base)
        if self.fault_model == "positive_family_confusion":
            if base and family_of(fixture) == self.family:
                return (self.replacement_issue or self.target_issue,)
            return tuple(base)
        if self.fault_model == "positive_intent_confusion":
            if base and intent_of(fixture) == self.intent_class:
                return (self.replacement_issue or self.target_issue,)
            return tuple(base)
        if self.fault_model == "all_positive_drop":
            if base:
                return tuple(i for i in base if i != self.target_issue)
            return tuple(base)
        if self.fault_model == "all_negative_overgeneralization":
            if not base:
                return (self.target_issue,)
            return tuple(base)
        if self.fault_model == "generic_issue_collapse":
            if self.target_issue in base:
                return ("generic_policy_problem",)
            return tuple(base)
        if self.fault_model == "previous_issue_confusion":
            return tuple(self.replacement_issue if i == self.target_issue else i for i in base)
        if self.fault_model == "next_issue_confusion":
            return tuple(self.replacement_issue if i == self.target_issue else i for i in base)
        if self.fault_model == "family_any_positive_drop":
            if base and family_of(fixture) == self.family:
                return tuple()
            return tuple(base)
        if self.fault_model == "intent_any_positive_drop":
            if base and intent_of(fixture) == self.intent_class:
                return tuple()
            return tuple(base)
        if self.fault_model == "family_any_negative_over":
            if not base and family_of(fixture) == self.family:
                return (self.target_issue,)
            return tuple(base)
        if self.fault_model == "intent_any_negative_over":
            if not base and intent_of(fixture) == self.intent_class:
                return (self.target_issue,)
            return tuple(base)
        if self.fault_model == "global_any_negative_target":
            if not base:
                return (self.target_issue,)
            return tuple(base)
        if self.fault_model == "global_any_positive_target":
            if base and self.target_issue not in base:
                return (self.target_issue,)
            return tuple(base)
        if self.fault_model == "claim_positive_confusion":
            if self.target_issue in base:
                return (self.replacement_issue or "claim_confused_policy_problem",)
            return tuple(base)
        if self.fault_model == "family_control_repair_regression":
            if not base and str(fixture.get("fixture_role", "")) == "negative_control" and family_of(fixture) == self.family:
                return (self.target_issue,)
            return tuple(base)
        if self.fault_model == "intent_control_repair_regression":
            if not base and str(fixture.get("fixture_role", "")) == "negative_control":
                return (self.target_issue,)
            return tuple(base)
        return tuple(base)

    def as_dict(self) -> Dict[str, str]:
        return {
            "mutant_id": self.mutant_id,
            "fault_model": self.fault_model,
            "target_issue": self.target_issue,
            "family": self.family,
            "intent_class": self.intent_class,
            "replacement_issue": self.replacement_issue,
        }


def load_fixtures(root: Path) -> List[Dict[str, Any]]:
    return json.loads((root / "artifact" / "data" / "deep_locked_fixtures.json").read_text(encoding="utf-8"))


def build_mutants(fixtures: Sequence[Mapping[str, Any]]) -> List[Mutant]:
    positives = [f for f in fixtures if expected_signature(f)]
    issues = sorted({expected_signature(f)[0] for f in positives})
    issue_family: Dict[str, str] = {}
    issue_intents: Dict[str, str] = {}
    issue_claims: Dict[str, str] = {}
    for f in positives:
        issue = expected_signature(f)[0]
        issue_family.setdefault(issue, family_of(f))
        issue_intents.setdefault(issue, intent_of(f))
        claims = f.get("source_claim_ids", [])
        if isinstance(claims, list) and claims:
            issue_claims.setdefault(issue, str(claims[0]))
        else:
            issue_claims.setdefault(issue, str(f.get("public_source_id", "")))
    family_negatives = {family_of(f) for f in fixtures if not expected_signature(f)}
    intent_negatives = {intent_of(f) for f in fixtures if not expected_signature(f)}
    mutants: List[Mutant] = []
    for idx, issue in enumerate(issues):
        fam = issue_family[issue]
        intent = issue_intents[issue]
        replacement = issues[(idx + 7) % len(issues)]
        mutants.append(Mutant(f"MF_DROP_{idx+1:03d}", "drop_issue", issue, fam, intent))
        mutants.append(Mutant(f"MF_CONFUSE_{idx+1:03d}", "confuse_issue", issue, fam, intent, replacement))
        mutants.append(Mutant(f"MF_FAMILY_DROP_{idx+1:03d}", "family_drop", issue, fam, intent))
        mutants.append(Mutant(f"MF_INTENT_DROP_{idx+1:03d}", "intent_drop", issue, fam, intent))
        if fam in family_negatives:
            mutants.append(Mutant(f"MF_FAMILY_OVER_{idx+1:03d}", "family_overgeneralization", issue, fam, intent))
        if intent in intent_negatives:
            mutants.append(Mutant(f"MF_INTENT_OVER_{idx+1:03d}", "intent_overgeneralization", issue, fam, intent))
        mutants.append(Mutant(f"MF_NEG_INJECT_{idx+1:03d}", "negative_control_injection", issue, fam, intent))
        mutants.append(Mutant(f"MF_CLAIM_OVER_{idx+1:03d}", "same_claim_overgeneralization", issue, fam, intent, issue_claims.get(issue, "")))
        mutants.append(Mutant(f"MF_POS_FAMILY_CONFUSE_{idx+1:03d}", "positive_family_confusion", issue, fam, intent, replacement))
        mutants.append(Mutant(f"MF_POS_INTENT_CONFUSE_{idx+1:03d}", "positive_intent_confusion", issue, fam, intent, replacement))
        mutants.append(Mutant(f"MF_ALL_POS_DROP_{idx+1:03d}", "all_positive_drop", issue, fam, intent))
        mutants.append(Mutant(f"MF_ALL_NEG_OVER_{idx+1:03d}", "all_negative_overgeneralization", issue, fam, intent))
        mutants.append(Mutant(f"MF_GENERIC_COLLAPSE_{idx+1:03d}", "generic_issue_collapse", issue, fam, intent))
        mutants.append(Mutant(f"MF_PREV_CONFUSE_{idx+1:03d}", "previous_issue_confusion", issue, fam, intent, issues[(idx - 1) % len(issues)]))
        mutants.append(Mutant(f"MF_NEXT_CONFUSE_{idx+1:03d}", "next_issue_confusion", issue, fam, intent, issues[(idx + 1) % len(issues)]))
        mutants.append(Mutant(f"MF_FAMILY_ANY_POS_DROP_{idx+1:03d}", "family_any_positive_drop", issue, fam, intent))
        mutants.append(Mutant(f"MF_INTENT_ANY_POS_DROP_{idx+1:03d}", "intent_any_positive_drop", issue, fam, intent))
        mutants.append(Mutant(f"MF_FAMILY_ANY_NEG_OVER_{idx+1:03d}", "family_any_negative_over", issue, fam, intent))
        mutants.append(Mutant(f"MF_INTENT_ANY_NEG_OVER_{idx+1:03d}", "intent_any_negative_over", issue, fam, intent))
        mutants.append(Mutant(f"MF_GLOBAL_NEG_TARGET_{idx+1:03d}", "global_any_negative_target", issue, fam, intent))
        mutants.append(Mutant(f"MF_GLOBAL_POS_TARGET_{idx+1:03d}", "global_any_positive_target", issue, fam, intent))
        mutants.append(Mutant(f"MF_CLAIM_POS_CONFUSE_{idx+1:03d}", "claim_positive_confusion", issue, fam, intent, issue_claims.get(issue, "")))
        mutants.append(Mutant(f"MF_FAMILY_CONTROL_REGRESS_{idx+1:03d}", "family_control_repair_regression", issue, fam, intent))
        mutants.append(Mutant(f"MF_INTENT_CONTROL_REGRESS_{idx+1:03d}", "intent_control_repair_regression", issue, fam, intent))
    return mutants


def kill_mutant(mutant: Mutant, fixtures: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    for f in fixtures:
        expected = expected_signature(f)
        predicted = mutant.predict(f)
        if predicted != expected:
            return {
                "mutant_id": mutant.mutant_id,
                "killed": True,
                "killing_fixture_id": str(f.get("id", "")),
                "fixture_role": str(f.get("fixture_role", "")),
                "expected_signature": list(expected),
                "mutant_signature": list(predicted),
                **mutant.as_dict(),
            }
    return {"mutant_id": mutant.mutant_id, "killed": False, **mutant.as_dict()}


def run_mutation_farm(root: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    fixtures = load_fixtures(root)
    mutants = build_mutants(fixtures)
    rows = [kill_mutant(m, fixtures) for m in mutants]
    by_fault = Counter(str(r.get("fault_model", "")) for r in rows)
    killed_by_fault = Counter(str(r.get("fault_model", "")) for r in rows if r.get("killed"))
    by_family = Counter(str(r.get("family", "")) for r in rows)
    killed = sum(1 for r in rows if r.get("killed"))
    summary = {
        "status": "pass" if killed == len(rows) else "fail",
        "problem_count": 0 if killed == len(rows) else len(rows) - killed,
        "mutants": len(rows),
        "killed_mutants": killed,
        "surviving_mutants": len(rows) - killed,
        "fault_models": dict(sorted(by_fault.items())),
        "killed_by_fault_model": dict(sorted(killed_by_fault.items())),
        "mutants_by_family": dict(sorted(by_family.items())),
        "fixtures_consulted": len(fixtures),
        "positive_issue_classes": len({expected_signature(f)[0] for f in fixtures if expected_signature(f)}),
        "interpretation": "Obligation-level semantic mutation farm over BEP-Deep; mutants are killed only by concrete locked fixtures and do not change the locked denominator.",
    }
    return rows, summary


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["mutant_id", "fault_model", "target_issue", "family", "intent_class", "replacement_issue", "killed", "killing_fixture_id", "fixture_role", "expected_signature", "mutant_signature"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            out = {k: row.get(k, "") for k in fieldnames}
            for k in ["expected_signature", "mutant_signature"]:
                if isinstance(out.get(k), list):
                    out[k] = ";".join(str(x) for x in out[k])
            writer.writerow(out)
