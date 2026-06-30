"""Identifier-blind replay audits for BEPGuard.

The locked denominator carries fixture IDs, source-claim IDs, roles, expected
labels, variants, and content hashes so that the release is traceable.  Those
fields must not be necessary for the semantic oracle.  This module executes the
oracle after erasing or replacing those fields, thereby testing whether the
method has memorized the benchmark rather than evaluating the policy surface,
intent class, and context.
"""
from __future__ import annotations

import copy
import hashlib
import json
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Tuple

sys.dont_write_bytecode = True

ERASED_METADATA = {
    "id",
    "fixture_hash",
    "fixture_role",
    "expected_issue",
    "public_source_id",
    "source_claim_ids",
    "variant",
    "policy_family",
}


def _import_semantics(root: Path):
    scripts = root / "artifact" / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import bep_semantics  # type: ignore
    return bep_semantics


def _fixtures(root: Path) -> List[Dict[str, Any]]:
    return json.loads((root / "artifact" / "data" / "deep_locked_fixtures.json").read_text(encoding="utf-8"))


def _repairs(root: Path) -> List[Dict[str, Any]]:
    return json.loads((root / "artifact" / "data" / "paired_repair_controls.json").read_text(encoding="utf-8"))


def _signature(findings: Iterable[Any]) -> Tuple[str, ...]:
    issues: List[str] = []
    for finding in findings:
        if hasattr(finding, "issue"):
            issues.append(str(getattr(finding, "issue")))
        elif isinstance(finding, Mapping):
            issues.append(str(finding.get("issue", "")))
    return tuple(sorted(i for i in issues if i))


def _expected(fixture: Mapping[str, Any]) -> Tuple[str, ...]:
    issue = str(fixture.get("expected_issue", "none"))
    return tuple() if issue in {"", "none"} else (issue,)


def _digest(obj: Mapping[str, Any]) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()[:16]


def _blind_copy(fixture: Mapping[str, Any], mode: str, ordinal: int) -> Dict[str, Any]:
    out = copy.deepcopy(dict(fixture))
    if mode == "source_blind":
        for k in ["public_source_id", "source_claim_ids"]:
            out.pop(k, None)
    elif mode == "role_blind":
        for k in ["fixture_role", "expected_issue", "variant"]:
            out.pop(k, None)
    elif mode == "family_blind":
        out.pop("policy_family", None)
    elif mode == "hash_blind":
        for k in ["id", "fixture_hash", "variant"]:
            out.pop(k, None)
    elif mode == "fully_blind":
        for k in ERASED_METADATA:
            out.pop(k, None)
    else:
        raise ValueError(f"unknown blind mode: {mode}")
    out["id"] = f"BLIND_{ordinal:05d}_{mode.upper()}_{_digest(out)}"
    return out


@dataclass(frozen=True)
class BlindRow:
    blind_id: str
    mode: str
    source_fingerprint: str
    original_role: str
    original_family: str
    original_claims: Tuple[str, ...]
    expected: Tuple[str, ...]
    actual: Tuple[str, ...]
    preserved: bool

    def as_dict(self) -> Dict[str, Any]:
        return {
            "blind_id": self.blind_id,
            "mode": self.mode,
            "source_fingerprint": self.source_fingerprint,
            "original_role": self.original_role,
            "original_family": self.original_family,
            "original_claims": list(self.original_claims),
            "expected": list(self.expected),
            "actual": list(self.actual),
            "preserved": self.preserved,
        }


def run_identifier_blind_replay(root: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    sem = _import_semantics(root)
    fixtures = _fixtures(root)
    modes = ["source_blind", "role_blind", "family_blind", "hash_blind", "fully_blind"]
    rows: List[BlindRow] = []
    ordinal = 0
    for fixture in fixtures:
        expected = _expected(fixture)
        claims = tuple(str(c) for c in fixture.get("source_claim_ids", []) if isinstance(fixture.get("source_claim_ids", []), list))
        for mode in modes:
            ordinal += 1
            blinded = _blind_copy(fixture, mode, ordinal)
            actual = _signature(sem.analyze_fixture(blinded))
            rows.append(BlindRow(
                blind_id=str(blinded["id"]),
                mode=mode,
                source_fingerprint=_digest(fixture),
                original_role=str(fixture.get("fixture_role", "")),
                original_family=str(fixture.get("policy_family", "")),
                original_claims=claims,
                expected=expected,
                actual=actual,
                preserved=actual == expected,
            ))
    failures = [r.as_dict() for r in rows if not r.preserved]
    by_mode = Counter(r.mode for r in rows)
    pass_by_mode = Counter(r.mode for r in rows if r.preserved)
    by_family = Counter(r.original_family for r in rows)
    claim_ids = {c for r in rows for c in r.original_claims}
    issue_classes = {r.expected[0] for r in rows if r.expected}
    return [r.as_dict() for r in rows], {
        "status": "pass" if not failures else "fail",
        "problem_count": len(failures),
        "problems": failures[:25],
        "fixtures_replayed": len(fixtures),
        "blind_modes": len(modes),
        "blind_replays": len(rows),
        "preserved_replays": sum(1 for r in rows if r.preserved),
        "by_mode": dict(sorted(by_mode.items())),
        "preserved_by_mode": dict(sorted(pass_by_mode.items())),
        "families_replayed": len(by_family),
        "claims_observed": len(claim_ids),
        "positive_issue_classes_replayed": len(issue_classes),
        "interpretation": "Identifier-blind replay erases source IDs, labels, fixture roles, families, hashes, and variants before re-executing the semantic oracle. Passing replays show that semantic judgments are driven by headers, layers, intent class, and context rather than locked benchmark identifiers.",
    }


def run_repair_delta_replay(root: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    sem = _import_semantics(root)
    positives = {str(f.get("id")): f for f in _fixtures(root) if _expected(f)}
    repairs = _repairs(root)
    rows: List[Dict[str, Any]] = []
    problems: List[Dict[str, Any]] = []
    for repair in repairs:
        pid = str(repair.get("paired_positive_fixture_id", ""))
        positive = positives.get(pid)
        if positive is None:
            problem = {"repair_id": repair.get("id", ""), "problem": "missing paired positive"}
            problems.append(problem); rows.append(problem); continue
        expected_pos = _expected(positive)
        pos_actual = _signature(sem.analyze_fixture(copy.deepcopy(positive)))
        rep_actual = _signature(sem.analyze_fixture(copy.deepcopy(repair)))
        blind_repair = _blind_copy(repair, "fully_blind", len(rows) + 1)
        blind_repair_actual = _signature(sem.analyze_fixture(blind_repair))
        header_delta = json.dumps(positive.get("headers", []), sort_keys=True) != json.dumps(repair.get("headers", []), sort_keys=True)
        context_delta = json.dumps(positive.get("context", {}), sort_keys=True) != json.dumps(repair.get("context", {}), sort_keys=True)
        layer_delta = json.dumps(positive.get("layers", []), sort_keys=True) != json.dumps(repair.get("layers", []), sort_keys=True)
        intent_delta = json.dumps(positive.get("intent", {}), sort_keys=True) != json.dumps(repair.get("intent", {}), sort_keys=True)
        row = {
            "positive_id": pid,
            "repair_id": str(repair.get("id", "")),
            "target_issue": list(expected_pos),
            "positive_actual": list(pos_actual),
            "repair_actual": list(rep_actual),
            "blind_repair_actual": list(blind_repair_actual),
            "header_delta": header_delta,
            "context_delta": context_delta,
            "layer_delta": layer_delta,
            "intent_delta": intent_delta,
            "repair_clears_issue": pos_actual == expected_pos and not rep_actual and not blind_repair_actual and (header_delta or context_delta or layer_delta or intent_delta),
        }
        rows.append(row)
        if not row["repair_clears_issue"]:
            problems.append(row)
    by_issue = Counter(tuple(row.get("target_issue", []))[0] if row.get("target_issue") else "none" for row in rows)
    return rows, {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems[:25],
        "positive_repairs_checked": len(rows),
        "repairs_clearing_issue": sum(1 for row in rows if row.get("repair_clears_issue")),
        "issue_classes_repaired": len(by_issue),
        "repairs_by_issue": dict(sorted(by_issue.items())),
        "interpretation": "Repair-delta replay executes every positive/paired-repair pair and repeats the repaired side after metadata erasure. A pass requires the positive to emit the target issue, the repair to be clean, the blind repair to remain clean, and the repair to make an observable header or context delta.",
    }


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: List[Mapping[str, Any]]) -> None:
    import csv
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("\n", encoding="utf-8"); return
    fieldnames = sorted({k for r in rows for k in r.keys()})
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: json.dumps(v, sort_keys=True) if isinstance(v, (list, dict, tuple)) else v for k, v in row.items()})
