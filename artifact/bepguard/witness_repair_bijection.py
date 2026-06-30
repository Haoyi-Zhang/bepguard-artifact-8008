"""Witness-to-repair bijection audit.

The main certificate gate checks that each positive certificate has a clean
paired repair.  This audit checks the stronger relational invariant: the 418
positive fixtures, minimized witnesses, proof-carrying certificates, and paired
repair controls form a one-to-one graph with no orphan positives, duplicate
repairs, duplicate certificates, or cross-issue repairs.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Mapping


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def audit_witness_repair_bijection(root: Path) -> Dict[str, Any]:
    problems: List[str] = []
    fixtures = _load_json(root / "artifact/data/deep_locked_fixtures.json")
    repairs = _load_json(root / "artifact/data/paired_repair_controls.json")
    witnesses = _load_json(root / "artifact/results/deep_locked/minimized_witnesses.json")
    certs = _load_json(root / "artifact/results/deep_locked/proof_carrying_witness_certificates.json")
    repair_delta = _load_json(root / "artifact/results/deep_locked/repair_delta_replay_audit.json")

    positives = {str(f["id"]): f for f in fixtures if str(f.get("expected_issue", "none")) not in {"", "none"}}
    controls = {str(f["id"]): f for f in fixtures if str(f.get("expected_issue", "none")) in {"", "none"}}
    repair_by_id = {str(r.get("id", "")): r for r in repairs}
    repairs_by_positive: Dict[str, List[Mapping[str, Any]]] = {}
    for repair in repairs:
        pid = str(repair.get("paired_positive_fixture_id", ""))
        repairs_by_positive.setdefault(pid, []).append(repair)
    witness_by_fixture = {str(w.get("fixture_id", "")): w for w in witnesses}
    cert_by_fixture = {str(c.get("fixture_id", "")): c for c in certs}

    if len(witness_by_fixture) != len(witnesses):
        problems.append("duplicate minimized witness fixture ids")
    if len(cert_by_fixture) != len(certs):
        problems.append("duplicate certificate fixture ids")
    if len(repair_by_id) != len(repairs):
        problems.append("duplicate paired repair ids")

    issue_counts = Counter()
    repair_operator_counts = Counter()
    for pid, positive in positives.items():
        expected_issue = str(positive.get("expected_issue"))
        issue_counts[expected_issue] += 1
        if pid not in witness_by_fixture:
            problems.append(f"positive fixture {pid} has no minimized witness")
        if pid not in cert_by_fixture:
            problems.append(f"positive fixture {pid} has no proof-carrying certificate")
        linked_repairs = repairs_by_positive.get(pid, [])
        if len(linked_repairs) != 1:
            problems.append(f"positive fixture {pid} has {len(linked_repairs)} paired repairs")
            continue
        repair = linked_repairs[0]
        rid = str(repair.get("id", ""))
        if str(repair.get("expected_issue", "none")) not in {"", "none"}:
            problems.append(f"paired repair {rid} is not a clean negative control")
        if str(repair.get("paired_target_issue", "")) != expected_issue:
            problems.append(f"paired repair {rid} target issue mismatch for {pid}")
        if str(repair.get("policy_family", "")) != str(positive.get("policy_family", "")):
            problems.append(f"paired repair {rid} policy family mismatch for {pid}")
        if str(repair.get("public_source_id", "")) != str(positive.get("public_source_id", "")):
            problems.append(f"paired repair {rid} source mismatch for {pid}")
        if str(repair.get("mutation_operator_class", "")):
            repair_operator_counts[str(repair.get("mutation_operator_class"))] += 1
        cert = cert_by_fixture.get(pid)
        if cert:
            if str(cert.get("paired_repair_control_id", "")) != rid:
                problems.append(f"certificate for {pid} points to {cert.get('paired_repair_control_id')} but repair is {rid}")
            if str(cert.get("issue", "")) != expected_issue:
                problems.append(f"certificate for {pid} issue mismatch")
            obligations = cert.get("obligations", {})
            false_obligations = sorted(k for k, v in obligations.items() if v is not True)
            if false_obligations:
                problems.append(f"certificate for {pid} has false obligations {false_obligations}")
        wit = witness_by_fixture.get(pid)
        if wit and str(wit.get("issue", "")) != expected_issue:
            problems.append(f"minimized witness for {pid} issue mismatch")

    orphan_repairs = sorted(pid for pid in repairs_by_positive if pid not in positives)
    if orphan_repairs:
        problems.append(f"repairs reference non-positive fixture ids: {orphan_repairs[:10]}")
    # Paired repairs are intentionally materialized as locked negative controls.
    # Require the collision rather than forbidding it, because this is what makes
    # the repair side part of the denominator and certificate surface.
    for rid, repair in repair_by_id.items():
        if rid not in controls:
            problems.append(f"paired repair id {rid} is not present as a locked negative-control fixture")

    if repair_delta.get("status") != "pass" or repair_delta.get("positive_repairs_checked") != len(positives):
        problems.append("repair-delta replay summary does not cover all positives")

    result = {
        "schema": "BEPGuardWitnessRepairBijection/v1",
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems[:80],
        "positive_fixtures": len(positives),
        "minimized_witnesses": len(witnesses),
        "proof_carrying_certificates": len(certs),
        "paired_repair_controls": len(repairs),
        "positives_with_exactly_one_repair": sum(1 for pid in positives if len(repairs_by_positive.get(pid, [])) == 1),
        "certificates_with_true_obligations": sum(1 for c in certs if all(v is True for v in c.get("obligations", {}).values())),
        "issue_classes": len(issue_counts),
        "repair_operator_classes": len(repair_operator_counts),
        "issue_counts": dict(sorted(issue_counts.items())),
        "repair_operator_counts": dict(sorted(repair_operator_counts.items())),
        "interpretation": "Checks that every positive witness has exactly one minimized witness, exactly one proof-carrying certificate, and exactly one clean paired repair with matching source, policy family, and target issue.",
    }
    return result


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
