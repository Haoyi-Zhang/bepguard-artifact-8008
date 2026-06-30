"""evidence-facing evidence cards for proof-carrying drift witnesses.

Evidence cards flatten the evidence graph into one human-readable object per
positive witness.  They are intentionally redundant: every card must bind the
fixture, issue, public claim, rule, witness explanation, proof certificate,
paired repair control, and decision-oracle support.  The audit is a repository
quality gate because a assessor should be able to inspect a finding without
reconstructing paths across many result files.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def build_evidence_cards(root: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    witnesses = _load_json(root / "artifact/results/deep_locked/full_witnesses.json")
    certs = _load_json(root / "artifact/results/deep_locked/proof_carrying_witness_certificates.json")
    repairs = _load_json(root / "artifact/data/paired_repair_controls.json")
    paths = _load_csv(root / "artifact/results/evidence_graph_paths.csv")
    source_spans = _load_csv(root / "artifact/source_span_ledger.csv")
    rules = _load_csv(root / "artifact/data/rule_to_source_ledger.csv") if (root / "artifact/data/rule_to_source_ledger.csv").exists() else []

    witness_by_id = {str(w.get("fixture_id", "")): w for w in witnesses}
    cert_by_fixture = {str(c.get("fixture_id", "")): c for c in certs}
    repair_by_pos = {str(r.get("paired_positive_fixture_id", "")): r for r in repairs}
    path_by_fixture = {str(p.get("fixture_id", "")): p for p in paths}
    spans_by_source = {str(s.get("claim_id", s.get("source_id", ""))): s for s in source_spans}
    rules_by_id = {str(r.get("rule_id", "")): r for r in rules}

    cards: List[Dict[str, Any]] = []
    problems: List[str] = []
    for fid, witness in sorted(witness_by_id.items()):
        cert = cert_by_fixture.get(fid)
        repair = repair_by_pos.get(fid)
        path = path_by_fixture.get(fid)
        if cert is None:
            problems.append(f"{fid}:missing certificate")
            continue
        if repair is None:
            problems.append(f"{fid}:missing paired repair")
            continue
        if path is None or path.get("path_verified") != "yes":
            problems.append(f"{fid}:missing verified evidence graph path")
            continue
        source_ids = [s for s in str(cert.get("source_claim_ids", "")).replace(";", ",").split(",") if s] if not isinstance(cert.get("source_claim_ids"), list) else [str(s) for s in cert.get("source_claim_ids", [])]
        rule_ids = [r for r in str(cert.get("rule_ids", "")).replace(";", ",").split(",") if r] if not isinstance(cert.get("rule_ids"), list) else [str(r) for r in cert.get("rule_ids", [])]
        missing_spans = [s for s in source_ids if s not in spans_by_source]
        missing_rules = [r for r in rule_ids if r and r not in rules_by_id]
        obligations = cert.get("obligations", {}) if isinstance(cert.get("obligations", {}), dict) else {}
        false_obligations = sorted(k for k, v in obligations.items() if v is not True)
        if missing_spans:
            problems.append(f"{fid}:source spans missing {missing_spans}")
        if missing_rules:
            problems.append(f"{fid}:rule rows missing {missing_rules}")
        if false_obligations:
            problems.append(f"{fid}:false certificate obligations {false_obligations}")
        if str(repair.get("expected_issue", "none")) != "none":
            problems.append(f"{fid}:repair is not clean")
        card = {
            "fixture_id": fid,
            "issue": str(witness.get("issue", cert.get("issue", ""))),
            "policy_family": str(witness.get("policy_family", cert.get("policy_family", ""))),
            "intent_class": str(witness.get("intent_class", "")),
            "source_claim_ids": source_ids,
            "rule_ids": rule_ids,
            "certificate_id": str(cert.get("certificate_id", "")),
            "paired_repair_control_id": str(repair.get("id", cert.get("paired_repair_control_id", ""))),
            "explanation": str(witness.get("explanation", "")),
            "witness_surface": witness.get("witness", {}),
            "repair_interpretation": str(repair.get("interpretation", "")),
            "evidence_path_verified": path.get("path_verified") == "yes",
            "certificate_obligations_true": not false_obligations,
        }
        cards.append(card)
    covered_issues = sorted({c["issue"] for c in cards})
    summary = {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems[:50],
        "evidence_cards": len(cards),
        "expected_positive_cards": 418,
        "issue_classes_covered": len(covered_issues),
        "covered_issues": covered_issues,
        "cards_with_verified_paths": sum(1 for c in cards if c["evidence_path_verified"]),
        "cards_with_true_certificate_obligations": sum(1 for c in cards if c["certificate_obligations_true"]),
        "interpretation": "One evidence-facing evidence card is materialized for every positive witness, binding source, rule, certificate, witness explanation, and paired repair control.",
    }
    return cards, summary


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
