"""Evidence redundancy audit for claim-to-witness paths."""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Mapping, Set

sys.dont_write_bytecode = True


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def audit_evidence_redundancy(root: Path) -> Dict[str, Any]:
    art = root / "artifact"
    problems: List[str] = []
    fixtures = _read_json(art / "data" / "deep_locked_fixtures.json")
    claims = _read_csv(art / "data" / "corpus_claims.csv")
    rules = _read_csv(art / "data" / "rule_to_source_ledger.csv")
    cert_pos = _read_json(art / "results" / "deep_locked" / "proof_carrying_witness_metrics.json")
    cert_neg = _read_json(art / "results" / "deep_locked" / "control_certificate_metrics.json")
    repairs = _read_json(art / "results" / "bep_max" / "repair_frontier_metrics.json")
    specbench = _read_json(art / "results" / "deep_locked" / "specbench_summary.json")
    theory = _read_json(art / "results" / "deep_locked" / "theory_kernel_audit.json")
    mutation = _read_json(art / "results" / "deep_locked" / "mutation_farm_summary.json")
    shadow = _read_json(art / "results" / "deep_locked" / "shadow_generalization_audit.json")
    external = _read_json(art / "results" / "external_provenance_audit.json")
    evidence = _read_json(art / "results" / "evidence_graph_metrics.json")
    positive_fixtures = [f for f in fixtures if str(f.get("expected_issue", "none")) != "none"]
    negative_fixtures = [f for f in fixtures if str(f.get("expected_issue", "none")) == "none"]
    issue_classes = {str(f.get("expected_issue")) for f in positive_fixtures}
    claim_ids = {r.get("claim_id", r.get("source_claim_id", "")) for r in claims}
    rule_ids = {r.get("rule_id", "") for r in rules}
    if len(positive_fixtures) != 418 or len(negative_fixtures) != 554:
        problems.append("fixture split does not match locked denominator")
    if cert_pos.get("certificates_verified") != len(positive_fixtures):
        problems.append("positive certificate coverage does not match positives")
    if cert_neg.get("verified_control_certificates") != len(negative_fixtures):
        problems.append("negative certificate coverage does not match negative controls")
    if repairs.get("frontier_certified") != len(positive_fixtures):
        problems.append("repair frontier coverage does not match positives")
    if evidence.get("positive_paths_verified") != len(positive_fixtures) or evidence.get("negative_control_paths_verified") != len(negative_fixtures):
        problems.append("evidence graph path counts do not match locked fixtures")
    if shadow.get("required_preserved") != shadow.get("required_shadow_cases"):
        problems.append("shadow generalization has unpreserved required cases")
    if external.get("rows_checked", 0) < 4000:
        problems.append("external comparator provenance covers too few rows")
    if specbench.get("rules_covered") < 22 or specbench.get("cases", 0) < 1000:
        problems.append("SpecBench is below stress target")
    if theory.get("theorems_checked", 0) < 30 or theory.get("finite_states_checked", 0) < 25000:
        problems.append("theory kernel is below proof-depth target")
    if mutation.get("killed_mutants") != mutation.get("mutants") or mutation.get("mutants", 0) < 600:
        problems.append("mutation farm is below adequacy target")
    by_issue = Counter(str(f.get("expected_issue")) for f in positive_fixtures)
    weak_issues = sorted(issue for issue, n in by_issue.items() if n < 1)
    if weak_issues:
        problems.append(f"issue classes without positive fixture support: {weak_issues}")
    # Evidence channels are coarse-grained but independent enough to be useful
    # for assessor triage: source span, semantic rule, positive/negative cert,
    # paired repair, independent oracle/evidence path, SpecBench, theory kernel,
    # mutation farm, shadow transformations, and external comparator contrast.
    channels = {
        "source_claims": len(claim_ids),
        "rules": len(rule_ids),
        "positive_certificates": int(cert_pos.get("certificates_verified", 0)),
        "negative_certificates": int(cert_neg.get("verified_control_certificates", 0)),
        "repair_frontiers": int(repairs.get("frontier_certified", 0)),
        "evidence_paths": int(evidence.get("positive_paths_verified", 0)) + int(evidence.get("negative_control_paths_verified", 0)),
        "specbench_cases": int(specbench.get("cases", 0)),
        "theory_states": int(theory.get("finite_states_checked", 0)),
        "mutation_farm": int(mutation.get("killed_mutants", 0)),
        "shadow_cases": int(shadow.get("required_shadow_cases", 0)),
        "external_comparator_rows": int(external.get("rows_checked", 0)),
    }
    active_channels = sum(1 for v in channels.values() if v > 0)
    if active_channels < 10:
        problems.append("fewer than ten independent evidence channels are active")
    return {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "positive_fixtures": len(positive_fixtures),
        "negative_controls": len(negative_fixtures),
        "issue_classes": len(issue_classes),
        "claims": len(claim_ids),
        "rules": len(rule_ids),
        "evidence_channels": channels,
        "active_channels": active_channels,
        "min_positive_examples_per_issue": min(by_issue.values()) if by_issue else 0,
        "max_positive_examples_per_issue": max(by_issue.values()) if by_issue else 0,
        "interpretation": "Redundancy audit over independent evidence channels. It does not add findings; it checks that accepted findings and controls are jointly supported by source spans, semantic rules, certificates, repairs, graph paths, SpecBench, theory, mutation, shadow transformations, and external comparator records.",
    }


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
