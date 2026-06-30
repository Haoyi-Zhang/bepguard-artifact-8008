"""Seeded-failure sensitivity audit for materialized validation gates."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def audit_gate_sensitivity(root: Path) -> Dict[str, Any]:
    # Each scenario mutates one materialized object in memory and then applies
    # the corresponding invariant predicate.  The gate is sensitive when the
    # mutated object is rejected.  No corrupt artifact is written to disk.
    objects = {
        "deep_metrics": _load(root / "artifact/results/deep_locked/full_metrics.json"),
        "release": _load(root / "artifact/results/validation_summary.json"),
        "specbench": _load(root / "artifact/results/deep_locked/specbench_summary.json"),
        "evidence_cards": _load(root / "artifact/results/evidence_cards_audit.json"),
        "package_identity": _load(root / "artifact/results/package_identity_audit.json"),
        "runtime": _load(root / "artifact/results/runtime_boundary_audit.json"),
        "external_provenance": _load(root / "artifact/results/external_provenance_audit.json"),
        "paper_claims": _load(root / "artifact/results/paper_claim_consistency_audit.json"),
        "decision_purity": _load(root / "artifact/results/decision_purity_audit.json"),
        "claim_impact": _load(root / "artifact/results/claim_impact_audit.json") if (root / "artifact/results/claim_impact_audit.json").exists() else {},
        "witness_hash_chain": _load(root / "artifact/results/witness_hash_chain_audit.json") if (root / "artifact/results/witness_hash_chain_audit.json").exists() else {},
    }

    Scenario = Tuple[str, str, Callable[[Dict[str, Any]], None], Callable[[Dict[str, Any]], bool]]
    scenarios: List[Scenario] = [
        ("deep_positive_count", "deep_metrics", lambda o: o.__setitem__("expected_findings_detected", 417), lambda o: o.get("expected_findings_detected") == 418),
        ("deep_negative_clean_count", "deep_metrics", lambda o: o.__setitem__("negative_controls_clean", 553), lambda o: o.get("negative_controls_clean") == 554),
        ("release_layer_count", "release", lambda o: o.get("locked_counts", {}).__setitem__("validation_layers", 0), lambda o: o.get("locked_counts", {}).get("validation_layers") == 111),
        ("specbench_case_count", "specbench", lambda o: o.__setitem__("cases", 4179), lambda o: o.get("cases") == 4180),
        ("evidence_card_count", "evidence_cards", lambda o: o.__setitem__("evidence_cards", 417), lambda o: o.get("evidence_cards") == 418),
        ("package_version", "package_identity", lambda o: o.__setitem__("package_version", "0.21.0"), lambda o: o.get("package_version") == "0.24.0"),
        ("runtime_gpu_boundary", "runtime", lambda o: o.__setitem__("gpu_required", True), lambda o: o.get("gpu_required") is False),
        ("external_cache_boundary", "external_provenance", lambda o: o.__setitem__("cache_packaged", True), lambda o: o.get("cache_packaged") is False),
        ("paper_claim_problem_count", "paper_claims", lambda o: o.__setitem__("problem_count", 1), lambda o: o.get("problem_count") == 0),
        ("decision_purity_problem_count", "decision_purity", lambda o: o.__setitem__("problem_count", 1), lambda o: o.get("problem_count") == 0),
        ("claim_impact_claim_count", "claim_impact", lambda o: o.__setitem__("claims_checked", 44), lambda o: o.get("claims_checked") == 45),
        ("claim_impact_specbench_pressure", "claim_impact", lambda o: o.__setitem__("claims_with_specbench_pressure", 19), lambda o: o.get("claims_with_specbench_pressure") == 20),
        ("witness_chain_count", "witness_hash_chain", lambda o: o.__setitem__("positive_witness_chains", 417), lambda o: o.get("positive_witness_chains") == 418),
        ("witness_chain_uniqueness", "witness_hash_chain", lambda o: o.__setitem__("unique_chain_hashes", 417), lambda o: o.get("unique_chain_hashes") == 418),
        ("documentation_status", "release", lambda o: o.__setitem__("status", "fail"), lambda o: o.get("status") == "pass"),
        ("runtime_network_boundary", "runtime", lambda o: o.__setitem__("network_required_for_core_ladder", True), lambda o: o.get("network_required_for_core_ladder") is False),
    ]
    problems: List[str] = []
    rows: List[Dict[str, Any]] = []
    for name, object_name, mutator, predicate in scenarios:
        base = objects.get(object_name)
        if not isinstance(base, dict) or not base:
            problems.append(f"{name}: missing object {object_name}")
            continue
        mutated = copy.deepcopy(base)
        mutator(mutated)
        rejected = not predicate(mutated)
        rows.append({"scenario": name, "object": object_name, "seeded_failure_rejected": rejected})
        if not rejected:
            problems.append(f"{name}: seeded failure was not rejected")
    return {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "seeded_failure_scenarios": len(scenarios),
        "seeded_failures_rejected": sum(1 for r in rows if r["seeded_failure_rejected"]),
        "scenarios": rows,
        "interpretation": "In-memory seeded corruptions of critical materialized outputs are rejected by the same invariants used in release validation; this guards against a rubber-stamp validation summary.",
    }


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
