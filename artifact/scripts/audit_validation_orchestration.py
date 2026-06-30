#!/usr/bin/env python3
"""Audit the release-validation orchestration contract.

The release has many executable gates.  The release summary gate should remain a
memory-stable checker over materialized outputs rather than a nested build system
that can fail nondeterministically in constrained review environments.  This
audit makes that contract executable instead of leaving it as prose.
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path
from typing import List

sys.dont_write_bytecode = True

from common_paths import package_root

REQUIRED_OUTPUT_TOKENS = {
    "admitted_source_snapshot_closure",
    "positive_certificates",
    "negative_certificates",
    "decision_oracle",
    "directive_fallback_conformance",
    "cross_policy_contracts",
    "baseline_contract",
    "reproducibility_ladder",
    "mutation_adequacy",
    "bep_max_integrity",
    "repair_frontier",
    "traceability_obligations",
    "source_span_closure",
    "reference_integrity",
    "anonymity",
    "clean_package",
    "release_consistency",
    "latex_source_integrity",
    "materialization_lineage",
    "protocol_rq_consistency",
    "validation_report_consistency",
    "semantic_recomputation",
    "release_language_integrity",
    "protocol_amendment_integrity",
    "bibliographic_metadata",
    "pdf_source_compile",
    "validation_orchestration",
    "typed_ir_schema",
    "semantic_lattice_proofs",
    "specbench",
    "metamorphic_relations",
    "certificate_recheck",
    "external_benchmark_contract",
    "external_baseline_full_run",
    "external_package_lock",
    "generated_oracle_tests",
    "repository_quality",
    "evidence_graph",
    "anti_overfit_leakage",
    "strict_reproducibility_smoke",
    "theory_kernel",
    "mutation_farm",
    "rule_maturity",
    "pdf_visual_density",
    "shadow_generalization",
    "external_provenance",
    "scale_stress",
    "evidence_redundancy",
    "figure_layout",
    "identifier_blind_replay",
    "repair_delta_replay",
    "theory_proof_cards",
    "causal_counterfactual_activation",
    "external_contrast_specificity",
    "benchmark_fingerprint_disjointness",
    "paper_claim_consistency",
    "runtime_boundary",
    "declarative_oracle",
    "label_flow",
    "issue_evidence_depth",
    "pdf_reference_boundary",
    "corpus_stability",
    "evidence_cards",
    "decision_purity",
    "documentation_consistency",
    "package_identity",
    "counterfactual_roundtrip",
    "oracle_explanation_equivalence",
    "rule_trace_matrix",
    "release_claim_drift",
    "oracle_triangulation",
    "static_code_health",
    "repair_locality",
    "rq_traceability",
    "claim_impact",
    "witness_hash_chain",
    "gate_sensitivity",
    "idempotence_replay",
    "claim_trace_saturation",
    "repair_compactness",
    "deterministic_reexecution",
    "interaction_coverage",
    "process_trace_hygiene",
    "threat_closure",
    "evidence_path_multiplicity",
    "minimal_pair_closure",
    "fold_stratification",
    "delivery_capsule",
    "paper_argument_surface",
    "release_hygiene",
    "stale_numeric_surface",
    "icse_criteria_closure",
    "contribution_trace",
    "reference_role_balance",
    "oracle_structural_independence",
    "deliverable_trio_readiness",
    "paper_rhetoric",
    "repository_entrypoint",
    "scorecard",
}
FORBIDDEN_CALL_QUALIFIERS = {"subprocess", "os.system", "os.popen", "shutil.rmtree"}


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def main() -> None:
    ap = argparse.ArgumentParser(description="Audit release-validation orchestration stability.")
    ap.add_argument("--root", default=None)
    ap.add_argument("--out", default="artifact/results/validation_orchestration_audit.json")
    args = ap.parse_args()

    root = Path(args.root).resolve() if args.root else package_root(__file__)
    script = root / "artifact/scripts/run_validation.py"
    problems: List[str] = []
    text = script.read_text(encoding="utf-8") if script.exists() else ""

    if not script.exists():
        problems.append("missing release validation script")
        tree = ast.parse("")
    else:
        try:
            tree = ast.parse(text)
        except SyntaxError as exc:
            problems.append(f"run_validation.py is not parseable: {exc}")
            tree = ast.parse("")

    imports_subprocess = False
    call_targets: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports_subprocess = imports_subprocess or any(alias.name == "subprocess" for alias in node.names)
        if isinstance(node, ast.ImportFrom):
            imports_subprocess = imports_subprocess or node.module == "subprocess"
        if isinstance(node, ast.Call):
            name = dotted_name(node.func)
            if name:
                call_targets.append(name)

    forbidden_calls = sorted({name for name in call_targets if name in FORBIDDEN_CALL_QUALIFIERS or name.startswith("subprocess.")})
    if imports_subprocess:
        problems.append("release validation imports subprocess")
    if forbidden_calls:
        problems.append(f"release validation uses forbidden nested execution calls: {forbidden_calls}")
    if "'validation_layers': 111" not in text and '"validation_layers": 111' not in text:
        problems.append("release validation does not declare the 111-layer expectation")
    missing_tokens = sorted(t for t in REQUIRED_OUTPUT_TOKENS if t not in text)
    if missing_tokens:
        problems.append(f"release validation omits required materialized-output checks: {missing_tokens}")

    result = {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "mode": "memory-stable materialized-output release gate",
        "release_gate_nested_subprocesses": len(forbidden_calls),
        "imports_subprocess": imports_subprocess,
        "required_materialized_checks": sorted(REQUIRED_OUTPUT_TOKENS),
        "heavy_gates_separately_reproducible": [
            "anti_overfit_leakage",
            "baseline_contract",
            "benchmark_fingerprint_disjointness",
            "bep_max_integrity",
            "bibliographic_metadata",
            "causal_counterfactual_activation",
            "certificate_recheck",
            "claim_impact",
            "claim_trace_saturation",
            "clean_package",
            "corpus_stability",
            "counterfactual_roundtrip",
            "cross_policy_contracts",
            "decision_oracle",
            "decision_purity",
            "declarative_oracle",
            "deterministic_reexecution",
            "directive_fallback_conformance",
            "documentation_consistency",
            "evidence_cards",
            "evidence_graph",
            "evidence_redundancy",
            "external_baseline_full_run",
            "external_benchmark_contract",
            "external_contrast_specificity",
            "external_package_lock",
            "external_provenance",
            "figure_layout",
            "gate_sensitivity",
            "generated_oracle_tests",
            "identifier_blind_replay",
            "idempotence_replay",
            "interaction_coverage",
            "process_trace_hygiene",
            "threat_closure",
            "evidence_path_multiplicity",
            "minimal_pair_closure",
            "fold_stratification",
            "delivery_capsule",
            "paper_argument_surface",
            "release_hygiene",
            "stale_numeric_surface",
            "icse_criteria_closure",
            "contribution_trace",
            "reference_role_balance",
            "oracle_structural_independence",
            "deliverable_trio_readiness",
            "paper_rhetoric",
            "repository_entrypoint",
            "scorecard",
            "issue_evidence_depth",
            "label_flow",
            "latex_source_integrity",
            "materialization_lineage",
            "metamorphic_relations",
            "mutation_adequacy",
            "mutation_farm",
            "negative_certificates",
            "oracle_explanation_equivalence",
            "oracle_triangulation",
            "package_identity",
            "paper_claim_consistency",
            "pdf_reference_boundary",
            "pdf_source_compile",
            "pdf_visual_density",
            "positive_certificates",
            "protocol_amendment_integrity",
            "protocol_rq_consistency",
            "reference_integrity",
            "release_claim_drift",
            "release_consistency",
            "release_language_integrity",
            "repair_compactness",
            "repair_delta_replay",
            "repair_frontier",
            "repair_locality",
            "repository_quality",
            "reproducibility_ladder",
            "rq_traceability",
            "rule_maturity",
            "rule_trace_matrix",
            "runtime_boundary",
            "scale_stress",
            "semantic_lattice_proofs",
            "semantic_recomputation",
            "shadow_generalization",
            "source_span_closure",
            "specbench",
            "static_code_health",
            "strict_reproducibility_smoke",
            "anonymity",
            "theory_kernel",
            "theory_proof_cards",
            "traceability_obligations",
            "typed_ir_schema",
            "validation_orchestration",
            "validation_report_consistency",
            "witness_hash_chain",
        ],
        "interpretation": "The release validation entry point checks materialized outputs from the expanded validation ladder and avoids nested subprocess orchestration. Heavy recomputation, source compilation, and reproduction-ladder gates remain executable as standalone scripts and their audit outputs are required by the release summary.",
    }
    write_json(root / args.out, result)
    print(json.dumps({"status": result["status"], "problem_count": len(problems), "nested_subprocesses": len(forbidden_calls)}, sort_keys=True))
    if problems:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
