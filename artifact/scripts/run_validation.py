#!/usr/bin/env python3
"""Memory-stable release validation summary for the release artifact.

This gate checks materialized outputs from the validation ladder. It does not
launch subprocesses: heavy gates such as semantic recomputation, PDF source
compilation, external comparator execution, and smoke tests remain separately
reproducible and are required here through their audit outputs.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True

import argparse, csv, json
from pathlib import Path

try:
    from common_paths import package_root
except ImportError:  # pragma: no cover
    package_root = None  # type: ignore[assignment]

EXPECT = {
    'fixtures': 972,
    'positives': 418,
    'negative_controls': 554,
    'bep_max_cases': 4306,
    'issue_classes': 25,
    'claims': 45,
    'semantic_protocol_rules': 35,
    'references': 72,
    'validation_layers': 111,
    'cross_policy_contracts': 7,
    'cross_policy_states': 111,
    'lattice_contracts': 6,
    'lattice_states': 186,
    'specbench_cases': 4180,
    'specbench_rules': 29,
    'metamorphic_checks': 3954,
    'generated_oracle_tests': 1390,
    'certificate_recheck_obligations': 4870,
    'python_lines_min': 20000,
    'theory_kernel_theorems': 30,
    'theory_kernel_states': 33513,
    'mutation_farm_mutants': 600,
    'shadow_required_cases': 9720,
    'scale_stress_cases': 48600,
    'reproduction_ladder_commands': 101,
    'identifier_blind_replays': 4860,
    'repair_delta_pairs': 418,
    'theory_proof_cards': 30,
    'causal_counterfactual_activations': 546,
    'external_contrast_rows': 4118,
    'benchmark_disjointness_rows': 9586,
    'paper_claims_checked': 9,
    'runtime_boundary_files_min': 350,
    'declarative_oracle_cases': 5152,
    'label_flow_files': 2,
    'issue_evidence_classes': 25,
    'issue_evidence_obligations': 200,
    'corpus_stability_replays': 2916,
    'evidence_cards': 418,
    'decision_purity_functions_min': 70,
    'documentation_documents_checked': 6,
    'counterfactual_roundtrips': 546,
    'oracle_equivalence_cases': 5152,
    'rule_trace_obligations': 280,
    'oracle_triangulation_cells': 2916,
    'static_health_files_min': 130,
    'rq_trace_obligations': 25,
    'release_claim_files': 4,
    'claim_trace_cards': 45,
    'fixture_bearing_claims': 26,
    'repair_compactness_pairs': 418,
    'deterministic_reexecution_commands': 5,
    'deterministic_reexecution_runs': 10,
    'interaction_policy_strata': 16,
    'interaction_policy_signatures': 13,
    'interaction_multi_policy_signatures': 5,
    'claim_impact_claims': 45,
    'claim_impact_rules': 35,
    'witness_hash_chains': 418,
    'gate_sensitivity_scenarios': 16,
    'idempotence_replay_commands': 8,
    'process_trace_files_min': 400,
    'threats': 14,
    'assessor_threat_bindings': 42,
    'evidence_path_cards': 418,
    'evidence_channels_required': 8,
    'minimal_pair_issue_classes': 25,
    'minimal_pair_obligations': 225,
    'fold_stratification_folds': 5,
    'delivery_capsule_required_files': 16,
    'paper_argument_required_phrases': 10,
    'icse_criteria': 5,
    'icse_evidence_bindings': 12,
    'contributions': 4,
    'reference_role_entries': 72,
    'oracle_structural_files': 3,
    'deliverable_artifact_files': 8,
    'repository_entrypoints': 6,
    'delivery_topics_required': 4,
    'quickstart_lanes': 4,
    'quickstart_commands': 5,
    'figure_reference_labels_min': 8,
    'supplement_alignment_surfaces': 4,
    'artifact_manifest_required_files': 10,
    'evidence_digest_inputs': 6,
    'triage_index_entries': 8,
    'release_delivery_surfaces': 3,
    'overclaim_surfaces': 5,
    'pdf_text_pdfs': 2,
    'public_provenance_rows_min': 20,
    'repository_upload_required_entries': 13,
    'strict_assessment_score_min': 95.0,
}



ROOT = package_root(__file__) if package_root is not None else Path.cwd()


def resolve(path: str) -> Path:
    candidate = Path(path)
    return candidate if candidate.is_absolute() else ROOT / candidate


def load(path: str):
    return json.loads(resolve(path).read_text(encoding="utf-8"))


def load_csv(path: str):
    with resolve(path).open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def require(cond: bool, problems: list[str], message: str) -> None:
    if not cond:
        problems.append(message)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="artifact/results/validation_summary.json")
    args = ap.parse_args()
    problems: list[str] = []

    denom = load("artifact/results/denominator_lock_summary.json")
    require(denom.get("workload") == "BEP-Deep", problems, "denominator summary is not BEP-Deep")
    require(denom.get("locked_fixtures_total") == EXPECT["fixtures"], problems, "denominator summary fixture count mismatch")
    require(denom.get("expected_positive_fixtures") == EXPECT["positives"], problems, "denominator summary positive count mismatch")
    require(denom.get("negative_control_fixtures") == EXPECT["negative_controls"], problems, "denominator summary negative-control count mismatch")

    deep = load("artifact/results/deep_locked/full_metrics.json")
    require(deep.get("fixtures") == EXPECT["fixtures"], problems, "unexpected BEP-Deep fixture count")
    require(deep.get("expected_findings_detected") == EXPECT["positives"], problems, "unexpected detected positive count")
    require(deep.get("negative_controls") == EXPECT["negative_controls"], problems, "unexpected negative-control count")
    require(deep.get("negative_controls_clean") == EXPECT["negative_controls"], problems, "negative controls not clean")

    checks = {
        "positive_certificates": load("artifact/results/deep_locked/proof_carrying_witness_metrics.json"),
        "negative_certificates": load("artifact/results/deep_locked/control_certificate_metrics.json"),
        "decision_oracle": load("artifact/results/deep_locked/decision_table_oracle_metrics.json"),
        "directive_fallback_conformance": load("artifact/results/deep_locked/directive_fallback_conformance.json"),
        "cross_policy_contracts": load("artifact/results/deep_locked/cross_policy_contracts.json"),
        "baseline_contract": load("artifact/results/baseline_contract_audit.json"),
        "reproducibility_ladder": load("artifact/results/reproducibility_ladder_audit.json"),
        "mutation_adequacy": load("artifact/results/deep_locked/semantic_mutation_adequacy.json"),
        "bep_max_integrity": load("artifact/results/bep_max/adversarial_suite_integrity.json"),
        "repair_frontier": load("artifact/results/bep_max/repair_frontier_metrics.json"),
        "traceability_obligations": load("artifact/results/deep_locked/traceability_obligation_metrics.json"),
        "source_span_closure": load("artifact/results/source_span_closure_metrics.json"),
        "reference_integrity": load("artifact/results/reference_integrity_audit.json"),
        "anonymity": load("artifact/results/anonymity_audit.json"),
        "clean_package": load("artifact/results/clean_package_check.json"),
        "release_consistency": load("artifact/results/release_consistency_audit.json"),
        "latex_source_integrity": load("artifact/results/latex_source_integrity_audit.json"),
        "materialization_lineage": load("artifact/results/materialization_lineage_audit.json"),
        "protocol_rq_consistency": load("artifact/results/protocol_rq_consistency_audit.json"),
        "validation_report_consistency": load("artifact/results/validation_report_consistency_audit.json"),
        "semantic_recomputation": load("artifact/results/semantic_recomputation_audit.json"),
        "release_language_integrity": load("artifact/results/release_language_integrity_audit.json"),
        "protocol_amendment_integrity": load("artifact/results/protocol_amendment_integrity_audit.json"),
        "bibliographic_metadata": load("artifact/results/bibliographic_metadata_audit.json"),
        "pdf_source_compile": load("artifact/results/pdf_source_compile_audit.json"),
        "validation_orchestration": load("artifact/results/validation_orchestration_audit.json"),
        "typed_ir_schema": load("artifact/results/deep_locked/typed_ir_schema_audit.json"),
        "semantic_lattice_proofs": load("artifact/results/deep_locked/semantic_lattice_proofs.json"),
        "specbench": load("artifact/results/deep_locked/specbench_summary.json"),
        "metamorphic_relations": load("artifact/results/deep_locked/metamorphic_relation_audit.json"),
        "certificate_recheck": load("artifact/results/deep_locked/certificate_recheck_audit.json"),
        "external_benchmark_contract": load("artifact/results/external_benchmark_contract_audit.json"),
        "external_baseline_full_run": load("artifact/results/external_baseline_full_run_audit.json"),
        "external_package_lock": load("artifact/external_baseline_package_lock.json"),
        "generated_oracle_tests": load("artifact/results/generated_oracle_tests.json"),
        "repository_quality": load("artifact/results/repository_quality_audit.json"),
        "evidence_graph": load("artifact/results/evidence_graph_metrics.json"),
        "anti_overfit_leakage": load("artifact/results/anti_overfit_leakage_audit.json"),
        "strict_reproducibility_smoke": load("artifact/results/strict_reproducibility_smoke.json"),
        "theory_kernel": load("artifact/results/deep_locked/theory_kernel_audit.json"),
        "mutation_farm": load("artifact/results/deep_locked/mutation_farm_summary.json"),
        "rule_maturity": load("artifact/results/rule_maturity_audit.json"),
        "pdf_visual_density": load("artifact/results/pdf_visual_density_audit.json"),
        "shadow_generalization": load("artifact/results/deep_locked/shadow_generalization_audit.json"),
        "external_provenance": load("artifact/results/external_provenance_audit.json"),
        "scale_stress": load("artifact/results/deep_locked/scale_stress_audit.json"),
        "evidence_redundancy": load("artifact/results/evidence_redundancy_audit.json"),
        "figure_layout": load("artifact/results/figure_layout_audit.json"),
        "identifier_blind_replay": load("artifact/results/deep_locked/identifier_blind_replay_audit.json"),
        "repair_delta_replay": load("artifact/results/deep_locked/repair_delta_replay_audit.json"),
        "theory_proof_cards": load("artifact/results/deep_locked/theory_proof_cards.json"),
        "causal_counterfactual_activation": load("artifact/results/deep_locked/causal_counterfactual_activation_audit.json"),
        "external_contrast_specificity": load("artifact/results/external_contrast_specificity_audit.json"),
        "benchmark_fingerprint_disjointness": load("artifact/results/deep_locked/benchmark_fingerprint_disjointness_audit.json"),
        "paper_claim_consistency": load("artifact/results/paper_claim_consistency_audit.json"),
        "runtime_boundary": load("artifact/results/runtime_boundary_audit.json"),
        "declarative_oracle": load("artifact/results/deep_locked/declarative_oracle_audit.json"),
        "label_flow": load("artifact/results/label_flow_audit.json"),
        "issue_evidence_depth": load("artifact/results/deep_locked/issue_evidence_depth_audit.json"),
        "pdf_reference_boundary": load("artifact/results/pdf_reference_boundary_audit.json"),
        "corpus_stability": load("artifact/results/deep_locked/corpus_stability_audit.json"),
        "evidence_cards": load("artifact/results/evidence_cards_audit.json"),
        "decision_purity": load("artifact/results/decision_purity_audit.json"),
        "documentation_consistency": load("artifact/results/documentation_consistency_audit.json"),
        "package_identity": load("artifact/results/package_identity_audit.json"),
        "counterfactual_roundtrip": load("artifact/results/deep_locked/counterfactual_roundtrip_audit.json"),
        "oracle_explanation_equivalence": load("artifact/results/deep_locked/oracle_equivalence_audit.json"),
        "rule_trace_matrix": load("artifact/results/rule_trace_matrix_audit.json"),
        "release_claim_drift": load("artifact/results/release_claim_drift_audit.json"),
        "oracle_triangulation": load("artifact/results/deep_locked/oracle_triangulation_audit.json"),
        "static_code_health": load("artifact/results/static_code_health_audit.json"),
        "repair_locality": load("artifact/results/deep_locked/repair_locality_audit.json"),
        "rq_traceability": load("artifact/results/rq_traceability_audit.json"),
        "claim_impact": load("artifact/results/claim_impact_audit.json"),
        "witness_hash_chain": load("artifact/results/witness_hash_chain_audit.json"),
        "gate_sensitivity": load("artifact/results/gate_sensitivity_audit.json"),
        "idempotence_replay": load("artifact/results/idempotence_replay_audit.json"),
        "claim_trace_saturation": load("artifact/results/deep_locked/source_claim_trace_audit.json"),
        "repair_compactness": load("artifact/results/deep_locked/repair_compactness_audit.json"),
        "deterministic_reexecution": load("artifact/results/deterministic_reexecution_audit.json"),
        "interaction_coverage": load("artifact/results/deep_locked/interaction_coverage_audit.json"),
        "process_trace_hygiene": load("artifact/results/process_trace_hygiene_audit.json"),
        "threat_closure": load("artifact/results/threat_closure_audit.json"),
        "evidence_path_multiplicity": load("artifact/results/evidence_path_multiplicity_audit.json"),
        "minimal_pair_closure": load("artifact/results/deep_locked/minimal_pair_closure_audit.json"),
        "fold_stratification": load("artifact/results/deep_locked/fold_stratification_audit.json"),
        "delivery_capsule": load("artifact/results/delivery_capsule_audit.json"),
        "paper_argument_surface": load("artifact/results/paper_argument_surface_audit.json"),
        "release_hygiene": load("artifact/results/release_hygiene_audit.json"),
        "stale_numeric_surface": load("artifact/results/stale_numeric_surface_audit.json"),
        "icse_criteria_closure": load("artifact/results/icse_criteria_closure_audit.json"),
        "contribution_trace": load("artifact/results/contribution_trace_audit.json"),
        "reference_role_balance": load("artifact/results/reference_role_balance_audit.json"),
        "oracle_structural_independence": load("artifact/results/oracle_structural_independence_audit.json"),
        "deliverable_trio_readiness": load("artifact/results/deliverable_trio_readiness_audit.json"),
        "paper_rhetoric": load("artifact/results/paper_rhetoric_audit.json"),
        "repository_entrypoint": load("artifact/results/repository_entrypoint_audit.json"),
        "scorecard": load("artifact/results/scorecard.json"),
        "paper_metadata_alignment": load("artifact/results/paper_metadata_alignment_audit.json"),
        "quickstart_readiness": load("artifact/results/quickstart_readiness_audit.json"),
        "figure_reference_closure": load("artifact/results/figure_reference_closure_audit.json"),
        "supplement_alignment": load("artifact/results/supplement_alignment_audit.json"),
        "artifact_manifest_reachability": load("artifact/results/artifact_manifest_reachability_audit.json"),
        "evidence_digest": load("artifact/results/evidence_digest_audit.json"),
        "triage_index": load("artifact/results/triage_index_audit.json"),
        "delivery_packet": load("artifact/results/delivery_packet_audit.json"),
        "overclaim_boundary": load("artifact/results/overclaim_boundary_audit.json"),
        "pdf_text_surface": load("artifact/results/pdf_text_surface_audit.json"),
        "public_provenance": load("artifact/results/public_provenance_audit.json"),
        "repository_upload": load("artifact/results/repository_upload_audit.json"),
    }

    root_sources = {r.get("source_id", "") for r in load_csv("artifact/source_snapshot_manifest.csv")}
    data_sources = {r.get("source_id", "") for r in load_csv("artifact/data/source_snapshot_manifest.csv")}
    span_sources = {r.get("source_id", "") for r in load_csv("artifact/source_span_ledger.csv")}
    claim_sources = {r.get("source_id", "") for r in load_csv("artifact/data/corpus_claims.csv")}
    checks["admitted_source_snapshot_closure"] = {
        "status": "pass" if root_sources == data_sources and claim_sources == span_sources and claim_sources.issubset(data_sources) else "fail",
        "root_source_ids": len(root_sources),
        "data_source_ids": len(data_sources),
        "claim_source_ids": len(claim_sources),
        "span_source_ids": len(span_sources),
    }

    require(len(checks) == EXPECT["validation_layers"], problems, "validation layer count mismatch")
    require(checks["admitted_source_snapshot_closure"]["status"] == "pass", problems, "admitted-source snapshot closure mismatch")
    require(checks["positive_certificates"].get("certificates_verified") == EXPECT["positives"], problems, "positive certificate count mismatch")
    require(checks["negative_certificates"].get("verified_control_certificates") == EXPECT["negative_controls"], problems, "negative-control certificate count mismatch")
    require(checks["decision_oracle"].get("locked_fixture_agreements") == EXPECT["fixtures"], problems, "decision-table agreement mismatch")
    require(checks["directive_fallback_conformance"].get("status") == "pass" and checks["directive_fallback_conformance"].get("cases_checked") == 6, problems, "directive fallback conformance mismatch")
    require(checks["cross_policy_contracts"].get("status") == "pass" and checks["cross_policy_contracts"].get("contracts") == EXPECT["cross_policy_contracts"] and checks["cross_policy_contracts"].get("states_checked") == EXPECT["cross_policy_states"], problems, "cross-policy contract verification mismatch")
    require(checks["baseline_contract"].get("status") == "pass" and checks["baseline_contract"].get("problem_count") == 0, problems, "baseline contract audit mismatch")
    require(checks["reproducibility_ladder"].get("status") == "pass" and checks["reproducibility_ladder"].get("commands_declared") == EXPECT["reproduction_ladder_commands"], problems, "reproducibility ladder audit mismatch")
    require(checks["mutation_adequacy"].get("killed_mutants") == checks["mutation_adequacy"].get("semantic_mutants") == 28, problems, "semantic mutation adequacy mismatch")
    require(checks["bep_max_integrity"].get("status") == "pass" and checks["bep_max_integrity"].get("suite_cases") == EXPECT["bep_max_cases"], problems, "BEP-Max integrity mismatch")
    require(checks["repair_frontier"].get("frontier_certified") == EXPECT["positives"], problems, "repair-frontier mismatch")
    require(checks["traceability_obligations"].get("status") == "pass" and checks["traceability_obligations"].get("issue_classes_passing_obligation_closure") == EXPECT["issue_classes"], problems, "traceability obligation closure mismatch")
    require(checks["source_span_closure"].get("status") == "pass" and checks["source_span_closure"].get("claims_with_exactly_one_source_span_row") == EXPECT["claims"], problems, "source-span closure mismatch")
    require(checks["reference_integrity"].get("status") == "pass" and checks["reference_integrity"].get("cited_keys") == EXPECT["references"], problems, "reference integrity mismatch")
    require(checks["anonymity"].get("status") == "pass" and checks["anonymity"].get("problem_count") == 0, problems, "anonymous-paper delivery audit mismatch")
    require(checks["clean_package"].get("problem_count") == 0, problems, "clean-package audit mismatch")
    require(checks["release_consistency"].get("status") == "pass", problems, "release consistency mismatch")
    require(checks["latex_source_integrity"].get("status") == "pass" and checks["latex_source_integrity"].get("problem_count") == 0, problems, "LaTeX source integrity mismatch")
    require(checks["materialization_lineage"].get("status") == "pass" and checks["materialization_lineage"].get("main_workload") == "BEP-Deep", problems, "materialization-lineage closure mismatch")
    require(checks["protocol_rq_consistency"].get("status") == "pass", problems, "protocol-RQ consistency mismatch")
    require(checks["validation_report_consistency"].get("status") == "pass" and checks["validation_report_consistency"].get("release_coding_validation_rows") == EXPECT["claims"], problems, "validation-report consistency mismatch")
    require(checks["semantic_recomputation"].get("status") == "pass" and checks["semantic_recomputation"].get("deep_detected_positives") == EXPECT["positives"] and checks["semantic_recomputation"].get("deep_clean_negative_controls") == EXPECT["negative_controls"], problems, "semantic-recomputation mismatch")
    require(checks["release_language_integrity"].get("status") == "pass" and checks["release_language_integrity"].get("problem_count") == 0, problems, "release-language integrity mismatch")
    require(checks["protocol_amendment_integrity"].get("status") == "pass" and checks["protocol_amendment_integrity"].get("problem_count") == 0 and checks["protocol_amendment_integrity"].get("amendment_count") == 99, problems, "protocol-amendment integrity mismatch")
    require(checks["bibliographic_metadata"].get("status") == "pass" and checks["bibliographic_metadata"].get("entries_checked") == EXPECT["references"], problems, "bibliographic metadata mismatch")
    require(checks["pdf_source_compile"].get("status") == "pass" and checks["pdf_source_compile"].get("main_pages") == 12 and checks["pdf_source_compile"].get("supplement_pages") == 8, problems, "PDF source compile mismatch")
    require(checks["validation_orchestration"].get("status") == "pass" and checks["validation_orchestration"].get("problem_count") == 0, problems, "validation orchestration mismatch")
    require(checks["typed_ir_schema"].get("status") == "pass" and checks["typed_ir_schema"].get("profile", {}).get("fixtures") == EXPECT["fixtures"], problems, "typed BEP-IR schema audit mismatch")
    require(checks["semantic_lattice_proofs"].get("status") == "pass" and checks["semantic_lattice_proofs"].get("contracts") == EXPECT["lattice_contracts"], problems, "semantic lattice proof mismatch")
    require(checks["specbench"].get("status") == "pass" and checks["specbench"].get("cases") == EXPECT["specbench_cases"] and checks["specbench"].get("rules_covered") == EXPECT["specbench_rules"], problems, "BEP-SpecBench audit mismatch")
    require(checks["metamorphic_relations"].get("status") == "pass" and checks["metamorphic_relations"].get("checks") == EXPECT["metamorphic_checks"], problems, "metamorphic relation audit mismatch")
    require(checks["certificate_recheck"].get("status") == "pass" and checks["certificate_recheck"].get("obligations_checked") == EXPECT["certificate_recheck_obligations"], problems, "independent certificate recheck mismatch")
    require(checks["external_benchmark_contract"].get("status") == "pass" and checks["external_benchmark_contract"].get("problem_count") == 0, problems, "external benchmark contract audit mismatch")
    require(checks["external_baseline_full_run"].get("status") == "pass" and checks["external_baseline_full_run"].get("rows_total", 0) >= 4000 and checks["external_baseline_full_run"].get("error_rows") == 0, problems, "external full-baseline execution mismatch")
    require(checks["external_package_lock"].get("status") == "pass" and checks["external_package_lock"].get("node_modules_packaged") is False, problems, "external package lock/cache-exclusion mismatch")
    require(checks["generated_oracle_tests"].get("status") == "pass" and checks["generated_oracle_tests"].get("tests_run") == EXPECT["generated_oracle_tests"], problems, "generated oracle test suite mismatch")
    require(checks["repository_quality"].get("status") == "pass" and checks["repository_quality"].get("score") >= 95 and checks["repository_quality"].get("python_lines") >= EXPECT["python_lines_min"], problems, "repository-quality audit mismatch")
    require(checks["evidence_graph"].get("status") == "pass" and checks["evidence_graph"].get("specbench_cases_linked") == EXPECT["specbench_cases"], problems, "evidence-graph closure mismatch")
    require(checks["anti_overfit_leakage"].get("status") == "pass" and checks["anti_overfit_leakage"].get("locked_fixture_ids_guarded") == EXPECT["fixtures"], problems, "anti-overfit leakage audit mismatch")
    require(checks["strict_reproducibility_smoke"].get("status") == "pass" and checks["strict_reproducibility_smoke"].get("commands_executed") == 6, problems, "strict reproducibility smoke mismatch")
    require(checks["theory_kernel"].get("status") == "pass" and checks["theory_kernel"].get("theorems_checked") == EXPECT["theory_kernel_theorems"] and checks["theory_kernel"].get("finite_states_checked") == EXPECT["theory_kernel_states"], problems, "finite theory-kernel audit mismatch")
    require(checks["mutation_farm"].get("status") == "pass" and checks["mutation_farm"].get("mutants") == EXPECT["mutation_farm_mutants"] and checks["mutation_farm"].get("killed_mutants") == EXPECT["mutation_farm_mutants"], problems, "semantic mutation farm mismatch")
    require(checks["rule_maturity"].get("status") == "pass" and checks["rule_maturity"].get("rules_checked") == EXPECT["semantic_protocol_rules"], problems, "rule-maturity closure mismatch")
    require(checks["pdf_visual_density"].get("status") == "pass" and checks["pdf_visual_density"].get("main_pages") == 12, problems, "PDF visual-density audit mismatch")
    require(checks["shadow_generalization"].get("status") == "pass" and checks["shadow_generalization"].get("required_shadow_cases") == EXPECT["shadow_required_cases"], problems, "BEP-Shadow generalization audit mismatch")
    require(checks["external_provenance"].get("status") == "pass" and checks["external_provenance"].get("cache_packaged") is False, problems, "external provenance/cache-exclusion audit mismatch")
    require(checks["scale_stress"].get("status") == "pass" and checks["scale_stress"].get("stress_cases") == EXPECT["scale_stress_cases"], problems, "BEP-Scale stress replay mismatch")
    require(checks["evidence_redundancy"].get("status") == "pass" and checks["evidence_redundancy"].get("active_channels", 0) >= 10, problems, "evidence redundancy audit mismatch")
    require(checks["figure_layout"].get("status") == "pass" and checks["figure_layout"].get("caption_count", 0) >= 5, problems, "LaTeX figure-layout audit mismatch")
    require(checks["identifier_blind_replay"].get("status") == "pass" and checks["identifier_blind_replay"].get("blind_replays") == EXPECT["identifier_blind_replays"], problems, "identifier-blind replay audit mismatch")
    require(checks["repair_delta_replay"].get("status") == "pass" and checks["repair_delta_replay"].get("positive_repairs_checked") == EXPECT["repair_delta_pairs"], problems, "repair-delta replay audit mismatch")
    require(checks["theory_proof_cards"].get("status") == "pass" and checks["theory_proof_cards"].get("proof_cards_checked") == EXPECT["theory_proof_cards"], problems, "theory proof-card audit mismatch")
    require(checks["causal_counterfactual_activation"].get("status") == "pass" and checks["causal_counterfactual_activation"].get("activated_controls") == EXPECT["causal_counterfactual_activations"], problems, "causal counterfactual activation mismatch")
    require(checks["external_contrast_specificity"].get("status") == "pass" and checks["external_contrast_specificity"].get("rows_total") == EXPECT["external_contrast_rows"], problems, "external contrast-specificity audit mismatch")
    require(checks["benchmark_fingerprint_disjointness"].get("status") == "pass" and checks["benchmark_fingerprint_disjointness"].get("rows_checked") == EXPECT["benchmark_disjointness_rows"], problems, "benchmark fingerprint-disjointness audit mismatch")
    require(checks["paper_claim_consistency"].get("status") == "pass" and checks["paper_claim_consistency"].get("claims_checked") == EXPECT["paper_claims_checked"], problems, "paper claim-consistency audit mismatch")
    require(checks["runtime_boundary"].get("status") == "pass" and checks["runtime_boundary"].get("network_required_for_core_ladder") is False, problems, "runtime boundary audit mismatch")
    require(checks["declarative_oracle"].get("status") == "pass" and checks["declarative_oracle"].get("cases_checked") == EXPECT["declarative_oracle_cases"], problems, "declarative third-oracle audit mismatch")
    require(checks["label_flow"].get("status") == "pass" and checks["label_flow"].get("pure_decision_files_checked") == EXPECT["label_flow_files"], problems, "label-flow separation audit mismatch")
    require(checks["issue_evidence_depth"].get("status") == "pass" and checks["issue_evidence_depth"].get("issue_evidence_obligations") == EXPECT["issue_evidence_obligations"], problems, "issue evidence-depth audit mismatch")
    require(checks["pdf_reference_boundary"].get("status") == "pass" and checks["pdf_reference_boundary"].get("references_only_pages") == "11-12", problems, "strict PDF references-only boundary mismatch")
    require(checks["corpus_stability"].get("status") == "pass" and checks["corpus_stability"].get("neutral_replays") == EXPECT["corpus_stability_replays"], problems, "whole-corpus stability replay mismatch")
    require(checks["evidence_cards"].get("status") == "pass" and checks["evidence_cards"].get("evidence_cards") == EXPECT["evidence_cards"], problems, "assessor evidence-card closure mismatch")
    require(checks["decision_purity"].get("status") == "pass" and checks["decision_purity"].get("pure_decision_functions_checked", 0) >= EXPECT["decision_purity_functions_min"], problems, "decision-purity audit mismatch")
    require(checks["documentation_consistency"].get("status") == "pass" and checks["documentation_consistency"].get("documents_checked") == EXPECT["documentation_documents_checked"], problems, "documentation consistency audit mismatch")
    require(checks["package_identity"].get("status") == "pass" and checks["package_identity"].get("package_name") == "BEPGuard" and checks["package_identity"].get("package_version") == "0.24.0", problems, "package identity/environment lock audit mismatch")
    require(checks["counterfactual_roundtrip"].get("status") == "pass" and checks["counterfactual_roundtrip"].get("required_roundtrips") == EXPECT["counterfactual_roundtrips"], problems, "counterfactual round-trip audit mismatch")
    require(checks["oracle_explanation_equivalence"].get("status") == "pass" and checks["oracle_explanation_equivalence"].get("cases_checked") == EXPECT["declarative_oracle_cases"] and checks["oracle_explanation_equivalence"].get("positive_certificate_crosschecks") == EXPECT["positives"], problems, "oracle explanation-equivalence audit mismatch")
    require(checks["rule_trace_matrix"].get("status") == "pass" and checks["rule_trace_matrix"].get("trace_obligations") == EXPECT["rule_trace_obligations"], problems, "rule trace-matrix audit mismatch")
    require(checks["release_claim_drift"].get("status") == "pass" and checks["release_claim_drift"].get("current_claims", {}).get("validation_layers") == str(EXPECT["validation_layers"]), problems, "release claim-drift audit mismatch")
    require(checks["oracle_triangulation"].get("status") == "pass" and checks["oracle_triangulation"].get("pairwise_agreements") == EXPECT["oracle_triangulation_cells"], problems, "oracle triangulation audit mismatch")
    require(checks["static_code_health"].get("status") == "pass" and checks["static_code_health"].get("python_files_checked", 0) >= 180 and checks["static_code_health"].get("pycache_directories") == 0, problems, "static code-health audit mismatch")
    require(checks["repair_locality"].get("status") == "pass" and checks["repair_locality"].get("positive_repair_pairs_checked") == EXPECT["repair_delta_pairs"] and checks["repair_locality"].get("intent_delta_repairs") == 0, problems, "repair-locality audit mismatch")
    require(checks["rq_traceability"].get("status") == "pass" and checks["rq_traceability"].get("rq_trace_obligations") == EXPECT["rq_trace_obligations"], problems, "RQ traceability audit mismatch")
    require(checks["claim_impact"].get("status") == "pass" and checks["claim_impact"].get("claims_checked") == EXPECT["claim_impact_claims"] and checks["claim_impact"].get("rules_referenced") == EXPECT["claim_impact_rules"], problems, "claim-impact closure mismatch")
    require(checks["witness_hash_chain"].get("status") == "pass" and (checks["witness_hash_chain"].get("positive_witness_chains") == EXPECT["witness_hash_chains"] or checks["witness_hash_chain"].get("unique_chain_hashes") == EXPECT["witness_hash_chains"]), problems, "witness hash-chain audit mismatch")
    require(checks["gate_sensitivity"].get("status") == "pass" and checks["gate_sensitivity"].get("seeded_failure_scenarios") == EXPECT["gate_sensitivity_scenarios"] and checks["gate_sensitivity"].get("seeded_failures_rejected") == EXPECT["gate_sensitivity_scenarios"], problems, "validation gate-sensitivity audit mismatch")
    require(checks["idempotence_replay"].get("status") == "pass" and checks["idempotence_replay"].get("commands_reexecuted") == EXPECT["idempotence_replay_commands"] and checks["idempotence_replay"].get("commands_passing") == EXPECT["idempotence_replay_commands"], problems, "idempotence replay audit mismatch")
    require(checks["claim_trace_saturation"].get("status") == "pass" and checks["claim_trace_saturation"].get("claim_cards") == EXPECT["claim_trace_cards"] and checks["claim_trace_saturation"].get("fixture_bearing_claims") == EXPECT["fixture_bearing_claims"], problems, "source-claim trace saturation mismatch")
    require(checks["repair_compactness"].get("status") == "pass" and checks["repair_compactness"].get("repair_pairs_checked") == EXPECT["repair_compactness_pairs"], problems, "repair-compactness audit mismatch")
    require(checks["deterministic_reexecution"].get("status") == "pass" and checks["deterministic_reexecution"].get("commands_reexecuted") == EXPECT["deterministic_reexecution_commands"] and checks["deterministic_reexecution"].get("total_subprocess_runs") == EXPECT["deterministic_reexecution_runs"], problems, "deterministic re-execution audit mismatch")
    require(checks["interaction_coverage"].get("status") == "pass" and checks["interaction_coverage"].get("policy_family_strata") == EXPECT["interaction_policy_strata"] and checks["interaction_coverage"].get("policy_signatures") == EXPECT["interaction_policy_signatures"] and checks["interaction_coverage"].get("multi_policy_signatures") == EXPECT["interaction_multi_policy_signatures"], problems, "policy interaction-coverage audit mismatch")
    require(checks["process_trace_hygiene"].get("status") == "pass" and checks["process_trace_hygiene"].get("files_checked", 0) >= EXPECT["process_trace_files_min"], problems, "process-trace hygiene audit mismatch")
    require(checks["threat_closure"].get("status") == "pass" and checks["threat_closure"].get("threats_checked") == EXPECT["threats"] and checks["threat_closure"].get("evidence_bindings") == EXPECT["assessor_threat_bindings"], problems, "assessor threat-closure audit mismatch")
    require(checks["evidence_path_multiplicity"].get("status") == "pass" and checks["evidence_path_multiplicity"].get("cards_checked") == EXPECT["evidence_path_cards"] and checks["evidence_path_multiplicity"].get("minimum_channels_present") == EXPECT["evidence_channels_required"], problems, "evidence-path multiplicity audit mismatch")
    require(checks["minimal_pair_closure"].get("status") == "pass" and checks["minimal_pair_closure"].get("issue_classes_checked") == EXPECT["minimal_pair_issue_classes"] and checks["minimal_pair_closure"].get("minimal_pair_obligations") == EXPECT["minimal_pair_obligations"], problems, "minimal-pair closure audit mismatch")
    require(checks["fold_stratification"].get("status") == "pass" and checks["fold_stratification"].get("folds") == EXPECT["fold_stratification_folds"] and checks["fold_stratification"].get("fixtures_checked") == EXPECT["fixtures"], problems, "fold-stratification audit mismatch")
    require(checks["delivery_capsule"].get("status") == "pass" and checks["delivery_capsule"].get("required_capsule_files") == EXPECT["delivery_capsule_required_files"], problems, "paper delivery-capsule audit mismatch")
    require(checks["paper_argument_surface"].get("status") == "pass" and checks["paper_argument_surface"].get("required_phrases_checked") == EXPECT["paper_argument_required_phrases"] and checks["paper_argument_surface"].get("sections") == 8, problems, "paper argument-surface audit mismatch")
    require(checks["release_hygiene"].get("status") == "pass" and checks["release_hygiene"].get("problem_count") == 0, problems, "release-hygiene audit mismatch")

    require(checks["stale_numeric_surface"].get("status") == "pass" and checks["stale_numeric_surface"].get("problem_count") == 0, problems, "stale numeric assessor surface audit mismatch")
    require(checks["icse_criteria_closure"].get("status") == "pass" and checks["icse_criteria_closure"].get("criteria_checked") == EXPECT["icse_criteria"] and checks["icse_criteria_closure"].get("evidence_bindings") >= EXPECT["icse_evidence_bindings"], problems, "ICSE criteria-to-evidence closure mismatch")
    require(checks["contribution_trace"].get("status") == "pass" and checks["contribution_trace"].get("contributions_checked") == EXPECT["contributions"], problems, "contribution trace audit mismatch")
    require(checks["reference_role_balance"].get("status") == "pass" and checks["reference_role_balance"].get("references_checked") == EXPECT["reference_role_entries"], problems, "reference role-balance audit mismatch")
    require(checks["oracle_structural_independence"].get("status") == "pass" and checks["oracle_structural_independence"].get("oracle_files_checked") == EXPECT["oracle_structural_files"] and checks["oracle_structural_independence"].get("hash_distinct") is True, problems, "oracle structural independence audit mismatch")
    require(checks["deliverable_trio_readiness"].get("status") == "pass" and checks["deliverable_trio_readiness"].get("main_pages") == 12 and checks["deliverable_trio_readiness"].get("supplement_pages") == 8 and checks["deliverable_trio_readiness"].get("artifact_link_source_files") == EXPECT["deliverable_artifact_files"], problems, "deliverable trio readiness audit mismatch")
    require(checks["paper_rhetoric"].get("status") == "pass" and checks["paper_rhetoric"].get("sections") == 8 and checks["paper_rhetoric"].get("subsections") == 0, problems, "paper rhetoric audit mismatch")
    require(checks["repository_entrypoint"].get("status") == "pass" and checks["repository_entrypoint"].get("entrypoints_checked") == EXPECT["repository_entrypoints"] and checks["repository_entrypoint"].get("reproduction_commands_seen") == EXPECT["reproduction_ladder_commands"], problems, "repository entrypoint audit mismatch")
    require(checks["scorecard"].get("status") == "pass" and float(checks["scorecard"].get("strict_assessment_score", 0)) >= EXPECT["strict_assessment_score_min"], problems, "release assessor scorecard mismatch")

    require(checks["paper_metadata_alignment"].get("status") == "pass" and checks["paper_metadata_alignment"].get("required_topics_checked") == EXPECT["delivery_topics_required"], problems, "paper delivery title/abstract/topic alignment mismatch")
    require(checks["quickstart_readiness"].get("status") == "pass" and checks["quickstart_readiness"].get("lanes_checked") == EXPECT["quickstart_lanes"] and checks["quickstart_readiness"].get("quickstart_commands_checked") >= EXPECT["quickstart_commands"], problems, "assessor quickstart readiness mismatch")
    require(checks["figure_reference_closure"].get("status") == "pass" and checks["figure_reference_closure"].get("tracked_labels", 0) >= EXPECT["figure_reference_labels_min"], problems, "figure/table reference closure mismatch")
    require(checks["supplement_alignment"].get("status") == "pass" and checks["supplement_alignment"].get("surfaces_checked") == EXPECT["supplement_alignment_surfaces"], problems, "main/supplement/artifact alignment mismatch")
    require(checks["artifact_manifest_reachability"].get("status") == "pass" and checks["artifact_manifest_reachability"].get("required_files_checked") == EXPECT["artifact_manifest_required_files"], problems, "artifact manifest reachability mismatch")
    require(checks["evidence_digest"].get("status") == "pass" and checks["evidence_digest"].get("digest_inputs") == EXPECT["evidence_digest_inputs"] and checks["evidence_digest"].get("claim_cards") == EXPECT["claims"] and checks["evidence_digest"].get("evidence_cards") == EXPECT["positives"], problems, "evidence digest ledger mismatch")
    require(checks["triage_index"].get("status") == "pass" and checks["triage_index"].get("entries_checked") == EXPECT["triage_index_entries"], problems, "assessor triage index mismatch")
    require(checks["delivery_packet"].get("status") == "pass" and checks["delivery_packet"].get("surfaces_checked") == EXPECT["release_delivery_surfaces"] and checks["delivery_packet"].get("validation_layers_seen") == EXPECT["validation_layers"], problems, "release delivery packet mismatch")
    require(checks["overclaim_boundary"].get("status") == "pass" and checks["overclaim_boundary"].get("surfaces_checked") == EXPECT["overclaim_surfaces"], problems, "overclaim-boundary audit mismatch")
    require(checks["pdf_text_surface"].get("status") == "pass" and checks["pdf_text_surface"].get("pdfs_checked") == EXPECT["pdf_text_pdfs"], problems, "compiled PDF text-surface audit mismatch")
    require(checks["public_provenance"].get("status") == "pass" and checks["public_provenance"].get("provenance_rows_checked", 0) >= EXPECT["public_provenance_rows_min"], problems, "public provenance/data-rights audit mismatch")
    require(checks["repository_upload"].get("status") == "pass" and checks["repository_upload"].get("required_include_entries") == EXPECT["repository_upload_required_entries"], problems, "manual repository-upload readiness audit mismatch")

    result = {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "locked_counts": EXPECT,
        "validation_layers_checked": sorted(checks),
        "interpretation": "Memory-stable release validation over the materialized release state. Heavy gates, including semantic recomputation and isolated source compilation, remain separately reproducible and are required here through their materialized audit outputs; this gate avoids nested subprocess orchestration to remain stable in constrained review environments.",
    }
    resolve(args.out).parent.mkdir(parents=True, exist_ok=True)
    resolve(args.out).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "problem_count": len(problems), "validation_layers_checked": len(checks)}, sort_keys=True))
    if problems:
        raise SystemExit(2)

if __name__ == "__main__":
    main()
