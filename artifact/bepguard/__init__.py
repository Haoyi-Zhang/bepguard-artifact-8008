"""BEPGuard research artifact support library.

The package contains deterministic, CPU-native utilities used by the anonymous
Browser-Enforced Policy intent-drift artifact.  Modules in this package are
kept separate from the historical script entry points so assessors can inspect
stable research objects instead of only command-line glue:

* ``ir`` defines a typed BEP-IR normalization and schema checker.
* ``lattice`` defines finite policy-decision lattices and proof contracts.
* ``specbench`` materializes source-derived boundary cases outside the locked
  BEP-Deep denominator.
* ``metamorphic`` checks semantic-preserving and repair-inducing relations.
* ``proof`` independently rechecks witness certificate closure.
* ``external`` checks external-baseline and benchmark-adapter contracts.
* ``repository`` audits codebase hygiene, determinism, and portability.
* ``corpus_stability`` replays the locked corpus under neutral perturbations.
* ``evidence_cards`` materializes evidence-facing source-to-repair evidence cards.
* ``decision_purity`` audits AST-level separation between decision logic and labels.
* ``documentation_consistency`` checks that paper/artifact text does not retain stale validation counts.
* ``package_identity`` checks package/environment identity closure.
* ``claim_trace`` materializes claim-level trace cards.
* ``repair_compactness`` checks that paired repairs are local counterfactual edits.
* ``deterministic_reexecution`` reruns selected lightweight gates twice.
* ``interaction_coverage`` exposes family and multi-policy coverage.
* ``static_health`` checks parseability, bytecode-cache absence, and local/debug residue.
* ``oracle_triangulation`` checks operational, decision-table, and declarative oracle agreement.
* ``repair_locality`` checks that repairs change policy/context surfaces without relabeling intent.
* ``rq_traceability`` checks that each research question is supported by paper text and materialized results.
* ``claim_impact`` audits source-claim impact across rules, fixtures, SpecBench, evidence cards, and repairs.
* ``witness_hash_chain`` materializes tamper-evident hash chains for positive witnesses.
* ``gate_sensitivity`` checks that seeded corruptions are rejected by validation invariants.
* ``idempotence`` re-executes lightweight evidence-facing gates to temporary outputs.

* ``stale_numeric_surface`` guards evidence-facing counts and version strings.
* ``icse_criteria`` maps official review criteria to materialized evidence.
* ``contribution_trace`` links paper contributions to result files.
* ``reference_roles`` checks reference role balance and non-padding.
* ``oracle_structural`` checks oracle source-surface independence.
* ``deliverable_trio`` checks main/supplement/artifact readiness.
* ``paper_rhetoric`` checks assessor-first writing surface.
* ``repository_entrypoints`` checks assessor navigation entrypoints.
* ``scorecard`` materializes a strict release self-review scorecard.
* ``paper_metadata`` checks title, abstract, and topic alignment for the aligned delivery surface.
* ``quickstart_readiness`` checks the assessor quickstart lanes and commands.
* ``figure_reference_closure`` checks that release LaTeX-native figures, tables, and algorithms are referenced.
* ``supplement_alignment`` checks main/supplement/artifact count synchronization.
* ``artifact_manifest`` checks reachability of capsule and result-index surfaces.
* ``evidence_digest`` materializes a stable digest over core claim/evidence/repair/reference surfaces.
* ``triage_index`` maps common assessor objections to evidence surfaces.
* ``delivery_packet`` checks the release main/supplement/artifact packet.

No module performs live website scanning, hosted service calls, account access,
GPU computation, or external inference calls.
"""
from __future__ import annotations

__all__ = [
    "ir",
    "lattice",
    "specbench",
    "metamorphic",
    "proof",
    "external",
    "repository",
    "documentation_consistency",
    "package_identity",
    "rq_traceability",
    "repair_locality",
    "oracle_triangulation",
    "static_health",
    "decision_purity",
    "evidence_cards",
    "corpus_stability",
    "claim_impact",
    "witness_hash_chain",
    "gate_sensitivity",
    "idempotence",
    "stale_numeric_surface",
    "icse_criteria",
    "contribution_trace",
    "reference_roles",
    "oracle_structural",
    "deliverable_trio",
    "paper_rhetoric",
    "repository_entrypoints",
    "scorecard",
    "paper_metadata",
    "quickstart_readiness",
    "figure_reference_closure",
    "supplement_alignment",
    "artifact_manifest",
    "evidence_digest",
    "triage_index",
    "delivery_packet",
]
__version__ = "0.24.0"
