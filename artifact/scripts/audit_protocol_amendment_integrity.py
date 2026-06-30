#!/usr/bin/env python3
"""Protocol-amendment integrity audit.

The protocol amendment ledger is the public explanation for post-lock changes.
This audit ensures that amendment identifiers are contiguous, parseable, closed,
and aligned with the release validation gates, so assessors do not have to infer
whether a validation layer was added without an amendment.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True

import argparse, csv, json, re
from pathlib import Path

EXPECTED_IDS = [f"A{i:03d}" for i in range(1, 100)]
REQUIRED_SUFFIXES = {
    "A015": "SEMANTIC_RECOMPUTATION_CLOSURE",
    "A016": "RELEASE_LANGUAGE_INTEGRITY",
    "A017": "BIBLIOGRAPHIC_METADATA_HYGIENE",
    "A018": "PDF_SOURCE_COMPILE_CLOSURE",
    "A019": "VALIDATION_ORCHESTRATION_STABILITY",
    "A020": "DIRECTIVE_FALLBACK_CONFORMANCE",
    "A021": "CORS_MODED_RESOURCE_OPT_IN",
    "A022": "BASELINE_CONTRACT_AND_DEEP_PROBE",
    "A023": "REPRODUCTION_LADDER_CONTRACT",
    "A024": "REPOSITORY_RESEARCH_INFRASTRUCTURE",
    "A025": "SPECBENCH_AND_PROPERTY_VALIDATION",
    "A026": "EVIDENCE_GRAPH_AND_ANTI_OVERFIT_AUDIT",
    "A027": "SPECBENCH_STRESS_AND_STRICT_SMOKE",
    "A028": "RULE_MATURITY_CLOSURE",
    "A029": "FINITE_THEORY_KERNEL",
    "A030": "SEMANTIC_MUTATION_FARM",
    "A031": "PAPER_SYNC_AND_VISUAL_DENSITY",
    "A032": "FULL_EXTERNAL_COMPARATOR_RUN",
    "A033": "THEORY_KERNEL_AND_MUTATION_FARM_EXPANSION",
    "A034": "SPECBENCH_STRESS_EXPANSION",
    "A035": "PAPER_SYNC_WITH_EXTERNAL_RUN",
    "A036": "SHADOW_GENERALIZATION_AND_OVERFIT_AUDIT",
    "A037": "THEORY_MUTATION_SPECBENCH_DEEPENING",
    "A038": "EXTERNAL_PROVENANCE_CACHE_EXCLUSION",
    "A039": "SCALE_STRESS_AND_EVIDENCE_REDUNDANCY",
    "A040": "LATEX_FIGURE_LAYOUT_AND_PAPER_SYNC",
    "A041": "IDENTIFIER_BLIND_REPLAY_AND_REPAIR_DELTA",
    "A042": "SPECBENCH_AND_SHADOW_COMPOSITE_STRESS",
    "A043": "PROOF_CARD_AND_SCALE_REPLAY_EXPANSION",
    "A044": "CAUSAL_COUNTERFACTUAL_ACTIVATION",
    "A045": "EXTERNAL_CONTRAST_SPECIFICITY",
    "A046": "BENCHMARK_DISJOINTNESS_AND_RUNTIME_BOUNDARY",
    "A047": "PAPER_CLAIM_CONSISTENCY_AND_SYNC",
    "A048": "THIRD_ORACLE_AND_LABEL_FLOW_SEPARATION",
    "A049": "ISSUE_EVIDENCE_DEPTH_CLOSURE",
    "A050": "STRICT_REFERENCES_ONLY_BOUNDARY",
    "A051": "RELEASE_BOUNDARY_SYNCHRONIZATION",
    "A052": "WHOLE_CORPUS_STABILITY_REPLAY",
    "A053": "ASSESSOR_EVIDENCE_CARDS",
    "A054": "DECISION_PURITY_AND_VERSION_CLOSURE",
    "A055": "DOCUMENTATION_FRESHNESS_AND_REPRODUCTION_LADDER",
    "A056": "RELEASE_STABILITY_SYNCHRONIZATION",
    "A057": "COUNTERFACTUAL_ROUNDTRIP_AND_ORACLE_EQUIVALENCE",
    "A058": "RULE_TRACE_MATRIX_CLOSURE",
    "A059": "RELEASE_CLAIM_DRIFT_GUARD",
    "A060": "ORACLE_TRIANGULATION_STATIC_HEALTH_REPAIR_LOCALITY_RQ",
    "A061": "CLAIM_IMPACT_CLOSURE",
    "A062": "WITNESS_HASH_CHAIN_PROVENANCE",
    "A063": "VALIDATION_GATE_SENSITIVITY",
    "A064": "IDEMPOTENCE_REPLAY_CLOSURE",
    "A065": "SOURCE_CLAIM_TRACE_SATURATION",
    "A066": "REPAIR_COMPACTNESS_AND_COUNTERFACTUAL_LOCALITY",
    "A067": "DETERMINISTIC_REEXECUTION_CONSISTENCY",
    "A068": "POLICY_INTERACTION_COVERAGE",
    "A069": "RELEASE_CLAIMTRACE_SYNCHRONIZATION",
    "A070": "PROCESS_TRACE_HYGIENE",
    "A071": "ASSESSOR_THREAT_CLOSURE",
    "A072": "EVIDENCE_PATH_MULTIPLICITY",
    "A073": "MINIMAL_PAIR_CLOSURE",
    "A074": "FOLD_STRATIFICATION",
    "A075": "DELIVERY_CAPSULE",
    "A076": "PAPER_ARGUMENT_SURFACE",
    "A077": "RELEASE_HYGIENE",
    "A078": "RELEASE_DELIVERY_SYNCHRONIZATION",
    "A079": "STALE_NUMERIC_SURFACE_CLOSURE",
    "A080": "ICSE_CRITERIA_EVIDENCE_CLOSURE",
    "A081": "CONTRIBUTION_TRACE_CLOSURE",
    "A082": "REFERENCE_ROLE_BALANCE",
    "A083": "ORACLE_STRUCTURAL_INDEPENDENCE",
    "A084": "DELIVERABLE_TRIO_READINESS",
    "A085": "PAPER_RHETORIC_AND_ARGUMENT_POLISH",
    "A086": "REPOSITORY_ENTRYPOINT_CLOSURE",
    "A087": "RELEASE_ASSESSOR_SCORECARD_AND_SYNCHRONIZATION",
    "A088": "DELIVERY_METADATA_ALIGNMENT",
    "A089": "ASSESSOR_QUICKSTART_READINESS",
    "A090": "FIGURE_REFERENCE_CLOSURE",
    "A091": "SUPPLEMENT_MAIN_ALIGNMENT",
    "A092": "ARTIFACT_MANIFEST_REACHABILITY",
    "A093": "EVIDENCE_DIGEST_LEDGER",
    "A094": "ASSESSOR_TRIAGE_INDEX",
    "A095": "RELEASE_DELIVERY_PACKET",
    "A096": "OVERCLAIM_BOUNDARY_CLOSURE",
    "A097": "COMPILED_PDF_TEXT_SURFACE",
    "A098": "PUBLIC_PROVENANCE_AND_DATA_RIGHTS",
    "A099": "REPOSITORY_UPLOAD_PACKET",
}

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--out", default="artifact/results/protocol_amendment_integrity_audit.json")
    args = ap.parse_args()
    root = Path(args.root)
    path = root / "artifact/protocol_amendments.csv"
    problems = []
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        rows = list(reader)
        fields = reader.fieldnames or []
    expected_fields = ["date", "amendment_id", "affected_section", "motivation", "change", "data_observed_before_change", "why_not_result_improving", "status"]
    if fields != expected_fields:
        problems.append(f"unexpected amendment ledger columns: {fields}")
    ids = [r.get("amendment_id", "") for r in rows]
    prefixes = [i.split("_", 1)[0] for i in ids]
    if prefixes != EXPECTED_IDS:
        problems.append(f"amendment ids are not contiguous A001-A099: {ids}")
    if len(ids) != len(set(ids)):
        problems.append("duplicate amendment ids present")
    for row in rows:
        if row.get("status") != "closed":
            problems.append(f"amendment not closed: {row.get('amendment_id')}")
        for field in expected_fields:
            if not row.get(field, "").strip():
                problems.append(f"empty {field} in {row.get('amendment_id')}")
    for prefix, suffix in REQUIRED_SUFFIXES.items():
        matches = [i for i in ids if i.startswith(prefix + "_")]
        if len(matches) != 1 or not matches[0].endswith(suffix):
            problems.append(f"{prefix} does not identify {suffix}: {matches}")
    # The release validation wrapper invokes this audit while constructing a new
    # summary, so this audit avoids a circular dependency on the summary it helps
    # produce.  It checks the amendment ledger itself; the wrapper checks layer
    # membership after all gates run.
    result = {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "amendment_count": len(rows),
        "amendment_ids": ids,
        "interpretation": "Checks that post-lock amendments are complete and closed; it does not change locked results.",
    }
    out = root / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "problem_count": len(problems), "amendments": len(rows)}, sort_keys=True))
    if problems:
        raise SystemExit(2)

if __name__ == "__main__":
    main()
