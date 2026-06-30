# Reproduction instructions

This artifact reproduces a deterministic, source-grounded fixture experiment for browser-enforced security policy engineering. It does not perform live website scanning, use private accounts, use commercial APIs, or claim public-web prevalence.

## Requirements

- Python 3.10 or newer.
- Optional: Node.js and npm for the unmodified CSP Evaluator wrapper.
- Optional for wrapper probes: a local `mdn-http-observatory-scan` executable, or `MDN_OBSERVATORY_BIN` pointing to that executable, and the pinned Chromium hstspreload Go module if those external baselines are to be executed. If an optional external baseline is unavailable, the wrapper records `unavailable`, `unsupported`, `excluded`, or `error`, and no project logic substitutes for it. The smoke-test path intentionally does not invoke `npx`; this avoids network-dependent package lookup while preserving the unmodified-baseline rule. The committed full public-package comparator output is a separate materialized run from a caller-supplied package work directory with package/version/provenance locks; dependency directories and package-manager caches are deliberately not shipped.

### Configuration matrix

| Environment | Required for | Expected behavior |
| --- | --- | --- |
| Python 3.10+ only | Core semantic reproduction, clean-package check, strict smoke, BEP-Deep oracle replay, 111-layer validation, mutation adequacy, proof/certificate and release-hygiene gates | Reproduces the core contributions and verifies committed baseline-output integrity without network access, private data, GPU computation, or hosted services. |
| Node.js/npm | Optional CSP Evaluator execution through the external wrapper | Used only when the assessor chooses to execute the unmodified external baseline locally; absence is recorded as an availability/status result and does not invalidate the core semantic results. |
| Go plus pinned Chromium hstspreload module | Optional hstspreload comparator execution | Supplementary external-baseline execution only; documented HSTS-preload criteria and committed provenance records remain checkable in Python-only mode. |
| `mdn-http-observatory-scan` or `MDN_OBSERVATORY_BIN` | Optional MDN HTTP Observatory wrapper execution | Supplementary external-baseline execution only; unavailable tools are reported explicitly rather than replaced with project-internal logic. |

A clean Python-only environment is sufficient to reproduce the semantic workload, validation ladder, mutation adequacy, package hygiene, and committed baseline-output integrity checks. Re-executing optional external baselines is supplementary contrastive evidence, not a prerequisite for reproducing the paper's core artifact claims.

## Reviewer triage path, about 15 minutes

Run these commands from the release root. They suppress Python bytecode so that the clean-package check remains meaningful after execution.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/check_artifact_clean.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/run_strict_reproducibility_smoke.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/decision_table_oracle.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/mutation_adequacy_audit.py

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=artifact python3 artifact/scripts/run_dependency_free_test_harness.py

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=artifact python3 -m unittest discover -s artifact/tests

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=artifact python3 artifact/scripts/audit_boundary_conditions.py

PYTHONDONTWRITEBYTECODE=1 python3 - <<'PY'
import json
from collections import Counter
from pathlib import Path
fixtures = json.loads(Path('artifact/data/deep_locked_fixtures.json').read_text(encoding='utf-8'))
roles = Counter(f['fixture_role'] for f in fixtures)
negative_controls = roles['negative_control'] + roles['paired_repair_negative_control']
print(json.dumps({'fixtures': len(fixtures), 'positives': roles['positive'], 'negative_controls': negative_controls}, sort_keys=True))
PY
```

Expected outputs: clean-package reports `problem_count: 0`; strict smoke reports `status: pass` and `commands_executed: 6`; the decision-table oracle reports 972/972 locked-fixture agreement and zero finite-state mismatches; mutation adequacy reports 28/28 killed semantic mutants; the dependency-free harness and `unittest` bridge execute 1,392 generated fixture, certificate, and hygiene tests without pytest; the boundary-condition audit reports 50 non-denominator cases with zero locked-fixture overlap; the denominator count reports 972 fixtures, 418 positives, and 554 negative controls.

Run the objection-closure gate when checking whether labels, oracles, baselines, and generalization evidence are non-circular:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_assessor_objection_closure.py
```

Expected output: `status: pass`, `problem_count: 0`, and six component closures covering source-grounded label provenance, oracle provenance, external-baseline disagreement, held-out generalization, claim-scope coverage, and walkthrough readiness.

## Locked input materialization

Runtime estimate: under 1 minute on a typical CPU-only assessor machine.

The commands below suppress Python bytecode emission so that a reproducer can run the smoke test and then re-run the clean-package check without producing transient cache files.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/materialize_locked_inputs.py
```

This materializes the claim-level corpus, fixture manifest, seed-lineage fixtures, admitted-source snapshot manifest, and synchronized rule-source ledgers. The materialized seed contains 45 source-grounded claims, 35 semantic rules, and 116 base fixtures that seed the BEP-Stress and BEP-Deep workloads. The command prints an explicit seed-lineage status object; it is not the main BEP-Deep denominator summary.

## Seed deterministic run

Runtime estimate: about 5-10 minutes for the full seed lineage block on a typical CPU-only machine.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/run_full_experiment.py   --fixtures artifact/data/locked_full_fixtures.json   --out-dir artifact/results/full_locked

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/minimize_witnesses.py   --fixtures artifact/data/locked_full_fixtures.json   --out artifact/results/full_locked/minimized_witnesses.json   --metrics artifact/results/full_locked/minimization_metrics.json

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/synthesize_repairs.py   --fixtures artifact/data/locked_full_fixtures.json   --out artifact/results/full_locked/repair_synthesis.csv   --fixed-fixtures artifact/results/full_locked/repaired_positive_fixtures.json   --metrics artifact/results/full_locked/repair_synthesis_metrics.json

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/generate_metamorphic_workload.py   --fixtures artifact/data/locked_full_fixtures.json   --out artifact/results/full_locked/metamorphic_workload.json   --summary artifact/results/full_locked/metamorphic_summary.csv   --metrics artifact/results/full_locked/metamorphic_metrics.json

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/baseline_header_presence.py   --fixtures artifact/data/locked_full_fixtures.json   --json-out artifact/results/full_locked/header_presence_baseline.json   --csv-out artifact/results/full_locked/header_presence_baseline.csv

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/baseline_hsts_preload_criterion.py   --fixtures artifact/data/locked_full_fixtures.json   --json-out artifact/results/full_locked/hsts_preload_criterion.json   --csv-out artifact/results/full_locked/hsts_preload_criterion.csv

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/baseline_wrappers.py   --mode availability   --fixtures artifact/data/locked_full_fixtures.json   --out artifact/results/full_locked/external_baseline_availability.json

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/baseline_wrappers.py   --mode fixture-probe   --fixtures artifact/data/locked_full_fixtures.json   --out artifact/results/full_locked/external_baseline_fixture_probe.json

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/summarize_locked_experiment.py   --fixtures artifact/data/locked_full_fixtures.json   --result-dir artifact/results/full_locked
```

The seed run should report 116 fixtures, 88 expected-positive witnesses detected, and 28 clean negative controls. The main-paper workload is BEP-Deep below; the seed run remains reproducible to show the expansion lineage.

## Validation audit

Runtime estimate: about 1-3 minutes.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/validate_corpus_and_coding.py --root .
PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_materialization_lineage.py
```

The audits check schema completeness, source-span/rule/fixture traceability, locked denominator consistency, claim and fixture hashes, admitted-source snapshot alignment, source-span coverage, rule proof-obligation coverage, and the separation between seed-lineage materialization and the main BEP-Deep denominator. It is a deterministic consistency audit and does not claim independent human inter-rater agreement.

## Clean-package check

Runtime estimate: under 1 minute.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/check_artifact_clean.py
```

The expected hygiene result is zero problems.


## Intermediate BEP-Stress deterministic workload

Runtime estimate: about 10-20 minutes for the full block, depending on filesystem speed.

BEP-Stress is retained as an intermediate lineage workload. It expands the seed denominator, adds source-grounded semantic edge families, applies semantic-preserving mutation operators, builds a typed effective-exposure graph, and validates deterministic counterfactual repairs. The main-paper workload is BEP-Deep, which adds paired repair controls and certification checks after this step.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/generate_extended_workload.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/run_full_experiment.py   --fixtures artifact/data/extended_fixtures.json   --out-dir artifact/results/extended_locked

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/minimize_witnesses.py   --fixtures artifact/data/extended_fixtures.json   --out artifact/results/extended_locked/minimized_witnesses.json   --metrics artifact/results/extended_locked/minimization_metrics.json

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/baseline_header_presence.py   --fixtures artifact/data/extended_fixtures.json   --json-out artifact/results/extended_locked/header_presence_baseline.json   --csv-out artifact/results/extended_locked/header_presence_baseline.csv

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/baseline_hsts_preload_criterion.py   --fixtures artifact/data/extended_fixtures.json   --json-out artifact/results/extended_locked/hsts_preload_criterion.json   --csv-out artifact/results/extended_locked/hsts_preload_criterion.csv

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/baseline_wrappers.py   --mode availability   --fixtures artifact/data/extended_fixtures.json   --out artifact/results/extended_locked/external_baseline_availability.json

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/baseline_wrappers.py   --mode fixture-probe   --fixtures artifact/data/extended_fixtures.json   --out artifact/results/extended_locked/external_baseline_fixture_probe.json

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/analyze_extended_results.py   --fixtures artifact/data/extended_fixtures.json   --result-dir artifact/results/extended_locked

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/build_exposure_graph.py   --fixtures artifact/data/extended_fixtures.json   --witnesses artifact/results/extended_locked/full_witnesses.json   --out-dir artifact/results/extended_locked

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/synthesize_repairs.py   --fixtures artifact/data/extended_fixtures.json   --out artifact/results/extended_locked/repair_synthesis.csv   --fixed-fixtures artifact/results/extended_locked/repaired_positive_fixtures.json   --metrics artifact/results/extended_locked/repair_synthesis_metrics.json

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/summarize_locked_experiment.py   --fixtures artifact/data/extended_fixtures.json   --result-dir artifact/results/extended_locked

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/validate_extended_artifacts.py
```

The BEP-Stress lineage run should report 554 fixtures, 418/418 expected positives detected, 136/136 negative controls clean, 418 repaired target issues, 348/348 stable semantic-preserving variants, a 4,123-node effective-exposure graph for the intermediate workload, and a passing extended validation summary.


## Main BEP-Deep deterministic workload

Runtime estimate: about 10-20 minutes for the full block in Python-only mode. Optional external wrapper probes may add time if external tools are installed.

BEP-Deep is the main workload reported by the paper. It adds paired repair negative controls to BEP-Stress and then reruns the semantic oracle, minimizer, controls, repair obligations, semantic-core verification, minimality certification, and summary analyses.
The denominator rationale is documented in `artifact/docs/workload_construction.md`.
The 50 boundary cases in `artifact/data/boundary_conditions.csv` are not part
of the positive/negative denominator; they document manual-review,
unsupported-scope, invalid-input, and not-evaluated surfaces.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/construct_paired_repair_controls.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/run_full_experiment.py \
  --fixtures artifact/data/deep_locked_fixtures.json \
  --out-dir artifact/results/deep_locked

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/minimize_witnesses.py \
  --fixtures artifact/data/deep_locked_fixtures.json \
  --out artifact/results/deep_locked/minimized_witnesses.json \
  --metrics artifact/results/deep_locked/minimization_metrics.json

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/certify_witness_minimality.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/validate_repair_obligations.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/verify_semantic_core.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/baseline_header_presence.py \
  --fixtures artifact/data/deep_locked_fixtures.json \
  --json-out artifact/results/deep_locked/header_presence_baseline.json \
  --csv-out artifact/results/deep_locked/header_presence_baseline.csv

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/baseline_hsts_preload_criterion.py \
  --fixtures artifact/data/deep_locked_fixtures.json \
  --json-out artifact/results/deep_locked/hsts_preload_criterion.json \
  --csv-out artifact/results/deep_locked/hsts_preload_criterion.csv

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/baseline_wrappers.py \
  --mode availability \
  --fixtures artifact/data/deep_locked_fixtures.json \
  --out artifact/results/deep_locked/external_baseline_availability.json

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/baseline_wrappers.py \
  --mode fixture-probe \
  --fixtures artifact/data/deep_locked_fixtures.json \
  --out artifact/results/deep_locked/external_baseline_fixture_probe.json

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/analyze_extended_results.py \
  --fixtures artifact/data/deep_locked_fixtures.json \
  --result-dir artifact/results/deep_locked
```

The BEP-Deep run should report 972 fixtures, 418/418 expected positives detected, 554/554 negative controls clean, 418/418 repairs removing target and all modeled issues, 418/418 minimality certificates, 554/554 negative-control certificates, 45/45 claim-coverage closure, 13/13 semantic-core invariants, and 348/348 stable semantic-preserving variants.

## Independent oracle and mutation-adequacy audit

Runtime estimate: about 2-5 minutes.

The release validation layer addresses oracle/workload coupling.  The first
script compares the operational witness generator with an independently written
decision-table oracle over all BEP-Deep fixtures and additional finite states.
The second script mutates semantic hinges in the decision oracle; BEP-Deep is
adequate for the checked hinges when all mutants are killed by locked positives
or negative controls.  The third script audits rule/source redundancy.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/decision_table_oracle.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/mutation_adequacy_audit.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_directive_fallback_conformance.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/verify_cross_policy_contracts.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/validate_evidence_redundancy.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/certify_proof_carrying_witnesses.py
```

The expected results are 972/972 locked-fixture agreements, 0 decision-table
mismatches over 351 generated finite states, 28/28 killed semantic mutants, 6/6 source-grounded directive-fallback conformance micro-obligations, 7 cross-policy contracts over 111 finite states, and
0 missing source identifiers in the rule/source ledger, and 418/418 verified proof-carrying witness certificates.



## BEPGuard research-infrastructure validation

Runtime estimate: about 15-30 minutes for the full block; the 111-layer validation summary is a compact alternative and typically completes in a few minutes.

These gates check the repository-level semantic infrastructure added around the locked denominator. They do not add or relabel fixtures; they verify typed BEP-IR shape, source-derived boundary obligations, metamorphic properties, independent certificate replay, external-benchmark adapter contracts, generated oracle tests, and repository hygiene.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_ir_schema.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/verify_lattice_proofs.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/run_specbench.py
PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_evidence_graph.py
PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_anti_overfit_leakage.py
PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/run_strict_reproducibility_smoke.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/verify_metamorphic_relations.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/recheck_witness_certificates.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_external_benchmark_contracts.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/run_generated_oracle_tests.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_repository_quality.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_counterfactual_roundtrip.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_oracle_equivalence.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_rule_trace_matrix.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_release_claim_drift.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_boundary_conditions.py
```

The expected results are 972 typed BEP-IR fixtures with zero schema problems, 6 semantic-lattice contracts over 186 finite states, 4,180 BEP-SpecBench boundary/representation-stress cases covering 29 rules, 2,916 whole-corpus neutral stability replays, 9 metamorphic relations over 3,954 checks, 4,870 independently replayed certificate obligations, evidence-graph closure over 418 positive and 554 negative paths, anti-overfitting leakage checks over 972 fixture ids and 418 certificate ids, 1,390 generated oracle tests, six-command strict smoke execution, 4,118 materialized public-package comparator invocations with zero unavailable/error rows in the committed full-run output, a 4,860-case identifier-blind replay, a 546-case causal counterfactual activation audit, a 418-pair repair-delta replay, a 30-card theory proof-card audit, a 48,600-case scale-stress replay, and 418 evidence-facing evidence cards, 78 pure decision functions checked for metadata separation, 546 counterfactual round-trips, 5,152 oracle explanation-equivalence cases, 280 rule trace-matrix obligations, a documentation-consistency audit over six release texts, oracle triangulation over 2,916 pairwise cells, static code-health over the Python release surface, repair-locality over 418 repairs, RQ traceability over 25 obligations, a claim-impact audit over 45 admitted claims and 35 rule links, 418 witness hash-chain provenance closures, 16/16 gate-sensitivity seeded-failure rejections, 8/8 idempotence replayed lightweight gates, a 14-threat assessor-threat matrix, 418 evidence-path multiplicity checks, 225 minimal-pair obligations, five deterministic stratification folds, process-trace hygiene, delivery capsule, paper-argument, release-hygiene audits, and a repository-quality score of at least 95, plus stale numeric surface, ICSE criteria closure, contribution trace, reference role-balance, oracle structural independence, deliverable trio, paper rhetoric, repository-entrypoint, and release assessor scorecard audits.
The boundary-condition audit separately checks 100 explicit non-denominator
cases and rejects overlap with the locked 972 fixtures.

## BEP-Max adversarial validation and repair-frontier checks

Runtime estimate: about 10-25 minutes for generation, integrity, repair-frontier, graph, and coverage checks.

The BEP-Max layer does not change the locked BEP-Deep denominator. It surrounds it with adversarial validation cases that stress formatting, irrelevant surfaces, near-repair confounders, contrastive repair pairs, local repair frontiers, and issue-class coverage.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/generate_adversarial_validation_suite.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_bep_max_integrity.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/certify_repair_frontier.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/build_exposure_graph.py \
  --fixtures artifact/data/deep_locked_fixtures.json \
  --witnesses artifact/results/deep_locked/full_witnesses.json \
  --certificates artifact/results/deep_locked/proof_carrying_witness_certificates.json \
  --paired-repairs artifact/data/paired_repair_controls.json \
  --out-dir artifact/results/bep_max

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_boundary_coverage.py
```

The expected BEP-Max results are 4,306/4,306 adversarial validation cases passed, 4,306/4,306 generated cases with fresh content hashes and valid source links, 418/418 contrastive repair pairs passed, 418/418 repair frontiers certified over 1,230 local candidates, and 25/25 issue classes with a complete validation ladder. The proof-carrying exposure graph should include repair-control and certificate edges.


## release closure, reference, and anonymity audits

Runtime estimate: about 10-20 minutes for the full release-closure block, excluding optional external tools.

These release deterministic audits check that the evaluation object remains closed over its admitted claims, rules, positives, negative controls, repair controls, certificates, references, and anonymous-paper delivery hygiene.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_traceability_obligations.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_source_span_closure.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_reference_integrity.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_anonymity.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_latex_source_integrity.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_validation_report_consistency.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_release_language_integrity.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_protocol_amendment_integrity.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_bibliographic_metadata.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_baseline_contract.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/run_reproducibility_ladder.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_validation_orchestration.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_pdf_source_compile.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_semantic_recomputation.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_release_consistency.py


PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_corpus_stability.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_evidence_cards.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_decision_purity.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_documentation_consistency.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_package_identity.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/run_validation.py
```

The expected results are 25/25 issue classes passing obligation closure, 45/45 admitted-source/source-span closure over admitted claims, a 45-row release coding-validation report synchronized with the admitted corpus, auxiliary source ledgers synchronized with the admitted-source snapshot manifest, explicit lineage-scope markers for the seed and BEP-Stress result directories, 72 cited keys matching 72 BibTeX entries and reference-ledger rows, zero anonymous-paper delivery and LaTeX-source-integrity hygiene problems, and passing validation-report, release-language integrity, bibliographic-metadata, PDF source-compile, protocol-amendment integrity, baseline-contract, directive-fallback conformance, cross-policy contract, reproducibility-ladder, typed BEP-IR, semantic-lattice, BEP-SpecBench, metamorphic-relation, certificate-recheck, evidence-graph, anti-overfitting leakage, identifier-blind replay, repair-delta replay, theory proof-card, strict-smoke, external-benchmark-contract, external-baseline-full-run, generated-oracle-test, repository-quality, semantic-recomputation, validation-orchestration, and release-consistency gates. The semantic-recomputation gate reruns BEP-Deep/BEP-Max outcomes from released inputs; the release-language integrity gate rejects pre-lock/candidate wording in source/resource ledgers; the protocol-amendment integrity gate checks that post-lock amendments A001-A099 are contiguous and closed; the release-consistency gate excludes self-updating audit outputs and self-indexing files from checksum closure, rejects stale duplicate root-level seed results, and rejects volatile runtime fields in deterministic result files. The 101 declared commands are checked by the reproduction-ladder audit. The release validation summary checks 111 materialized layers, including the BEPGuard research-infrastructure, full external-comparator, causal-counterfactual, benchmark-disjointness, paper-claim, runtime-boundary, corpus-stability, evidence-card, decision-purity, counterfactual-round-trip, oracle-equivalence, rule-trace-matrix, release-claim-drift, oracle-triangulation, static code-health, repair-locality, RQ-traceability, claim-impact, hash-chain, gate-sensitivity, idempotence, documentation-consistency, process-trace hygiene, assessor-threat closure, evidence-path multiplicity, minimal-pair closure, fold stratification, delivery capsule, paper-argument, and release-hygiene gates.


## Claim-impact, hash-chain, sensitivity, and idempotence gates

Runtime estimate: about 5-10 minutes.

These lightweight inspection-facing gates close claim-impact, witness hash-chain, gate-sensitivity, and idempotence evidence without changing the locked denominator or labels.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_claim_impact.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_witness_hash_chain.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_gate_sensitivity.py

PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_idempotence_replay.py
```

The expected outputs are 45/45 claim-impact closure, 418/418 witness hash-chain objects, 16/16 gate-sensitivity seeded failures rejected, and 8/8 idempotence replays passing.

 The reproduction surface includes claim trace-saturation, repair compactness, deterministic re-execution, and interaction coverage gates in addition to the release validation summary.

The release paper delivery-alignment layer also checks title/abstract/topic metadata, assessor quickstart readiness, figure-reference closure, supplement alignment, artifact manifest reachability, evidence digests, assessor triage, and release delivery packet readiness.

release surface closure also includes overclaim-boundary, compiled-PDF text-surface, public-provenance/data-rights, and repository-upload readiness audits. These gates do not change the locked denominator or labels; they harden the release paper and manual repository-upload package.
