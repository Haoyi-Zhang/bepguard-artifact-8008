# assessor Quickstart

This artifact is organized for three assessor paths. All commands are CPU-native and use only the Python standard library for core validation.

## Five-minute capsule check

Run the reviewer triage gate:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/reviewer_verify.py
```

This script sets `PYTHONPATH=artifact` for its child processes, suppresses
bytecode caches, and runs the clean package check, release validation summary,
dependency-free generated tests, standard-library `unittest` bridge, smoke
gate, decision-table oracle, mutation adequacy, boundary-condition audit,
assessor-objection closure, and release-consistency audit.

The equivalent explicit commands are:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=artifact python3 artifact/scripts/run_validation.py --out artifact/results/validation_summary.json
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=artifact python3 artifact/scripts/run_dependency_free_test_harness.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=artifact python3 -m unittest discover -s artifact/tests
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=artifact python3 artifact/scripts/audit_boundary_conditions.py
```

This checks the locked denominator, the 111 validation-layer summary, paper/source closure, references, anonymity, package hygiene, and the delivery-surface gates.
The two test commands execute the same generated fixture and certificate test
surface without requiring pytest.

## Five-minute manual certificate spot-check

For a human-readable trace, inspect one CSP report-only witness:

- Fixture: `LF_CSP_RO_01`
- Source claim: `CL_CSP_01`
- Rule: `R_CSP_REPORT_ONLY_MONITOR`
- Certificate: `PCW-8b710c9af12e726ca597`
- Repair control: `LF_CSP_RO_01__repair__paired_negative`

The fixture records a report-only CSP surface for a script load from
`https://evil.example`. The source claim records that report-only CSP monitors
rather than enforces blocking. The certificate records the emitted issue
`csp_report_only_not_enforced`, links the rule and claim, verifies minimality,
and checks that the paired repair control is clean. The same path can be read
in the fixture data, source-claim ledger, rule-source ledger, proof-carrying
certificate table, and evidence card output.

## Twenty-minute semantic replay

Run the representative semantic replay gates:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=artifact python3 artifact/scripts/audit_semantic_recomputation.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=artifact python3 artifact/scripts/audit_oracle_equivalence.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=artifact python3 artifact/scripts/audit_identifier_blind_replay.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=artifact python3 artifact/scripts/audit_evidence_cards.py
```

These commands recompute the core semantic result, independently replay the declarative oracle, test metadata-erased fixtures, and inspect evidence-facing evidence cards.

## Assessor objection closure

Run the independence and generalization closure gate:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_assessor_objection_closure.py
```

The output files are `artifact/results/assessor_objection_closure_audit.json`, `artifact/results/ground_truth_provenance_audit.json`, `artifact/results/oracle_provenance_audit.json`, `artifact/results/external_baseline_disagreement_audit.json`, `artifact/results/heldout_generalization_audit.json`, `artifact/results/claim_extraction_coverage_audit.json`, and `artifact/results/assessor_walkthrough_audit.json`.

## Workload and boundary orientation

Read `artifact/docs/workload_construction.md` for the 972-fixture denominator
rationale and `artifact/docs/boundary_conditions.md` for the 100 explicit
non-denominator cases. The boundary catalog is meant to prevent the artifact
from silently converting ambiguous, malformed, runtime-dependent, or unmodeled
surfaces into artificial successes.

## Full assessor ladder

The declared full ladder is stored in `reproduction_ladder.json`. It has 101 commands grouped by source closure, semantic replay, anti-overfit checks, external comparator provenance, paper/PDF audits, and release hygiene. The ladder is deterministic and records no volatile runtime fields.

## External comparator note

Public-package comparator records are materialized with package/version/provenance locks. Dependency directories and caches are not packaged. External comparator flags are contrastive evidence only; the intent-drift labels come from source-grounded semantic obligations.
The Python-only path reproduces the core semantic workload and checks the
integrity of the committed comparator output. Optional live comparator
re-execution requires the corresponding public tools, such as Node.js/npm for
CSP Evaluator, Go plus the pinned hstspreload module, or a local MDN HTTP
Observatory command. Missing optional tools are reported as availability
statuses; no project-internal logic substitutes for an unavailable baseline.
See `artifact/docs/external_baseline_reproducibility.md` for the exact boundary:
the archived 4,118-row comparator run is supplementary and is not required for
the Python-only core reproduction path.
