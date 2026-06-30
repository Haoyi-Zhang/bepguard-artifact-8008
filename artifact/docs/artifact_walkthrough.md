# Artifact Walkthrough

## 5-minute path

Run the release summary:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/run_validation.py --out artifact/results/validation_summary.json
```

Key results are in `artifact/results/validation_summary.json`, `artifact/results/reproducibility_ladder_audit.json`, and `artifact/results/assessor_objection_closure_audit.json`.

## 30-minute path

Run:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/check_artifact_clean.py
PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/run_strict_reproducibility_smoke.py
PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/decision_table_oracle.py
PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/mutation_adequacy_audit.py
PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_assessor_objection_closure.py
```

This path checks package hygiene, the representative smoke commands, the independent decision-table oracle, mutation adequacy, and the source/oracle/baseline/held-out objection closure.

## Interpret the outputs

- `status: pass` and `problem_count: 0` mean the gate accepted the current materialized release state.
- The locked denominator is 972 BEP-Deep fixtures: 418 positives and 554 negative controls.
- The 48,600 BEP-Scale cases are robustness checks over the locked denominator.
- BEP-SpecBench is the non-denominator held-out generalization surface.
- Public baselines are contrastive; disagreements are exposed rather than hidden.

## Where to inspect claims

- Source and label provenance: `artifact/docs/ground_truth_provenance.md`.
- Oracle separation: `artifact/docs/oracle_provenance.md`.
- Baseline disagreement: `artifact/docs/baseline_disagreement.md`.
- Held-out generalization: `artifact/docs/heldout_generalization.md`.
- Claim-scope limits: `artifact/docs/claim_extraction_coverage.md`.
