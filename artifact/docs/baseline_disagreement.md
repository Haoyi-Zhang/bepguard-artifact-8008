# Baseline Disagreement

Public-package comparator outputs are contrastive evidence. They are not treated as the source of BEPGuard labels, and BEPGuard is not assumed correct just because a baseline disagrees. The Python-only reproduction path verifies the semantic denominator and the comparator status/provenance contract; rerunning the public packages themselves requires an optional caller-supplied package work directory.

The artifact materializes a full public comparator run with 4,118 fixture-level invocations and zero unavailable or error rows. The disagreement matrix maps each comparator row to the locked fixture role and reports four cells for each baseline:

- both BEPGuard and the public comparator flag;
- BEPGuard-only;
- baseline-only;
- neither flags.

The sampled disagreement rows in `artifact/results/external_baseline_disagreement_matrix.csv` include fixture id, policy family, expected issue, source claim ids, and the adjudication basis. The adjudication basis is the public source-grounded semantic obligation, not agreement with any single baseline.

If public packages are absent, wrapper probes must report explicit unavailable,
unsupported, excluded, or error statuses. Such rows are not converted into
BEPGuard successes and are not used as primary evidence for the locked
positive/negative denominator.

Run:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_assessor_objection_closure.py
```
