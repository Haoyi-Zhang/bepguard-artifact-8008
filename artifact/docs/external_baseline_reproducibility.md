# External Baseline Reproducibility Boundary

External comparators are contrastive evidence, not the source of BEPGuard's
labels. The core artifact claims are reproducible with Python-only commands
over the locked source-grounded denominator. The public-package comparator run
is supplementary and exists to show how unmodified public tools behave on the
same fixtures when a caller supplies the optional package environment.

## What the Python-Only Artifact Reproduces

The default reviewer path verifies:

- the locked BEP-Deep denominator and semantic oracle replay;
- independent decision-table agreement;
- mutation adequacy and seeded-failure sensitivity;
- anti-overfitting, identifier-disjointness, and boundary-condition audits;
- the external-baseline status contract, package locks, and provenance rows;
- that unavailable optional tools are not replaced by project-internal logic.

This path does not require npm, Go, MDN Observatory, Webhint, Chromium
hstspreload, network access, hosted scanners, private accounts, or cached
package directories.

## What Is Supplementary

The 4,118-row public-package comparator output is an archived supplementary
run. It is checksum-closed, package/version locked, and provenance-audited, but
it is not required to reproduce the core semantic claims. If an assessor wants
to rerun those tools, the assessor must provide the optional package work
directory described by `external_baseline_package_lock.json` and
`external_package_manifest.csv`.

When optional tools are absent, wrapper commands must report `unavailable`,
`unsupported`, `excluded`, or `error`. They must not synthesize a public-tool
answer from BEPGuard's internal oracle.

## Reviewer Checks

Run the status-contract and provenance checks:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_external_benchmark_contracts.py
PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_external_provenance.py
PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_external_baseline_full.py
```

Expected output: all three checks report `status: pass` and `problem_count: 0`.
The provenance checks validate the archived comparator rows; they do not turn
the archived comparator run into a Python-only core claim.
