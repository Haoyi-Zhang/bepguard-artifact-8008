# Assessor Trust Model

The artifact exposes many audit scripts because different reviewer concerns
need different evidence. Reviewers do not need to read the audit list as 111
separate claims. The checks collapse into five trust categories.

1. Reproducibility: clean package, validation summary, dependency-free tests,
   strict smoke, and release consistency.
2. Semantic independence: operational oracle replay, decision-table oracle,
   mutation adequacy, and semantic-core checks.
3. Overfit resistance: identifier leakage, benchmark-disjointness, shadow
   generalization, gate sensitivity, and explicit boundary cases.
4. External contrast: optional public-tool status contracts, package locks,
   provenance rows, and clear separation from internal controls.
5. Submission hygiene: anonymity, process-trace hygiene, quickstart readiness,
   repository entrypoints, and upload manifest checks.

The recommended reviewer path is therefore not to run every command first. Run
`artifact/scripts/reviewer_verify.py` to check the release surface, then inspect
the five categories above if a specific concern remains.
