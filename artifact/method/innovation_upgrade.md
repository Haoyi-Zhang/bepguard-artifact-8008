# Protocol-Amended Workload and Algorithmic Upgrade

This document records the release substantive upgrade from the seed deterministic denominator to the BEP-Deep workload. The upgrade is part of the research artifact because it changes the executable research object: from a single-step semantic witness generator over seed fixtures to a repairable, mutation-tested effective-exposure witness graph.

## Upgraded research objects

1. **BEP-Deep workload.** The executable denominator contains 972 deterministic fixtures derived from 116 base fixtures, 554 intermediate stress fixtures, and 418 paired repair controls. It includes 418 expected-positive semantic conflicts and 554 negative controls.
2. **Metamorphic operators.** Header-name case changes, header-order changes within a generated surface, and policy whitespace perturbations check whether semantic judgments are stable under irrelevant syntactic changes.
3. **Additional semantic edges.** The upgrade adds layered CSP composition, CSP framing delivery surfaces, duplicate and exact-value CORS cases, dynamic CORS cache variation, invalid and scoped HSTS cases, preload-oriented HSTS criteria, CORP same-site/same-origin scope, and Permissions-Policy over-allowance.
4. **Typed effective-exposure graph.** The graph connects claims, fixtures, generated surfaces, contexts, effective judgments, and issue classes, making each witness navigable rather than only reported as a row.
5. **Counterfactual repair synthesis.** For each positive witness, deterministic issue-specific edits are applied and checked under the same oracle. A repaired fixture is not deployment advice; it is a validated counterfactual for benchmark and CI-style regression use.

## release result summary

- BEP-Deep fixtures: 972.
- Expected-positive semantic conflicts: 418.
- Negative controls: 554, including 418 paired repair controls.
- Detected expected witnesses: 418/418.
- Clean negative controls: 554/554.
- Semantic-preserving variants: 348/348 preserved.
- Repairs: target issue removed for 418/418 positive fixtures.
- Effective-exposure graph: 6,881 nodes and 10,570 edges for BEP-Deep, with 25 issue nodes.
- Header-presence control disagreement: 322 semantic positives missed by the control.

## Claim boundary

BEP-Deep is not a live-web prevalence study and does not claim deployed-site vulnerability rates. It is a source-grounded deterministic stress workload for evaluating whether an executable model can connect intent, generated policy, context, effective judgment, witness minimization, graph explanation, and repair synthesis.


## Additional hardening

The BEP-Deep revision adds paired repair negative controls, a finite-state semantic-core verifier for 13 invariants over 165 abstract states, exact header-subset minimality certification for all 418 witnesses, and repair-obligation validation that checks target removal, all-modeled-issue removal, intent preservation, source preservation, and issue-class-specific change scope.
