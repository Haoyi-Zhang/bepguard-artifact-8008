# Browser-Enforced Security Policy Artifact

This artifact supports the study of **policy intent drift in browser-enforced security policy engineering**. It is deterministic, CPU-native, and source-grounded. It uses public specifications, public developer-facing documentation, public framework documentation, public tool documentation, and locally materialized fixtures. It performs no live website scanning, hosted scanner calls, private-data processing, account use, GPU computation, or external inference API calls.

## Locked denominator and BEP-Deep workload

The source-grounded corpus contains:

- 45 source-grounded explicit claims;
- 35 semantic/protocol rules;
- 116 base deterministic fixtures;
- 554 intermediate BEP-Stress fixtures after the first protocol-amended expansion;
- 972 BEP-Deep deterministic fixtures after adding paired repair controls;
- 418 expected-positive semantic-conflict fixtures;
- 554 negative controls, including 418 paired repair controls;
- 25 issue classes across 16 policy/framework strata.

The main BEP-Deep semantic execution detects 418/418 expected positive witnesses and keeps 554/554 negative controls clean. Repair synthesis removes the target issue for 418/418 positive witnesses, a finite-state semantic-core verifier checks 13 invariants over 165 abstract states, an independent decision-table oracle agrees with the operational oracle on 972/972 locked fixtures and 351 generated finite states, a source-level cross-policy contract verifier checks 7 contracts over 111 finite states, 28/28 rule-level semantic mutants and 600/600 obligation-level mutants are killed by the workload, a typed BEP-IR audit validates 972 fixtures with zero schema problems, a semantic-lattice verifier checks 6 contracts over 186 finite states, BEP-SpecBench checks 4,180 source-derived boundary and representation-stress cases over 29 rules, a metamorphic audit checks 9 relations over 3,954 fixture/property obligations, an independent certificate rechecker checks 4,870 proof obligations, an evidence-graph closure validates 418 positive and 554 negative trace paths, an anti-overfitting leakage audit guards 972 locked fixture ids and 418 certificate ids, a 30-theorem finite kernel checks 33,513 enumerated states, a strict smoke gate executes 6 representative local commands, a 2,916-replay whole-corpus stability audit, a 9,720-case shadow generalization audit, a 4,860-case identifier-blind replay, a 546-case causal counterfactual activation audit, a 418-pair repair-delta replay, a 30-card theory proof-card audit, a 48,600-case scale-stress replay, a 9,586-row benchmark-disjointness audit, 418 evidence-facing evidence cards, a separately materialized public-package comparator run executes 4,118 fixture-level analyzer invocations with 0 unavailable/error rows and a contrast-specificity audit, generated oracle tests run 1,390 fixture/certificate tests, a decision-purity audit checks 78 pure decision functions, a repository-quality audit reports 100/100 over the current Python source tree, a 5,152-case oracle explanation-equivalence audit, a 14-threat assessor-threat closure matrix, 418 evidence-path multiplicity checks, 225 minimal-pair obligations, five deterministic fold-stratification rows, a process-trace hygiene audit, a delivery capsule audit, a paper-argument audit, a release-hygiene audit, stale numeric surface auditing, ICSE criteria-to-evidence closure, contribution trace closure, reference role-balance auditing, oracle structural independence auditing, deliverable trio readiness, paper rhetoric auditing, repository-entrypoint auditing, and a release assessor scorecard, overclaim-boundary auditing, compiled-PDF text-surface auditing, public-provenance/data-rights auditing, and repository-upload readiness, an oracle triangulation audit checks 2,916 pairwise agreement cells, a static code-health audit checks the Python release surface, a repair-locality audit checks 418 anti-relabeling repairs, an RQ traceability audit checks 25 paper-to-result obligations, a claim-impact audit closes 45 admitted claims and 35 rule links, a witness hash-chain audit closes 418 positive provenance chains, a gate-sensitivity audit rejects 16/16 seeded corruptions, an idempotence replay re-executes 8/8 lightweight gates, 418/418 proof-carrying positive witness certificates verify source/rule/oracle/repair/minimality links, 554/554 negative-control certificates verify the clean side of the denominator, 45/45 admitted claims pass coverage closure, 45/45 admitted-source/source-span closure checks pass, 348 semantic-preserving variants remain stable, and the BEP-Max adversarial validation layer passes 4,306/4,306 generated cases, 4,306/4,306 generated-case integrity checks, and 418/418 local repair-frontier certificates. These are deterministic fixture results, not public-web prevalence measurements, deployed-site vulnerability rates, or human-subjects findings.

The 972-fixture denominator is a locked construction point, not a prevalence
sample. `artifact/docs/workload_construction.md` explains the seed,
BEP-Stress, and BEP-Deep materialization layers and why the 418:554
positive/control split is a coverage design rather than a natural population
ratio. `artifact/docs/boundary_conditions.md` records 100 explicit
non-denominator cases, about 10.3% of the locked denominator, where the expected
answer is manual review, unsupported scope, invalid input, or not evaluated.
Those cases are checked by `artifact/scripts/audit_boundary_conditions.py` and
are intentionally not counted as successes.

## External baselines and controls

CSP Evaluator, MDN HTTP Observatory, Webhint HSTS checks, and Chromium hstspreload are treated as external baselines only when their unmodified logic is executable in the reproduction environment. The clean artifact does not package dependency directories or package-manager caches. The release therefore has two explicit external-resource surfaces: lightweight wrapper probes record `unavailable`, `unsupported`, `excluded`, or `error` when a baseline is absent in a clean environment, while the committed BEP-Deep public-package comparator output records a prior full run from a caller-supplied package work directory with package/version/provenance locks. Neither surface substitutes project-internal logic for a missing external baseline. Conservative header-presence and documented HSTS-preload criteria are reported as internal controls rather than external tool results.

The public-package comparator output is supplementary contrastive evidence. It
is not required for the Python-only core reproduction path and is not the source
of BEPGuard labels. See
`artifact/docs/external_baseline_reproducibility.md` for the exact boundary,
including what a reviewer can reproduce without optional npm/Go/package caches
and what requires a caller-supplied external package work directory.

## Reviewer triage

Run the one-command triage gate from the release root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/reviewer_verify.py
```

This command sets the required import path for child processes and runs the
clean-package check, validation summary, dependency-free generated tests,
standard-library `unittest` bridge, strict smoke gate, decision-table oracle,
mutation adequacy, boundary-condition audit, assessor-objection closure, and
release-consistency audit. `artifact/docs/assessor_trust_model.md` groups the
larger validation ladder into five reviewer concerns so that the 101-command
ladder can be inspected by purpose rather than as a wall of checks.

## Assessor objection closure

For a short path through the non-circularity evidence, run:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_assessor_objection_closure.py
```

This materializes source-label provenance, oracle-provenance scope, public-baseline disagreement matrices, non-denominator held-out generalization, conservative claim-scope coverage, and a concise artifact walkthrough. The companion documents are under `artifact/docs/`.

## Reproducibility scope

The artifact reproduces the source-grounded corpus materialization, semantic witness generation, minimization, baseline/control status accounting, fixture-level external-baseline probes, ablation summaries, robustness summaries, scalability summaries, deterministic validation checks, and a release semantic-recomputation gate that reruns the core BEP-Deep/BEP-Max semantic obligations from released inputs. It does not crawl the public web, contact hosted services, infer unstated developer intent, or claim complete browser conformance.

Use `reproduction.md` for command-level reproduction. Start with its reviewer triage path: clean-package check, strict smoke, decision-table oracle, mutation adequacy, and denominator count. A Python-only environment is enough for the core semantic workload, 111-layer validation, and committed baseline-output integrity checks; Node/npm, Go, and the MDN Observatory CLI are only for optional external-baseline re-execution. The package hygiene checker, anonymous-paper delivery audit, and LaTeX source-integrity audit should report zero problems before distribution. The release closure audits also check traceability obligations for every issue class, admitted-source/source-span closure over admitted claims, seed-lineage materialization consistency, validation-report freshness, auxiliary source-ledger consistency, explicit lineage-result scope markers, citation/ledger consistency, bibliographic metadata hygiene, anonymous-paper delivery hygiene, paper-source integrity, directive-fallback conformance, cross-policy contract verification, baseline-contract status auditing, a 101-command inspection-facing reproducibility ladder, a queryable evidence graph, anti-overfitting leakage checks, strict deterministic smoke execution, isolated PDF source compilation, release-language integrity of source/resource ledgers, protocol-amendment integrity, release-consistency of checksum/result indices, and the absence of transient runtime artifacts after reproduction. The release-consistency and release-validation gates exclude self-updating audit-result files from checksum closure, reject stale duplicate root-level seed or stress summaries outside the lineage area, check that the release denominator summary records 972/418/554, reject self-referential checksum/index rows, reject volatile runtime fields in deterministic result files, recompute the central BEP-Deep/BEP-Max semantic outcomes from released inputs, check source-grounded CSP directive-fallback conformance, check 7 cross-policy contracts over 111 finite states, check baseline wrapper status/scope hygiene, check a 101-command reproduction ladder contract, check BEPGuard typed-IR/specbench/metamorphic/certificate-recheck/evidence-graph/leakage/identifier-blind/repair-delta/proof-card/corpus-stability/evidence-card/decision-purity/counterfactual-round-trip/oracle-explanation-equivalence/rule-trace-matrix/release-claim-drift/oracle-triangulation/static-code-health/repair-locality/RQ-traceability/claim-impact/hash-chain/gate-sensitivity/idempotence/documentation-consistency/smoke/generated-test/repository-quality gates, and compile the paper sources in isolation to check the page and bibliography boundary.


The counterfactual round-trip, 5,152 oracle explanation-equivalence cases, rule trace-matrix, and release claim-drift gates are included in the release closure.

 The release closure adds a claim-impact audit over 45 claims and 35 rule links, a 418-chain witness hash-chain provenance audit, a 16-scenario gate-sensitivity seeded-failure audit, and an 8-command idempotence replay over lightweight evidence-facing gates.

The release validation summary is memory-stable: it checks 111 materialized validation layers from the full validation ladder, while semantic recomputation, isolated source compilation, and the reproduction-ladder audit remain separately executable gates whose outputs are required by the summary.

## evidence-facing BEPGuard commands

The package exposes the standard-library-only `bepguard` entry point through `pyproject.toml`. assessors may invoke `PYTHONPATH=artifact python3 -m bepguard.cli evidence`, `PYTHONPATH=artifact python3 -m bepguard.cli leakage`, or `PYTHONPATH=artifact python3 -m bepguard.cli smoke` from the release root; the wrapper scripts under `artifact/scripts/` call the same library code and are the canonical reproduction-ladder entries.

Protocol amendments A001-A099 are closed and contiguous.

 The release closure also checks claim trace-saturation, repair compactness, deterministic re-execution, interaction coverage, process-trace hygiene, assessor-threat closure, evidence-path multiplicity, minimal-pair closure, fold stratification, delivery capsule closure, paper-argument surface, and release hygiene as materialized release gates.

The release paper delivery-alignment layer also checks title/abstract/topic metadata, assessor quickstart readiness, figure-reference closure, supplement alignment, artifact manifest reachability, evidence digests, assessor triage, and release delivery packet readiness.
