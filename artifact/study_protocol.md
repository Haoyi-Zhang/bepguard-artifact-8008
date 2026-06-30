# Locked Study Protocol v0.3

Status: locked with recorded protocol amendments for the BEP-Stress deterministic workload and the subsequent BEP-Deep repair-control hardening. The amendments expand algorithmic and workload coverage before upgraded interpretation; they do not delete failures, relabel old rows, change metrics after execution, or reinterpret fixture results as prevalence.

## Research object

The study concerns policy intent drift in browser-enforced security policy engineering: explicit public intent claims are compared against framework/generated policy surfaces and browser-effective judgments under a fixed BEP-IR fragment.

## RQs

RQ1. Can explicit public policy-intent claims be lowered into traceable BEP-IR obligations without inferring unstated developer motivation?

RQ2. Which semantic conflict witness families are produced by the locked encoded fragments over the locked deterministic corpus?

RQ3. How do declared-scope baselines and conservative controls disagree with the BEP-IR semantic witness oracle?

RQ4. Which semantic components are necessary for the locked witness set, and do minimization, robustness, and scalability checks preserve the results?

RQ5. Do independent decision rules, finite-state checks, semantic mutants, proof-carrying witness certificates, BEP-Max integrity checks, and source/evidence closure audits support the adequacy of the BEP-Deep evaluation object?

## Locked denominator

* Source-grounded claim rows: 45.
* Base locked fixture rows: 116.
* Intermediate BEP-Stress fixture rows: 554.
* Main-paper BEP-Deep fixture rows: 972.
* Expected-positive BEP-Deep fixtures: 418.
* BEP-Deep negative controls: 554, including 418 paired repair controls.
* Semantic/protocol rules: 35.
* Issue classes: 25.
* Policy-family strata: 16.
* Semantic-preserving variants: 348.
* Finite-state semantic-core invariants: 13 invariants over 165 abstract states.
* Certified witness minimality obligations: one-deletion minimality and exact header-subset minimality.

The authoritative hashes are recorded in `protocol_lock.json` and `checksum_manifest.csv`.

## Inclusion criteria

A source claim is admitted when it is public, traceable to a source span or stable source section, states an explicit policy behavior or documented generation behavior, and maps to at least one rule, baseline-scope record, or contextual-evidence category.

A fixture is admitted when it is generated before execution from the locked source/rule set, has a stable fixture hash, declares its expected issue before oracle execution, and belongs to either the expected-positive or negative-control denominator.

## Exclusion criteria

The study excludes live websites, private data, real accounts, hosted scanner calls, commercial APIs, GPU-dependent processing, inferred developer motivation, exploit payload construction, and policy behaviors outside the encoded fragments.

## Baselines and controls

* CSP Evaluator v1.1.8 wrapper: unmodified CSP-specific baseline where executable.
* MDN HTTP Observatory v1.6.2 wrapper: declared unavailable/failed in the clean environment; not substituted.
* Chromium hstspreload pinned Go package: declared unavailable for execution in the clean environment; not substituted.
* Conservative header-presence control: internal negative-control baseline, not external tool.
* Documented HSTS preload criterion: internal documented criterion control, not Chromium helper execution.

Unavailable external baselines remain unavailable in results and cannot be reclassified as false negatives or replaced by internal logic.

## Metrics

* Expected-positive detection count.
* Negative-control cleanliness count.
* Issue-class counts.
* Baseline/control confusion or status counts under declared applicability.
* One-deletion minimization preservation and byte reduction.
* Component ablation detection loss.
* Robustness by locked variant group.
* Scalability under deterministic replication.

## Stopping conditions

The upgraded full run stops after the BEP-Deep fixtures are executed once by the semantic oracle, all declared baselines/controls either run or report unavailable status, minimization preserves positive witnesses, repair synthesis is evaluated, paired repair controls are checked as negative controls, semantic-core invariants are verified over the finite abstract state space, mutation preservation is checked, the effective-exposure graph is built, the independent decision-table oracle agrees on all locked fixtures and generated finite states, semantic mutation adequacy is checked, evidence redundancy is audited, and summaries/checksums are written.

## Amendment policy

Any future change to RQs, denominator, expected labels, negative controls, metrics, baseline applicability, ablation map, or stopping conditions must be recorded in `protocol_amendments.csv` before execution. A006 records the workload expansion that created the BEP-Stress denominator. A007 records BEP-Deep repair-control hardening and semantic certification. A008 records independent decision-table oracle validation, semantic mutation adequacy, and evidence redundancy auditing without changing labels or selecting results. A013 records seed-lineage materialization closure and synchronized ledger aliases. A014 records validation-report freshness, auxiliary source-ledger consistency, and explicit lineage-result scope markers. No later amendment changes the BEP-Deep results.

## Claim boundary

The executed experiment is a deterministic source-grounded fixture study. It does not estimate prevalence on the live web and does not claim complete browser-conformance coverage.


## A009 proof-carrying witness certificate validation

The release validation layer generates one certificate for each expected-positive witness. Each certificate binds fixture id, issue label, source claim ids, semantic rule ids, independent decision-table result, paired repair control, minimality result, and repair-obligation result. The certificate checker is run after the locked oracle and does not change labels or select results. The expected burden is 418/418 verified certificates.


A010 BEP-Max adversarial validation: the locked BEP-Deep denominator remains unchanged, while an adversarial validation suite checks 4,306 generated cases, 418 contrastive repair pairs, 418 local repair frontiers, certificate/repair edges in the exposure graph, and complete validation ladders for all 25 issue classes. This is a validation burden, not a relabeling or prevalence expansion.


## A013 materialization-lineage closure

The seed materializer is retained so assessors can reproduce the expansion lineage, but it is not the main BEP-Deep denominator. A013 makes that distinction explicit: the materializer prints a scope-tagged seed-lineage status object, refreshes all canonical rule-ledger aliases, records the lineage lock as non-main, and adds a materialization-lineage audit to the release validation gate. This changes only release consistency and traceability; it does not add, remove, or relabel fixtures, claims, metrics, baselines, or outcomes.


## A014 validation-report and lineage-scope closure

The release includes human-readable validation reports and auxiliary source ledgers in addition to the machine-checked claim, source-span, and fixture tables. A014 requires those reports and ledgers to be regenerated from the release 45-claim admitted corpus and the release admitted-source snapshot universe. It also requires explicit scope markers for seed and BEP-Stress lineage result directories so that assessors do not confuse lineage outputs with the main BEP-Deep denominator. This is a release-consistency and traceability amendment only; it does not change RQs, metrics, fixture labels, baselines, negative controls, certificates, oracle outputs, or result counts.

## A015 semantic recomputation closure

A015 adds a release semantic-recomputation gate. Earlier release gates checked that materialized summaries, ledgers, and closure reports agreed with the release denominator. The new gate additionally recomputes the BEP-Deep operational oracle, the independent decision-table oracle, finite-state cross-checks, and BEP-Max source/hash/label/oracle closure from released inputs. This is a release validation burden only; it does not change RQs, metrics, fixture labels, baselines, negative controls, certificates, oracle definitions, or result counts.


## Release-language integrity closure

The release release treats source/resource metadata as part of the reproducible evaluation object. A016 adds a release-language integrity gate that rejects unresolved pre-lock wording such as pending fixture status, future package pinning, or undefined project license language in release-facing ledgers. This gate changes only package hygiene and traceability presentation; it does not alter BEP-Deep/BEP-Max denominators, labels, metrics, baselines, or outcomes.


## Protocol-amendment integrity closure

The release validation gate also checks that post-lock amendments are contiguous, parseable, closed, and aligned with the release validation layers. This prevents release-state drift in the protocol ledger without changing scientific labels, denominators, or outcomes.

### A017: Bibliographic metadata hygiene

A017 treats cited-reference metadata as part of reference integrity. The citation set and reference count remain fixed, but cited records with published DOI metadata are represented as their published venue records rather than stale preprint-style entries. The accompanying audit checks BibTeX class, DOI, and venue metadata for selected published records and rejects conference-entry records that still describe arXiv/preprint venues. This is bibliography hygiene only; it does not change study data, claims, fixtures, labels, or results.

### A018: PDF source-compilation closure

A018 adds an isolated source-compile gate. The release validation compiles the main paper with LaTeX and BibTeX and compiles the supplement in a temporary directory, then checks page counts, the reference-page boundary, undefined citations/references, and overfull boxes. The gate leaves no build products in the release package and does not affect experimental labels, counts, or claims.


## A019 validation orchestration stability

A019 separates validation orchestration from heavyweight recomputation. The release validation entry point now checks materialized outputs from the full validation ladder without launching nested heavy subprocesses; the semantic-recomputation and isolated source-compilation audits remain standalone reproducible gates whose outputs are required by the release summary. The source-compile audit also probes candidate BibTeX executables before selection and bounds LaTeX log capture so the gate remains robust in constrained review environments. This changes validation reliability only and does not alter RQs, denominators, labels, metrics, baselines, or outcomes.
