# Workload Construction and Denominator Rationale

BEPGuard's main result is a deterministic source-grounded workload, not a
sample of deployed websites. The locked BEP-Deep denominator has 972 fixtures:
418 expected-positive semantic-conflict fixtures and 554 negative controls. The
count is a closure point: every admitted source claim, semantic rule, issue
class, paired repair control, and proof-carrying witness must have a traceable
row in the released ledgers.

## Construction Pipeline

The workload is built in three materialized layers.

1. Seed layer: 45 admitted public-source claims and 35 semantic rules produce
   116 base fixtures. This layer preserves the claim-to-rule-to-fixture spine.
2. BEP-Stress layer: source-derived edge families and representation variants
   expand the seed into 554 intermediate fixtures. This layer is retained only
   as lineage evidence.
3. BEP-Deep layer: each expected-positive semantic conflict receives a paired
   repair control and certificate obligations, producing the locked 972-fixture
   denominator used by the core artifact claims.

The 418:554 split is therefore not a prevalence estimate and not a natural
web-population ratio. It reflects 418 source-grounded expected-positive
obligations plus the negative controls needed to test clean behavior, paired
repair behavior, and semantic-preserving stability.

## Independence Checks

The release uses several checks to reduce method/workload coupling risk.

- Fixture identifiers and certificate identifiers are audited so method code
  cannot memorize the locked denominator outside generated artifacts.
- BEP-SpecBench and shadow-generalization cases are identifier-disjoint from
  BEP-Deep and stress rule boundaries without changing the locked denominator.
- The decision-table oracle is implemented separately from the operational
  witness generator and checks both locked fixtures and generated finite states.
- Gate-sensitivity tests seed corruptions into expected counts, package
  identity, runtime boundaries, external-provenance boundaries, documentation
  status, and witness-chain uniqueness; all seeded corruptions must be rejected.
- Boundary cases that are ambiguous, conflicting, incomplete, malformed,
  runtime-dependent, deployment-dependent, external-state-dependent, or outside
  the modeled policy surface are cataloged separately from the denominator.

These checks do not make the workload a random or exhaustive public-web sample.
They support the narrower claim that the released source-grounded denominator
is internally consistent, non-memorized by identifier, and surrounded by
negative controls and out-of-scope boundaries.

## Coverage Criteria

The locked denominator covers 25 issue classes across 16 policy/framework
strata. A fixture can enter BEP-Deep only when it has:

- a public source claim and source-span identifier;
- a rule link in the semantic protocol ledger;
- a declared fixture role;
- an expected issue signature or negative-control role;
- a traceable repair or clean-control obligation where applicable;
- stable hashes in the release checksum and result ledgers.

Cases that fail these entry criteria are not converted into positive or
negative rows. They are documented in `artifact/docs/boundary_conditions.md`
and checked by `artifact/scripts/audit_boundary_conditions.py`.
