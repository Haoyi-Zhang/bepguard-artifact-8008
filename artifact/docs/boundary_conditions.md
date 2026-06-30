# Boundary Conditions and Expected Non-Answers

The main BEP-Deep denominator is intentionally strict: it contains fixtures
where a public source claim, semantic rule, fixture role, and expected oracle
signature can be locked. BEPGuard should not force every security-policy
surface into that denominator.

`artifact/data/boundary_conditions.csv` records 100 non-denominator cases, about
10.3% of the locked BEP-Deep denominator. They cover eleven families:

The ratio is intentionally modest because these rows are a reviewer-facing
boundary audit, not a second benchmark split. Each row is selected to exercise a
distinct reason that BEPGuard must abstain, reject malformed input, or require
manual review; adding many near-duplicate boundary rows would make the packet
larger without changing the locked denominator or the non-answer contract.

- ambiguous intent where the source text states a goal but not an enforceable
  obligation;
- unmodeled directives outside the 35 locked semantic rules;
- non-HTTP policy surfaces where the final browser-observed header is absent;
- malformed headers that fail the released parser contract;
- runtime-mutated policies that depend on private request, tenant, edge, or
  feature-flag state;
- browser-divergent behavior that depends on experimental flags, enterprise
  policy, extension intervention, or external list update timing.
- conflicting public sources where the correct obligation requires human
  adjudication;
- partial policy information where the final browser-observed context is
  missing;
- multi-header interactions outside the locked rule arity;
- deployment-chain uncertainty after the application source emits a header;
- external browser, network, or service state not included in the release.

These rows are not hidden failures and are not counted as positives or
negative controls. Their expected actions are `manual_review`,
`unsupported_scope`, `invalid_input`, or `not_evaluated`. The audit rejects any
boundary row that overlaps the locked fixture identifiers or is scored as a
pass/fail result.

Run:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 artifact/scripts/audit_boundary_conditions.py
```

Expected output: `status: pass`, `problem_count: 0`, `boundary_cases: 100`,
and a boundary-case ratio of about `0.1029` relative to the 972-fixture locked
denominator.
