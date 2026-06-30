# Ground Truth Provenance

BEPGuard uses a conservative source-grounded denominator. The locked labels are derived from public source spans and semantic rule obligations, not from an opaque run of the operational evaluator.

The auditable chain is:

1. `artifact/data/source_snapshot_manifest.csv` records each public source, URL, version or access date, and hash.
2. `artifact/data/corpus_claims.csv` records 45 admitted source-grounded claims with source spans, claim hashes, policy families, fixture roles, and rule ids.
3. `artifact/source_span_ledger.csv` repeats the claim-to-source-span evidence surface for quick inspection.
4. `artifact/data/rule_to_source_ledger.csv` records 35 encoded semantic obligations and their source spans.
5. `artifact/data/deep_locked_fixtures.json` links every BEP-Deep fixture to source claim ids and expected issue semantics.

This is not a human-subject annotation study and does not claim human inter-rater agreement. The artifact instead exposes a deterministic public-source ledger: an assessor can trace each admitted claim to a public source span, a rule obligation, and the fixtures that use it. The source-span and rule ledgers are checked by `artifact/scripts/audit_assessor_objection_closure.py` and the existing source-span closure gates.

