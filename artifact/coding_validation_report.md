# Coding and traceability validation report

This validation pass checks the locked source-grounded corpus and the release BEP-Deep denominator. It is a deterministic traceability and consistency audit, not a human inter-coder-agreement procedure and not a public-web prevalence study.

## Summary

* Source-grounded claims checked: 45
* Fixture-backed claims checked: 26
* Context or baseline claims checked: 19
* Semantic rule records checked: 35
* BEP-Deep fixture manifest rows checked: 972
* BEP-Deep fixture rows checked: 972
* Expected-positive fixtures checked: 418
* Negative controls checked: 554
* Paired repair negative controls checked: 418
* Failed validation checks: 0
* Status: pass

## Validation criteria

A claim passes if it has a public source identifier, an HTTP(S) source URL, a section/span locator, an explicit paraphrased claim, a known semantic rule reference, and a declared role in or outside the executable denominator. A fixture passes if it appears in the BEP-Deep manifest, links only to known source claims, has a stable hash, and its locked finding behavior matches the expected issue or negative-control label. A rule passes the audit if its source references resolve and its status is one of the locked semantic statuses: encoded, partially encoded, framework context, planned/context, or baseline scope.

## Adjudication stance

The corpus distinguishes executed semantic fixtures from context and baseline claims. Context/planned claims are retained to bound model scope and source interpretation, but they do not create emitted semantic-conflict outcomes. Baseline-scope claims are used only to interpret tool applicability and are not counted as browser-effective semantic labels. This treatment prevents source review from turning into an unsupported prevalence or developer-behavior claim.

## Outputs

* `artifact/results/coding_validation_report.csv` records claim-level pass/fail checks.
* `artifact/results/coding_validation_summary.json` records the validation summary.
* `artifact/data/fixture_validation_audit.csv` records fixture-level hash and manifest consistency.
* `artifact/data/rule_validation_audit.csv` records rule-source consistency.

## Scope

This report validates traceability, source-span coverage, label consistency, denominator integrity, and release BEP-Deep materialization. It does not replace a live deployment study or human-subjects study; the manuscript frames the empirical layer as a source-grounded deterministic boundary workload.
