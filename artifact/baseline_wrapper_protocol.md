# Baseline Wrapper Protocol

Status: pre-lock protocol component. This document records how external tools may be invoked without modifying their internal logic.

## Non-modification rule

External baselines are executed as released packages, source checkouts, or command-line tools. The project may add only adapters that provide inputs, capture outputs, and convert outputs into a comparison table. Any compatibility patch required inside an external tool disqualifies that run from being reported as an unmodified baseline.

## Baseline roles

### CSP Evaluator

Role: CSP-specific review baseline.

Pinned release record: `csp_evaluator` npm package version 1.1.8, with package metadata recorded; unavailable execution is reported explicitly.

Input unit: a single `Content-Security-Policy` or `Content-Security-Policy-Report-Only` string.

Output captured: raw evaluator findings plus normalized finding categories. The raw output must be archived separately from normalized comparison tables.

Known limitation: it is not a cross-policy or framework-generation oracle. It is expected to miss non-CSP drift classes, and this limitation must be reported as scope, not as a defect.

### MDN HTTP Observatory

Role: security-header scanner and grading baseline.

Pinned release record: `mdn-http-observatory` release v1.6.2.

Input unit: a local fixture host/path served by the project fixture server. The public hosted API is excluded from the experiment to avoid rate limits, remote service dependencies, and live-site scanning.

Output captured: raw JSON scan response and normalized test/grade fields.

Known limitation: scanner grades are not browser-effective semantic witnesses. The comparison metric is disagreement between scanner output and semantic oracle labels.

### Chromium hstspreload

Role: pinned HSTS preload eligibility baseline.

Pinned release record: Go pseudo-version `v0.0.0-20250618200047-d624d7c87b33`, with module metadata recorded; unavailable execution is reported explicitly.

Input unit: domain name or local equivalent accepted by the unmodified tool. If the unmodified tool cannot operate on local fixtures without network behavior, it must be removed as an executable baseline and retained only as documented external criteria.

Output captured: raw CLI output and normalized pass/fail/issue codes.

Known limitation: preload eligibility is narrower than HSTS browser-effective semantics. It cannot be treated as a general HSTS oracle.

## Availability probe

The current environment has runtime support for Python, Node/npm/npx, and Go, but does not have the npm packages or HSTS preload CLI installed. The availability probe is only an environment check; it is not a baseline experiment and must not be reported as a result.

## Fixture-server rule

Scanner-style baselines must run only against local deterministic fixtures. The local server maps fixture ids to fixed response headers. It does not perform outbound requests and does not host real websites.

## Output normalization

For each baseline output, normalization must preserve:

1. baseline name and version;
2. fixture id;
3. original raw output location;
4. normalized status;
5. normalized finding class;
6. whether the baseline had enough input information to judge the fixture;
7. whether disagreement is due to unsupported policy family, unsupported context, or a true semantic mismatch.

Unsupported-context cases are not false negatives. They must be counted separately from semantic disagreement.

## Gate decision

This protocol is sufficient for wrapper design but not sufficient to pass the full external-resource gate. The remaining blockers are local package acquisition/integrity pins, exact release/source pins for framework fixtures, baseline raw-output schemas, and a compiled Chromium hstspreload helper if the HSTS executable baseline is used.
