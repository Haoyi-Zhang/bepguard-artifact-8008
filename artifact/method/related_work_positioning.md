# Related-Work Positioning and Paper-Style Survey

Status: post-L positioning input for outline construction. This file is not paper prose.

## Positioning thesis

The paper must be written as a software-engineering contribution about browser-policy maintenance, not as a header scanner, website measurement, or browser-bug study. The closest work is Site Policy, CSP/CORS deployment analysis, CSP differential testing, and security-header scanners. The new boundary is source-grounded policy-intent drift across explicit developer-facing claims, generated policy surfaces, and browser-effective semantics, with minimal semantic conflict witnesses as the technical object.

## Required contrasts

1. Against CSP deployment work: we are cross-policy/cross-framework and deterministic/source-grounded, not deployment-prevalence measurement.
2. Against CORS empirical work: we include request-context semantics but do not claim CORS prevalence.
3. Against Site Policy: we are not site/origin-wide per-page inconsistency or policy proposal; we are intent/generation/effective-semantics drift.
4. Against DiffCSP/browser differential testing: we do not search browser engine bugs.
5. Against CSP Evaluator/Observatory/hstspreload/checklists: they are baselines/controls, not research substitutes.

## Style decisions for the first full draft

- Use 7--8 main sections. Do not fragment into many small sections.
- Put the motivating witness family before the formal definitions.
- Introduce BEP-IR as a research abstraction, not an implementation format.
- State theorem scope narrowly.
- Report L results as source-grounded deterministic findings, never as web prevalence.
- Keep artifact mechanics out of the paper body; use research objects and tables instead.
