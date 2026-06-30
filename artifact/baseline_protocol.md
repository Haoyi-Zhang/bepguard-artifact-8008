# Baseline Wrapping Protocol

Status: locked for full-experiment preparation; amended by A022 to use canonical comparator statuses and BEP-Deep fixture-level probes.

## Principle

External baselines are never edited internally. Wrappers are limited to input preparation, local invocation, timeout handling, status recording, and output normalization. If a baseline cannot run in the local environment, the result is `unavailable`, `unsupported`, `excluded`, or `error` as appropriate; project logic is not substituted for that baseline.

External-baseline outputs are contrastive and supplementary. The Python-only
core artifact claims are supported by source-grounded semantic obligations,
negative controls, independent oracle replay, mutation adequacy, and boundary
audits. A public comparator disagreement is never used as the ground-truth
label, and a missing public tool is never replaced by BEPGuard logic.

## Network boundary

The full study excludes live third-party website scanning. Scanner-style baselines may run only against the deterministic local fixture server. The wrapper must reject non-localhost targets unless an explicit protocol amendment is recorded; the default protocol does not allow such an amendment for full experiments.

## Baseline classes

* CSP Evaluator: unmodified npm package/library, invoked only on CSP header strings.
* MDN HTTP Observatory: unmodified local CLI/package, invoked only on local fixture URLs.
* Chromium hstspreload: unmodified command/package when installed and pinned; otherwise the documented preload criterion is reported as a conservative non-executable comparison.
* Header-presence control: internal negative-control baseline, reported separately and never described as prior work.
* Documented HSTS-preload criterion control: internal criterion check, reported separately from Chromium hstspreload when the external package is unavailable.

## Output status values

* `available`: baseline ran and produced raw output.
* `unavailable`: baseline package/command was absent in the execution environment.
* `unsupported`: the fixture is outside the baseline's documented input domain.
* `error`: baseline invocation failed after timeout or malformed output; raw failure category is recorded.
* `excluded`: running the baseline would violate the no-third-party-scanning boundary.
* `not_applicable`: the wrapper or control has no meaningful judgment for the fixture role being summarized.

## Normalization

Raw outputs are stored in a machine-readable file. Normalized columns may contain only: baseline id, fixture id, status, whether the baseline flags any issue, issue categories when available, and unsupported/error reason. Normalized output cannot rewrite baseline categories to match the project oracle.

## Wrapper audit checklist

1. The baseline version, URL, license, and access date appear in `external_resources.csv`.
2. The wrapper calls the baseline without source edits.
3. The wrapper records status rather than silently skipping failures.
4. The wrapper rejects non-local targets.
5. Internal controls are separated from external baselines in all tables.
6. BEP-Deep has an availability file, a fixture-level external-baseline probe, and a comparison summary.
7. The baseline-contract audit checks that external baseline rows are not remapped into semantic confusion counts without a declared oracle mapping.
8. Documentation must state whether a comparator result is reviewer-rerunnable
   in the current Python-only package or archived supplementary evidence that
   requires an optional caller-supplied package work directory.
