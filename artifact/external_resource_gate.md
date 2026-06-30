# External resource gate status

Status: completed for locked full-experiment execution with explicit unavailable-baseline accounting and supplementary comparator boundaries.

The gate does not require every public baseline to be executable in every runtime. It requires that each baseline/source be pinned, licensed, wrapped without internal modification, and either executed or recorded with an exact unavailable/unsupported status. The locked execution follows that rule. Public-package comparator rows are supplementary contrastive evidence unless the assessor supplies the optional external package work directory; the Python-only core reproduction does not depend on them.

## Completed

- External resources are recorded in `external_resources.csv` with role, URL, version or snapshot target, license field, access date, relevance, wrapper plan, modification policy and gate status.
- CSP Evaluator is pinned to `csp_evaluator@1.1.8`; an npm lockfile is recorded and the unmodified package executed through the project wrapper on applicable CSP fixtures.
- MDN HTTP Observatory is pinned to `@mdn/mdn-http-observatory@1.6.2`; current runtime installation is unsupported/unavailable, so wrapper output records that status and no project substitute is used.
- Chromium `hstspreload` is pinned to Go pseudo-version `v0.0.0-20250618200047-d624d7c87b33`; current Go module acquisition is unavailable, so wrapper output records that status and no project substitute is used.
- Internal conservative controls are clearly separated from external baselines.
- Baseline acquisition and execution status are recorded in `baseline_acquisition_status.csv` and full run outputs.
- `docs/external_baseline_reproducibility.md` states which checks are
  Python-only, which checks validate archived provenance, and which optional
  reruns require npm/Go/public-tool installations outside the clean package.

## Gate consequence

The project may execute the locked full experiment using the materialized denominator. External unavailable statuses must be reported as such in evaluation and cannot be replaced by internal logic.
The committed comparator output may be cited only as archived supplementary
contrastive evidence unless the optional external environment is recreated.
