# Proof Obligations and Paper-Level Theorem Skeleton

Status: proof skeleton for the executable formal core. The main paper should use the theorem statements for the core model and place routine case analyses or rule tables in the supplement. The statements below are scoped to the locked fragment and do not claim complete browser conformance.

## Model recap

A locked evidence observation is normalized into a finite set of BEP-IR policy objects. Each policy object records a policy family, disposition, delivery surface, directive map, and provenance. A browser/request context records scheme, origin, target origin, request mode, credential mode, destination, initiator, rendering mode, and user-agent state. The effective-exposure judgment `Eff(P, C, e) ⇓ a` returns `allow`, `block`, `report`, `no_effect`, or `unknown`.

A semantic conflict witness is admissible only when the expected action is derived from an explicit source-grounded intent claim and the observed action is a non-`unknown` effective-exposure judgment that contradicts that expected action.

## Theorem T1: Normalization determinism

**Statement.** For any finite multiset of headers `H`, context-independent generation state `G`, and provenance map `π`, normalization yields a unique canonical BEP-IR policy multiset up to stable ordering.

**Assumptions.** Header names are canonicalized case-insensitively; directive tokenization uses the locked family parsers; malformed values are retained as `invalid` objects rather than silently dropped.

**Proof sketch.** Proceed by structural induction over the ordered header multiset after stable canonicalization. Each family parser is a total function over token strings because every malformed branch returns `invalid`. Directive maps are constructed by deterministic insertion under the locked duplicate-handling rule. Stable sorting removes order variance. Therefore two runs over the same `H`, `G`, and `π` produce equal canonical multisets.

**Evaluation dependency.** This theorem supports reproducibility of fixture hashes and witness regeneration.

## Theorem T2: Encoded effective-directive determinism

**Statement.** For every encoded policy family and locked request/resource edge, effective directive selection returns at most one concrete action or the explicit boundary value `unknown`.

**Assumptions.** The theorem is limited to encoded fragments: CSP delivery/report-only/fallback/framing/composition, layered policy generation, CORS credentialed shareability/cache variation/exact-value handling, HSTS transport/state/scope/preload transitions, COEP/CORP/CORS embedding, cross-origin isolation preconditions, CORP scope, and Permissions-Policy allowlist disabling or over-allowance.

**Proof sketch.** Case split by policy family. CSP delivery first resolves disposition; report-only policies produce `report` and never `block` by the report-only rule. CSP fallback follows a fixed precedence chain and therefore chooses the first present directive or `unknown`. CORS compares credential mode, ACAO, and ACAC using a finite ordered decision table. HSTS transition rules are mutually exclusive on secure versus insecure transport and on `max-age=0` versus positive max-age. COEP/CORP/CORS and Permissions-Policy fragments use finite predicate combinations. Each case has disjoint guards; unhandled cases return `unknown`.

**Evaluation dependency.** This theorem justifies treating repeated analysis over the locked fixture set as deterministic.

## Theorem T3: Report-only non-blocking

**Statement.** A CSP policy delivered only through `Content-Security-Policy-Report-Only` cannot be the sole cause of a `block` judgment in the locked CSP fragment.

**Assumptions.** No concurrent enforced CSP policy is present for the same protected edge. The theorem concerns the BEP-IR fragment, not all browser reporting side effects.

**Proof sketch.** Normalization assigns disposition `report` to report-only delivery. The effective-exposure rule for disposition `report` maps policy violations to `report`, not `block`. Since there is no enforced policy in the premise, no rule with a `block` conclusion is enabled. Therefore the sole result is `report` or `no_effect`, never `block`.

**Evaluation dependency.** This theorem supports the witness class `csp_report_only_not_enforced`.

## Theorem T4: Witness soundness for locked fragments

**Statement.** Every emitted semantic conflict witness in the locked experiment is backed by (i) at least one explicit source-grounded claim, (ii) a fixture whose hash appears in the locked fixture manifest, and (iii) a non-`unknown` effective-exposure judgment contradicting the coded expected action.

**Assumptions.** The locked corpus tables and fixture manifests pass the deterministic validation audit. The analyzer emits witnesses only through the single witness constructor that checks source claim ids, fixture hash, expected label, and effective action.

**Proof sketch.** Inspect the witness constructor. It receives a fixture only after manifest membership and hash checks. It receives an expected action from the intent object stored in that fixture, whose source claim ids must occur in the validated claim table. It computes an effective-exposure action and rejects `unknown`. The constructor emits a witness only when the result matches the contradiction predicate for the target issue class. Therefore every emitted witness satisfies the three properties.

**Evaluation dependency.** This theorem supports reporting 418 BEP-Deep source-grounded witnesses without claiming live-web prevalence.

## Theorem T5: Negative-control preservation

**Statement.** If a locked negative-control fixture encodes the non-conflicting side of a source-grounded rule and the effective-exposure judgment is non-`unknown`, the analyzer emits no witness for that fixture unless a different encoded rule contradicts the same fixture intent.

**Assumptions.** Negative controls are locked with expected issue `none`; the validation audit confirms the fixture role and manifest label; the analyzer does not use baseline outputs as semantic oracle inputs.

**Proof sketch.** The witness constructor requires a target issue class derived from a contradiction predicate. Negative-control fixtures have no target issue label. For each encoded non-conflicting side, the effective judgment agrees with the expected action or yields `no_effect`; neither satisfies the contradiction predicate. Since baseline outputs are not used as oracle inputs, external tool flags cannot create semantic witnesses. Therefore no witness is emitted except in a separately traceable rule conflict, which the locked validation would record as a fixture labeling error.

**Evaluation dependency.** This theorem supports the clean 554/554 BEP-Deep negative-controls result.

## Theorem T6: One-deletion minimizer preservation

**Statement.** For a witness payload `p`, target issue `q`, fixed deletion operator set `D`, and deterministic oracle `O`, the minimizer returns a payload `p'` such that `O(p')` still contains `q`, and no single deletion from `D` applied to `p'` preserves `q`.

**Assumptions.** The minimizer never changes the target issue, source claim id, or oracle. It considers only the locked deletion operators: response-header deletion, CSP directive/source-token deletion, and HSTS directive-segment deletion.

**Proof sketch.** The algorithm repeatedly tests candidate deletions and commits a deletion only when the oracle still emits `q`. By induction over committed deletions, the current payload always preserves `q`. The loop terminates because each committed deletion reduces a finite payload measure and failed candidates are not reintroduced. At termination, every single available deletion has been tested and rejected, hence no one-step deletion in `D` preserves `q`.

**Evaluation dependency.** This theorem supports reporting one-deletion minimal witnesses, not global minimality.

## Boundary theorem: conservative unknown handling

**Statement.** When a fixture edge requires semantics outside the locked rule ledger, the model returns `unknown` or excludes that edge from semantic accuracy denominators rather than converting it into a positive or negative witness.

**Proof sketch.** Rule dispatch is keyed by the locked rule ledger. Missing rules fall through to the explicit `unknown` action. The experiment protocol states that `unknown` edges are not counted as true or false semantic findings. Therefore the model is conservative with respect to unsupported browser behavior.

## Paper placement plan

Main paper: T1/T2 in abbreviated form, T3 and T4 as central correctness statements, T6 as the minimization guarantee. Supplement: full case analysis for encoded families, negative-control preservation, and boundary theorem.
