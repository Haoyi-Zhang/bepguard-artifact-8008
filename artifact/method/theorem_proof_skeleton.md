# Theorem and Proof Skeleton for Policy Intent Drift

Status: paperization-preparation skeleton. These statements define the proof obligations that the paper may state after prose integration. They do not expand the claim beyond the locked executable fragments.

## Objects

Let `H` be a finite multiset of response header fields. Let `C` be a finite browser/request/rendering context over the locked dimensions: scheme, document origin, target origin, request mode, credentials mode, destination, rendering mode, and HSTS user-agent state. Let `Normalize(H, G, pi)` produce a finite set of BEP-IR policies with family, disposition, delivery, directives, and provenance. Let `Eff(P, C, e)` be the partial effective-exposure judgment whose result is one of `{allow, block, report, no_effect, unknown}`. Let `Intent` contain only explicit source-grounded claims admitted by the coding protocol. Let `Witness(Intent, H, C, e)` be emitted only when an explicit expected action contradicts a defined effective-exposure judgment.

## Theorem 1: Normalization idempotence

**Statement.** For every header multiset `H`, generation state `G`, and provenance map `pi` in the encoded grammar, applying `Normalize` to an already normalized BEP-IR policy set changes neither the set of normalized policy records nor their directive maps, modulo stable ordering of records and directive tokens.

**Assumptions.** Header names are case-folded, directive names are case-normalized within each family, multiplicity is represented explicitly, malformed fields are represented as `invalid`, and provenance is append-only.

**Proof skeleton.** By structural induction over normalized records. Base cases are empty header multisets and singleton fields. Inductive cases follow from canonical case-folding, deterministic directive tokenization, explicit multiplicity preservation, and invalid-field retention. Since normalization does not drop an already normalized directive or synthesize a new directive absent from the input record, a second pass is observationally equivalent to the first.

## Theorem 2: Fallback/default determinism

**Statement.** For every encoded policy family and encoded directive fragment, effective directive selection returns at most one selected directive, or explicit `unknown` at the boundary of the model.

**Assumptions.** Each encoded family has a total priority order for its modeled fallback relation; duplicate headers are represented as multiple policies and composed by the family-specific rule before directive selection; unsupported directives are mapped to `unknown` rather than silently interpreted.

**Proof skeleton.** Case analysis by family. CSP fetch fallback uses the locked fallback order for modeled fetch directives. CORS modeled fields are selected directly from the normalized ACAO/ACAC/Vary fields. HSTS state transitions select the unique max-age directive if the header parses within the fragment. COEP/CORP/CORS and Permissions-Policy fragments have explicit source/feature membership checks. No case contains two incomparable selected directives; where the public source does not determine a unique result, the model emits `unknown`.

## Theorem 3: Report-only non-blocking

**Statement.** In the encoded CSP fragment, a policy delivered solely as `Content-Security-Policy-Report-Only` can generate a `report` judgment but cannot be the sole cause of a `block` judgment.

**Assumptions.** The observation contains no separate enforced CSP policy that blocks the same edge; the report-only header is syntactically within the modeled fragment; the edge is a modeled fetch edge.

**Proof skeleton.** The CSP disposition component is inspected before enforcement. The transition for `report` disposition emits `report` on violation and does not enter the blocking branch. The only blocking transition requires `disposition = enforce`. Therefore no derivation tree with a sole report-only policy can conclude `block`.

## Theorem 4: Witness soundness

**Statement.** Every emitted semantic conflict witness in the locked experiment contains: (1) an admitted explicit intent claim; (2) a normalized policy/context object traceable to a locked fixture or source-grounded generation rule; and (3) a defined effective-exposure judgment that contradicts the coded expected action.

**Assumptions.** The experiment uses the locked claim table, fixture manifest, rule-to-source ledger, and no post-lock label or denominator changes. The oracle emits no witness when `Eff` returns `unknown`.

**Proof skeleton.** The witness generation algorithm enumerates only claims admitted by the corpus lock. Candidate edges are obtained from fixture records whose source-claim references resolve. Each edge is evaluated by `Eff`; if the result is `unknown`, the algorithm records a boundary case and does not emit a witness. Emission requires a mismatch predicate between expected and observed actions. Thus each witness is grounded and contradictory under the model.

## Theorem 5: Negative-control preservation

**Statement.** For each locked negative-control fixture, the semantic oracle emits no conflict witness under the encoded fragments.

**Assumptions.** Negative controls are locked before execution and preserve the same source-span, rule, and context schema as positives. The model does not infer unstated intent.

**Proof skeleton.** For each negative-control class, the expected action and effective-exposure judgment agree by construction: explicit `script-src` overrides fallback, authorized CORS responses remain shareable, HTTPS HSTS responses with positive max-age remain stateful, compatible CORP/CORS resources are embeddable, and enabled features remain enabled. Since witness emission requires contradiction, no witness is emitted.

## Theorem 6: One-deletion minimizer preservation

**Statement.** The minimized payload returned by the current minimizer preserves the target issue under the same oracle and fixed deletion operators, and is one-deletion minimal with respect to those operators.

**Assumptions.** The oracle is deterministic; deletion operators are the locked set over headers, modeled directives, source tokens, and HSTS directive segments; the minimizer stops only after testing all remaining single deletions.

**Proof skeleton.** The minimizer accepts a deletion only if re-running the oracle returns the target issue label. Therefore target preservation is an invariant after each accepted deletion. At termination, every remaining single deletion has been tested and rejected because it either removes the target issue or violates the oracle's definedness conditions. Thus the result is one-deletion minimal under the locked operator set.

## Theorem 7: Boundary conservatism

**Statement.** If an effective behavior required by a source-grounded claim is outside the encoded semantics, the model returns `unknown` or excludes the edge from accuracy-style metrics; it does not emit a conflict witness by guessing browser behavior.

**Assumptions.** Unknown-producing rules are not remapped into allow/block/report/no_effect during evaluation, and boundary cases are reported in failure analysis.

**Proof skeleton.** By inspection of the witness generation precondition: witness emission requires a defined effective judgment. Since `unknown` is not a defined contradiction, no witness can be emitted from an unknown edge. This establishes conservative under-approximation of conflict reporting.
