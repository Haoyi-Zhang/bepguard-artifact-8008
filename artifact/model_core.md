# BEP-IR Core Model

Status: locked executable-formal-core description for the release protocol. This file defines the research objects that the implementation, validation ladder, and study protocol preserve. It is not paper prose.

## 1. Research objects

A browser-enforced security-policy observation is a tuple:

`o = <u, H, C, G, I>`

where `u` is a source unit, `H` is a multiset of response headers, `C` is a browser/request context, `G` is a framework or deployment generation state, and `I` is the set of explicit intent claims extracted from public developer-facing evidence.

BEP-IR normalizes the tuple into:

`P = <family, disposition, delivery, directives, provenance>`

* `family ∈ {CSP, CORS, HSTS, COEP, CORP, COOP, PermissionsPolicy, Other}`.
* `disposition ∈ {enforce, report, generate, absent, invalid}`.
* `delivery ∈ {http_response, meta, framework_api, middleware_default, proxy_layer, documentation_claim}`.
* `directives` is a finite map from directive/header-field names to normalized values.
* `provenance` records source unit ids, framework state, and extraction rule ids.

A context is:

`C = <scheme, origin, target_origin, request_mode, credentials_mode, destination, initiator, rendering_mode, user_agent_state>`.

The implementation covers a strict subset of this context: CSP delivery/report-only/fallback/nonce rendering, CORS credentialed shareability, HSTS HTTPS-only processing and state clearing, and COEP/CORP/CORS no-cors embedding.

## 2. Effective-exposure judgment

The core semantic judgment is:

`Eff(P, C, e) ⇓ a`

where `e` is a resource edge or navigation edge and `a ∈ {allow, block, report, no_effect, unknown}`. `unknown` is not a vulnerability label; it is an explicit boundary when the source evidence or encoded semantics is insufficient.

Examples of encoded fragments:

* CSP report-only: a policy with disposition `report` can produce `report`, but it cannot produce `block` for the resource edge under the same policy.
* CSP fetch fallback: if a fetch directive such as `script-src` is absent, the effective directive may be inherited from `default-src` when the CSP algorithm defines that fallback.
* CORS credentialed wildcard: a response with `Access-Control-Allow-Origin: *` is not shareable for a credentialed request when credentials mode requires credential inclusion.
* HSTS delivery: an HSTS header delivered over an untrusted or non-secure transport has no HSTS storage effect.
* HSTS clearing: a valid secure response containing `max-age=0` removes the known HSTS host state.
* COEP require-corp: a `require-corp` document blocks certain cross-origin `no-cors` resource edges unless the resource is compatible through CORP or CORS.

## 3. Intent claims and drift

An explicit intent claim is:

`ι = <source_unit, subject, expected_action, scope, confidence, evidence_span>`.

The full experiment admits only explicit claims. It excludes inferred author motivation, unstated best practices, and claims that require private deployment data.

A semantic drift witness is:

`w = <ι, o, e, expected_action, observed_action, explanation, minimized_payload>`

such that `expected_action` is entailed by `ι` under the coding protocol and `observed_action = Eff(P, C, e)` contradicts it under the encoded semantics. The witness is source-grounded if every element of `ι`, `P`, and `C` is traceable to a source unit, deterministic fixture rule, or locked synthetic-generation rule.

## 4. Algorithms

### A1. Normalize headers to BEP-IR

Input: multiset of response headers `H`, framework state `G`, provenance map `π`.
Output: finite set of policies `P`.

1. Canonicalize header names case-insensitively.
2. Preserve multiplicity for duplicate policy headers.
3. Parse family-specific directive syntax into normalized directive maps.
4. Attach disposition and delivery.
5. Emit `invalid` rather than dropping malformed fields.

Complexity: `O(|H| + T)`, where `T` is the total number of directive tokens.

### A2. Build effective exposure graph

Input: normalized policies `P`, request/resource contexts `C`, deterministic fixture edges `E`.
Output: graph `X = <V, E, labels>` with edge labels from `Eff`.

Complexity: `O(|E| * J)`, where `J` is the cost of the policy-family judgment for an edge. For the current encoded fragments, `J` is linear in the number of relevant directives for that family.

### A3. Generate semantic conflict witnesses

Input: intent claims `I`, exposure graph `X`, matching relation between claims and edges.
Output: witnesses `W`.

For each `ι ∈ I`, enumerate source-grounded candidate edges whose context is in scope. Compute `Eff` for each edge and compare it to the expected action. Emit a witness only when the contradiction is defined without using `unknown`.

Complexity: `O(|I| * |E_ι| * J)`, where `E_ι` is the candidate edge set matched to claim `ι`.

### A4. Minimize witness payloads

Input: witness payload `p`, target issue `q`, oracle `O`.
Output: 1-minimal payload under a fixed deletion operator set.

The current implementation applies deletion-based minimization over response headers, CSP directives/source tokens, and HSTS directive segments. The guarantee is 1-minimality with respect to those deletion operators, not global string minimality.

Worst-case oracle calls: `O(k^2)` for `k` removable units under classic deletion-based delta debugging. For monotone deletion classes, the expected number of oracle calls is lower, but the protocol reports measured calls rather than assuming monotonicity.

## 5. Proof obligations for the paper

* **PO1 Normalization idempotence.** Re-normalizing a BEP-IR policy does not change the normalized policy set, except for stable ordering.
* **PO2 Fallback determinism.** For each encoded policy family and directive fragment, effective directive selection returns at most one result or explicit `unknown`.
* **PO3 Report-only non-blocking.** A report-only CSP can generate a report judgment but cannot be the sole cause of a block judgment in the model.
* **PO4 Witness soundness.** Every emitted witness corresponds to an explicit intent claim and an effective-exposure judgment that contradicts the coded expected action.
* **PO5 Minimizer preservation.** The minimized payload preserves the target issue under the same oracle and deletion operators.
* **PO6 Boundary conservatism.** When the model cannot encode a browser behavior from public sources, it emits `unknown` and the evaluation excludes that edge from accuracy metrics while recording it in failure analysis.

## 6. Non-goals and boundaries

The model is not a complete browser implementation, not a site scanner, and not a vulnerability exploit generator. It does not claim prevalence on the live web. It studies source-grounded policy intent drift in developer-facing policy engineering artifacts.
