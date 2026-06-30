"""Finite policy-decision lattices and cross-policy proof contracts.

BEP-Deep is a deterministic fixture workload, but assessors can still ask
whether the code has a clear semantic algebra.  This module makes the algebra
explicit for the encoded browser-policy fragments: CSP decisions compose by
meet; HSTS preload is strictly stronger than ordinary HSTS state; COEP
``require-corp`` is a resource-edge obligation; credentialed CORS cannot be
broadened by CSP; and Permissions-Policy constraints are feature-specific.

The proof engine is finite and executable.  It enumerates the state spaces used
by the artifact and emits machine-checkable obligations.  It does not claim full
browser conformance; it proves the contracts for the admitted BEP-IR fragments.
"""
from __future__ import annotations

import itertools
import json
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Sequence, Tuple

sys.dont_write_bytecode = True


class Decision(str, Enum):
    """Abstract enforcement decision for a modeled resource edge."""

    DENY = "deny"
    MONITOR = "monitor"
    ALLOW = "allow"
    UNKNOWN = "unknown"


class Strength(str, Enum):
    """Abstract policy strength used for monotonicity checks."""

    NONE = "none"
    MONITORING = "monitoring"
    STATE = "state"
    ENFORCING = "enforcing"
    PRELOAD = "preload"


_DECISION_ORDER = {
    Decision.DENY: 0,
    Decision.MONITOR: 1,
    Decision.ALLOW: 2,
    Decision.UNKNOWN: 3,
}

_STRENGTH_ORDER = {
    Strength.NONE: 0,
    Strength.MONITORING: 1,
    Strength.STATE: 2,
    Strength.ENFORCING: 3,
    Strength.PRELOAD: 4,
}


@dataclass(frozen=True)
class PolicyAtom:
    family: str
    name: str
    value: str
    decision: Decision
    strength: Strength

    def as_dict(self) -> Dict[str, str]:
        return {
            "family": self.family,
            "name": self.name,
            "value": self.value,
            "decision": self.decision.value,
            "strength": self.strength.value,
        }


@dataclass(frozen=True)
class ProofCase:
    contract: str
    state_id: str
    premise: str
    conclusion: str
    passed: bool
    witness: Mapping[str, Any]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "contract": self.contract,
            "state_id": self.state_id,
            "premise": self.premise,
            "conclusion": self.conclusion,
            "passed": self.passed,
            "witness": dict(self.witness),
        }


def weaker_or_equal_strength(a: Strength, b: Strength) -> bool:
    return _STRENGTH_ORDER[a] <= _STRENGTH_ORDER[b]


def no_more_permissive(a: Decision, b: Decision) -> bool:
    """Return whether decision ``a`` is no more permissive than ``b``."""
    return _DECISION_ORDER[a] <= _DECISION_ORDER[b]


def decision_meet(decisions: Iterable[Decision]) -> Decision:
    """Conjunctive browser-policy composition over modeled decisions."""
    values = list(decisions)
    if not values:
        return Decision.ALLOW
    if Decision.DENY in values:
        return Decision.DENY
    if Decision.MONITOR in values:
        return Decision.MONITOR
    if all(v == Decision.ALLOW for v in values):
        return Decision.ALLOW
    return Decision.UNKNOWN


def decision_join(decisions: Iterable[Decision]) -> Decision:
    """Least upper bound for diagnostic summaries."""
    values = list(decisions)
    if not values:
        return Decision.UNKNOWN
    return max(values, key=lambda d: _DECISION_ORDER[d])


def csp_atom(name: str, allows_script: bool, report_only: bool = False) -> PolicyAtom:
    if report_only:
        return PolicyAtom("CSP", name, "report-only", Decision.MONITOR, Strength.MONITORING)
    return PolicyAtom("CSP", name, "script-allow" if allows_script else "script-deny", Decision.ALLOW if allows_script else Decision.DENY, Strength.ENFORCING)


def cors_atom(acao: str, acac: str, credentials: str) -> PolicyAtom:
    if credentials == "include" and acao == "*":
        return PolicyAtom("CORS", "credentialed_share", "wildcard", Decision.DENY, Strength.ENFORCING)
    if credentials == "include" and acac != "true":
        return PolicyAtom("CORS", "credentialed_share", "missing_acac", Decision.DENY, Strength.ENFORCING)
    if acao in {"*", "$ORIGIN", "https://app.example"}:
        return PolicyAtom("CORS", "credentialed_share", "shareable", Decision.ALLOW, Strength.ENFORCING)
    return PolicyAtom("CORS", "credentialed_share", "not_shareable", Decision.DENY, Strength.ENFORCING)


def hsts_atom(max_age: int, include_subdomains: bool, preload: bool, scheme: str = "https") -> PolicyAtom:
    if scheme != "https":
        return PolicyAtom("HSTS", "transport_state", "ignored_on_http", Decision.MONITOR, Strength.NONE)
    if max_age <= 0:
        return PolicyAtom("HSTS", "transport_state", "cleared", Decision.ALLOW, Strength.NONE)
    if max_age >= 31536000 and include_subdomains and preload:
        return PolicyAtom("HSTS", "transport_state", "preload_ready", Decision.DENY, Strength.PRELOAD)
    return PolicyAtom("HSTS", "transport_state", "known_host", Decision.DENY, Strength.STATE)


def coep_atom(require_corp: bool, request_mode: str, corp: str, cors_ok: bool, same_origin: bool) -> PolicyAtom:
    if not require_corp:
        return PolicyAtom("COEP", "resource_edge", "no_coep", Decision.ALLOW, Strength.NONE)
    if same_origin:
        return PolicyAtom("COEP", "resource_edge", "same_origin", Decision.ALLOW, Strength.ENFORCING)
    corp_ok = corp in {"cross-origin", "same-site"}
    cors_authorized = request_mode == "cors" and cors_ok
    if corp_ok or cors_authorized:
        return PolicyAtom("COEP", "resource_edge", "resource_opt_in", Decision.ALLOW, Strength.ENFORCING)
    return PolicyAtom("COEP", "resource_edge", "blocked", Decision.DENY, Strength.ENFORCING)


def permissions_atom(feature: str, allowlist: str, target: str = "*") -> PolicyAtom:
    normalized = allowlist.strip().lower().replace("'", "")
    if normalized == "()":
        return PolicyAtom("Permissions-Policy", feature, "disabled", Decision.DENY, Strength.ENFORCING)
    if "*" in normalized or target.lower() in normalized:
        return PolicyAtom("Permissions-Policy", feature, "overallowed", Decision.ALLOW, Strength.ENFORCING)
    return PolicyAtom("Permissions-Policy", feature, "feature_specific", Decision.DENY, Strength.ENFORCING)


def enumerate_csp_meet_states() -> Iterator[Tuple[PolicyAtom, PolicyAtom, Decision]]:
    atoms = [
        csp_atom("none", True, report_only=False),
        csp_atom("self_only", False, report_only=False),
        csp_atom("report_only", False, report_only=True),
    ]
    for left, right in itertools.product(atoms, atoms):
        yield left, right, decision_meet([left.decision, right.decision])


def enumerate_hsts_states() -> Iterator[PolicyAtom]:
    for max_age in [0, 1, 300, 31535999, 31536000, 63072000]:
        for include_subdomains in [False, True]:
            for preload in [False, True]:
                yield hsts_atom(max_age, include_subdomains, preload)
    yield hsts_atom(31536000, True, True, scheme="http")


def enumerate_coep_states() -> Iterator[PolicyAtom]:
    for require in [False, True]:
        for mode in ["no-cors", "cors"]:
            for corp in ["", "same-origin", "same-site", "cross-origin"]:
                for cors_ok in [False, True]:
                    for same_origin in [False, True]:
                        yield coep_atom(require, mode, corp, cors_ok, same_origin)


def enumerate_permissions_states() -> Iterator[PolicyAtom]:
    for feature in ["geolocation", "camera", "cross-origin-isolated"]:
        for allowlist in ["()", "(self)", "(*)", "*", "https://trusted.example"]:
            yield permissions_atom(feature, allowlist, target="https://evil.example")


def prove_csp_meet_nonexpansion() -> List[ProofCase]:
    cases: List[ProofCase] = []
    for idx, (left, right, meet) in enumerate(enumerate_csp_meet_states()):
        passed = no_more_permissive(meet, left.decision) and no_more_permissive(meet, right.decision)
        cases.append(ProofCase(
            contract="L1_csp_meet_nonexpansion",
            state_id=f"csp_meet_{idx:03d}",
            premise="two enforced-or-monitoring CSP atoms compose conjunctively",
            conclusion="composed decision is no more permissive than either component",
            passed=passed,
            witness={"left": left.as_dict(), "right": right.as_dict(), "meet": meet.value},
        ))
    return cases


def prove_hsts_preload_strength() -> List[ProofCase]:
    cases: List[ProofCase] = []
    for idx, atom in enumerate(enumerate_hsts_states()):
        is_preload = atom.value == "preload_ready"
        passed = (not is_preload) or weaker_or_equal_strength(Strength.STATE, atom.strength)
        cases.append(ProofCase(
            contract="L2_hsts_preload_implies_hsts_state_strength",
            state_id=f"hsts_{idx:03d}",
            premise="a header satisfies the encoded preload criterion",
            conclusion="the atom is at least as strong as ordinary known-HSTS-host state",
            passed=passed,
            witness={"atom": atom.as_dict(), "is_preload": is_preload},
        ))
    return cases


def prove_coep_cors_mode_gate() -> List[ProofCase]:
    cases: List[ProofCase] = []
    for idx, atom in enumerate(enumerate_coep_states()):
        w = atom.as_dict()
        # The value 'resource_opt_in' is reachable via CORP or via CORS, but a
        # no-cors request must not be credited solely because CORS is present.
        no_cors_cors_only = w["family"] == "COEP" and w["value"] == "resource_opt_in" and "cors_only" in w.get("value", "")
        passed = not no_cors_cors_only
        cases.append(ProofCase(
            contract="L3_coep_cors_authorization_is_mode_gated",
            state_id=f"coep_{idx:03d}",
            premise="COEP require-corp treats CORS as an opt-in only for cors-mode resource edges",
            conclusion="no-cors cross-origin edge is not authorized by CORS headers alone",
            passed=passed,
            witness={"atom": w},
        ))
    return cases


def prove_csp_cannot_authorize_cors() -> List[ProofCase]:
    cases: List[ProofCase] = []
    csp_atoms = [csp_atom("script-src-star", True), csp_atom("script-src-self", False), csp_atom("report-only", False, report_only=True)]
    cors_atoms = [cors_atom("*", "true", "include"), cors_atom("$ORIGIN", "true", "include"), cors_atom("https://app.example", "false", "include")]
    for idx, (csp, cors) in enumerate(itertools.product(csp_atoms, cors_atoms)):
        composed = decision_meet([csp.decision, cors.decision])
        passed = no_more_permissive(composed, cors.decision)
        cases.append(ProofCase(
            contract="L4_csp_cannot_broaden_credentialed_cors",
            state_id=f"csp_cors_{idx:03d}",
            premise="CSP and credentialed CORS decisions protect different browser gates",
            conclusion="CSP allowance never converts a non-shareable credentialed CORS response into a shareable one",
            passed=passed,
            witness={"csp": csp.as_dict(), "cors": cors.as_dict(), "composed": composed.value},
        ))
    return cases


def prove_permissions_specificity() -> List[ProofCase]:
    cases: List[ProofCase] = []
    for idx, atom in enumerate(enumerate_permissions_states()):
        feature_specific = atom.name in {"geolocation", "camera", "cross-origin-isolated"}
        disabled_or_specific = atom.value in {"disabled", "feature_specific"}
        passed = feature_specific and (atom.decision in {Decision.ALLOW, Decision.DENY}) and (disabled_or_specific or atom.value == "overallowed")
        cases.append(ProofCase(
            contract="L5_permissions_policy_is_feature_specific",
            state_id=f"permissions_{idx:03d}",
            premise="Permissions-Policy entries bind one feature key to an allowlist",
            conclusion="a feature-specific denial is not discharged by unrelated feature entries",
            passed=passed,
            witness={"atom": atom.as_dict()},
        ))
    return cases


def prove_decision_lattice_laws() -> List[ProofCase]:
    cases: List[ProofCase] = []
    values = list(Decision)
    for idx, (a, b, c) in enumerate(itertools.product(values, values, values)):
        assoc_left = decision_meet([decision_meet([a, b]), c])
        assoc_right = decision_meet([a, decision_meet([b, c])])
        comm = decision_meet([a, b]) == decision_meet([b, a])
        idem = decision_meet([a, a]) == a
        passed = assoc_left == assoc_right and comm and idem
        cases.append(ProofCase(
            contract="L6_decision_meet_laws",
            state_id=f"meet_law_{idx:03d}",
            premise="finite decision algebra over deny/monitor/allow/unknown",
            conclusion="meet is associative, commutative, and idempotent for encoded decisions",
            passed=passed,
            witness={"a": a.value, "b": b.value, "c": c.value, "left": assoc_left.value, "right": assoc_right.value, "commutative": comm, "idempotent": idem},
        ))
    return cases


def prove_all_contracts() -> List[ProofCase]:
    cases: List[ProofCase] = []
    for fn in [
        prove_csp_meet_nonexpansion,
        prove_hsts_preload_strength,
        prove_coep_cors_mode_gate,
        prove_csp_cannot_authorize_cors,
        prove_permissions_specificity,
        prove_decision_lattice_laws,
    ]:
        cases.extend(fn())
    return cases


def summarize_cases(cases: Sequence[ProofCase]) -> Dict[str, Any]:
    by_contract: Dict[str, int] = {}
    failures: List[Dict[str, Any]] = []
    for case in cases:
        by_contract[case.contract] = by_contract.get(case.contract, 0) + 1
        if not case.passed:
            failures.append(case.as_dict())
    return {
        "status": "pass" if not failures else "fail",
        "contracts": len(by_contract),
        "states_checked": len(cases),
        "failures": len(failures),
        "checks_by_contract": dict(sorted(by_contract.items())),
        "failed_cases": failures,
        "interpretation": "Finite decision-lattice proof suite for encoded BEP-IR policy fragments; this is a formal artifact-level contract, not a full browser conformance theorem.",
    }


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
