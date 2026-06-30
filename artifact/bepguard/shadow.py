"""Shadow-generalization audits for BEPGuard.

The locked BEP-Deep denominator must not be a memorized lookup table.  This
module creates semantics-preserving shadow workloads from every locked fixture
without reusing locked identifiers.  Each shadow case is produced by a typed
transformation that should preserve the effective policy judgment: header-name
canonicalization, field-order perturbation, irrelevant metadata, context-noise
extension, and fixture-domain alpha-renaming.  The verifier then re-executes the
operational semantics and checks that the expected issue signature is preserved.

The audit is intentionally outside the empirical denominator: it is a
non-overfitting robustness and representation-invariance gate, not a new set of
positive/negative research labels.
"""
from __future__ import annotations

import copy
import hashlib
import json
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Sequence, Tuple

sys.dont_write_bytecode = True


def _import_semantics(root: Path):
    scripts = root / "artifact" / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import bep_semantics  # type: ignore
    return bep_semantics


def load_fixtures(root: Path) -> List[Dict[str, Any]]:
    return json.loads((root / "artifact" / "data" / "deep_locked_fixtures.json").read_text(encoding="utf-8"))


def expected_signature(fixture: Mapping[str, Any]) -> Tuple[str, ...]:
    issue = str(fixture.get("expected_issue", "none"))
    return tuple() if issue == "none" else (issue,)


def actual_signature(findings: Iterable[Any]) -> Tuple[str, ...]:
    issues: List[str] = []
    for finding in findings:
        if hasattr(finding, "issue"):
            issues.append(str(getattr(finding, "issue")))
        elif isinstance(finding, Mapping):
            issues.append(str(finding.get("issue", "")))
    return tuple(sorted(i for i in issues if i))


def _header_case_fold(fixture: Dict[str, Any]) -> None:
    for header in fixture.get("headers", []):
        if isinstance(header, dict):
            header["name"] = str(header.get("name", "")).lower()
    for layer in fixture.get("layers", []) if isinstance(fixture.get("layers", []), list) else []:
        for header in layer.get("headers", []) if isinstance(layer, dict) else []:
            if isinstance(header, dict):
                header["name"] = str(header.get("name", "")).lower()


def _header_mixed_case(fixture: Dict[str, Any]) -> None:
    def mix(name: str) -> str:
        parts = name.split("-")
        return "-".join(part[:1].upper() + part[1:].lower() for part in parts)
    for header in fixture.get("headers", []):
        if isinstance(header, dict):
            header["name"] = mix(str(header.get("name", "")))


def _reverse_headers(fixture: Dict[str, Any]) -> None:
    headers = fixture.get("headers", [])
    if isinstance(headers, list):
        fixture["headers"] = list(reversed(headers))


def _sort_irrelevant_stable(fixture: Dict[str, Any]) -> None:
    headers = fixture.get("headers", [])
    if isinstance(headers, list):
        fixture["headers"] = sorted(headers, key=lambda h: (str(h.get("name", "")), str(h.get("value", ""))) if isinstance(h, dict) else ("", ""))


def _append_irrelevant_metadata(fixture: Dict[str, Any]) -> None:
    headers = fixture.get("headers", [])
    if isinstance(headers, list):
        fixture["headers"] = list(headers) + [
            {"name": "X-BEPGuard-Shadow", "value": "representation-noop"},
            {"name": "Referrer-Policy", "value": "strict-origin-when-cross-origin"},
            {"name": "Server-Timing", "value": "shadow;dur=0"},
        ]


def _append_context_noise(fixture: Dict[str, Any]) -> None:
    ctx = dict(fixture.get("context", {})) if isinstance(fixture.get("context", {}), dict) else {}
    ctx.update({
        "shadow_probe": True,
        "request_id": "shadow-fixed",
        "accept_language": "en-US",
        "viewport_width": 1280,
        "ignored_cache_key": "noop",
    })
    fixture["context"] = ctx




def _append_observability_noop(fixture: Dict[str, Any]) -> None:
    headers = fixture.get("headers", [])
    if isinstance(headers, list):
        fixture["headers"] = list(headers) + [
            {"name": "X-Request-ID", "value": "blind-fixed"},
            {"name": "Traceparent", "value": "00-00000000000000000000000000000000-0000000000000000-00"},
        ]


def _append_cache_metadata_noop(fixture: Dict[str, Any]) -> None:
    headers = fixture.get("headers", [])
    if isinstance(headers, list):
        fixture["headers"] = list(headers) + [
            {"name": "ETag", "value": "\"shadow-fixed\""},
            {"name": "Last-Modified", "value": "Mon, 01 Jan 2024 00:00:00 GMT"},
        ]


def _append_transport_metadata_noop(fixture: Dict[str, Any]) -> None:
    headers = fixture.get("headers", [])
    if isinstance(headers, list):
        fixture["headers"] = list(headers) + [
            {"name": "Alt-Svc", "value": "h3=\":443\"; ma=86400"},
            {"name": "Accept-Ranges", "value": "bytes"},
        ]


def _append_browser_context_noop(fixture: Dict[str, Any]) -> None:
    ctx = dict(fixture.get("context", {})) if isinstance(fixture.get("context", {}), dict) else {}
    ctx.update({
        "user_activation": False,
        "service_worker_state": "none",
        "navigation_type": "navigate",
        "storage_partition": "default",
    })
    fixture["context"] = ctx

def _alpha_rename_fixture_domains(fixture: Dict[str, Any]) -> None:
    # Preserve same-origin/same-site relations under reserved fixture domains.
    mapping = {
        "https://app.example": "https://alpha.example",
        "https://admin.example": "https://admin-alpha.example",
        "https://shop.example": "https://shop-alpha.example",
        "https://docs.example": "https://docs-alpha.example",
        "https://cdn.example": "https://assets.example",
        "https://static.test": "https://static-alpha.test",
        "https://evil.example": "https://adversary.example",
        "https://other.example": "https://other-alpha.example",
        "http://cdn.example": "http://assets.example",
    }
    text = json.dumps(fixture, sort_keys=True)
    for old, new in mapping.items():
        text = text.replace(old, new)
    updated = json.loads(text)
    fixture.clear()
    fixture.update(updated)


def _alpha_rename_no_string_values(fixture: Dict[str, Any]) -> None:
    # Rename only context origins, leaving header values unchanged.  This guards
    # source-list dependence separately from full fixture alpha-renaming.
    ctx = dict(fixture.get("context", {})) if isinstance(fixture.get("context", {}), dict) else {}
    for key, value in list(ctx.items()):
        if value == "https://app.example":
            ctx[key] = "https://alpha.example"
        elif value == "https://cdn.example":
            ctx[key] = "https://assets.example"
        elif value == "https://evil.example":
            ctx[key] = "https://adversary.example"
    fixture["context"] = ctx


Transform = Tuple[str, str, Callable[[Dict[str, Any]], None]]
TRANSFORMS: Sequence[Transform] = [
    ("header_lowercase", "Header names are lowercased.", _header_case_fold),
    ("header_mixedcase", "Header names are canonical mixed case.", _header_mixed_case),
    ("header_reverse", "Header field order is reversed.", _reverse_headers),
    ("header_sort", "Header fields are sorted deterministically.", _sort_irrelevant_stable),
    ("irrelevant_metadata", "Irrelevant response metadata is appended.", _append_irrelevant_metadata),
    ("context_noise", "Ignored context fields are appended.", _append_context_noise),
    ("observability_noop", "Tracing and request-id metadata is appended.", _append_observability_noop),
    ("cache_metadata_noop", "Cache metadata that is irrelevant to the modeled judgment is appended.", _append_cache_metadata_noop),
    ("transport_metadata_noop", "Transport metadata that is irrelevant to the modeled judgment is appended.", _append_transport_metadata_noop),
    ("browser_context_noop", "Browser-context fields outside the encoded fragment are appended.", _append_browser_context_noop),
]

# Alpha-renaming is evaluated separately.  It is intentionally not required to
# preserve all fixtures because source-list strings may name a concrete origin;
# the audit records those as semantic, not representation, dependencies.
OPTIONAL_TRANSFORMS: Sequence[Transform] = [
    ("alpha_full", "Reserved fixture domains are consistently alpha-renamed.", _alpha_rename_fixture_domains),
    ("alpha_context_only", "Context origins are alpha-renamed while headers are held fixed.", _alpha_rename_no_string_values),
]


@dataclass(frozen=True)
class ShadowRow:
    shadow_id: str
    source_fixture_fingerprint: str
    transform: str
    role: str
    expected_issues: Tuple[str, ...]
    actual_issues: Tuple[str, ...]
    preserved: bool
    optional: bool
    note: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "shadow_id": self.shadow_id,
            "source_fixture_fingerprint": self.source_fixture_fingerprint,
            "transform": self.transform,
            "role": self.role,
            "expected_issues": list(self.expected_issues),
            "actual_issues": list(self.actual_issues),
            "preserved": self.preserved,
            "optional": self.optional,
            "note": self.note,
        }


def _fingerprint(fixture: Mapping[str, Any]) -> str:
    text = json.dumps(fixture, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _make_shadow(base: Mapping[str, Any], transform: Transform, ordinal: int) -> Dict[str, Any]:
    name, _desc, fn = transform
    fixture = copy.deepcopy(dict(base))
    fn(fixture)
    # Remove locked identifiers from the executable object.  The shadow_id is a
    # digest, not a copy of the locked fixture id.
    fixture["id"] = f"SHADOW_{ordinal:05d}_{name.upper()}_{_fingerprint(fixture)}"
    fixture["variant"] = f"shadow-{name}-{ordinal:05d}"
    return fixture


def run_shadow_audit(root: Path) -> Tuple[List[ShadowRow], Dict[str, Any]]:
    sem = _import_semantics(root)
    fixtures = load_fixtures(root)
    rows: List[ShadowRow] = []
    ordinal = 0
    for fixture in fixtures:
        expected = expected_signature(fixture)
        fp = _fingerprint(fixture)
        for transform in TRANSFORMS:
            ordinal += 1
            shadow = _make_shadow(fixture, transform, ordinal)
            actual = actual_signature(sem.analyze_fixture(shadow))
            rows.append(ShadowRow(str(shadow["id"]), fp, transform[0], str(fixture.get("fixture_role", "")), expected, actual, actual == expected, False, transform[1]))
        for transform in OPTIONAL_TRANSFORMS:
            ordinal += 1
            shadow = _make_shadow(fixture, transform, ordinal)
            actual = actual_signature(sem.analyze_fixture(shadow))
            rows.append(ShadowRow(str(shadow["id"]), fp, transform[0], str(fixture.get("fixture_role", "")), expected, actual, actual == expected, True, transform[1]))
    required = [r for r in rows if not r.optional]
    optional = [r for r in rows if r.optional]
    failures = [r.as_dict() for r in required if not r.preserved]
    optional_preserved = sum(1 for r in optional if r.preserved)
    by_transform = Counter(r.transform for r in rows)
    required_by_transform = Counter(r.transform for r in required)
    summary = {
        "status": "pass" if not failures else "fail",
        "problem_count": len(failures),
        "fixtures_transformed": len(fixtures),
        "required_transforms": len(TRANSFORMS),
        "optional_transforms": len(OPTIONAL_TRANSFORMS),
        "required_shadow_cases": len(required),
        "required_preserved": sum(1 for r in required if r.preserved),
        "optional_shadow_cases": len(optional),
        "optional_preserved": optional_preserved,
        "optional_dependency_cases": len(optional) - optional_preserved,
        "shadow_cases_total": len(rows),
        "by_transform": dict(sorted(by_transform.items())),
        "required_by_transform": dict(sorted(required_by_transform.items())),
        "failures": failures[:25],
        "interpretation": "Required transformations are semantics-preserving representation changes over every locked BEP-Deep fixture. Optional alpha-renaming rows expose genuine origin-string dependencies and are reported, not required, so the audit cannot hide overfitting by deleting semantic dependencies.",
    }
    return rows, summary


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
