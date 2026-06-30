"""Typed BEP-IR normalization, schema validation, and corpus invariants.

The earlier artifact already contained executable semantics, but much of the
validation logic consumed dictionaries directly.  This module provides a typed
intermediate representation layer that assessors can inspect independently.  It
turns released fixture objects into explicit BEP-IR records, checks stable hash
closure, validates source/intent/header shape, exposes canonical response-header
composition, and produces deterministic corpus-quality metrics.

The module is deliberately conservative: it checks exactly the released fixture
schema and does not infer new labels, add observations, or contact external
services.  It is intended to make the released benchmark easier to audit as a
research object rather than as a collection of ad hoc JSON rows.
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Mapping, MutableMapping, Optional, Sequence, Tuple
from urllib.parse import urlparse

sys.dont_write_bytecode = True

_HEADER_NAME = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+(?:-[A-Za-z0-9!#$%&'*+.^_`|~-]+)*$")
_RESERVED_FIXTURE_HOSTS = {"example", "invalid", "test", "localhost"}
_ALLOWED_ROLES = {"positive", "negative_control", "paired_repair_negative_control"}
_NEGATIVE_LIKE_ROLES = _ALLOWED_ROLES - {"positive"}
_REQUIRED_TOP_KEYS = {
    "id",
    "fixture_role",
    "headers",
    "context",
    "intent",
    "policy_family",
    "source_claim_ids",
    "fixture_hash",
}
_REQUIRED_CONTEXT_KEYS = {"document_origin"}
_REQUIRED_INTENT_KEYS = {"class", "claim"}


@dataclass(frozen=True)
class HeaderField:
    """A normalized HTTP response header field used by BEP-IR."""

    name: str
    value: str

    @property
    def canonical_name(self) -> str:
        return canonical_header_name(self.name)

    def as_dict(self) -> Dict[str, str]:
        return {"name": self.name, "value": self.value}


@dataclass(frozen=True)
class PolicyLayer:
    """A deterministic policy-generation layer for composed fixtures."""

    layer: str
    op: str
    headers: Tuple[HeaderField, ...]

    def as_dict(self) -> Dict[str, Any]:
        return {"layer": self.layer, "op": self.op, "headers": [h.as_dict() for h in self.headers]}


@dataclass(frozen=True)
class Intent:
    """Explicit policy intent attached to a released fixture."""

    klass: str
    claim: str

    def as_dict(self) -> Dict[str, str]:
        return {"class": self.klass, "claim": self.claim}


@dataclass(frozen=True)
class FixtureIR:
    """A typed normalized BEP-IR fixture."""

    fixture_id: str
    fixture_role: str
    expected_issue: str
    policy_family: str
    intent: Intent
    context: Mapping[str, Any]
    headers: Tuple[HeaderField, ...]
    layers: Tuple[PolicyLayer, ...]
    source_claim_ids: Tuple[str, ...]
    public_source_id: str
    variant: str
    fixture_hash: str
    raw: Mapping[str, Any] = field(repr=False)

    def materialize_without_hash(self) -> Dict[str, Any]:
        """Return the stable JSON object used for fixture-hash computation."""
        obj: Dict[str, Any] = {
            "context": dict(self.context),
            "expected_issue": self.expected_issue,
            "fixture_role": self.fixture_role,
            "headers": [h.as_dict() for h in self.headers],
            "id": self.fixture_id,
            "intent": self.intent.as_dict(),
            "policy_family": self.policy_family,
            "source_claim_ids": list(self.source_claim_ids),
        }
        if self.layers:
            obj["layers"] = [l.as_dict() for l in self.layers]
        if self.public_source_id:
            obj["public_source_id"] = self.public_source_id
        if self.variant:
            obj["variant"] = self.variant
        return obj

    def effective_headers(self) -> Tuple[List[Dict[str, str]], List[Dict[str, Any]]]:
        """Compose headers using the BEP-IR layer semantics.

        ``append`` preserves existing fields, ``set`` replaces fields with the
        same canonical name, and ``remove`` deletes fields with that canonical
        name.  The function mirrors the executable oracle but is intentionally
        local to this typed module so schema validation can run without importing
        the full semantic analyzer.
        """
        headers: List[Dict[str, str]] = [h.as_dict() for h in self.headers]
        trace: List[Dict[str, Any]] = [
            {"layer_index": 0, "layer_name": "flat_response", "op": "base", "header": h.name}
            for h in self.headers
        ]
        for idx, layer in enumerate(self.layers, 1):
            op = layer.op.lower()
            if op == "remove":
                remove_names = {h.canonical_name for h in layer.headers}
                headers = [h for h in headers if canonical_header_name(h.get("name", "")) not in remove_names]
                trace.append({"layer_index": idx, "layer_name": layer.layer, "op": op, "header": ";".join(sorted(remove_names))})
                continue
            for header in layer.headers:
                wanted = header.canonical_name
                if op == "set":
                    headers = [h for h in headers if canonical_header_name(h.get("name", "")) != wanted]
                headers.append(header.as_dict())
                trace.append({"layer_index": idx, "layer_name": layer.layer, "op": op, "header": header.name})
        return headers, trace


@dataclass(frozen=True)
class SchemaProblem:
    """A structured fixture-schema problem."""

    fixture_id: str
    severity: str
    code: str
    message: str

    def as_dict(self) -> Dict[str, str]:
        return {"fixture_id": self.fixture_id, "severity": self.severity, "code": self.code, "message": self.message}


@dataclass(frozen=True)
class CorpusProfile:
    """Aggregate structural profile for a fixture corpus."""

    fixtures: int
    positives: int
    negative_controls: int
    source_claims: int
    intent_classes: int
    policy_families: int
    header_fields: int
    layered_fixtures: int
    max_effective_headers: int
    max_layers: int
    duplicate_fixture_ids: Tuple[str, ...]
    duplicate_hashes: Tuple[str, ...]
    orphan_source_claims: Tuple[str, ...]
    problems: Tuple[SchemaProblem, ...]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "fixtures": self.fixtures,
            "positives": self.positives,
            "negative_controls": self.negative_controls,
            "source_claims": self.source_claims,
            "intent_classes": self.intent_classes,
            "policy_families": self.policy_families,
            "header_fields": self.header_fields,
            "layered_fixtures": self.layered_fixtures,
            "max_effective_headers": self.max_effective_headers,
            "max_layers": self.max_layers,
            "duplicate_fixture_ids": list(self.duplicate_fixture_ids),
            "duplicate_hashes": list(self.duplicate_hashes),
            "orphan_source_claims": list(self.orphan_source_claims),
            "problem_count": len(self.problems),
            "problems": [p.as_dict() for p in self.problems],
        }


def stable_json(obj: Any) -> str:
    """Return the canonical JSON string used by released hash ledgers."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def stable_sha256(obj: Any) -> str:
    """Return a full SHA-256 digest for a stable JSON object."""
    return hashlib.sha256(stable_json(obj).encode("utf-8")).hexdigest()


def fixture_hash(obj: Mapping[str, Any]) -> str:
    """Return the released 16-hex fixture hash with ``fixture_hash`` excluded."""
    copy = dict(obj)
    copy.pop("fixture_hash", None)
    return stable_sha256(copy)[:16]


def canonical_header_name(name: str) -> str:
    """Canonicalize an HTTP header field name for equality checks."""
    return "-".join(part.capitalize() for part in str(name).strip().split("-"))


def normalize_header(raw: Mapping[str, Any]) -> HeaderField:
    """Parse and normalize a header object."""
    return HeaderField(name=str(raw.get("name", "")), value=str(raw.get("value", "")))


def normalize_layer(raw: Mapping[str, Any], index: int) -> PolicyLayer:
    """Parse a policy layer with deterministic defaults."""
    headers_raw = raw.get("headers", [])
    headers = tuple(normalize_header(h) for h in headers_raw if isinstance(h, Mapping)) if isinstance(headers_raw, list) else tuple()
    return PolicyLayer(layer=str(raw.get("layer", raw.get("name", f"layer{index}"))), op=str(raw.get("op", "append")).lower(), headers=headers)


def parse_fixture(raw: Mapping[str, Any]) -> FixtureIR:
    """Convert a released dictionary fixture into typed BEP-IR."""
    intent_raw = raw.get("intent", {}) if isinstance(raw.get("intent", {}), Mapping) else {}
    context_raw = raw.get("context", {}) if isinstance(raw.get("context", {}), Mapping) else {}
    headers_raw = raw.get("headers", []) if isinstance(raw.get("headers", []), list) else []
    layers_raw = raw.get("layers", []) if isinstance(raw.get("layers", []), list) else []
    source_claim_ids = raw.get("source_claim_ids", []) if isinstance(raw.get("source_claim_ids", []), list) else []
    return FixtureIR(
        fixture_id=str(raw.get("id", "")),
        fixture_role=str(raw.get("fixture_role", "")),
        expected_issue=str(raw.get("expected_issue", "")),
        policy_family=str(raw.get("policy_family", "")),
        intent=Intent(klass=str(intent_raw.get("class", "")), claim=str(intent_raw.get("claim", ""))),
        context=dict(context_raw),
        headers=tuple(normalize_header(h) for h in headers_raw if isinstance(h, Mapping)),
        layers=tuple(normalize_layer(l, i) for i, l in enumerate(layers_raw) if isinstance(l, Mapping)),
        source_claim_ids=tuple(str(x) for x in source_claim_ids),
        public_source_id=str(raw.get("public_source_id", "")),
        variant=str(raw.get("variant", "")),
        fixture_hash=str(raw.get("fixture_hash", "")),
        raw=dict(raw),
    )


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def load_fixtures(path: Path) -> List[FixtureIR]:
    data = load_json(path)
    if not isinstance(data, list):
        raise ValueError(f"fixture file is not a JSON list: {path}")
    return [parse_fixture(row) for row in data if isinstance(row, Mapping)]


def _is_fixture_origin(value: str) -> bool:
    """Return whether a value is a deterministic fixture origin.

    The locked corpus uses deliberately non-routable pseudo-origins such as
    ``https://app.example`` and ``https://evil.example``.  Some paired fixtures
    also use policy-role names as labels rather than IANA-reserved test TLDs.
    The schema audit therefore checks URL syntax and rejects local filesystem
    paths or opaque identifiers; it does not treat the choice of pseudo-TLD as
    a browser-semantics label.
    """
    parsed = urlparse(value)
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in {"http", "https"}:
        return False
    if not host:
        return False
    if "/" in host or "\\" in host or host.startswith(".") or host.endswith("."):
        return False
    return host == "localhost" or "." in host


def _problem(fixture_id: str, code: str, message: str, severity: str = "error") -> SchemaProblem:
    return SchemaProblem(fixture_id=fixture_id or "<missing>", severity=severity, code=code, message=message)


def validate_fixture(fixture: FixtureIR, admitted_claims: Optional[set[str]] = None) -> List[SchemaProblem]:
    """Validate one BEP-IR fixture against release invariants."""
    problems: List[SchemaProblem] = []
    raw_keys = set(fixture.raw)
    missing = sorted(_REQUIRED_TOP_KEYS - raw_keys)
    for key in missing:
        problems.append(_problem(fixture.fixture_id, "missing_top_level_key", f"missing key {key}"))
    if not fixture.fixture_id:
        problems.append(_problem(fixture.fixture_id, "missing_fixture_id", "fixture id is empty"))
    if fixture.fixture_role not in _ALLOWED_ROLES:
        problems.append(_problem(fixture.fixture_id, "invalid_fixture_role", f"role {fixture.fixture_role!r} is not allowed"))
    if fixture.fixture_role == "positive" and not fixture.expected_issue:
        problems.append(_problem(fixture.fixture_id, "positive_without_expected_issue", "positive fixture lacks expected_issue"))
    # Negative-like fixtures may retain expected_issue as target provenance for the paired
    # repair/control relation.  Detection labels are recomputed by the semantic oracle, so
    # the IR audit treats this field as provenance rather than an expected positive result.
    if not fixture.policy_family:
        problems.append(_problem(fixture.fixture_id, "missing_policy_family", "policy_family is empty"))
    if not fixture.intent.klass or not fixture.intent.claim:
        problems.append(_problem(fixture.fixture_id, "missing_intent", "intent class or claim is empty"))
    for key in _REQUIRED_CONTEXT_KEYS:
        if key not in fixture.context:
            problems.append(_problem(fixture.fixture_id, "missing_context_key", f"context lacks {key}"))
    for origin_key in ("document_origin", "resource_origin", "request_origin", "ancestor_origin", "target_origin"):
        if origin_key in fixture.context:
            value = str(fixture.context.get(origin_key, ""))
            if value and value != "*" and not _is_fixture_origin(value):
                problems.append(_problem(fixture.fixture_id, "malformed_fixture_origin", f"{origin_key} uses malformed fixture origin {value!r}"))
    for hidx, header in enumerate(fixture.headers):
        if not header.name:
            problems.append(_problem(fixture.fixture_id, "empty_header_name", f"header {hidx} name is empty"))
        if header.name and not _HEADER_NAME.match(header.name):
            problems.append(_problem(fixture.fixture_id, "malformed_header_name", f"header {hidx} has malformed name {header.name!r}"))
        if "\n" in header.value or "\r" in header.value:
            problems.append(_problem(fixture.fixture_id, "header_value_line_break", f"header {hidx} contains a line break"))
    for lidx, layer in enumerate(fixture.layers):
        if layer.op not in {"append", "set", "remove"}:
            problems.append(_problem(fixture.fixture_id, "invalid_layer_op", f"layer {lidx} op {layer.op!r} is invalid"))
        if not layer.layer:
            problems.append(_problem(fixture.fixture_id, "empty_layer_name", f"layer {lidx} name is empty"))
        if not layer.headers:
            problems.append(_problem(fixture.fixture_id, "empty_layer_headers", f"layer {lidx} carries no headers", severity="warning"))
    if not fixture.source_claim_ids:
        problems.append(_problem(fixture.fixture_id, "missing_source_claim", "fixture has no source_claim_ids"))
    if admitted_claims is not None:
        for claim_id in fixture.source_claim_ids:
            if claim_id not in admitted_claims:
                problems.append(_problem(fixture.fixture_id, "unknown_source_claim", f"source claim {claim_id!r} not admitted"))
    computed = fixture_hash(fixture.raw)
    if fixture.fixture_hash != computed:
        problems.append(_problem(fixture.fixture_id, "fixture_hash_mismatch", f"stored {fixture.fixture_hash!r}, computed {computed!r}"))
    return problems


def profile_corpus(fixtures: Sequence[FixtureIR], admitted_claims: Optional[set[str]] = None) -> CorpusProfile:
    """Return aggregate corpus profile and schema problems."""
    problems: List[SchemaProblem] = []
    ids = [f.fixture_id for f in fixtures]
    hashes = [f.fixture_hash for f in fixtures]
    id_counts = Counter(ids)
    hash_counts = Counter(hashes)
    for f in fixtures:
        problems.extend(validate_fixture(f, admitted_claims=admitted_claims))
    all_claims = {c for f in fixtures for c in f.source_claim_ids}
    orphan_claims = tuple(sorted(all_claims - admitted_claims)) if admitted_claims is not None else tuple()
    effective_header_counts = [len(f.effective_headers()[0]) for f in fixtures]
    return CorpusProfile(
        fixtures=len(fixtures),
        positives=sum(1 for f in fixtures if f.fixture_role == "positive"),
        negative_controls=sum(1 for f in fixtures if f.fixture_role in _NEGATIVE_LIKE_ROLES),
        source_claims=len(all_claims),
        intent_classes=len({f.intent.klass for f in fixtures}),
        policy_families=len({f.policy_family for f in fixtures}),
        header_fields=sum(len(f.headers) for f in fixtures),
        layered_fixtures=sum(1 for f in fixtures if f.layers),
        max_effective_headers=max(effective_header_counts or [0]),
        max_layers=max((len(f.layers) for f in fixtures), default=0),
        duplicate_fixture_ids=tuple(sorted(k for k, v in id_counts.items() if v > 1)),
        duplicate_hashes=tuple(sorted(k for k, v in hash_counts.items() if v > 1)),
        orphan_source_claims=orphan_claims,
        problems=tuple(problems),
    )


def claim_ids_from_csv(path: Path) -> set[str]:
    return {row.get("claim_id", "") for row in load_csv(path) if row.get("claim_id")}


def issue_signature(findings: Iterable[Mapping[str, Any]]) -> Tuple[str, ...]:
    """Return a deterministic issue signature for an analyzer result."""
    return tuple(sorted(str(f.get("issue", "")) for f in findings if f.get("issue")))


def source_claim_distribution(fixtures: Sequence[FixtureIR]) -> Dict[str, int]:
    counts: Counter[str] = Counter()
    for fixture in fixtures:
        counts.update(fixture.source_claim_ids)
    return dict(sorted(counts.items()))


def intent_distribution(fixtures: Sequence[FixtureIR]) -> Dict[str, int]:
    return dict(sorted(Counter(f.intent.klass for f in fixtures).items()))


def policy_distribution(fixtures: Sequence[FixtureIR]) -> Dict[str, int]:
    return dict(sorted(Counter(f.policy_family for f in fixtures).items()))


def header_distribution(fixtures: Sequence[FixtureIR]) -> Dict[str, int]:
    counter: Counter[str] = Counter()
    for fixture in fixtures:
        headers, _ = fixture.effective_headers()
        counter.update(canonical_header_name(h.get("name", "")) for h in headers)
    return dict(sorted(counter.items()))


def stable_profile_report(fixtures: Sequence[FixtureIR], admitted_claims: Optional[set[str]] = None) -> Dict[str, Any]:
    """Build a evidence-facing BEP-IR profile report."""
    profile = profile_corpus(fixtures, admitted_claims=admitted_claims)
    return {
        "status": "pass" if not profile.problems and not profile.duplicate_fixture_ids and not profile.duplicate_hashes and not profile.orphan_source_claims else "fail",
        "profile": profile.as_dict(),
        "intent_distribution": intent_distribution(fixtures),
        "policy_distribution": policy_distribution(fixtures),
        "header_distribution": header_distribution(fixtures),
        "source_claim_distribution": source_claim_distribution(fixtures),
        "interpretation": "Typed BEP-IR schema and corpus-profile audit. It validates released fixture structure and hash closure without changing the locked denominator or labels.",
    }
