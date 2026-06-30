"""Support functions for generated oracle tests without pytest dependency."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping, Tuple

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

from bepguard.generated_oracles import CERTIFICATE_ORACLE, LOCKED_FIXTURE_ORACLE, expected_issues
import bep_semantics  # type: ignore

_FIXTURES = None
_FIXTURE_INDEX = None


def load_fixtures() -> list[dict[str, Any]]:
    """Load released BEP-Deep fixtures once for generated tests."""
    global _FIXTURES
    if _FIXTURES is None:
        _FIXTURES = json.loads((ROOT / "data" / "deep_locked_fixtures.json").read_text(encoding="utf-8"))
    return _FIXTURES


def fixture_index() -> dict[str, Mapping[str, Any]]:
    """Return released fixtures keyed by id."""
    global _FIXTURE_INDEX
    if _FIXTURE_INDEX is None:
        _FIXTURE_INDEX = {str(f.get("id", "")): f for f in load_fixtures()}
    return _FIXTURE_INDEX


def issue_signature(findings: Iterable[Any]) -> Tuple[str, ...]:
    """Return sorted issue signature from BEP semantic findings."""
    issues = []
    for finding in findings:
        if hasattr(finding, "issue"):
            issues.append(str(getattr(finding, "issue")))
        elif isinstance(finding, Mapping):
            issues.append(str(finding.get("issue", "")))
    return tuple(sorted(i for i in issues if i))


def assert_fixture_issues(fixture_id: str) -> None:
    """Assert operational oracle agrees with the generated static fixture oracle."""
    fixture = fixture_index()[fixture_id]
    actual = issue_signature(bep_semantics.analyze_fixture(dict(fixture)))
    expected = expected_issues(fixture_id)
    assert actual == expected, f"{fixture_id}: expected {expected}, got {actual}"


def assert_certificate_target(certificate_id: str) -> None:
    """Assert a generated certificate oracle row points to a recomputed target."""
    row = CERTIFICATE_ORACLE[certificate_id]
    fixture_id = str(row["fixture_id"])
    issue = str(row["issue"])
    assert issue in expected_issues(fixture_id), f"{certificate_id}: target issue {issue} absent from static fixture oracle"
    assert fixture_id in fixture_index(), f"{certificate_id}: missing fixture {fixture_id}"
    assert row["rule_ids"], f"{certificate_id}: missing rule ids"
    assert row["source_claim_ids"], f"{certificate_id}: missing source claim ids"
