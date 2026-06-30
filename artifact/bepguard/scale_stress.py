"""Deterministic CPU-native scale-stress replay for BEPGuard."""
from __future__ import annotations

import copy
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Tuple

sys.dont_write_bytecode = True


def _import_semantics(root: Path):
    scripts = root / "artifact" / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import bep_semantics  # type: ignore
    return bep_semantics


def _issue_signature(findings: Iterable[Any]) -> Tuple[str, ...]:
    issues: List[str] = []
    for finding in findings:
        if hasattr(finding, "issue"):
            issues.append(str(getattr(finding, "issue")))
        elif isinstance(finding, Mapping):
            issues.append(str(finding.get("issue", "")))
    return tuple(sorted(i for i in issues if i))


def _expected(fixture: Mapping[str, Any]) -> Tuple[str, ...]:
    issue = str(fixture.get("expected_issue", "none"))
    return tuple() if issue == "none" else (issue,)


def _variant(fixture: Mapping[str, Any], i: int) -> Dict[str, Any]:
    out = copy.deepcopy(dict(fixture))
    headers = out.get("headers", [])
    if isinstance(headers, list):
        if i % 2 == 0:
            headers = list(reversed(headers))
        if i % 3 == 0:
            headers = list(headers) + [{"name": "X-Scale-Stress", "value": str(i)}]
        if i % 5 == 0:
            for header in headers:
                if isinstance(header, dict):
                    header["name"] = str(header.get("name", "")).lower()
        out["headers"] = headers
    ctx = dict(out.get("context", {})) if isinstance(out.get("context", {}), dict) else {}
    ctx[f"scale_noise_{i % 7}"] = f"noop-{i}"
    out["context"] = ctx
    digest = hashlib.sha256(json.dumps(out, sort_keys=True).encode("utf-8")).hexdigest()[:12]
    out["id"] = f"SCALE_{i:02d}_{digest}"
    out["variant"] = f"scale-stress-{i:02d}"
    return out


def run_scale_stress(root: Path, multiplier: int = 50) -> Dict[str, Any]:
    sem = _import_semantics(root)
    fixtures = json.loads((root / "artifact" / "data" / "deep_locked_fixtures.json").read_text(encoding="utf-8"))
    problems: List[Dict[str, Any]] = []
    roles = Counter()
    total = 0
    for fixture in fixtures:
        expected = _expected(fixture)
        roles[str(fixture.get("fixture_role", ""))] += multiplier
        for i in range(multiplier):
            total += 1
            test = _variant(fixture, i)
            actual = _issue_signature(sem.analyze_fixture(test))
            if actual != expected:
                problems.append({
                    "source_fingerprint": hashlib.sha256(json.dumps(fixture, sort_keys=True).encode("utf-8")).hexdigest()[:16],
                    "variant": i,
                    "expected": list(expected),
                    "actual": list(actual),
                })
                if len(problems) >= 25:
                    break
        if problems:
            break
    return {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "base_fixtures": len(fixtures),
        "multiplier": multiplier,
        "stress_cases": total if not problems else total,
        "expected_stress_cases": len(fixtures) * multiplier,
        "roles": dict(sorted(roles.items())),
        "interpretation": "CPU-native scale-stress replay applies deterministic representation-preserving variants to every BEP-Deep fixture and re-executes the semantic oracle. It records count closure, not wall-clock measurements, to keep the release deterministic.",
    }


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
