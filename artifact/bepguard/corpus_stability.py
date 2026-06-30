"""Whole-corpus semantic stability checks for locked BEP fixtures.

The audit stresses whether the executable semantics depend only on policy-relevant
fields.  It replays every locked fixture under neutral representation changes
that should not affect browser-effective judgments: adding an unknown response
header, adding an unused context field, and reversing flat header order.  This
is deliberately independent of fixture identifiers and labels: labels are used
only after replay to compare the neutral variant with the original issue set.
"""
from __future__ import annotations

import csv
import copy
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

sys.dont_write_bytecode = True


def _import_semantics(root: Path):
    scripts = root / "artifact" / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import bep_semantics  # type: ignore
    return bep_semantics


def _issues(sem: Any, fixture: Dict[str, Any]) -> Tuple[str, ...]:
    return tuple(sorted(str(f.issue) for f in sem.analyze_fixture(fixture)))


def _load_fixtures(root: Path) -> List[Dict[str, Any]]:
    return json.loads((root / "artifact" / "data" / "deep_locked_fixtures.json").read_text(encoding="utf-8"))


def _neutral_variants(fixture: Dict[str, Any]) -> Iterable[Tuple[str, Dict[str, Any]]]:
    # Unknown response fields are ignored by the encoded browser-policy fragment.
    add_header = copy.deepcopy(fixture)
    headers = list(add_header.get("headers", [])) if isinstance(add_header.get("headers", []), list) else []
    headers.append({"name": "X-BEPGuard-Neutral", "value": "ignored-by-semantic-fragment"})
    add_header["headers"] = headers
    yield "unknown_header_added", add_header

    # Unused context metadata must not influence semantic decisions.
    add_context = copy.deepcopy(fixture)
    ctx = dict(add_context.get("context", {})) if isinstance(add_context.get("context", {}), dict) else {}
    ctx["bepguard_neutral_trace"] = "semantic-noop"
    add_context["context"] = ctx
    yield "unused_context_added", add_context

    # Header order is irrelevant for the encoded fragments except where duplicate
    # header presence itself matters; reversing preserves multiplicity.
    reverse_headers = copy.deepcopy(fixture)
    headers2 = list(reverse_headers.get("headers", [])) if isinstance(reverse_headers.get("headers", []), list) else []
    reverse_headers["headers"] = list(reversed(headers2))
    yield "flat_header_order_reversed", reverse_headers


def run_corpus_stability_audit(root: Path) -> Tuple[List[Dict[str, str]], Dict[str, Any]]:
    sem = _import_semantics(root)
    fixtures = _load_fixtures(root)
    rows: List[Dict[str, str]] = []
    problems: List[str] = []
    positives = 0
    controls = 0
    for fx in fixtures:
        fid = str(fx.get("id", ""))
        role = str(fx.get("fixture_role", ""))
        base = _issues(sem, fx)
        if base:
            positives += 1
        else:
            controls += 1
        for mode, variant in _neutral_variants(fx):
            replay = _issues(sem, variant)
            ok = replay == base
            if not ok:
                problems.append(f"{fid}:{mode}:{base}->{replay}")
            rows.append({
                "fixture_id": fid,
                "fixture_role": role,
                "neutral_mode": mode,
                "base_issues": ";".join(base) or "none",
                "replay_issues": ";".join(replay) or "none",
                "status": "preserved" if ok else "changed",
            })
    summary = {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems[:50],
        "locked_fixtures_checked": len(fixtures),
        "positive_fixtures_checked": positives,
        "negative_controls_checked": controls,
        "neutral_modes": 3,
        "neutral_replays": len(rows),
        "preserved_replays": sum(1 for r in rows if r["status"] == "preserved"),
        "interpretation": "Every locked fixture was replayed under three policy-irrelevant representation perturbations.  The gate guards against accidental dependence on irrelevant headers, unused context metadata, or flat header ordering.",
    }
    return rows, summary


def write_csv(path: Path, rows: List[Dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["fixture_id", "fixture_role", "neutral_mode", "base_issues", "replay_issues", "status"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader(); writer.writerows(rows)


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
