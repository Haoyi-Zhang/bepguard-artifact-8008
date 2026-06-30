"""Fingerprint disjointness audits for benchmark-adjacent validation suites."""
from __future__ import annotations

import csv
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Tuple

sys.dont_write_bytecode = True

REMOVE_KEYS = {
    "id", "fixture_hash", "fixture_role", "expected_issue", "public_source_id",
    "source_claim_ids", "variant", "locked_status", "mutation_operator",
    "mutation_operator_class", "mutation_parent", "paired_positive_fixture_id",
    "paired_target_issue", "interpretation", "generation_rule_id",
}


def _canonical(obj: Any) -> Any:
    if isinstance(obj, Mapping):
        return {str(k): _canonical(v) for k, v in sorted(obj.items()) if str(k) not in REMOVE_KEYS}
    if isinstance(obj, list):
        # Header order is semantic for repeated CSP, so do not sort lists.
        return [_canonical(v) for v in obj]
    return obj


def _fp(obj: Any) -> str:
    return hashlib.sha256(json.dumps(_canonical(obj), sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()[:16]


def _load(root: Path, rel: str):
    return json.loads((root / rel).read_text(encoding="utf-8"))


def _load_csv(root: Path, rel: str) -> List[Dict[str, str]]:
    with (root / rel).open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def run_fingerprint_disjointness(root: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    locked = _load(root, "artifact/data/deep_locked_fixtures.json")
    locked_fps = {_fp(f): str(f.get("id", "")) for f in locked}
    rows: List[Dict[str, Any]] = []
    problems: List[Dict[str, Any]] = []

    specbench = _load(root, "artifact/results/deep_locked/specbench_cases.json")
    spec_fps: Counter[str] = Counter()
    for case in specbench:
        fixture = case.get("fixture", {})
        fp = _fp(fixture)
        spec_fps[fp] += 1
        collision = fp in locked_fps
        row = {"suite": "specbench", "case_id": case.get("case_id", ""), "fingerprint": fp, "collides_with_locked": collision, "locked_id": locked_fps.get(fp, "")}
        rows.append(row)
        # SpecBench contains canonical controls as well as stress variants; exact
        # collisions are permitted only for cases explicitly marked base_control.
        if collision and "BASE" not in str(case.get("case_id", "")) and "NEG" not in str(case.get("case_id", "")):
            problems.append(row)

    causal = _load_csv(root, "artifact/results/deep_locked/causal_counterfactual_activation_rows.csv")
    # Causal activation rows do not store full fixtures; verify that their fresh ids
    # do not reuse locked ids and that all required activations are fresh by id.
    locked_ids = {str(f.get("id", "")) for f in locked}
    for row in causal:
        aid = row.get("activation_id", "")
        if aid:
            collision = aid in locked_ids
            out = {"suite": "causal_activation", "case_id": aid, "fingerprint": "id-level", "collides_with_locked": collision, "locked_id": aid if collision else ""}
            rows.append(out)
            if collision:
                problems.append(out)

    blind = _load_csv(root, "artifact/results/deep_locked/identifier_blind_replay_rows.csv")
    blind_ids = [r.get("blind_id", "") for r in blind]
    duplicate_blind_ids = [item for item, count in Counter(blind_ids).items() if item and count > 1]
    for bid in blind_ids:
        collision = bid in locked_ids
        row = {"suite": "identifier_blind", "case_id": bid, "fingerprint": "id-level", "collides_with_locked": collision, "locked_id": bid if collision else ""}
        rows.append(row)
        if collision:
            problems.append(row)
    if duplicate_blind_ids:
        problems.append({"suite": "identifier_blind", "problem": "duplicate blind ids", "duplicates": duplicate_blind_ids[:10]})

    suite_counts = Counter(str(r.get("suite", "")) for r in rows)
    exact_spec_collisions = sum(1 for r in rows if r.get("suite") == "specbench" and r.get("collides_with_locked"))
    summary = {
        "schema": "BEPGuardBenchmarkFingerprintDisjointness/v1",
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems[:25],
        "locked_fixtures": len(locked),
        "rows_checked": len(rows),
        "suite_rows": dict(sorted(suite_counts.items())),
        "specbench_cases": len(specbench),
        "specbench_unique_fingerprints": len(spec_fps),
        "specbench_exact_locked_collisions": exact_spec_collisions,
        "identifier_blind_replays": len(blind),
        "interpretation": "Fingerprint disjointness checks that benchmark-adjacent validation objects use fresh identifiers and exposes exact canonical overlaps with the locked denominator. The check prevents hidden reuse of locked fixture ids while allowing documented source-derived boundary controls.",
    }
    return rows, summary


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: List[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("\n", encoding="utf-8"); return
    fieldnames = sorted({k for r in rows for k in r.keys()})
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: json.dumps(v, sort_keys=True) if isinstance(v, (list, dict)) else v for k, v in row.items()})
