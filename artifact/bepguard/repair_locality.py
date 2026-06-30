"""Repair locality and semantic-delta audit for paired BEP repairs.

The paired repair controls are useful only if they are local semantic repairs, not
large rewrites or label-only flips.  This audit compares every expected-positive
fixture with its paired negative control, checks protected source/intent fields,
replays both sides with the executable semantics, and records the observable
edit script over headers, generated layers, and request context.
"""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

sys.dont_write_bytecode = True


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _import_semantics(root: Path) -> Any:
    scripts = root / "artifact" / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import bep_semantics  # type: ignore
    return bep_semantics


def _canon_header(h: Dict[str, Any]) -> Tuple[str, str]:
    return (str(h.get("name", "")).strip().lower(), str(h.get("value", "")))


def _canon_layer(layer: Dict[str, Any]) -> str:
    return json.dumps(layer, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _issue_set(sem: Any, fixture: Dict[str, Any]) -> Tuple[str, ...]:
    return tuple(sorted(str(f.issue) for f in sem.analyze_fixture(fixture)))


def _multiset_delta(a: Iterable[Any], b: Iterable[Any]) -> Tuple[int, int]:
    ca = Counter(a)
    cb = Counter(b)
    removed = sum((ca - cb).values())
    added = sum((cb - ca).values())
    return removed, added


def audit_repair_locality(root: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    sem = _import_semantics(root)
    fixtures = {str(f.get("id", "")): f for f in _load_json(root / "artifact/data/deep_locked_fixtures.json")}
    repairs = _load_json(root / "artifact/data/paired_repair_controls.json")
    certs = {str(c.get("fixture_id", "")): c for c in _load_json(root / "artifact/results/deep_locked/proof_carrying_witness_certificates.json")}
    rows: List[Dict[str, Any]] = []
    problems: List[str] = []
    edit_hist = Counter()
    for repair in repairs:
        fid = str(repair.get("paired_positive_fixture_id", ""))
        original = fixtures.get(fid)
        target = str(repair.get("paired_target_issue", ""))
        if original is None:
            problems.append(f"{fid}: missing original positive fixture")
            continue
        cert = certs.get(fid)
        original_issues = _issue_set(sem, original)
        repair_issues = _issue_set(sem, repair)
        if target not in original_issues:
            problems.append(f"{fid}: target issue {target} not emitted by original {original_issues}")
        if target in repair_issues or repair_issues:
            problems.append(f"{fid}: repair is not clean: {repair_issues}")
        for field in ["policy_family", "public_source_id"]:
            if str(original.get(field, "")) != str(repair.get(field, "")):
                problems.append(f"{fid}: protected field {field} changed")
        if original.get("source_claim_ids") != repair.get("source_claim_ids"):
            problems.append(f"{fid}: source_claim_ids changed")
        if original.get("intent", {}).get("class") != repair.get("intent", {}).get("class"):
            problems.append(f"{fid}: intent class changed")
        if cert and str(cert.get("paired_repair_control_id", "")) != str(repair.get("id", "")):
            problems.append(f"{fid}: certificate points to different paired repair")
        header_removed, header_added = _multiset_delta([_canon_header(h) for h in original.get("headers", [])], [_canon_header(h) for h in repair.get("headers", [])])
        layer_removed, layer_added = _multiset_delta([_canon_layer(l) for l in original.get("layers", [])], [_canon_layer(l) for l in repair.get("layers", [])])
        ctx_keys = set(original.get("context", {})) | set(repair.get("context", {}))
        context_changes = sum(1 for k in ctx_keys if original.get("context", {}).get(k) != repair.get("context", {}).get(k))
        edit_count = header_removed + header_added + layer_removed + layer_added + context_changes
        if edit_count == 0:
            problems.append(f"{fid}: paired repair has no observable header/layer/context edit")
        if edit_count > 4:
            problems.append(f"{fid}: paired repair edit script too broad ({edit_count})")
        edit_hist[str(edit_count)] += 1
        rows.append({
            "fixture_id": fid,
            "repair_id": str(repair.get("id", "")),
            "target_issue": target,
            "original_issues": ";".join(original_issues),
            "repair_issues": ";".join(repair_issues) or "none",
            "headers_removed": header_removed,
            "headers_added": header_added,
            "layers_removed": layer_removed,
            "layers_added": layer_added,
            "context_fields_changed": context_changes,
            "edit_count": edit_count,
            "protected_source_and_intent_preserved": "yes" if not any(p.startswith(fid + ": protected") or p.startswith(fid + ": source") or p.startswith(fid + ": intent") for p in problems) else "no",
        })
    summary = {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems[:80],
        "repair_pairs_checked": len(rows),
        "repairs_clean": sum(1 for r in rows if r["repair_issues"] == "none"),
        "target_issues_removed": sum(1 for r in rows if r["target_issue"] not in str(r["repair_issues"]).split(";")),
        "protected_source_and_intent_preserved": sum(1 for r in rows if r["protected_source_and_intent_preserved"] == "yes"),
        "max_edit_count": max((int(r["edit_count"]) for r in rows), default=0),
        "mean_edit_count": round(sum(int(r["edit_count"]) for r in rows) / len(rows), 4) if rows else 0.0,
        "edit_count_histogram": dict(sorted(edit_hist.items(), key=lambda kv: int(kv[0]))),
        "interpretation": "Paired repairs are checked as local semantic deltas over headers, generated layers, and request context while preserving source claim and intent fields. Label-only or broad rewrites fail this gate.",
    }
    return rows, summary


def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    fields = ["fixture_id", "repair_id", "target_issue", "original_issues", "repair_issues", "headers_removed", "headers_added", "layers_removed", "layers_added", "context_fields_changed", "edit_count", "protected_source_and_intent_preserved"]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader(); writer.writerows(rows)


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
