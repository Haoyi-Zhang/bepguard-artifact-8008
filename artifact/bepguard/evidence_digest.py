"""Canonical digest audit for claim, witness, repair, and reference evidence."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List

INPUTS = [
    "artifact/results/deep_locked/source_claim_trace_audit.json",
    "artifact/results/deep_locked/evidence_cards.json",
    "artifact/results/deep_locked/repair_compactness_audit.json",
    "artifact/results/evidence_graph_metrics.json",
    "artifact/reference_ledger.csv",
    "paper/references.bib",
]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_evidence_digest(root: Path) -> Dict[str, Any]:
    problems: List[str] = []
    items: List[Dict[str, Any]] = []
    h = hashlib.sha256()
    for rel in INPUTS:
        path = root / rel
        if not path.exists():
            problems.append(f"missing digest input: {rel}")
            continue
        digest = _sha256(path)
        h.update(rel.encode("utf-8") + b"\0" + digest.encode("ascii") + b"\0")
        items.append({"path": rel, "sha256": digest, "bytes": path.stat().st_size})
    # Light semantic count checks bind the digest to the expected evidence objects.
    claim = json.loads((root / "artifact/results/deep_locked/source_claim_trace_audit.json").read_text(encoding="utf-8")) if (root / "artifact/results/deep_locked/source_claim_trace_audit.json").exists() else {}
    cards = json.loads((root / "artifact/results/deep_locked/evidence_cards.json").read_text(encoding="utf-8")) if (root / "artifact/results/deep_locked/evidence_cards.json").exists() else []
    repair = json.loads((root / "artifact/results/deep_locked/repair_compactness_audit.json").read_text(encoding="utf-8")) if (root / "artifact/results/deep_locked/repair_compactness_audit.json").exists() else {}
    if claim.get("claim_cards") != 45:
        problems.append("claim trace card count mismatch")
    if not isinstance(cards, list) or len(cards) != 418:
        problems.append("evidence card count mismatch")
    if repair.get("repair_pairs_checked") != 418:
        problems.append("repair compactness pair count mismatch")
    return {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "digest_inputs": len(items),
        "release_evidence_digest": h.hexdigest(),
        "claim_cards": claim.get("claim_cards"),
        "evidence_cards": len(cards) if isinstance(cards, list) else 0,
        "repair_pairs": repair.get("repair_pairs_checked"),
        "items": items,
        "interpretation": "Provides a stable digest over the core source-claim, evidence-card, repair, graph, and reference surfaces so late-stage edits cannot silently drift the evidence pack.",
    }


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
