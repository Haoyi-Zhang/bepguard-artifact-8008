"""Canonical witness hash-chain audit.

The audit binds each positive witness to its proof certificate, paired repair,
evidence card, and source/rule identifiers using a deterministic SHA-256 chain.
It is not a cryptographic proof of truth; it is a tamper-evident provenance
check over the release objects that a assessor can recompute offline.
"""
from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha(obj: Any) -> str:
    return hashlib.sha256(_canon(obj).encode("utf-8")).hexdigest()


def _write_csv(path: Path, rows: Iterable[Dict[str, Any]], fields: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fields})


def build_witness_hash_chain(root: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    fixtures = {str(f.get("id", "")): f for f in _load_json(root / "artifact/data/deep_locked_fixtures.json")}
    certs = {str(c.get("fixture_id", "")): c for c in _load_json(root / "artifact/results/deep_locked/proof_carrying_witness_certificates.json")}
    repairs = {str(r.get("paired_positive_fixture_id", "")): r for r in _load_json(root / "artifact/data/paired_repair_controls.json")}
    cards = {str(c.get("fixture_id", "")): c for c in _load_json(root / "artifact/results/deep_locked/evidence_cards.json")}
    witnesses = {str(w.get("fixture_id", "")): w for w in _load_json(root / "artifact/results/deep_locked/full_witnesses.json")}

    problems: List[str] = []
    rows: List[Dict[str, Any]] = []
    positive_ids = sorted(fid for fid, fx in fixtures.items() if fx.get("fixture_role") == "positive")
    for fid in positive_ids:
        fx = fixtures.get(fid)
        cert = certs.get(fid)
        repair = repairs.get(fid)
        card = cards.get(fid)
        witness = witnesses.get(fid)
        missing = [name for name, obj in [("fixture", fx), ("certificate", cert), ("repair", repair), ("evidence_card", card), ("witness", witness)] if obj is None]
        if missing:
            problems.append(f"{fid}: missing {missing}")
            continue
        source_ids = tuple(str(x) for x in cert.get("source_claim_ids", []))
        rule_ids = tuple(str(x) for x in cert.get("rule_ids", []))
        if tuple(str(x) for x in card.get("source_claim_ids", [])) != source_ids:
            problems.append(f"{fid}: card/certificate source claim mismatch")
        if tuple(str(x) for x in card.get("rule_ids", [])) != rule_ids:
            problems.append(f"{fid}: card/certificate rule mismatch")
        if str(repair.get("expected_issue")) != "none":
            problems.append(f"{fid}: paired repair not clean")
        chain_obj = {
            "fixture": fx,
            "witness": witness,
            "certificate": cert,
            "repair": repair,
            "evidence_card": card,
            "source_claim_ids": source_ids,
            "rule_ids": rule_ids,
        }
        rows.append({
            "fixture_id": fid,
            "certificate_id": cert.get("certificate_id", ""),
            "paired_repair_control_id": repair.get("id", ""),
            "source_claim_ids": ";".join(source_ids),
            "rule_ids": ";".join(rule_ids),
            "fixture_hash": _sha(fx)[:16],
            "certificate_hash": _sha(cert)[:16],
            "repair_hash": _sha(repair)[:16],
            "evidence_card_hash": _sha(card)[:16],
            "witness_chain_hash": _sha(chain_obj),
        })
    hashes = [r["witness_chain_hash"] for r in rows]
    duplicate_hashes = sorted({h for h in hashes if hashes.count(h) > 1})
    if duplicate_hashes:
        problems.append(f"duplicate witness-chain hashes: {duplicate_hashes[:5]}")
    summary = {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems[:80],
        "positive_witness_chains": len(rows),
        "unique_chain_hashes": len(set(hashes)),
        "expected_positive_witness_chains": 418,
        "chains_with_certificate": sum(1 for r in rows if r["certificate_id"]),
        "chains_with_paired_repair": sum(1 for r in rows if r["paired_repair_control_id"]),
        "interpretation": "Canonical hash chains bind each positive fixture to its witness, proof certificate, paired repair control, evidence card, source claims, and rule identifiers.",
    }
    return rows, summary


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_rows(path: Path, rows: List[Dict[str, Any]]) -> None:
    fields = ["fixture_id", "certificate_id", "paired_repair_control_id", "source_claim_ids", "rule_ids", "fixture_hash", "certificate_hash", "repair_hash", "evidence_card_hash", "witness_chain_hash"]
    _write_csv(path, rows, fields)
