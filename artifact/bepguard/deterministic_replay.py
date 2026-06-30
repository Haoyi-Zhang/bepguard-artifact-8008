"""Two-pass deterministic replay audit for lightweight BEPGuard gates."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

sys.dont_write_bytecode = True


def _digest(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _stable(obj: Any) -> Any:
    """Drop large examples and retain deterministic audit-relevant fields."""
    if isinstance(obj, dict):
        return {k: _stable(v) for k, v in obj.items() if k not in {"problems", "claim_profiles", "rule_profiles", "issue_counts", "repair_operator_counts"}}
    if isinstance(obj, list):
        return [_stable(v) for v in obj]
    return obj


def run_deterministic_replay(root: Path) -> Dict[str, Any]:
    if str(root / "artifact") not in sys.path:
        sys.path.insert(0, str(root / "artifact"))
    from bepguard.corpus_stability import run_corpus_stability_audit
    from bepguard.decision_purity import audit_decision_purity
    from bepguard.documentation_consistency import audit_documentation_consistency
    from bepguard.evidence_cards import build_evidence_cards
    from bepguard.issue_evidence_depth import audit_issue_evidence_depth
    from bepguard.package_identity import audit_package_identity
    from bepguard.claim_rule_coverage import audit_claim_rule_coverage
    from bepguard.witness_repair_bijection import audit_witness_repair_bijection

    replay_units: List[Tuple[str, Any]] = [
        ("corpus_stability", lambda: run_corpus_stability_audit(root)[1]),
        ("decision_purity", lambda: audit_decision_purity(root)),
        ("documentation_consistency", lambda: audit_documentation_consistency(root)),
        ("evidence_cards", lambda: build_evidence_cards(root)[1]),
        ("issue_evidence_depth", lambda: audit_issue_evidence_depth(root)[1]),
        ("package_identity", lambda: audit_package_identity(root)),
        ("claim_rule_coverage", lambda: audit_claim_rule_coverage(root)),
        ("witness_repair_bijection", lambda: audit_witness_repair_bijection(root)),
    ]
    problems: List[str] = []
    rows: List[Dict[str, Any]] = []
    for name, fn in replay_units:
        first = _stable(fn())
        second = _stable(fn())
        h1, h2 = _digest(first), _digest(second)
        status1 = first.get("status") if isinstance(first, dict) else "unknown"
        status2 = second.get("status") if isinstance(second, dict) else "unknown"
        row = {"unit": name, "first_hash": h1, "second_hash": h2, "status_first": status1, "status_second": status2, "deterministic": h1 == h2 and status1 == "pass" and status2 == "pass"}
        rows.append(row)
        if not row["deterministic"]:
            problems.append(f"{name}: nondeterministic or non-pass replay")
    return {
        "schema": "BEPGuardTwoPassDeterministicReplay/v1",
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "replay_units": len(replay_units),
        "stable_replays": sum(1 for r in rows if r["deterministic"]),
        "rows": rows,
        "interpretation": "Recomputes selected lightweight audits twice in one process and compares canonical hashes, guarding against hidden nondeterminism in evidence-facing validation gates.",
    }


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
