"""Proof-card audit for the finite semantic theorem kernel."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping

sys.dont_write_bytecode = True


def audit_theory_proof_cards(root: Path) -> Dict[str, Any]:
    kernel = json.loads((root / "artifact" / "results" / "deep_locked" / "theory_kernel_audit.json").read_text(encoding="utf-8"))
    problems: List[str] = []
    cards: List[Dict[str, Any]] = []
    for index, obligation in enumerate(kernel.get("obligations", []), start=1):
        name = str(obligation.get("name", ""))
        theorem = str(obligation.get("theorem", ""))
        proof_kind = str(obligation.get("proof_kind", ""))
        states = int(obligation.get("states_checked", 0) or 0)
        status = str(obligation.get("status", ""))
        card = {
            "card_id": f"PC{index:03d}",
            "obligation": name,
            "claim": theorem,
            "proof_kind": proof_kind,
            "finite_states": states,
            "auditable_replay": status == "pass" and states > 0 and len(theorem) >= 24 and bool(proof_kind),
        }
        cards.append(card)
        if not card["auditable_replay"]:
            problems.append(f"incomplete proof card for {name}")
    if len(cards) != int(kernel.get("theorems_checked", -1)):
        problems.append("proof-card count does not match theorem-kernel count")
    if sum(c["finite_states"] for c in cards) != int(kernel.get("finite_states_checked", -1)):
        problems.append("proof-card state total does not match theorem-kernel total")
    return {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "proof_cards": cards,
        "proof_cards_checked": len(cards),
        "finite_states_accounted": sum(c["finite_states"] for c in cards),
        "kernel_theorems": kernel.get("theorems_checked"),
        "kernel_states": kernel.get("finite_states_checked"),
        "interpretation": "Proof-card audit converts every finite theorem obligation into a compact auditable claim/proof-kind/state-count record and checks that the cards exactly account for the executable theorem kernel.",
    }


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
