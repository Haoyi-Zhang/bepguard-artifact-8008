#!/usr/bin/env python3
"""Materialize and audit evidence-facing evidence cards."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
sys.dont_write_bytecode = True
from common_paths import package_root


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=None)
    ap.add_argument("--cards-out", default="artifact/results/deep_locked/evidence_cards.json")
    ap.add_argument("--out", default="artifact/results/evidence_cards_audit.json")
    args = ap.parse_args()
    root = Path(args.root).resolve() if args.root else package_root(__file__)
    sys.path.insert(0, str(root / "artifact"))
    from bepguard.evidence_cards import build_evidence_cards, write_json
    cards, summary = build_evidence_cards(root)
    write_json(root / args.cards_out, cards)
    write_json(root / args.out, summary)
    print(json.dumps({"status": summary["status"], "problem_count": summary["problem_count"], "evidence_cards": summary["evidence_cards"]}, sort_keys=True))
    if summary["status"] != "pass":
        raise SystemExit(2)

if __name__ == "__main__":
    main()
