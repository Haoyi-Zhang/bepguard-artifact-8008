#!/usr/bin/env python3
"""Audit AST-level purity of core decision functions."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
sys.dont_write_bytecode = True
from common_paths import package_root


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=None)
    ap.add_argument("--out", default="artifact/results/decision_purity_audit.json")
    args = ap.parse_args()
    root = Path(args.root).resolve() if args.root else package_root(__file__)
    sys.path.insert(0, str(root / "artifact"))
    from bepguard.decision_purity import audit_decision_purity, write_json
    result = audit_decision_purity(root)
    write_json(root / args.out, result)
    print(json.dumps({"status": result["status"], "problem_count": result["problem_count"], "pure_decision_functions_checked": result["pure_decision_functions_checked"]}, sort_keys=True))
    if result["status"] != "pass":
        raise SystemExit(2)

if __name__ == "__main__":
    main()
