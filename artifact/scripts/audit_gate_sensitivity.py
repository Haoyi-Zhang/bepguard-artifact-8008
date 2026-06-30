#!/usr/bin/env python3
"""Audit that critical materialized gates reject seeded in-memory failures."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
sys.dont_write_bytecode = True
from common_paths import package_root


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=None)
    ap.add_argument("--out", default="artifact/results/gate_sensitivity_audit.json")
    args = ap.parse_args()
    root = Path(args.root).resolve() if args.root else package_root(__file__)
    sys.path.insert(0, str(root / "artifact"))
    from bepguard.gate_sensitivity import audit_gate_sensitivity, write_json
    result = audit_gate_sensitivity(root)
    write_json(root / args.out, result)
    print(json.dumps({"status": result["status"], "problem_count": result["problem_count"], "seeded_failure_scenarios": result["seeded_failure_scenarios"]}, sort_keys=True))
    if result["status"] != "pass":
        raise SystemExit(2)

if __name__ == "__main__":
    main()
