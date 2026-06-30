#!/usr/bin/env python3
"""Run deterministic BEP-Scale stress replay."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
sys.dont_write_bytecode = True
from common_paths import package_root


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=None)
    parser.add_argument("--multiplier", type=int, default=50)
    parser.add_argument("--out", default="artifact/results/deep_locked/scale_stress_audit.json")
    args = parser.parse_args()
    root = Path(args.root).resolve() if args.root else package_root(__file__)
    if str(root / "artifact") not in sys.path:
        sys.path.insert(0, str(root / "artifact"))
    from bepguard.scale_stress import run_scale_stress, write_json
    result = run_scale_stress(root, multiplier=args.multiplier)
    write_json(root / args.out, result)
    print(json.dumps({"status": result["status"], "problem_count": result["problem_count"], "stress_cases": result["stress_cases"]}, sort_keys=True))
    if result["status"] != "pass":
        raise SystemExit(2)

if __name__ == "__main__":
    main()
