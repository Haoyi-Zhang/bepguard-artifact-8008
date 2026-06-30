#!/usr/bin/env python3
"""Run the BEPGuard semantic mutation farm."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
from common_paths import package_root


def main() -> None:
    parser = argparse.ArgumentParser(description="Run large obligation-level semantic mutation farm.")
    parser.add_argument("--root", default=None)
    parser.add_argument("--rows-out", default="artifact/results/deep_locked/mutation_farm_cases.csv")
    parser.add_argument("--summary-out", default="artifact/results/deep_locked/mutation_farm_summary.json")
    args = parser.parse_args()
    root = Path(args.root).resolve() if args.root else package_root(__file__)
    if str(root / "artifact") not in sys.path:
        sys.path.insert(0, str(root / "artifact"))
    from bepguard.mutation_farm import run_mutation_farm, write_csv, write_json
    rows, summary = run_mutation_farm(root)
    write_csv(root / args.rows_out, rows)
    write_json(root / args.summary_out, summary)
    print(json.dumps({"status": summary["status"], "mutants": summary["mutants"], "killed_mutants": summary["killed_mutants"], "problem_count": summary["problem_count"]}, sort_keys=True))
    if summary["status"] != "pass":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
