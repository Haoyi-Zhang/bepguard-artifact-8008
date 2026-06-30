#!/usr/bin/env python3
"""Generate and verify the BEP-SpecBench boundary workload."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from common_paths import package_root


def main() -> None:
    parser = argparse.ArgumentParser(description="Run source-derived BEP-SpecBench cases outside the locked denominator.")
    parser.add_argument("--root", default=None)
    parser.add_argument("--cases-out", default="artifact/results/deep_locked/specbench_cases.json")
    parser.add_argument("--results-out", default="artifact/results/deep_locked/specbench_results.csv")
    parser.add_argument("--summary-out", default="artifact/results/deep_locked/specbench_summary.json")
    args = parser.parse_args()
    root = Path(args.root).resolve() if args.root else package_root(__file__)
    if str(root / "artifact") not in sys.path:
        sys.path.insert(0, str(root / "artifact"))
    from bepguard.specbench import run_specbench, summarize, write_json, write_results_csv

    cases, results = run_specbench(root)
    summary = summarize(cases, results)
    write_json(root / args.cases_out, [case.as_dict() for case in cases])
    write_results_csv(root / args.results_out, results)
    write_json(root / args.summary_out, summary)
    print(json.dumps({"status": summary["status"], "cases": summary["cases"], "rules_covered": summary["rules_covered"], "problem_count": summary["problem_count"]}, sort_keys=True))
    if summary["status"] != "pass":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
