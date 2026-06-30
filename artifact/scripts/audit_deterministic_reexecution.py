#!/usr/bin/env python3
"""Execute selected inspection-facing gates twice and compare output digests."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
sys.dont_write_bytecode = True
from common_paths import package_root


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=None)
    ap.add_argument("--rows-out", default="artifact/results/deterministic_reexecution_rows.csv")
    ap.add_argument("--out", default="artifact/results/deterministic_reexecution_audit.json")
    args = ap.parse_args()
    root = Path(args.root).resolve() if args.root else package_root(__file__)
    sys.path.insert(0, str(root / "artifact"))
    from bepguard.deterministic_reexecution import run_deterministic_reexecution_audit, write_csv, write_json
    rows, summary = run_deterministic_reexecution_audit(root)
    write_csv(root / args.rows_out, rows)
    write_json(root / args.out, summary)
    print(json.dumps({"status": summary["status"], "problem_count": summary["problem_count"], "commands_reexecuted": summary["commands_reexecuted"], "total_subprocess_runs": summary["total_subprocess_runs"]}, sort_keys=True))
    if summary["status"] != "pass":
        raise SystemExit(2)

if __name__ == "__main__":
    main()
