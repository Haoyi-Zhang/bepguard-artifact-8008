#!/usr/bin/env python3
"""Independently recheck proof-carrying witness and control certificates."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from common_paths import package_root


def main() -> None:
    parser = argparse.ArgumentParser(description="Recheck witness certificates with an independent proof-obligation implementation.")
    parser.add_argument("--root", default=None)
    parser.add_argument("--out", default="artifact/results/deep_locked/certificate_recheck_audit.json")
    parser.add_argument("--cases", default="artifact/results/deep_locked/certificate_recheck_cases.csv")
    args = parser.parse_args()
    root = Path(args.root).resolve() if args.root else package_root(__file__)
    if str(root / "artifact") not in sys.path:
        sys.path.insert(0, str(root / "artifact"))
    from bepguard.proof import run_independent_recheck, summarize, write_csv, write_json

    rows = run_independent_recheck(root)
    summary = summarize(rows)
    write_csv(root / args.cases, rows)
    write_json(root / args.out, summary)
    print(json.dumps({"status": summary["status"], "obligations_checked": summary["obligations_checked"], "problem_count": summary["problem_count"]}, sort_keys=True))
    if summary["status"] != "pass":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
