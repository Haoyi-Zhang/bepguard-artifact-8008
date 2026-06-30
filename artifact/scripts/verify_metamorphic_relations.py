#!/usr/bin/env python3
"""Run metamorphic preservation and repair relations over BEP-Deep fixtures."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from common_paths import package_root


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify metamorphic relations over released BEP-Deep fixtures.")
    parser.add_argument("--root", default=None)
    parser.add_argument("--fixtures", default="artifact/data/deep_locked_fixtures.json")
    parser.add_argument("--limit-per-relation", type=int, default=None)
    parser.add_argument("--out", default="artifact/results/deep_locked/metamorphic_relation_audit.json")
    parser.add_argument("--cases", default="artifact/results/deep_locked/metamorphic_relation_cases.csv")
    args = parser.parse_args()
    root = Path(args.root).resolve() if args.root else package_root(__file__)
    if str(root / "artifact") not in sys.path:
        sys.path.insert(0, str(root / "artifact"))
    from bepguard.metamorphic import run_relations, summarize, write_csv, write_json

    fixtures = json.loads((root / args.fixtures).read_text(encoding="utf-8"))
    results = run_relations(root, fixtures, limit_per_relation=args.limit_per_relation)
    summary = summarize(results)
    write_csv(root / args.cases, results)
    write_json(root / args.out, summary)
    print(json.dumps({"status": summary["status"], "relations": summary["relations"], "checks": summary["checks"], "problem_count": summary["problem_count"]}, sort_keys=True))
    if summary["status"] != "pass":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
