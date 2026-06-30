#!/usr/bin/env python3
"""Audit rule-to-source/evidence trace matrix."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
sys.dont_write_bytecode = True
from common_paths import package_root


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=None)
    ap.add_argument("--rows-out", default="artifact/results/rule_trace_matrix_rows.csv")
    ap.add_argument("--out", default="artifact/results/rule_trace_matrix_audit.json")
    args = ap.parse_args()
    root = Path(args.root).resolve() if args.root else package_root(__file__)
    sys.path.insert(0, str(root / "artifact"))
    from bepguard.rule_trace_matrix import audit_rule_trace_matrix, write_csv, write_json
    rows, summary = audit_rule_trace_matrix(root)
    write_csv(root / args.rows_out, rows)
    write_json(root / args.out, summary)
    print(json.dumps({"status": summary["status"], "problem_count": summary["problem_count"], "rules_checked": summary["rules_checked"]}, sort_keys=True))
    if summary["status"] != "pass":
        raise SystemExit(2)

if __name__ == "__main__":
    main()
