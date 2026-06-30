#!/usr/bin/env python3
"""Audit evidence depth for every issue class."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
sys.dont_write_bytecode = True
from common_paths import package_root


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=None)
    ap.add_argument("--rows-out", default="artifact/results/deep_locked/issue_evidence_depth_rows.csv")
    ap.add_argument("--out", default="artifact/results/deep_locked/issue_evidence_depth_audit.json")
    args = ap.parse_args()
    root = Path(args.root).resolve() if args.root else package_root(__file__)
    sys.path.insert(0, str(root / "artifact"))
    from bepguard.issue_evidence_depth import audit_issue_evidence_depth, write_csv, write_json
    rows, summary = audit_issue_evidence_depth(root)
    write_csv(root / args.rows_out, rows)
    write_json(root / args.out, summary)
    print(json.dumps({"status": summary["status"], "problem_count": summary["problem_count"], "issue_classes": summary["issue_classes_checked"]}, sort_keys=True))
    if summary["status"] != "pass":
        raise SystemExit(2)

if __name__ == "__main__":
    main()
