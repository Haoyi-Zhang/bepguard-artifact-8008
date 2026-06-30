#!/usr/bin/env python3
"""Audit admitted-claim impact across source spans, fixtures, SpecBench, evidence cards, and repairs."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
sys.dont_write_bytecode = True
from common_paths import package_root


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=None)
    ap.add_argument("--out", default="artifact/results/claim_impact_audit.json")
    ap.add_argument("--matrix-out", default="artifact/results/deep_locked/claim_impact_matrix.csv")
    args = ap.parse_args()
    root = Path(args.root).resolve() if args.root else package_root(__file__)
    sys.path.insert(0, str(root / "artifact"))
    from bepguard.claim_impact import build_claim_impact_matrix, write_json, write_matrix
    rows, summary = build_claim_impact_matrix(root)
    write_matrix(root / args.matrix_out, rows)
    write_json(root / args.out, summary)
    print(json.dumps({"status": summary["status"], "problem_count": summary["problem_count"], "claims_checked": summary["claims_checked"]}, sort_keys=True))
    if summary["status"] != "pass":
        raise SystemExit(2)

if __name__ == "__main__":
    main()
