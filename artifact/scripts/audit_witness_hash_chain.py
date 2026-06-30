#!/usr/bin/env python3
"""Audit canonical hash-chain closure for positive witnesses."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
sys.dont_write_bytecode = True
from common_paths import package_root


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=None)
    ap.add_argument("--out", default="artifact/results/witness_hash_chain_audit.json")
    ap.add_argument("--chain-out", default="artifact/results/deep_locked/witness_hash_chains.csv")
    args = ap.parse_args()
    root = Path(args.root).resolve() if args.root else package_root(__file__)
    sys.path.insert(0, str(root / "artifact"))
    from bepguard.witness_hash_chain import build_witness_hash_chain, write_json, write_rows
    rows, summary = build_witness_hash_chain(root)
    write_rows(root / args.chain_out, rows)
    write_json(root / args.out, summary)
    print(json.dumps({"status": summary["status"], "problem_count": summary["problem_count"], "positive_witness_chains": summary["positive_witness_chains"]}, sort_keys=True))
    if summary["status"] != "pass":
        raise SystemExit(2)

if __name__ == "__main__":
    main()
