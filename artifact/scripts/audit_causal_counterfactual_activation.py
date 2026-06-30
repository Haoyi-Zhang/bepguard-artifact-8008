#!/usr/bin/env python3
"""Run causal counterfactual activation over clean BEP-Deep controls."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
sys.dont_write_bytecode = True
from common_paths import package_root


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=None)
    parser.add_argument("--rows-out", default="artifact/results/deep_locked/causal_counterfactual_activation_rows.csv")
    parser.add_argument("--out", default="artifact/results/deep_locked/causal_counterfactual_activation_audit.json")
    args = parser.parse_args()
    root = Path(args.root).resolve() if args.root else package_root(__file__)
    sys.path.insert(0, str(root / "artifact"))
    from bepguard.causal_counterfactual import run_causal_activation_audit, write_csv, write_json
    rows, summary = run_causal_activation_audit(root)
    write_csv(root / args.rows_out, rows)
    write_json(root / args.out, summary)
    print(json.dumps({"status": summary["status"], "problem_count": summary["problem_count"], "required_activations": summary["required_activations"]}, sort_keys=True))
    if summary["status"] != "pass":
        raise SystemExit(2)

if __name__ == "__main__":
    main()
