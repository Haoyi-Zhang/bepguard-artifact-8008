#!/usr/bin/env python3
"""Run finite decision-lattice proof obligations for BEP-IR fragments."""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from common_paths import package_root


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify finite decision-lattice proof obligations.")
    parser.add_argument("--root", default=None)
    parser.add_argument("--out", default="artifact/results/deep_locked/semantic_lattice_proofs.json")
    parser.add_argument("--cases", default="artifact/results/deep_locked/semantic_lattice_proof_cases.csv")
    args = parser.parse_args()
    root = Path(args.root).resolve() if args.root else package_root(__file__)
    if str(root / "artifact") not in sys.path:
        sys.path.insert(0, str(root / "artifact"))
    from bepguard.lattice import prove_all_contracts, summarize_cases

    cases = prove_all_contracts()
    result = summarize_cases(cases)
    out = root / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    csv_path = root / args.cases
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        fieldnames = ["contract", "state_id", "premise", "conclusion", "passed", "witness"]
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for case in cases:
            row = case.as_dict()
            row["witness"] = json.dumps(row["witness"], sort_keys=True)
            writer.writerow(row)
    print(json.dumps({"status": result["status"], "contracts": result["contracts"], "states_checked": result["states_checked"], "failures": result["failures"]}, sort_keys=True))
    if result["status"] != "pass":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
