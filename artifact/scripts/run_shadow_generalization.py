#!/usr/bin/env python3
"""Run the BEP-Shadow generalization and representation-invariance audit."""
from __future__ import annotations
import argparse, csv, json, sys
from pathlib import Path
sys.dont_write_bytecode = True
from common_paths import package_root


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=None)
    parser.add_argument("--rows-out", default="artifact/results/deep_locked/shadow_generalization_rows.csv")
    parser.add_argument("--summary-out", default="artifact/results/deep_locked/shadow_generalization_audit.json")
    args = parser.parse_args()
    root = Path(args.root).resolve() if args.root else package_root(__file__)
    if str(root / "artifact") not in sys.path:
        sys.path.insert(0, str(root / "artifact"))
    from bepguard.shadow import run_shadow_audit, write_json
    rows, summary = run_shadow_audit(root)
    out = root / args.rows_out
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        fieldnames = ["shadow_id", "source_fixture_fingerprint", "transform", "role", "expected_issues", "actual_issues", "preserved", "optional", "note"]
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            data = row.as_dict()
            data["expected_issues"] = ";".join(data["expected_issues"])
            data["actual_issues"] = ";".join(data["actual_issues"])
            writer.writerow(data)
    write_json(root / args.summary_out, summary)
    print(json.dumps({"status": summary["status"], "problem_count": summary["problem_count"], "required_shadow_cases": summary["required_shadow_cases"], "required_preserved": summary["required_preserved"]}, sort_keys=True))
    if summary["status"] != "pass":
        raise SystemExit(2)

if __name__ == "__main__":
    main()
