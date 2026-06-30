#!/usr/bin/env python3
"""Audit the materialized external full-baseline run."""
from __future__ import annotations
import json, sys
sys.dont_write_bytecode = True
from common_paths import package_root
ROOT = package_root(__file__)
if str(ROOT / "artifact") not in sys.path:
    sys.path.insert(0, str(ROOT / "artifact"))
from bepguard.external_full import summarize_external_full, write_json  # noqa: E402

def main() -> None:
    result = json.loads((ROOT / "artifact/results/deep_locked/external_baseline_full_run.json").read_text(encoding="utf-8"))
    audit = summarize_external_full(result)
    write_json(ROOT / "artifact/results/external_baseline_full_run_audit.json", audit)
    print(json.dumps({"status": audit["status"], "problem_count": audit["problem_count"], "rows_total": audit["rows_total"]}, sort_keys=True))
    if audit["status"] != "pass":
        raise SystemExit(2)

if __name__ == "__main__":
    main()
