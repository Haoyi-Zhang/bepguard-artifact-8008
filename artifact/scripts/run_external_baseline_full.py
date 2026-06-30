#!/usr/bin/env python3
"""Run public external comparator packages over BEP-Deep fixtures."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
sys.dont_write_bytecode = True
from common_paths import package_root
ROOT = package_root(__file__)
if str(ROOT / "artifact") not in sys.path:
    sys.path.insert(0, str(ROOT / "artifact"))
from bepguard.external_full import run_external_full, summarize_external_full, write_json  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--node-workdir", required=True, help="directory containing node_modules with pinned public comparator packages")
    ap.add_argument("--fixtures", default="artifact/data/deep_locked_fixtures.json")
    ap.add_argument("--out", default="artifact/results/deep_locked/external_baseline_full_run.json")
    ap.add_argument("--audit-out", default="artifact/results/external_baseline_full_run_audit.json")
    args = ap.parse_args()
    result = run_external_full(ROOT, ROOT / args.fixtures, ROOT / args.out, Path(args.node_workdir))
    audit = summarize_external_full(result)
    write_json(ROOT / args.audit_out, audit)
    # Also make the evidence graph consume the real full fixture probe.
    write_json(ROOT / "artifact/results/deep_locked/external_baseline_fixture_probe.json", {"availability": {"status": "executed"}, "results": result["rows"], "summary": result["summary"]})
    print(json.dumps({"status": audit["status"], "rows_total": audit["rows_total"], "fixtures": audit["fixtures_evaluated"]}, sort_keys=True))
    if audit["status"] != "pass":
        raise SystemExit(2)

if __name__ == "__main__":
    main()
