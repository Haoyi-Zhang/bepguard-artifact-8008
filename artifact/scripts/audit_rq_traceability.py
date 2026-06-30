#!/usr/bin/env python3
"""Entry point for RQ-to-paper-to-artifact traceability auditing."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
sys.dont_write_bytecode = True
from common_paths import package_root


def main() -> None:
    ap = argparse.ArgumentParser(description="Audit RQ-to-paper-to-artifact traceability.")
    ap.add_argument("--root", default=None)
    ap.add_argument("--out", default="artifact/results/rq_traceability_audit.json")
    args = ap.parse_args()
    root = Path(args.root).resolve() if args.root else package_root(__file__)
    sys.path.insert(0, str(root / "artifact"))
    from bepguard.rq_traceability import audit_rq_traceability, write_json
    result = audit_rq_traceability(root)
    write_json(root / args.out, result)
    print(json.dumps({"status": result["status"], "problem_count": result["problem_count"], "rq_trace_obligations": result["rq_trace_obligations"]}, sort_keys=True))
    if result["status"] != "pass":
        raise SystemExit(2)
if __name__ == "__main__":
    main()
