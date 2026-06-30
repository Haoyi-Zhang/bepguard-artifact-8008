#!/usr/bin/env python3
"""Audit deterministic runtime boundary and transient/cache exclusions."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
sys.dont_write_bytecode = True
from common_paths import package_root


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=None)
    parser.add_argument("--out", default="artifact/results/runtime_boundary_audit.json")
    args = parser.parse_args()
    root = Path(args.root).resolve() if args.root else package_root(__file__)
    sys.path.insert(0, str(root / "artifact"))
    from bepguard.runtime_boundary import audit_runtime_boundary, write_json
    result = audit_runtime_boundary(root)
    write_json(root / args.out, result)
    print(json.dumps({"status": result["status"], "problem_count": result["problem_count"], "files_checked": result["files_checked"]}, sort_keys=True))
    if result["status"] != "pass":
        raise SystemExit(2)

if __name__ == "__main__":
    main()
