#!/usr/bin/env python3
"""Entry point for static code-health auditing of the release artifact."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
sys.dont_write_bytecode = True
from common_paths import package_root


def main() -> None:
    ap = argparse.ArgumentParser(description="Audit static code health for the release artifact.")
    ap.add_argument("--root", default=None)
    ap.add_argument("--out", default="artifact/results/static_code_health_audit.json")
    args = ap.parse_args()
    root = Path(args.root).resolve() if args.root else package_root(__file__)
    sys.path.insert(0, str(root / "artifact"))
    from bepguard.static_health import audit_static_code_health, write_json
    result = audit_static_code_health(root)
    write_json(root / args.out, result)
    print(json.dumps({"status": result["status"], "problem_count": result["problem_count"], "python_files_checked": result["python_files_checked"]}, sort_keys=True))
    if result["status"] != "pass":
        raise SystemExit(2)
if __name__ == "__main__":
    main()
