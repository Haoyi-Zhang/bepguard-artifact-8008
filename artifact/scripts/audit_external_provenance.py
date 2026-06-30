#!/usr/bin/env python3
"""Audit external comparator provenance and cache exclusion."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
sys.dont_write_bytecode = True
from common_paths import package_root


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=None)
    parser.add_argument("--out", default="artifact/results/external_provenance_audit.json")
    args = parser.parse_args()
    root = Path(args.root).resolve() if args.root else package_root(__file__)
    if str(root / "artifact") not in sys.path:
        sys.path.insert(0, str(root / "artifact"))
    from bepguard.external_provenance import audit_external_provenance, write_json
    result = audit_external_provenance(root)
    write_json(root / args.out, result)
    print(json.dumps({"status": result["status"], "problem_count": result["problem_count"], "rows_checked": result["rows_checked"], "packages_locked": result["packages_locked"]}, sort_keys=True))
    if result["status"] != "pass":
        raise SystemExit(2)

if __name__ == "__main__":
    main()
