#!/usr/bin/env python3
"""Audit external benchmark and baseline adapter contracts."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from common_paths import package_root


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit external package pins, baseline statuses, and no-substitution contracts.")
    parser.add_argument("--root", default=None)
    parser.add_argument("--out", default="artifact/results/external_benchmark_contract_audit.json")
    args = parser.parse_args()
    root = Path(args.root).resolve() if args.root else package_root(__file__)
    if str(root / "artifact") not in sys.path:
        sys.path.insert(0, str(root / "artifact"))
    from bepguard.external import audit_all, write_json

    result = audit_all(root)
    write_json(root / args.out, result)
    print(json.dumps({"status": result["status"], "problem_count": result["problem_count"]}, sort_keys=True))
    if result["status"] != "pass":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
