#!/usr/bin/env python3
"""Run anti-overfitting leakage checks over method code and benchmark surfaces."""
from __future__ import annotations
import json
import sys
sys.dont_write_bytecode = True

from common_paths import package_root

ROOT = package_root(__file__)
if str(ROOT / "artifact") not in sys.path:
    sys.path.insert(0, str(ROOT / "artifact"))

from bepguard.leakage import audit, write_json  # noqa: E402


def main() -> None:
    result = audit(ROOT)
    write_json(ROOT / "artifact" / "results" / "anti_overfit_leakage_audit.json", result)
    print(json.dumps({"status": result["status"], "problem_count": result["problem_count"], "method_files_scanned": result["method_files_scanned"]}, sort_keys=True))
    if result["status"] != "pass":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
