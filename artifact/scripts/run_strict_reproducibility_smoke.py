#!/usr/bin/env python3
"""Execute a strict deterministic smoke gate over representative BEPGuard checks."""
from __future__ import annotations
import json
import sys
sys.dont_write_bytecode = True

from common_paths import package_root

ROOT = package_root(__file__)
if str(ROOT / "artifact") not in sys.path:
    sys.path.insert(0, str(ROOT / "artifact"))

from bepguard.smoke import execute, write_json  # noqa: E402


def main() -> None:
    result = execute(ROOT)
    write_json(ROOT / "artifact" / "results" / "strict_reproducibility_smoke.json", result)
    print(json.dumps({"status": result["status"], "problem_count": result["problem_count"], "commands_executed": result["commands_executed"]}, sort_keys=True))
    if result["status"] != "pass":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
