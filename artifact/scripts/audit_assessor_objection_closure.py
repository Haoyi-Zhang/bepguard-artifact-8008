#!/usr/bin/env python3
"""Materialize assessor-facing independence and generalization closure audits."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from common_paths import package_root


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=None)
    args = parser.parse_args()
    root = Path(args.root).resolve() if args.root else package_root(__file__)
    if str(root / "artifact") not in sys.path:
        sys.path.insert(0, str(root / "artifact"))
    from bepguard.assessor_objection_closure import run_assessor_objection_closure

    result = run_assessor_objection_closure(root)
    print(json.dumps({"status": result["status"], "problem_count": result["problem_count"], "components": len(result["components"])}, sort_keys=True))
    if result["status"] != "pass":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
