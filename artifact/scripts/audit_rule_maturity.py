#!/usr/bin/env python3
"""Audit source-rule maturity and coverage closure."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
from common_paths import package_root


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit that release source rules are mature and covered.")
    parser.add_argument("--root", default=None)
    parser.add_argument("--out", default="artifact/results/rule_maturity_audit.json")
    args = parser.parse_args()
    root = Path(args.root).resolve() if args.root else package_root(__file__)
    if str(root / "artifact") not in sys.path:
        sys.path.insert(0, str(root / "artifact"))
    from bepguard.rule_closure import audit_rule_closure, write_json
    result = audit_rule_closure(root)
    write_json(root / args.out, result)
    print(json.dumps({"status": result["status"], "problem_count": result["problem_count"], "rules_checked": result["rules_checked"], "rules_with_planned_status": result["rules_with_planned_status"]}, sort_keys=True))
    if result["status"] != "pass":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
