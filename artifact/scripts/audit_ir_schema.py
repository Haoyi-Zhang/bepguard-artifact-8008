#!/usr/bin/env python3
"""Run the typed BEP-IR schema and corpus-profile audit."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from common_paths import package_root


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate released fixtures against the typed BEP-IR schema.")
    parser.add_argument("--root", default=None)
    parser.add_argument("--fixture-file", default="artifact/data/deep_locked_fixtures.json")
    parser.add_argument("--claims", default="artifact/data/corpus_claims.csv")
    parser.add_argument("--out", default="artifact/results/deep_locked/typed_ir_schema_audit.json")
    args = parser.parse_args()
    root = Path(args.root).resolve() if args.root else package_root(__file__)
    if str(root / "artifact") not in sys.path:
        sys.path.insert(0, str(root / "artifact"))
    from bepguard.ir import claim_ids_from_csv, load_fixtures, stable_profile_report

    fixtures = load_fixtures(root / args.fixture_file)
    claims = claim_ids_from_csv(root / args.claims)
    result = stable_profile_report(fixtures, admitted_claims=claims)
    out = root / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    profile = result.get("profile", {})
    print(json.dumps({"status": result["status"], "problem_count": profile.get("problem_count", 0), "fixtures": profile.get("fixtures")}, sort_keys=True))
    if result["status"] != "pass":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
