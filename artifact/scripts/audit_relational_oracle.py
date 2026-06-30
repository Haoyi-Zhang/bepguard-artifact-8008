#!/usr/bin/env python3
"""Third-oracle audit for BEPGuard's declarative relational oracle."""
from __future__ import annotations
import argparse, csv, json, sys
from pathlib import Path
sys.dont_write_bytecode = True
from common_paths import package_root


def expected_from_fixture(fx):
    issue = str(fx.get("expected_issue", "none"))
    return tuple() if issue in {"", "none"} else (issue,)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=None)
    ap.add_argument("--rows-out", default="artifact/results/deep_locked/declarative_oracle_rows.csv")
    ap.add_argument("--out", default="artifact/results/deep_locked/declarative_oracle_audit.json")
    args = ap.parse_args()
    root = Path(args.root).resolve() if args.root else package_root(__file__)
    sys.path.insert(0, str(root / "artifact"))
    sys.path.insert(0, str(root / "artifact" / "scripts"))
    from bepguard.declarative_oracle import declarative_issues
    import bep_semantics  # type: ignore

    fixtures = json.loads((root / "artifact/data/deep_locked_fixtures.json").read_text(encoding="utf-8"))
    spec_cases = json.loads((root / "artifact/results/deep_locked/specbench_cases.json").read_text(encoding="utf-8"))
    rows = []
    problems = []
    issue_classes = set()
    for fx in fixtures:
        expected = expected_from_fixture(fx)
        declared = declarative_issues(fx)
        operational = tuple(sorted(f.issue for f in bep_semantics.analyze_fixture(fx)))
        ok = declared == expected == operational
        if not ok:
            problems.append(f"locked:{fx.get('id')}:{declared}:{expected}:{operational}")
        if expected:
            issue_classes.update(expected)
        rows.append({
            "suite": "BEP-Deep",
            "case_id": str(fx.get("id", "")),
            "expected": ";".join(expected) or "none",
            "declarative": ";".join(declared) or "none",
            "operational": ";".join(operational) or "none",
            "status": "pass" if ok else "mismatch",
        })
    for case in spec_cases:
        fx = case.get("fixture", {})
        expected = tuple(sorted(str(x) for x in case.get("expected_issues", [])))
        declared = declarative_issues(fx)
        operational = tuple(sorted(f.issue for f in bep_semantics.analyze_fixture(fx)))
        ok = declared == expected == operational
        if not ok:
            problems.append(f"specbench:{case.get('case_id')}:{declared}:{expected}:{operational}")
        rows.append({
            "suite": "BEP-SpecBench",
            "case_id": str(case.get("case_id", "")),
            "expected": ";".join(expected) or "none",
            "declarative": ";".join(declared) or "none",
            "operational": ";".join(operational) or "none",
            "status": "pass" if ok else "mismatch",
        })
    rows_path = root / args.rows_out
    rows_path.parent.mkdir(parents=True, exist_ok=True)
    with rows_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["suite", "case_id", "expected", "declarative", "operational", "status"])
        writer.writeheader(); writer.writerows(rows)
    result = {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems[:50],
        "locked_fixtures_checked": len(fixtures),
        "specbench_cases_checked": len(spec_cases),
        "cases_checked": len(rows),
        "issue_classes_checked": len(issue_classes),
        "mismatches": len(problems),
        "interpretation": "Third-oracle agreement audit: a declarative, label-free clause oracle is compared with the operational oracle and expected locked/specbench outcomes. The declarative oracle itself does not read fixture labels or identifiers.",
    }
    out = root / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "problem_count": len(problems), "cases_checked": len(rows)}, sort_keys=True))
    if problems:
        raise SystemExit(2)

if __name__ == "__main__":
    main()
