#!/usr/bin/env python3
"""Release-language integrity audit for release artifact metadata.

The goal is to prevent pre-lock or provisional wording from surviving in the
paper delivery artifact.  It checks release-facing ledgers that assessors are likely
to inspect first.  It intentionally excludes code comments and historical
protocol amendment rationales, where words such as "candidate" may be technical.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True

import argparse, json, re
from pathlib import Path

CHECKED_FILES = [
    "artifact/source_manifest.csv",
    "artifact/external_resources.csv",
    "artifact/corpus_lock.csv",
    "artifact/coding_protocol.md",
    "artifact/baseline_wrapper_protocol.md",
    "artifact/source_snapshot_manifest.csv",
    "artifact/source_span_ledger.csv",
    "artifact/data/source_snapshot_manifest.csv",
    "artifact/data/source_acquisition_log.csv",
    "artifact/data/source_snapshot_ledger.csv",
]
# Phrases that indicate unfinished pre-lock state in release release metadata.
BAD_PATTERNS = [
    r"license to define",
    r"release terms to record",
    r"verify release",
    r"must be verified before bibliography releaseization",
    r"must pin before L",
    r"before L",
    r"needs_package_fixture",
    r"needs_release_fixture",
    r"pending_package_fixture",
    r"pending_release_fixture",
    r"accepted_evidence_source_pending_fixture",
    r"pre-lock coding protocol candidate",
    r"package pin .* pending fixture",
    r"release corpus must store",
    r"runtime experiment must pin",
    r"generated-header fixture still requires",
    r"future CORS oracle",
    r"Full corpus source candidate",
    r"release snapshot must",
    r"release source snapshot must",
    r"intent-label candidate",
    r"candidate claims",
    r"candidate version",
    r"package candidate",
]

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--out", default="artifact/results/release_language_integrity_audit.json")
    args = ap.parse_args()
    root = Path(args.root)
    problems = []
    hits = []
    compiled = [(pat, re.compile(pat, re.I)) for pat in BAD_PATTERNS]
    for rel in CHECKED_FILES:
        p = root / rel
        if not p.exists():
            continue
        text = p.read_text(encoding="utf-8", errors="ignore")
        for lineno, line in enumerate(text.splitlines(), 1):
            for pat, rx in compiled:
                if rx.search(line):
                    hits.append({"path": rel, "line": lineno, "pattern": pat, "text": line[:240]})
    if hits:
        problems.append(f"provisional release language found in {len(hits)} checked lines")

    # release release should not ship unused pre-lock plan CSVs that still carry
    # candidate status labels and are not consumed by the reproduction path.
    obsolete_plan_files = [
        "artifact/data/ablation_plan.csv",
        "artifact/data/baseline_tasks.csv",
        "artifact/data/negative_control_plan.csv",
        "artifact/data/scalability_plan.csv",
    ]
    present_plans = [rel for rel in obsolete_plan_files if (root / rel).exists()]
    if present_plans:
        problems.append(f"obsolete pre-lock plan files still packaged: {present_plans}")

    # Project-local code should have an anonymous release license.
    license_path = root / "artifact/LICENSE"
    if not license_path.exists():
        problems.append("artifact/LICENSE missing")
    else:
        lic = license_path.read_text(encoding="utf-8", errors="ignore")
        if "Anonymous Authors" not in lic or "MIT License" not in lic:
            problems.append("artifact/LICENSE is not the anonymous MIT-style release license")

    result = {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "checked_files": [rel for rel in CHECKED_FILES if (root / rel).exists()],
        "provisional_language_hits": hits,
        "interpretation": "Checks release-facing metadata for unfinished pre-lock/candidate language and obsolete plan files. It does not alter locked labels, metrics, or results.",
    }
    out = root / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "problem_count": len(problems), "hits": len(hits)}, sort_keys=True))
    if problems:
        raise SystemExit(2)

if __name__ == "__main__":
    main()
