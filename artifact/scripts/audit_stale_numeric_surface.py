#!/usr/bin/env python3
"""Audit evidence-facing stale numeric claim surfaces."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
sys.dont_write_bytecode = True
from common_paths import package_root


def main() -> None:
    ap = argparse.ArgumentParser(); ap.add_argument('--root', default=None); ap.add_argument('--out', default='artifact/results/stale_numeric_surface_audit.json')
    args = ap.parse_args(); root = Path(args.root).resolve() if args.root else package_root(__file__)
    sys.path.insert(0, str(root/'artifact'))
    from bepguard.stale_numeric_surface import run_stale_numeric_surface, write_json
    summary = run_stale_numeric_surface(root); write_json(root/args.out, summary)
    print(json.dumps({'status': summary['status'], 'problem_count': summary['problem_count'], 'files_checked': summary['files_checked']}, sort_keys=True))
    if summary['status'] != 'pass': raise SystemExit(2)

if __name__ == '__main__': main()
