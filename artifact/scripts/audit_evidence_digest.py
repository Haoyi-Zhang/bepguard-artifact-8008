#!/usr/bin/env python3
"""Audit canonical evidence digest closure."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
sys.dont_write_bytecode = True
from common_paths import package_root


def main() -> None:
    ap = argparse.ArgumentParser(); ap.add_argument('--root', default=None); ap.add_argument('--out', default='artifact/results/evidence_digest_audit.json')
    args = ap.parse_args(); root = Path(args.root).resolve() if args.root else package_root(__file__)
    sys.path.insert(0, str(root/'artifact'))
    from bepguard.evidence_digest import run_evidence_digest, write_json
    summary = run_evidence_digest(root); write_json(root/args.out, summary)
    print(json.dumps({'status': summary['status'], 'problem_count': summary['problem_count'], 'digest_inputs': summary['digest_inputs']}, sort_keys=True))
    if summary['status'] != 'pass': raise SystemExit(2)
if __name__ == '__main__': main()
