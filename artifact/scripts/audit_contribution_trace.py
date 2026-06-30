"""Run the audit contribution trace audit and write its materialized result."""
#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
sys.dont_write_bytecode=True
from common_paths import package_root

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--root', default=None); ap.add_argument('--out', default='artifact/results/contribution_trace_audit.json')
    args=ap.parse_args(); root=Path(args.root).resolve() if args.root else package_root(__file__)
    sys.path.insert(0, str(root/'artifact'))
    from bepguard.contribution_trace import run_contribution_trace, write_json
    s=run_contribution_trace(root); write_json(root/args.out, s)
    print(json.dumps({'status':s['status'],'problem_count':s['problem_count'],'contributions_checked':s['contributions_checked']}, sort_keys=True))
    if s['status']!='pass': raise SystemExit(2)
if __name__=='__main__': main()
