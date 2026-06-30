"""Run the audit paper rhetoric audit and write its materialized result."""
#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
sys.dont_write_bytecode=True
from common_paths import package_root

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--root', default=None); ap.add_argument('--out', default='artifact/results/paper_rhetoric_audit.json')
    args=ap.parse_args(); root=Path(args.root).resolve() if args.root else package_root(__file__)
    sys.path.insert(0, str(root/'artifact'))
    from bepguard.paper_rhetoric import run_paper_rhetoric, write_json
    s=run_paper_rhetoric(root); write_json(root/args.out, s)
    print(json.dumps({'status':s['status'],'problem_count':s['problem_count'],'sections':s['sections']}, sort_keys=True))
    if s['status']!='pass': raise SystemExit(2)
if __name__=='__main__': main()
