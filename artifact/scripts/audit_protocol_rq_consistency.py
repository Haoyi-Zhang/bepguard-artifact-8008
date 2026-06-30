#!/usr/bin/env python3
"""Check that paper and protocol expose the same locked research questions."""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True

import json, re
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
EXPECTED = ["RQ1", "RQ2", "RQ3", "RQ4", "RQ5"]


def rq_set_from_text(text: str) -> list[str]:
    return sorted(set(re.findall(r"\bRQ[1-5]\b", text)), key=lambda x: int(x[2:]))


def main():
    problems=[]
    study=(ROOT/'artifact/study_protocol.md').read_text(encoding='utf-8')
    main=(ROOT/'paper/main.tex').read_text(encoding='utf-8')
    protocol=json.loads((ROOT/'artifact/protocol_lock.json').read_text(encoding='utf-8'))
    corpus=json.loads((ROOT/'artifact/protocol_corpus_lock.json').read_text(encoding='utf-8'))
    study_rqs=rq_set_from_text(study)
    main_rqs=rq_set_from_text(main)
    protocol_rqs=protocol.get('locked_rqs',[])
    corpus_rqs=corpus.get('frozen_rqs',[])
    for name, got in [('study_protocol',study_rqs),('main_tex',main_rqs),('protocol_lock',protocol_rqs),('protocol_corpus_lock',corpus_rqs)]:
        if got != EXPECTED:
            problems.append(f'{name} RQs are {got}, expected {EXPECTED}')
    out={
        'status':'pass' if not problems else 'fail',
        'problem_count':len(problems),
        'problems':problems,
        'expected_rqs':EXPECTED,
        'study_protocol_rqs':study_rqs,
        'main_tex_rqs':main_rqs,
        'protocol_lock_rqs':protocol_rqs,
        'protocol_corpus_lock_rqs':corpus_rqs,
        'interpretation':'RQ-consistency audit: the protocol, main paper, and lineage lock must expose the same locked research questions so validation gates cannot drift from the reported claim structure.'
    }
    target=ROOT/'artifact/results/protocol_rq_consistency_audit.json'
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    print(json.dumps({'status':out['status'],'problem_count':out['problem_count'],'rqs':len(EXPECTED)},sort_keys=True))
    if problems: raise SystemExit(2)

if __name__=='__main__': main()
