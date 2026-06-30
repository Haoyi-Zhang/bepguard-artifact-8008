#!/usr/bin/env python3
"""Evidence redundancy audit for source-grounded BEP-Deep rules and claims."""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True

import argparse, csv, json
from pathlib import Path
from collections import Counter, defaultdict
from typing import Dict, List


def read_csv(path: str) -> List[Dict[str,str]]:
    with open(path, newline='', encoding='utf-8') as fh:
        return list(csv.DictReader(fh))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--source-manifest', default='artifact/source_manifest.csv')
    ap.add_argument('--claims', default='artifact/data/corpus_claims.csv')
    ap.add_argument('--rules', default='artifact/data/rule_to_source_ledger.csv')
    ap.add_argument('--out-dir', default='artifact/results/deep_locked')
    args = ap.parse_args()
    sources = {r['source_id']: r for r in read_csv(args.source_manifest)}
    claims = read_csv(args.claims)
    rules = read_csv(args.rules)
    out = Path(args.out_dir); out.mkdir(parents=True, exist_ok=True)

    source_type_by_claim = Counter()
    admitted_by_type = Counter()
    for c in claims:
        sid = c.get('source_id','')
        stype = sources.get(sid,{}).get('source_type', c.get('claim_type','unknown'))
        source_type_by_claim[stype] += 1
        if c.get('included_in_denominator','').lower() == 'yes':
            admitted_by_type[stype] += 1

    rule_rows = []
    rule_missing_sources = []
    rule_source_types = Counter()
    rules_with_normative = 0
    for r in rules:
        sids = [x.strip() for x in r.get('source_ids','').split(';') if x.strip()]
        types = sorted({sources.get(sid,{}).get('source_type','unknown') for sid in sids})
        has_norm = any(t == 'specification' for t in types)
        if has_norm: rules_with_normative += 1
        for t in types: rule_source_types[t] += 1
        if not sids or any(sid not in sources for sid in sids): rule_missing_sources.append(r.get('rule_id',''))
        rule_rows.append({
            'rule_id': r.get('rule_id',''),
            'policy_family': r.get('policy_family',''),
            'encoded_status': r.get('encoded_status',''),
            'source_ids': ';'.join(sids) or 'none',
            'source_types': ';'.join(types) or 'none',
            'has_normative_spec_source': str(has_norm).lower(),
        })
    with (out/'evidence_redundancy_audit.csv').open('w', newline='', encoding='utf-8') as fh:
        w = csv.DictWriter(fh, fieldnames=list(rule_rows[0].keys()))
        w.writeheader(); w.writerows(rule_rows)
    metrics = {
        'claims': len(claims),
        'admitted_claims': sum(1 for c in claims if c.get('included_in_denominator','').lower() == 'yes'),
        'source_types_by_claim': dict(source_type_by_claim),
        'admitted_claims_by_source_type': dict(admitted_by_type),
        'rules': len(rules),
        'rules_with_normative_spec_source': rules_with_normative,
        'rules_without_normative_spec_source': len(rules)-rules_with_normative,
        'rule_source_type_incidence': dict(rule_source_types),
        'rules_with_missing_source_ids': rule_missing_sources,
        'interpretation': 'Source redundancy audit over public evidence ledgers; rule soundness still depends on encoded fragment assumptions.',
    }
    (out/'evidence_redundancy_metrics.json').write_text(json.dumps(metrics, indent=2, sort_keys=True)+'\n', encoding='utf-8')
    print(json.dumps(metrics, sort_keys=True))
    if rule_missing_sources:
        sys.exit(1)

if __name__ == '__main__':
    main()
