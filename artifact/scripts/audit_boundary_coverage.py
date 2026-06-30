#!/usr/bin/env python3
"""Audit semantic boundary coverage for BEP-Deep and BEP-Max validation.

The audit asks whether every modeled issue class is supported by the validation
ladder expected in the paper: positive witness, ordinary or paired negative
control, proof-carrying certificate, repair-frontier row, mutation kill, and
adversarial-preserving cases.  It also summarizes coverage of policy families
and context axes without treating the workload as a deployed-web sample.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True

import argparse, csv, json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Set


def load_json(path: str):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def read_csv(path: str) -> List[Dict[str, str]]:
    with open(path, newline='', encoding='utf-8') as fh:
        return list(csv.DictReader(fh))


def axis_value(fx: Dict[str, object], axis: str) -> str:
    ctx = fx.get('context', {}) if isinstance(fx.get('context'), dict) else {}
    headers = fx.get('headers', []) if isinstance(fx.get('headers'), list) else []
    names = {str(h.get('name','')).lower() for h in headers if isinstance(h, dict)}
    if axis == 'delivery':
        if 'content-security-policy' in names: return 'enforced_csp'
        if 'content-security-policy-report-only' in names: return 'report_only_csp'
        if 'content-security-policy-meta' in names: return 'meta_csp'
        return 'non_csp'
    if axis == 'credentials': return str(ctx.get('credentials_mode', 'none'))
    if axis == 'transport': return str(ctx.get('scheme', 'none'))
    if axis == 'request_mode': return str(ctx.get('request_mode', 'none'))
    if axis == 'rendering': return 'static' if ctx.get('static_render') else ('dynamic' if ctx.get('rendering_variant') else 'none')
    if axis == 'stateful': return 'hsts_state' if 'strict-transport-security' in names else 'stateless'
    if axis == 'composition': return 'layers' if fx.get('layers') else ('multi_header' if len(headers) > 1 else 'single_surface')
    if axis == 'resource_relation':
        return 'has_resource_origin' if ctx.get('resource_origin') else ('has_request_origin' if ctx.get('request_origin') else 'none')
    return 'unknown'


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--fixtures', default='artifact/data/deep_locked_fixtures.json')
    ap.add_argument('--certificates', default='artifact/results/deep_locked/proof_carrying_witness_certificates.json')
    ap.add_argument('--mutation', default='artifact/results/deep_locked/semantic_mutation_adequacy.csv')
    ap.add_argument('--repair-frontier', default='artifact/results/bep_max/repair_frontier_audit.csv')
    ap.add_argument('--adversarial', default='artifact/results/bep_max/adversarial_validation_audit.csv')
    ap.add_argument('--out-dir', default='artifact/results/bep_max')
    args = ap.parse_args()
    fixtures = load_json(args.fixtures)
    certs = load_json(args.certificates)
    muts = read_csv(args.mutation)
    frontier = read_csv(args.repair_frontier)
    adversarial = read_csv(args.adversarial)
    positives_by_issue: Dict[str, Set[str]] = defaultdict(set)
    negatives_by_issue: Dict[str, int] = defaultdict(int)
    families: Counter[str] = Counter()
    axes = ['delivery','credentials','transport','request_mode','rendering','stateful','composition','resource_relation']
    axis_counts = {a: Counter() for a in axes}
    for fx in fixtures:
        families[str(fx.get('policy_family',''))] += 1
        for a in axes: axis_counts[a][axis_value(fx,a)] += 1
        issue = str(fx.get('expected_issue','none'))
        if issue == 'none':
            target = str(fx.get('paired_target_issue','ordinary_negative'))
            negatives_by_issue[target] += 1
        else:
            positives_by_issue[issue].add(str(fx.get('id')))
    cert_by_issue = Counter(str(c.get('issue','')) for c in certs)
    frontier_by_issue = Counter(r['target_issue'] for r in frontier if r.get('frontier_certified') == 'true')
    killed_mutants = sum(1 for m in muts if m.get('killed') == 'true')
    adv_by_source = Counter(r['source_fixture_id'] for r in adversarial if r.get('passed') == 'true')
    rows = []
    for issue, ids in sorted(positives_by_issue.items()):
        rows.append({
            'issue': issue,
            'positive_fixtures': len(ids),
            'negative_or_paired_controls': negatives_by_issue.get(issue, 0),
            'certificates': cert_by_issue.get(issue, 0),
            'frontier_certified': frontier_by_issue.get(issue, 0),
            'adversarial_variants_passed': sum(adv_by_source.get(fid, 0) for fid in ids),
            'adequacy_ladder_complete': str(len(ids)>0 and negatives_by_issue.get(issue,0)>0 and cert_by_issue.get(issue,0)==len(ids) and frontier_by_issue.get(issue,0)==len(ids)).lower()
        })
    out = Path(args.out_dir); out.mkdir(parents=True, exist_ok=True)
    with (out/'boundary_coverage_audit.csv').open('w', newline='', encoding='utf-8') as fh:
        w=csv.DictWriter(fh, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    metrics = {
        'issue_classes': len(rows),
        'issue_classes_with_complete_ladder': sum(1 for r in rows if r['adequacy_ladder_complete']=='true'),
        'policy_families': len(families),
        'family_counts': dict(families),
        'axis_value_counts': {a: dict(c) for a,c in axis_counts.items()},
        'semantic_mutants_killed': killed_mutants,
        'adversarial_validation_cases_passed': sum(1 for r in adversarial if r.get('passed') == 'true'),
        'interpretation': 'Boundary-coverage audit over modeled semantic families; not live-web representativeness.',
    }
    (out/'boundary_coverage_metrics.json').write_text(json.dumps(metrics, indent=2, sort_keys=True)+'\n', encoding='utf-8')
    print(json.dumps(metrics, sort_keys=True))
    if metrics['issue_classes_with_complete_ladder'] != metrics['issue_classes']:
        sys.exit(1)

if __name__ == '__main__':
    main()
