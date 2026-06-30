"""Deterministic fold-stratification audit.

BEPGuard does not train a statistical classifier, so train/test splitting is not
the evaluation design.  This audit nevertheless exposes whether the locked
workload is concentrated in one slice by hashing fixtures into deterministic
folds and checking that each fold contains positives, controls, issue diversity,
and policy-family diversity.
"""
from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Tuple

FOLDS = 5


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding='utf-8'))


def _fold(fid: str) -> int:
    return int(hashlib.sha256(fid.encode('utf-8')).hexdigest(), 16) % FOLDS


def run_fold_stratification(root: Path) -> Tuple[List[Dict[str, str]], Dict[str, Any]]:
    fixtures = _load(root / 'artifact/data/deep_locked_fixtures.json')
    buckets: List[List[Dict[str, Any]]] = [[] for _ in range(FOLDS)]
    for fx in fixtures:
        buckets[_fold(str(fx.get('id','')))].append(fx)
    rows: List[Dict[str, str]] = []
    problems: List[str] = []
    for idx, bucket in enumerate(buckets):
        positives = [f for f in bucket if f.get('fixture_role') == 'positive']
        controls = [f for f in bucket if f.get('fixture_role') != 'positive']
        issues = {f.get('expected_issue') for f in positives if f.get('expected_issue')}
        families = {f.get('policy_family') for f in bucket if f.get('policy_family')}
        claims = {c for f in bucket for c in (f.get('source_claim_ids') or [])}
        row = {'fold': str(idx), 'fixtures': str(len(bucket)), 'positives': str(len(positives)), 'controls': str(len(controls)), 'issue_classes': str(len(issues)), 'policy_families': str(len(families)), 'source_claims': str(len(claims)), 'status': 'pass'}
        if len(positives) < 70 or len(controls) < 90 or len(issues) < 20 or len(families) < 15:
            row['status'] = 'fail'
            problems.append(f'fold {idx} insufficiently stratified: {row}')
        rows.append(row)
    summary = {'status': 'pass' if not problems else 'fail', 'problem_count': len(problems), 'problems': problems, 'folds': FOLDS, 'fixtures_checked': len(fixtures), 'minimum_fold_fixtures': min(len(b) for b in buckets), 'maximum_fold_fixtures': max(len(b) for b in buckets), 'interpretation': 'Deterministic hash-fold stratification audit; not used for training, but guards against workload concentration across issue classes, policy families, and source claims.'}
    return rows, summary


def write_csv(path: Path, rows: List[Dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields=['fold','fixtures','positives','controls','issue_classes','policy_families','source_claims','status']
    with path.open('w', newline='', encoding='utf-8') as fh:
        w=csv.DictWriter(fh, fieldnames=fields); w.writeheader(); w.writerows(rows)


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True)+'\n', encoding='utf-8')
