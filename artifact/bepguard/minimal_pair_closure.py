"""Minimal-pair closure audit for each semantic issue class."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

OBLIGATIONS = ['locked_positive','matched_control','positive_certificate','paired_repair','specbench_pressure','mutant_kill','causal_activation','shadow_replay','identifier_blind_replay']


def _to_int(v: str) -> int:
    try: return int(v)
    except Exception: return 0


def run_minimal_pair_closure(root: Path) -> Tuple[List[Dict[str, str]], Dict[str, Any]]:
    rows_in: List[Dict[str, str]] = []
    with (root / 'artifact/results/deep_locked/issue_evidence_depth_rows.csv').open(newline='', encoding='utf-8') as fh:
        rows_in = list(csv.DictReader(fh))
    rows: List[Dict[str, str]] = []
    problems: List[str] = []
    min_obligations = 999
    for r in rows_in:
        checks = {
            'locked_positive': _to_int(r.get('locked_positives','0')) > 0,
            'matched_control': _to_int(r.get('matched_intent_controls','0')) > 0,
            'positive_certificate': _to_int(r.get('positive_certificates','0')) == _to_int(r.get('locked_positives','0')),
            'paired_repair': _to_int(r.get('paired_repairs','0')) == _to_int(r.get('locked_positives','0')),
            'specbench_pressure': _to_int(r.get('specbench_positive_cases','0')) > 0,
            'mutant_kill': _to_int(r.get('killed_mutants','0')) > 0,
            'causal_activation': _to_int(r.get('causal_activations','0')) > 0,
            'shadow_replay': _to_int(r.get('shadow_preserved_replays','0')) > 0,
            'identifier_blind_replay': _to_int(r.get('identifier_blind_preserved_replays','0')) > 0,
        }
        ok_count = sum(checks.values())
        min_obligations = min(min_obligations, ok_count)
        missing = [k for k,v in checks.items() if not v]
        if missing:
            problems.append(f"{r.get('issue','')}: missing {','.join(missing)}")
        out = {'issue': r.get('issue',''), 'intent_class': r.get('intent_class',''), 'obligations_present': str(ok_count), 'missing_obligations': ';'.join(missing), 'status': 'pass' if not missing else 'fail'}
        rows.append(out)
    summary = {
        'status': 'pass' if not problems else 'fail',
        'problem_count': len(problems),
        'problems': problems[:100],
        'issue_classes_checked': len(rows),
        'obligations_per_issue': len(OBLIGATIONS),
        'minimal_pair_obligations': len(rows) * len(OBLIGATIONS),
        'minimum_obligations_present': min_obligations if rows else 0,
        'interpretation': 'Per-issue minimal-pair closure: each issue class must have positives, matched controls, certificates, repairs, source-derived boundary pressure, mutation pressure, causal activation, and representation-invariant replays.',
    }
    return rows, summary


def write_csv(path: Path, rows: List[Dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields=['issue','intent_class','obligations_present','missing_obligations','status']
    with path.open('w', newline='', encoding='utf-8') as fh:
        w=csv.DictWriter(fh, fieldnames=fields); w.writeheader(); w.writerows(rows)


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True)+'\n', encoding='utf-8')
