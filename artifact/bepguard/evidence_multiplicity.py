"""Evidence-path multiplicity audit."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

CHANNELS = ['source_claim', 'semantic_rule', 'witness_surface', 'certificate', 'paired_repair', 'graph_path', 'explanation', 'certificate_obligations']


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding='utf-8'))


def run_evidence_path_multiplicity(root: Path) -> Tuple[List[Dict[str, str]], Dict[str, Any]]:
    cards = _load_json(root / 'artifact/results/deep_locked/evidence_cards.json')
    paths = {}
    with (root / 'artifact/results/evidence_graph_paths.csv').open(newline='', encoding='utf-8') as fh:
        for r in csv.DictReader(fh):
            if r.get('path_type') == 'positive_witness':
                paths[r.get('fixture_id','')] = r
    rows: List[Dict[str, str]] = []
    problems: List[str] = []
    min_channels = 999
    for card in cards:
        fid = str(card.get('fixture_id',''))
        present = {
            'source_claim': bool(card.get('source_claim_ids')),
            'semantic_rule': bool(card.get('rule_ids')),
            'witness_surface': bool(card.get('witness_surface')),
            'certificate': bool(card.get('certificate_id')),
            'paired_repair': bool(card.get('paired_repair_control_id')),
            'graph_path': fid in paths and str(paths[fid].get('path_verified','')).lower() == 'yes',
            'explanation': bool(str(card.get('explanation','')).strip()),
            'certificate_obligations': card.get('certificate_obligations_true') is True,
        }
        count = sum(1 for v in present.values() if v)
        min_channels = min(min_channels, count)
        if count < len(CHANNELS):
            problems.append(f'{fid} has only {count}/{len(CHANNELS)} evidence channels')
        rows.append({'fixture_id': fid, 'issue': str(card.get('issue','')), 'channels_present': str(count), 'missing_channels': ';'.join(k for k,v in present.items() if not v), 'status': 'pass' if count == len(CHANNELS) else 'fail'})
    summary = {
        'status': 'pass' if not problems else 'fail',
        'problem_count': len(problems),
        'problems': problems[:100],
        'cards_checked': len(cards),
        'channels_required': len(CHANNELS),
        'minimum_channels_present': min_channels if cards else 0,
        'total_channel_obligations': len(cards) * len(CHANNELS),
        'interpretation': 'Every positive witness evidence card must expose all assessor-relevant channels: source claim, rule, witness surface, certificate, repair, graph path, explanation, and certificate obligation status.',
    }
    return rows, summary


def write_csv(path: Path, rows: List[Dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields=['fixture_id','issue','channels_present','missing_channels','status']
    with path.open('w', newline='', encoding='utf-8') as fh:
        w=csv.DictWriter(fh, fieldnames=fields); w.writeheader(); w.writerows(rows)


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True)+'\n', encoding='utf-8')
