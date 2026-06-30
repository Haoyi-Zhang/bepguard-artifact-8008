"""Release hygiene audit for stale/transient residues not caught by generic checks."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

BAD_NAME_PREFIXES = ('tmp_', 'temp_', 'debug_', 'draft_', 'old_')
BAD_NAME_SUBSTRINGS = ('scratch', '.bak')
REQUIRED_RESULT_FILES = [
    'artifact/results/validation_summary.json',
    'artifact/results/result_index.csv',
    'artifact/checksum_manifest.csv',
    'artifact/results/process_trace_hygiene_audit.json',
]


def run_release_hygiene(root: Path) -> Dict[str, Any]:
    problems: List[str] = []
    suspect = []
    for p in root.rglob('*'):
        if not p.is_file():
            continue
        name = p.name.lower()
        if name.startswith(BAD_NAME_PREFIXES) or any(s in name for s in BAD_NAME_SUBSTRINGS):
            suspect.append(str(p.relative_to(root)).replace('\\','/'))
    if suspect:
        problems.append(f'suspect transient/stale filenames present: {suspect[:20]}')
    for rel in REQUIRED_RESULT_FILES:
        if not (root/rel).exists():
            problems.append(f'missing required hygiene-linked file: {rel}')
    return {'status': 'pass' if not problems else 'fail', 'problem_count': len(problems), 'problems': problems[:100], 'suspect_files': suspect[:100], 'files_scanned': sum(1 for p in root.rglob('*') if p.is_file()), 'interpretation': 'Scans for stale/transient filename residues and required release-hygiene outputs after multi-round hardening.'}


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True)+'\n', encoding='utf-8')
