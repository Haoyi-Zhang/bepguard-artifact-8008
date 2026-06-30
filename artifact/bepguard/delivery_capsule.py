"""Anonymous paper delivery-capsule audit."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

REQUIRED = [
    'paper/main.pdf','paper/supplement.pdf','paper/main.tex','paper/supplement.tex','paper/references.bib',
    'artifact/README.md','artifact/reproduction.md','artifact/pyproject.toml','artifact/requirements.txt','artifact/environment_lock.json','artifact/LICENSE',
    'artifact/results/validation_summary.json','artifact/results/reproducibility_ladder_audit.json','artifact/results/clean_package_check.json','artifact/checksum_manifest.csv','artifact/results/result_index.csv',
]
FORBIDDEN_NAMES = {'__pycache__','.git','.pytest_cache','.mypy_cache','node_modules'}
FORBIDDEN_PREFIXES = ('tmp_', 'scratch_', 'debug_')


def run_delivery_capsule(root: Path) -> Dict[str, Any]:
    problems: List[str] = []
    top = sorted(p.name for p in root.iterdir() if p.name != '.DS_Store')
    if top != ['artifact','paper']:
        problems.append(f'top-level entries are {top}, expected artifact/paper')
    missing = [p for p in REQUIRED if not (root/p).exists()]
    problems.extend([f'missing required capsule file: {p}' for p in missing])
    forbidden = []
    prefixed = []
    for p in root.rglob('*'):
        parts = set(p.parts)
        if parts & FORBIDDEN_NAMES:
            forbidden.append(str(p.relative_to(root)))
        if p.is_file() and p.name.startswith(FORBIDDEN_PREFIXES):
            prefixed.append(str(p.relative_to(root)))
    if forbidden:
        problems.append(f'forbidden dependency/transient directories present: {forbidden[:10]}')
    if prefixed:
        problems.append(f'temporary/debug-like files present: {prefixed[:10]}')
    # Package-local hygiene summaries must already pass.  The top-level release
    # validation summary is checked by run_validation.py to avoid a circular
    # readiness dependency.
    for rel in ['artifact/results/clean_package_check.json','artifact/results/anonymity_audit.json']:
        path = root / rel
        if path.exists():
            obj = json.loads(path.read_text(encoding='utf-8'))
            if obj.get('status') == 'fail' or int(obj.get('problem_count') or 0) != 0:
                problems.append(f'{rel} is not passing')
    validation_summary = root / 'artifact/results/validation_summary.json'
    if validation_summary.exists():
        try:
            obj = json.loads(validation_summary.read_text(encoding='utf-8'))
            if len(obj.get('validation_layers_checked', [])) != 111:
                problems.append('artifact/results/validation_summary.json does not expose 111 validation layers')
        except Exception as exc:
            problems.append(f'artifact/results/validation_summary.json is not readable JSON: {exc}')
    return {'status': 'pass' if not problems else 'fail', 'problem_count': len(problems), 'problems': problems[:100], 'required_capsule_files': len(REQUIRED), 'top_level_entries': top, 'interpretation': 'Checks that the delivery capsule exposes exactly the anonymous paper, supplement, code/artifact, reproduction instructions, manifests, and validation summaries without dependency caches or temporary files.'}


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True)+'\n', encoding='utf-8')
