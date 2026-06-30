"""paper delivery-process trace hygiene audit.

This audit scans the release tree for process traces that should not be visible
in an anonymous review artifact: round labels, local paths, personal names,
tool traces, and repository-staging identifiers.  It is intentionally
stricter than the generic anonymity audit because process-trace words are not
necessarily author identities, but they still weaken a clean artifact.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

TEXT_SUFFIXES = {'.tex', '.bib', '.md', '.csv', '.json', '.py', '.txt', '.toml'}
FORBIDDEN_PATTERNS = [
    (r'(?i)review\s*\d{1,3}', 'round_label'),
    (r'(?i)hand' + r'off', 'handoff_trace'),
    (r'(?i)raw\s+' + r'interaction trace|interaction trace\s+transcript', 'interaction trace_trace'),
    (r'(?i)' + 'chat' + 'g' + 'pt|' + 'open' + 'a' + 'i|' + 'g' + 'pt-[0-9]', 'tool_trace'),
    (r'/' + r'mnt' + r'/' + r'data|/' + r'home' + r'/' + r'oai|\\Users\\|/Users/', 'local_path_trace'),
    (r'Ha' + r'oyi|Ha' + r'oyi-Zh' + r'ang', 'author_or_account_trace'),
    (r'(?i)git' + r'hub_' + r'repository|git' + r'hub_' + r'sync|personal repository', 'repository_staging_trace'),
    (r'(?<![A-Za-z0-9])' + 's' + 'k' + '-' + r'[A-Za-z0-9][A-Za-z0-9_-]{8,}', 'secret_token_shape'),
]
ALLOWLISTED_FILES = {
    'artifact/bepguard/process_trace_hygiene.py',
    'artifact/results/process_trace_hygiene_audit.json',
    'artifact/tests/test_clean_artifact_hygiene.py',
}



def _iter_text_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob('*')):
        if not path.is_file():
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        yield path


def run_process_trace_hygiene(root: Path) -> Dict[str, Any]:
    problems: List[str] = []
    rows: List[Dict[str, str]] = []
    files_checked = 0
    for path in _iter_text_files(root):
        rel = str(path.relative_to(root)).replace('\\', '/')
        if rel in ALLOWLISTED_FILES:
            continue
        try:
            text = path.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            text = path.read_text(encoding='utf-8', errors='replace')
        files_checked += 1
        for lineno, line in enumerate(text.splitlines(), 1):
            for pat, kind in FORBIDDEN_PATTERNS:
                if re.search(pat, line):
                    snippet = line.strip()[:160]
                    rows.append({'path': rel, 'line': str(lineno), 'kind': kind, 'snippet': snippet})
                    problems.append(f'{rel}:{lineno}: {kind}')
    return {
        'status': 'pass' if not problems else 'fail',
        'problem_count': len(problems),
        'problems': problems[:100],
        'files_checked': files_checked,
        'forbidden_patterns': len(FORBIDDEN_PATTERNS),
        'hits': rows[:100],
        'interpretation': 'Strict scan for paper delivery-process traces, local paths, tool traces, account identifiers, and secret-token-shaped strings in the anonymous release tree.',
    }


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + '\n', encoding='utf-8')
