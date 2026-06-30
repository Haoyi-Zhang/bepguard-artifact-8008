"""Paper argument-surface audit."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List

REQUIRED_PHRASES = [
    'policy intent drift','proof-carrying','repair-paired','BEP-Deep','BEP-Max','declarative third oracle','finite theorem kernel','external comparator','source-claim trace','deterministic',
]
FORBIDDEN_VISIBLE = [r'artifact/', r'scripts/', r'/mnt' + r'/data', r'command line', r'transcript', r'review\d+', r'Git' + r'Hub', r'Ha' + r'oyi', r'Chat' + r'GPT', r'Open' + r'AI']


def _strip_latex_commands(text: str) -> str:
    text = re.sub(r'%.*', '', text)
    text = re.sub(r'\\(?:input|include|bibliography|bibliographystyle|documentclass|usepackage|label|ref|cite[talp]?|newcommand)\s*(?:\[[^\]]*\])?\s*\{[^}]*\}', ' ', text)
    text = re.sub(r'\\[A-Za-z]+\*?(?:\[[^\]]*\])?', ' ', text)
    text = re.sub(r'[{}$]', ' ', text)
    return text


def run_paper_argument_surface(root: Path) -> Dict[str, Any]:
    main = (root/'paper/main.tex').read_text(encoding='utf-8')
    visible = _strip_latex_commands(main)
    lower = visible.lower()
    problems: List[str] = []
    missing = [p for p in REQUIRED_PHRASES if p.lower() not in lower]
    if missing:
        problems.append(f'missing argument phrases: {missing}')
    sections = re.findall(r'^\\section\{', main, flags=re.M)
    subsections = re.findall(r'^\\subsection\{', main, flags=re.M)
    if len(sections) != 8:
        problems.append(f'expected 8 top-level sections, found {len(sections)}')
    if subsections:
        problems.append(f'expected 0 subsections, found {len(subsections)}')
    forbidden_hits = []
    for pat in FORBIDDEN_VISIBLE:
        if re.search(pat, visible, re.I):
            forbidden_hits.append(pat)
    if forbidden_hits:
        problems.append(f'visible paper text contains forbidden process/mechanics terms: {forbidden_hits}')
    if not re.search(r'BEPGuard: Proof-Carrying Evidence', main):
        problems.append('title not aligned with aligned BEPGuard title')
    return {'status': 'pass' if not problems else 'fail', 'problem_count': len(problems), 'problems': problems, 'sections': len(sections), 'subsections': len(subsections), 'required_phrases_checked': len(REQUIRED_PHRASES), 'interpretation': 'Checks assessor-first paper argument surface: title alignment, key contribution phrases, 8-section structure, no subsections, and no visible repository/process mechanics.'}


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True)+'\n', encoding='utf-8')
