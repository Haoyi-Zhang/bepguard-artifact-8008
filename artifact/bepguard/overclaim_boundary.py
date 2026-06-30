"""Overclaim-boundary audit for the release research surface.

The artifact deliberately distinguishes semantic intent-drift evidence from
claims that would require a live-web prevalence study, exploitability study,
human-subject experiment, or full browser-conformance campaign.  This audit
scans the paper, supplement, and release overview for unsafe claim patterns and
also checks that the release retains explicit scope discipline.
"""
from __future__ import annotations
import json, re
from pathlib import Path
from typing import Any, Dict, List

SURFACES = [
    "paper/main.tex",
    "paper/supplement.tex",
    "artifact/README.md",
    "artifact/reproduction.md",
    "artifact/study_protocol.md",
]

# Patterns that are unsafe unless clearly negated in local context.  They encode
# the paper's locked scope: semantic evaluation, not prevalence/exploitability.
CONTEXT_FORBIDDEN = [
    r"live[- ]web prevalence",
    r"deployed[- ]site vulnerability rate",
    r"deployed vulnerability rate",
    r"proves? exploitability",
    r"exploitability proof",
    r"human inter[- ]rater",
    r"developer usability",
    r"user study",
    r"full browser conformance",
    r"complete browser conformance",
    r"full web platform",
    r"private data",
    r"commercial API",
    r"GPU[- ]dependent",
]

ABSOLUTE_FORBIDDEN = [
    r"guaranteed acceptance",
    r"guarantees acceptance",
    r"best[- ]paper level",
    r"high-impact paper",
    r"unassailable",
    r"no limitations",
]

REQUIRED_SCOPE_TOKENS = [
    "semantic evaluation object",
    "not a scanner",
    "prevalence estimate",
    "not exploitability",
    "negative controls",
    "external comparators",
]

NEGATORS = ["not", "no", "nor", "without", "does not", "do not", "is not", "are not", "rather than", "exclude", "excludes", "excluded", "claim"]


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return ""


def _negated(text: str, start: int) -> bool:
    window = text[max(0, start - 120): start + 120].lower()
    sent_start = max(text.rfind('.', 0, start), text.rfind('\n', 0, start)) + 1
    sent_end_candidates = [i for i in [text.find('.', start), text.find('\n', start)] if i != -1]
    sent_end = min(sent_end_candidates) if sent_end_candidates else min(len(text), start + 240)
    sentence = text[sent_start:sent_end].lower()
    return any(tok in window for tok in NEGATORS) or any(tok in sentence for tok in NEGATORS)


def run_overclaim_boundary(root: Path) -> Dict[str, Any]:
    problems: List[str] = []
    checked = 0
    for rel in SURFACES:
        path = root / rel
        if not path.exists():
            problems.append(f"missing surface {rel}")
            continue
        checked += 1
        text = _read(path)
        lower = text.lower()
        for pat in ABSOLUTE_FORBIDDEN:
            if re.search(pat, lower, flags=re.I):
                problems.append(f"absolute forbidden overclaim pattern {pat!r} in {rel}")
        for pat in CONTEXT_FORBIDDEN:
            for m in re.finditer(pat, lower, flags=re.I):
                if not _negated(lower, m.start()):
                    problems.append(f"unqualified overclaim pattern {pat!r} in {rel}")
                    break
    main = _read(root / "paper/main.tex").lower()
    missing = [tok for tok in REQUIRED_SCOPE_TOKENS if tok.lower() not in main]
    if missing:
        problems.append(f"main paper missing scope-discipline tokens {missing}")
    return {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems[:100],
        "surfaces_checked": checked,
        "context_patterns_checked": len(CONTEXT_FORBIDDEN),
        "absolute_patterns_checked": len(ABSOLUTE_FORBIDDEN),
        "required_scope_tokens": len(REQUIRED_SCOPE_TOKENS),
        "interpretation": "Checks that the release paper and artifact describe source-grounded semantic evidence without overclaiming live-web prevalence, exploitability, human-subject evidence, or full browser conformance.",
    }


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
