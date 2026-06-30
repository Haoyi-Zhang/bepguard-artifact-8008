"""Audit human-facing release text against materialized validation counts."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List

EXPECTED = {
    "validation_layers": 111,
    "reproduction_ladder_commands": 101,
    "protocol_last": "A099",
    "specbench_cases": 4180,
    "declarative_oracle_cases": 5152,
    "corpus_stability_replays": 2916,
    "evidence_cards": 418,
    "references": 72,
    "main_pages": 12,
    "body_pages": "1-10",
    "references_only_pages": "11-12",
    "version": "0.24.0",
}

STALE_PATTERNS = [
    r"42 materialized validation layers",
    r"52 / 52",
    r"57 / 57",
    r"57 materialized layers",
    r"61 / 61",
    r"61 materialized layers",
    r"66 / 66",
    r"66 materialized validation layers",
    r"70 / 70",
    r"70 materialized validation layers",
    r"74 / 74",
    r"74 materialized validation layers",
    r"78 / 78",
    r"78 materialized validation layers",
    r"82 / 82",
    r"82 materialized validation layers",
    r"90 / 90",
    r"90 materialized validation layers",
    r"41-command reproduction ladder",
    r"46-command reproduction ladder",
    r"50-command reproduction ladder",
    r"56-command reproduction ladder",
    r"60-command reproduction ladder",
    r"64-command reproduction ladder",
    r"68-command reproduction ladder",
    r"72-command reproduction ladder",
    r"80-command reproduction ladder",
    r"A001-A047",
    r"A001-A051",
    r"A001-A055",
    r"A001-A056",
    r"A001-A060",
    r"A001-A064",
    r"A001-A068",
    r"A001-A078",
]

def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.exists() else ""


def _pyproject_version(text: str) -> str:
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    return m.group(1) if m else ""


def audit_documentation_consistency(root: Path) -> Dict[str, Any]:
    problems: List[str] = []
    readme = _read(root / "artifact/README.md")
    repro = _read(root / "artifact/reproduction.md")
    main = _read(root / "paper/main.tex")
    supp = _read(root / "paper/supplement.tex")
    pyproject = _read(root / "artifact/pyproject.toml")
    init_text = _read(root / "artifact/bepguard/__init__.py")

    docs = {
        "README.md": readme,
        "reproduction.md": repro,
        "main.tex": main,
        "supplement.tex": supp,
    }
    for name, text in docs.items():
        for pattern in STALE_PATTERNS:
            if re.search(pattern, text):
                problems.append(f"{name}: stale wording matches {pattern}")

    required_tokens = {
        "README.md": ["111", "101-command", "A001-A099", "4,180", "5,152", "oracle triangulation", "static code-health", "repair-locality", "RQ traceability", "counterfactual round-trip", "rule trace-matrix", "claim-impact", "hash-chain", "gate-sensitivity", "idempotence", "process-trace", "threat", "minimal-pair", "fold", "delivery capsule"],
        "reproduction.md": ["111", "101", "A001-A099", "4,180", "5,152", "oracle triangulation", "static code-health", "repair-locality", "RQ traceability", "counterfactual round-trip", "rule trace-matrix", "claim-impact", "hash-chain", "gate-sensitivity", "idempotence", "process-trace", "threat", "minimal-pair", "fold", "delivery capsule"],
        "main.tex": ["111", "101", "4,180", "5,152", "decision-table oracle", "declarative third oracle", "finite theorems", "repair-delta", "release reproducibility", "evidence-graph", "hash-chain", "gate-sensitivity", "idempotence", "threat closure", "minimal-pair", "fold stratification"],
        "supplement.tex": ["111", "101", "4,180", "5,152", "oracle", "pure decision-function", "repair", "counterfactual", "rule trace", "process-trace", "threat", "minimal-pair", "fold", "stale numeric", "review-criteria", "contribution trace", "reference role", "oracle structural", "deliverable trio", "paper rhetoric", "repository-entrypoint", "release scorecard", "overclaim", "PDF text", "public provenance", "repository upload"],
    }
    for name, tokens in required_tokens.items():
        text = docs.get(name, "")
        for token in tokens:
            if token not in text:
                problems.append(f"{name}: missing current documentation token {token!r}")

    py_ver = _pyproject_version(pyproject)
    if py_ver != EXPECTED["version"]:
        problems.append(f"pyproject version {py_ver!r} != {EXPECTED['version']!r}")
    if f'__version__ = "{EXPECTED["version"]}"' not in init_text:
        problems.append("bepguard.__version__ does not match pyproject version")

    result = {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems[:80],
        "documents_checked": len(docs) + 2,
        "expected_counts": EXPECTED,
        "interpretation": "Human-facing release text, paper sources, and package identity are checked against the current validation contract so stale review-round counts cannot survive into the artifact.",
    }
    return result


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
