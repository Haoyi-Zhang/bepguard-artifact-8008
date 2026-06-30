#!/usr/bin/env python3
"""Repository hygiene checker for release packages."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, List

sys.dont_write_bytecode = True

try:
    from common_paths import package_root
except ModuleNotFoundError:  # imported as scripts.check_artifact_clean in tests
    from .common_paths import package_root

FORBIDDEN_DIRS = {"__pycache__", ".ipynb_checkpoints", ".git", ".mypy_cache", ".pytest_cache"}
FORBIDDEN_SUFFIXES = {".pyc", ".aux", ".bbl", ".blg", ".log", ".out", ".synctex.gz", ".toc", ".fls", ".fdb_latexmk"}
ALLOWED_TOP = {"paper", "artifact"}
TEXT_SUFFIXES = {".bib", ".cfg", ".csv", ".go", ".ini", ".json", ".md", ".py", ".sh", ".toml", ".txt", ".tex", ".yaml", ".yml"}
LOCAL_PATH_PATTERNS = [
    re.compile(r"(?<![A-Za-z0-9_./-])/(?:data|etc|home|mnt|opt|root|tmp|usr|var)/[^\s\"']+"),
    re.compile(r"[A-Za-z]:\\[^\s\"']+"),
]


def has_forbidden_suffix(path: Path) -> bool:
    name = path.name
    return any(name.endswith(suffix) for suffix in FORBIDDEN_SUFFIXES)


def scan(root: Path) -> Dict[str, object]:
    root = root.resolve()
    problems: List[str] = []
    tops = {p.name for p in root.iterdir() if p.name != ".DS_Store"}
    extra = sorted(tops - ALLOWED_TOP)
    missing = sorted(ALLOWED_TOP - tops)
    for name in extra:
        problems.append(f"unexpected top-level entry: {name}")
    for name in missing:
        problems.append(f"missing top-level entry: {name}")
    fixture_files = {
        "artifact/scripts/check_artifact_clean.py",
        "artifact/tests/test_clean_artifact_hygiene.py",
        "artifact/results/clean_package_check.json",
    }
    for path in root.rglob("*"):
        rel = path.relative_to(root)
        rel_text = rel.as_posix()
        if path.is_dir() and path.name in FORBIDDEN_DIRS:
            problems.append(f"forbidden directory: {rel_text}")
            continue
        if path.is_file() and has_forbidden_suffix(path):
            problems.append(f"forbidden transient file: {rel_text}")
        if path.is_file() and path.suffix.lower() in TEXT_SUFFIXES:
            if rel_text in fixture_files:
                continue
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except UnicodeDecodeError:
                continue
            for line_no, line in enumerate(lines, start=1):
                stripped = line.strip()
                if stripped.startswith("#!"):
                    continue
                for pattern in LOCAL_PATH_PATTERNS:
                    if pattern.search(line):
                        problems.append(f"local path pattern in: {rel_text}:{line_no}")
                        break
                else:
                    continue
                break
    return {"root": "release-root", "problem_count": len(problems), "problems": problems}


def main() -> None:
    parser = argparse.ArgumentParser(description="Check package hygiene.")
    parser.add_argument("--root", default=None)
    parser.add_argument("--out", default="artifact/results/clean_package_check.json")
    args = parser.parse_args()
    root = package_root(args.root) if args.root else package_root(__file__)
    result = scan(root)
    out = root / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"problem_count": result["problem_count"], "out": args.out}, sort_keys=True))
    if result["problem_count"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
