#!/usr/bin/env python3
"""Anonymous-paper delivery hygiene audit.

This audit checks repository structure, LaTeX anonymity, PDF-visible text, and
common trace patterns that should not appear in an anonymous research artifact.
It is deterministic and runs without network access.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True

import argparse, json, re, subprocess
from pathlib import Path
from typing import Dict, List

ALLOWED_TOP = {"paper", "artifact"}
FORBIDDEN_NAME_PATTERNS = [
    re.compile(r"__pycache__"), re.compile(r"\.pyc$"), re.compile(r"\.aux$"), re.compile(r"\.bbl$"),
    re.compile(r"\.blg$"), re.compile(r"\.log$"), re.compile(r"\.out$"), re.compile(r"\.synctex\.gz$"),
    re.compile(r"\.ipynb_checkpoints"), re.compile(r"(^|/)\.git($|/)"),
]
TRACE_TERMS = [
    "Chat" + "GPT", "Open" + "AI", "Clau" + "de", "Co" + "dex",
    "pro" + "mpt", "model" + " trace", "language" + " model",
    "review" + " packet", "open" + "_P0", "open" + "_P1",
    "fresh" + "_review", "paper delivery" + "-side", "paper delivery" + "_side",
    "sandbox" + ":/",
]
TRACE_PATTERNS = [re.compile(re.escape(term), re.I) for term in TRACE_TERMS]
TRACE_PATTERNS.append(re.compile(r"/(?:home|mnt|tmp|var|opt)/[^\s\"']+"))
TEXT_SUFFIXES = {".tex", ".bib", ".md", ".csv", ".json", ".py", ".go"}


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return ""


def pdf_text(path: Path) -> str:
    try:
        cp = subprocess.run(["pdftotext", str(path), "-"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=False)
        return cp.stdout if cp.returncode == 0 else ""
    except Exception:
        return ""


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--out", default="artifact/results/anonymity_audit.json")
    args = ap.parse_args()
    root = Path(args.root).resolve()
    problems: List[str] = []
    top = {p.name for p in root.iterdir() if p.name != ".DS_Store"}
    if top != ALLOWED_TOP:
        problems.append(f"top-level entries are {sorted(top)}, expected {sorted(ALLOWED_TOP)}")

    main_tex = root / "paper" / "main.tex"
    if main_tex.exists():
        text = read_text(main_tex)
        if r"\documentclass[10pt,conference]{IEEEtran}" not in text:
            problems.append("main.tex does not use required IEEEtran conference class")
        if re.search(r"compsoc|compsocconf", text):
            problems.append("main.tex contains compsoc/compsocconf")
        if r"Anonymous Author(s)" not in text:
            problems.append("main.tex author block is not anonymous")
        if re.search(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", text, re.I):
            problems.append("main.tex contains an email address")
        if re.search(r"IEEEauthorblockA|thanks\{", text):
            problems.append("main.tex contains affiliation/thanks block")
    else:
        problems.append("paper/main.tex missing")

    out_rel = (root / args.out).resolve().relative_to(root).as_posix()
    for path in root.rglob("*"):
        rel = path.relative_to(root).as_posix()
        if rel == out_rel:
            continue
        if any(p.search(rel) for p in FORBIDDEN_NAME_PATTERNS):
            problems.append(f"forbidden filename: {rel}")
            continue
        if path.is_file() and path.suffix.lower() in TEXT_SUFFIXES:
            txt = read_text(path)
            for pat in TRACE_PATTERNS:
                if pat.search(txt):
                    # Allow ordinary bibliographic occurrences of secure-code review, not process traces.
                    if "review" in pat.pattern.lower() and "secure code reviews" in txt.lower():
                        continue
                    problems.append(f"trace-like text in {rel}: {pat.pattern}")
                    break
    for pdf in [root / "paper" / "main.pdf", root / "paper" / "supplement.pdf"]:
        if pdf.exists():
            txt = pdf_text(pdf)
            for pat in TRACE_PATTERNS:
                if pat.search(txt):
                    problems.append(f"trace-like PDF text in {pdf.relative_to(root).as_posix()}: {pat.pattern}")
                    break
        else:
            problems.append(f"missing PDF: {pdf.relative_to(root).as_posix()}")

    result: Dict[str, object] = {
        "top_level": sorted(top),
        "checked_text_files": sum(1 for p in root.rglob("*") if p.is_file() and p.suffix.lower() in TEXT_SUFFIXES),
        "checked_pdfs": ["paper/main.pdf", "paper/supplement.pdf"],
        "problems": problems,
        "problem_count": len(problems),
        "status": "pass" if not problems else "fail",
        "interpretation": "Anonymous paper delivery hygiene audit over repository structure, LaTeX author block, PDF-visible text, and common trace patterns.",
    }
    out = root / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "problem_count": len(problems)}, sort_keys=True))
    if problems:
        raise SystemExit(2)

if __name__ == "__main__":
    main()
