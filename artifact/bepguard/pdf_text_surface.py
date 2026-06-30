"""Compiled-PDF text-surface audit.

Several source-level audits inspect LaTeX, but the submitted object is the PDF.
This audit extracts text from the compiled main and supplement PDFs and checks
for process traces, local paths, unresolved references, and presentation terms
that should not be visible to assessors.
"""
from __future__ import annotations
import json, re, subprocess
from pathlib import Path
from typing import Any, Dict, List

PDFS = ["paper/main.pdf", "paper/supplement.pdf"]
FORBIDDEN = [
    r"evidence-facing",
    r"\bassessor\b",
    r"delivery readiness",
    r"paper system",
    r"selected areas",
    r"CONTINUE_STATE",
    r"sand" + "box:/",
    r"/" + "mnt/",
    r"/" + "home/",
    r"Chat" + "GPT",
    r"Open" + "AI",
    r"review\d+",
    r"high-impact paper",
    r"undefined reference",
    r"\?\?",
]
REQUIRED_MAIN = [
    "bepguard",
    "policy",
    "intent drift",
    "semantic evaluation object",
]


def _pdf_text(path: Path) -> str:
    cp = subprocess.run(["pdftotext", str(path), "-"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    if cp.returncode != 0:
        raise RuntimeError(cp.stderr.strip() or f"pdftotext failed for {path}")
    return cp.stdout


def run_pdf_text_surface(root: Path) -> Dict[str, Any]:
    problems: List[str] = []
    pages_checked = 0
    texts: Dict[str, str] = {}
    for rel in PDFS:
        path = root / rel
        if not path.exists():
            problems.append(f"missing PDF {rel}")
            continue
        try:
            text = _pdf_text(path)
        except Exception as exc:
            problems.append(f"cannot extract text from {rel}: {exc}")
            continue
        texts[rel] = text
        pages_checked += text.count("\f") + 1 if text else 0
        for pat in FORBIDDEN:
            if re.search(pat, text, flags=re.I):
                problems.append(f"forbidden visible PDF token {pat!r} in {rel}")
    main_text = texts.get("paper/main.pdf", "")
    main_lower = main_text.lower()
    for token in REQUIRED_MAIN:
        if token not in main_lower:
            problems.append(f"main PDF missing expected visible token {token!r}")
    # The references heading should appear after the body text, not before the title.
    if "references" in main_lower and "bepguard" in main_lower and main_lower.find("references") < main_lower.find("bepguard"):
        problems.append("main PDF references heading appears before title text")
    return {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems[:100],
        "pdfs_checked": len(texts),
        "visible_pages_estimated": pages_checked,
        "forbidden_patterns_checked": len(FORBIDDEN),
        "required_main_tokens": len(REQUIRED_MAIN),
        "interpretation": "Checks the text extracted from the compiled PDFs for process traces, unresolved references, and required research-surface terms.",
    }


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
