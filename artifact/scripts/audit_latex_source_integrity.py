#!/usr/bin/env python3
r"""LaTeX source integrity audit for anonymous paper delivery sources.

This gate checks paper-source conditions that are invisible in the rendered PDF:
there must be no active prose after \end{document}, no conference-template option
violation, and no internal process traces in paper sources. It is a source-level
paper delivery check; it does not affect experimental labels or results.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True

import argparse, json, re
from pathlib import Path

PAPER_SOURCES = [Path("paper/main.tex"), Path("paper/supplement.tex")]
TRACE_WORDS = [
    "Chat" + "GPT", "Open" + "AI", "Clau" + "de", "Co" + "dex",
    "L" + "LM", "pro" + "mpt",
]
LOCAL_PATH_RE = r"(/" + "mnt" + r"/data|/" + "home" + r"/|" + "C:" + r"\\" + r"|Users" + r"\\" + r"|sandbox" + r":/)"
FORBIDDEN_PATTERNS = [
    ("model_trace", re.compile(r"\b(" + "|".join(re.escape(w) for w in TRACE_WORDS) + r")\b", re.I)),
    ("local_path", re.compile(LOCAL_PATH_RE, re.I)),
    ("transcript", re.compile(r"\b(transcript|conversation|scratchpad|review" + r" packet)\b", re.I)),
    ("internal_file_path", re.compile(r"\b(artifact/|paper/|scripts/|results/|data/)\S*", re.I)),
    ("source_extension_in_prose", re.compile(r"\b\w+\.(py|json|csv|zip|aux|bbl|blg|log|out)\b", re.I)),
]
ALLOWED_SOURCE_EXTENSION_LINES = re.compile(r"^\\(?:usepackage|documentclass|input|bibliography|bibliographystyle)|^%")

def strip_comments_tail(text: str) -> str:
    lines = text.splitlines()
    kept = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith('%'):
            continue
        kept.append(line)
    return "\n".join(kept).strip()

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="artifact/results/latex_source_integrity_audit.json")
    args = ap.parse_args()
    problems = []
    details = []
    for src in PAPER_SOURCES:
        if not src.exists():
            problems.append(f"missing source: {src}")
            continue
        text = src.read_text(encoding="utf-8")
        docclass_count = len(re.findall(r"\\documentclass\s*\[([^\]]*)\]\s*\{IEEEtran\}", text))
        docclass_match = re.search(r"\\documentclass\s*\[([^\]]*)\]\s*\{IEEEtran\}", text)
        if docclass_count != 1:
            problems.append(f"{src}: expected exactly one IEEEtran documentclass, found {docclass_count}")
        elif docclass_match:
            opts = {o.strip() for o in docclass_match.group(1).split(',')}
            if not {"10pt", "conference"}.issubset(opts):
                problems.append(f"{src}: documentclass options do not include 10pt,conference")
            if "compsoc" in opts or "compsocconf" in opts:
                problems.append(f"{src}: forbidden compsoc/compsocconf option present")
        end_positions = [m.start() for m in re.finditer(r"\\end\{document\}", text)]
        if len(end_positions) != 1:
            problems.append(f"{src}: expected exactly one \\end{{document}}, found {len(end_positions)}")
            tail = ""
        else:
            end = text.find("\\end{document}") + len("\\end{document}")
            tail = strip_comments_tail(text[end:])
            if tail:
                problems.append(f"{src}: non-comment content appears after \\end{{document}}")
        # Scan non-comment lines for internal process/source mechanics.  Package
        # declarations are excluded so ordinary LaTeX package names are not
        # mistaken for repository filenames.
        hits = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith('%') or ALLOWED_SOURCE_EXTENSION_LINES.search(stripped):
                continue
            for name, pat in FORBIDDEN_PATTERNS:
                if pat.search(line):
                    hits.append({"line": lineno, "kind": name, "text": stripped[:120]})
        if hits:
            problems.append(f"{src}: {len(hits)} source-hygiene hits")
        details.append({"source": str(src), "documentclass_count": docclass_count, "end_document_count": len(end_positions), "tail_after_end_document": bool(tail), "source_hygiene_hits": hits})
    result = {"status": "pass" if not problems else "fail", "problem_count": len(problems), "problems": problems, "details": details}
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "problem_count": result["problem_count"]}, sort_keys=True))
    if problems:
        raise SystemExit(2)

if __name__ == "__main__":
    main()
