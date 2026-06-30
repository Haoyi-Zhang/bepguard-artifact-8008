"""Rendered-PDF density and page-boundary audit for the camera-ready-sized draft."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

sys.dont_write_bytecode = True


def _count_bib_entries(text: str) -> int:
    return len(re.findall(r"^@\w+\s*\{", text, re.M))


def _count_cites(text: str) -> int:
    keys = set()
    for match in re.finditer(r"\\cite\{([^}]+)\}", text):
        keys.update(k.strip() for k in match.group(1).split(",") if k.strip())
    return len(keys)


def _render_density(pdf_path: Path, dpi: int = 120) -> List[Dict[str, Any]]:
    try:
        import fitz  # type: ignore
    except Exception as exc:  # pragma: no cover - environment diagnostic
        return [{"error": f"PyMuPDF unavailable: {exc}"}]
    doc = fitz.open(str(pdf_path))
    scale = dpi / 72.0
    mat = fitz.Matrix(scale, scale)
    pages: List[Dict[str, Any]] = []
    for index, page in enumerate(doc):
        pix = page.get_pixmap(matrix=mat, colorspace=fitz.csGRAY, alpha=False)
        data = pix.samples
        w, h = pix.width, pix.height
        min_x, min_y, max_x, max_y = w, h, -1, -1
        # Scan rendered grayscale bytes; values below 250 are treated as ink.
        for y in range(h):
            row = data[y*w:(y+1)*w]
            for x, value in enumerate(row):
                if value < 250:
                    if x < min_x: min_x = x
                    if y < min_y: min_y = y
                    if x > max_x: max_x = x
                    if y > max_y: max_y = y
        if max_x < 0:
            bbox = None
            bottom_fraction = 0.0
        else:
            bbox = [min_x, min_y, max_x + 1, max_y + 1]
            bottom_fraction = (max_y + 1) / h
        pages.append({
            "page": index + 1,
            "width": w,
            "height": h,
            "ink_bbox": bbox,
            "ink_bottom_fraction": round(bottom_fraction, 4),
            "text_excerpt": " ".join(page.get_text("text").split())[:120],
        })
    return pages


def audit_pdf_density(root: Path) -> Dict[str, Any]:
    problems: List[str] = []
    main_pdf = root / "paper" / "main.pdf"
    main_tex = root / "paper" / "main.tex"
    bib = root / "paper" / "references.bib"
    if not main_pdf.exists():
        problems.append("main.pdf missing")
        pages: List[Dict[str, Any]] = []
    else:
        pages = _render_density(main_pdf)
        if pages and "error" in pages[0]:
            problems.append(str(pages[0]["error"]))
    if len(pages) != 12:
        problems.append(f"main.pdf has {len(pages)} rendered pages, expected 12")
    if len(pages) >= 12:
        for page in pages[:10]:
            if float(page.get("ink_bottom_fraction", 0.0)) < 0.88:
                problems.append(f"body page {page.get('page')} does not visually fill the expected text block")
        p10_text = pages[9].get("text_excerpt", "")
        p11_text = pages[10].get("text_excerpt", "")
        if "references" in p10_text.lower():
            problems.append("references begin before page 11")
        if "references" not in p11_text.lower():
            problems.append("page 11 does not start the references region")
    bib_entries = _count_bib_entries(bib.read_text(encoding="utf-8")) if bib.exists() else 0
    cited_keys = _count_cites(main_tex.read_text(encoding="utf-8")) if main_tex.exists() else 0
    if not (70 <= bib_entries <= 80):
        problems.append(f"BibTeX entry count {bib_entries} is outside 70-80 target")
    if cited_keys != bib_entries:
        problems.append(f"cited-key count {cited_keys} does not match BibTeX entry count {bib_entries}")
    return {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "main_pages": len(pages),
        "body_pages_checked": min(len(pages), 10),
        "min_body_ink_bottom_fraction": min([float(p.get("ink_bottom_fraction", 0.0)) for p in pages[:10]], default=0.0),
        "page_10_ink_bottom_fraction": pages[9].get("ink_bottom_fraction") if len(pages) >= 10 else None,
        "references_start_page": 11 if len(pages) >= 11 and "references" in str(pages[10].get("text_excerpt", "")).lower() else None,
        "bib_entries": bib_entries,
        "cited_keys": cited_keys,
        "render_dpi": 120,
        "page_metrics": pages,
        "interpretation": "Rendered-PDF audit for page density and page-boundary discipline; it checks release PDF shape and reference-count target after LaTeX compilation.",
    }


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
