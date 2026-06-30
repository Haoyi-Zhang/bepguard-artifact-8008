"""Strict rendered-PDF boundary audit for 10-page body plus references-only pages."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

sys.dont_write_bytecode = True


def _pages(pdf_path: Path) -> List[Dict[str, Any]]:
    try:
        import fitz  # type: ignore
    except Exception as exc:  # pragma: no cover
        return [{"error": f"PyMuPDF unavailable: {exc}"}]
    doc = fitz.open(str(pdf_path))
    out: List[Dict[str, Any]] = []
    for i, page in enumerate(doc):
        text = " ".join(page.get_text("text").split())
        pix = page.get_pixmap(matrix=fitz.Matrix(120/72, 120/72), colorspace=fitz.csGRAY, alpha=False)
        data = pix.samples; w = pix.width; h = pix.height
        bottom = 0
        for y in range(h):
            row = data[y*w:(y+1)*w]
            if any(v < 250 for v in row):
                bottom = y + 1
        out.append({"page": i + 1, "text": text, "text_prefix": text[:180], "ink_bottom_fraction": round(bottom / h, 4)})
    return out


def _is_reference_heading_prefix(text: str) -> bool:
    norm = re.sub(r"\s+", " ", text.strip()).upper()
    return norm.startswith("REFERENCES") or norm.startswith("R EFERENCES")


def audit_pdf_boundary(root: Path) -> Dict[str, Any]:
    problems: List[str] = []
    pages = _pages(root / "paper" / "main.pdf")
    if pages and "error" in pages[0]:
        problems.append(str(pages[0]["error"]))
    if len(pages) != 12:
        problems.append(f"main.pdf has {len(pages)} pages, expected 12")
    if len(pages) >= 12:
        p10, p11, p12 = pages[9], pages[10], pages[11]
        if _is_reference_heading_prefix(p10["text"]):
            problems.append("references begin on body page 10")
        if not _is_reference_heading_prefix(p11["text"]):
            problems.append(f"page 11 is not references-only; prefix={p11['text_prefix']!r}")
        if re.search(r"\bBEP-IR\b|\bBEPGuard\b|policy intent drift|browser-effective", p11["text"][:300], re.I):
            problems.append("page 11 contains body-like text before the references region")
        if p10["ink_bottom_fraction"] < 0.88:
            problems.append(f"page 10 visual density too low: {p10['ink_bottom_fraction']}")
        if not re.search(r"\[\d+\]", p11["text"] + " " + p12["text"]):
            problems.append("references pages do not contain numbered bibliography entries")
    return {
        "status": "pass" if not problems else "fail",
        "problem_count": len(problems),
        "problems": problems,
        "main_pages": len(pages),
        "body_pages": "1-10" if len(pages) == 12 else "unknown",
        "references_only_pages": "11-12" if len(pages) == 12 and not problems else "unverified",
        "page_10_ink_bottom_fraction": pages[9].get("ink_bottom_fraction") if len(pages) >= 10 else None,
        "page_11_prefix": pages[10].get("text_prefix") if len(pages) >= 11 else None,
        "page_12_prefix": pages[11].get("text_prefix") if len(pages) >= 12 else None,
        "interpretation": "Strict rendered-PDF boundary audit: page 10 must remain body text, page 11 must start with the references heading, and no body-like prose may precede references on page 11.",
    }


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
